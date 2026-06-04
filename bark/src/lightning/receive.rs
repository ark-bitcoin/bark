use anyhow::Context;
use bitcoin::Amount;
use futures::StreamExt;
use lightning_invoice::Bolt11Invoice;
use log::{error, info, warn};
use server_rpc::protos;

use ark::lightning::{Bolt11InvoiceExt, PaymentHash};

use crate::Wallet;
use crate::actions::DriveMode;
use crate::actions::lightning::receive::{
	Htlcs, LightningReceive, LightningReceiveState, Progress,
	ln_recv_action_id, start_lightning_receive
};
use crate::movement::MovementStatus;
use crate::movement::update::MovementUpdate;

impl Wallet {
	/// Returns every in-progress lightning receive checkpoint, newest first.
	pub async fn pending_lightning_receives(&self) -> anyhow::Result<Vec<LightningReceive>> {
		let mut result = Vec::new();
		for cp in self.inner.db.get_all_wallet_action_checkpoints().await? {
			if let Some(recv) = cp.into_lightning_receive() {
				result.push(recv);
			}
		}
		Ok(result)
	}

	/// Calculates how much balance can currently be claimed via inbound
	/// lightning payments. Invoices that have not yet been paid (and so hold
	/// no HTLC vtxos) are not included.
	pub async fn claimable_lightning_receive_balance(&self) -> anyhow::Result<Amount> {
		let mut total = Amount::ZERO;
		for recv in self.pending_lightning_receives().await? {
			let vtxo_ids = match &recv.progress {
				Progress::AwaitingPayment => continue,
				Progress::HtlcsReady(htlcs) => &htlcs.vtxo_ids,
				Progress::PreimageRevealed(htlcs) => &htlcs.vtxo_ids,
			};
			for id in vtxo_ids {
				total += self.get_vtxo_by_id(*id).await?.vtxo.amount();
			}
		}
		Ok(total)
	}

	/// Drives every pending lightning receive forward by one step (or to
	/// completion if it's ready). Each action runs to its next park
	/// independently; errors on one don't stop the others.
	pub async fn sync_pending_lightning_receives(&self) -> anyhow::Result<()> {
		let pending = self.pending_lightning_receives().await?;
		if pending.is_empty() {
			return Ok(());
		}
		info!("Syncing {} pending lightning receives", pending.len());
		for recv in pending {
			let id = recv.id();
			if let Err(e) = self.drive_action(recv, DriveMode::UntilParkOrDone).await {
				warn!("Failed to sync lightning receive {}: {:#}", id, e);
			}
		}
		Ok(())
	}

	/// Fetches the current checkpoint for the given payment hash, if any.
	pub async fn lightning_receive_checkpoint(&self, hash: PaymentHash)
		-> anyhow::Result<Option<LightningReceive>>
	{
		Ok(self.inner.db.get_wallet_action_checkpoint(&ln_recv_action_id(hash)).await?
			.and_then(|cp| cp.into_lightning_receive()))
	}

	/// Triage a payment hash: settled, in-progress, or unknown.
	pub async fn lightning_receive_state(&self, hash: PaymentHash)
		-> anyhow::Result<LightningReceiveState>
	{
		if let Some(settled) = self.inner.db.get_settled_lightning_receive(hash).await? {
			return Ok(LightningReceiveState::Settled(settled));
		}
		if let Some(cp) = self.lightning_receive_checkpoint(hash).await? {
			return Ok(LightningReceiveState::InProgress(cp));
		}
		bail!("no pending lightning receive found for this payment hash");
	}

	/// Create, store and return a [`Bolt11Invoice`] for an incoming
	/// lightning payment.
	///
	/// This mints the invoice (and a fresh preimage) and persists an
	/// `AwaitingPayment` checkpoint; it does not wait for payment. The
	/// background sync (or an explicit [`Self::try_claim_lightning_receive`])
	/// drives the receive once an inbound HTLC arrives.
	///
	/// An optional `description` is embedded as the invoice memo. An optional
	/// `token` authenticates the later claim when the wallet owns no spendable
	/// vtxo to prove ownership with.
	pub async fn bolt11_invoice(
		&self,
		amount: Amount,
		description: Option<String>,
		token: Option<String>,
	) -> anyhow::Result<Bolt11Invoice> {
		let start = start_lightning_receive(self, amount, description, token).await?;
		self.inner.db.upsert_wallet_action_checkpoint(&start.id(), &start.clone().into()).await?;
		Ok(start.invoice.clone())
	}

	/// Cancel a pending lightning receive.
	///
	/// Only valid before the server has granted HTLC-recv vtxos (i.e. while
	/// the receive is still in [`Progress::AwaitingPayment`]): we ask the
	/// server to cancel the hold invoice and drop our checkpoint. Once HTLCs
	/// are granted the server has committed, so we refuse — the receive must
	/// complete or be abandoned on its own near expiry.
	pub async fn cancel_lightning_receive(&self, hash: PaymentHash) -> anyhow::Result<()> {
		let key = ln_recv_action_id(hash);
		// Don't fight a live drive of the same action.
		let _guard = self.inner.lock_manager.try_lock(&key).await
			.context("receive operation already in progress for this payment")?;

		let recv = self.lightning_receive_checkpoint(hash).await?
			.context("no pending lightning receive found for this payment hash")?;

		match recv.progress {
			Progress::AwaitingPayment => {
				// Best-effort server cancel: an abandoned hold invoice just
				// expires server-side, so don't fail the local cancel on error.
				if let Ok((mut srv, _)) = self.require_server().await {
					if let Err(e) = srv.client.cancel_lightning_receive(
						protos::CancelLightningReceiveRequest { payment_hash: hash.to_vec() },
					).await {
						warn!("server did not cancel lightning receive {}: {}", hash, e);
					}
				}
				self.stop_wallet_action(&key).await?;
				Ok(())
			},
			Progress::HtlcsReady(_) => {
				bail!("cannot cancel: HTLCs already granted; the receive will complete \
					or be abandoned near expiry");
			},
			Progress::PreimageRevealed(_) => {
				bail!("cannot cancel: preimage has already been revealed");
			},
		}
	}

	/// Fall back to exiting a stuck lightning receive's HTLC vtxos on-chain.
	///
	/// Once the preimage has been revealed, a failed claim leaves the receive
	/// pending rather than auto-exiting (see [`Progress::PreimageRevealed`]).
	/// This lets the caller explicitly publish the preimage on-chain by
	/// exiting the HTLC vtxos, finishing the receive as failed.
	///
	/// Preconditions:
	/// - the preimage must already have been revealed (the receive is in
	///   [`Progress::PreimageRevealed`]);
	/// - the HTLC vtxos must still be present.
	pub async fn attempt_lightning_receive_exit(
		&self,
		payment: impl Into<PaymentHash>,
	) -> anyhow::Result<()> {
		let hash = payment.into();
		let key = ln_recv_action_id(hash);
		// Don't fight a live drive of the same action.
		let _guard = self.inner.lock_manager.try_lock(&key).await
			.context("receive operation already in progress for this payment")?;

		let recv = self.lightning_receive_checkpoint(hash).await?
			.context("no pending lightning receive found for this payment hash")?;

		let htlcs = match &recv.progress {
			Progress::PreimageRevealed(htlcs) => htlcs,
			_ => bail!("preimage must be revealed before attempting to exit"),
		};

		self.exit_lightning_receive_htlcs(&recv, htlcs).await?;

		// The receive is now terminal: release any locks and drop the
		// checkpoint row.
		self.stop_wallet_action(&key).await?;
		Ok(())
	}

	/// Escalation: when the preimage has been revealed but the claim cannot
	/// complete, exit the HTLC vtxos on-chain and finish the movement as
	/// failed. Driven explicitly by the caller via
	/// [`Wallet::attempt_lightning_receive_exit`]; the receive is never
	/// auto-exited.
	pub async fn exit_lightning_receive_htlcs(
		&self,
		recv: &LightningReceive,
		htlcs: &Htlcs,
	) -> anyhow::Result<()> {
		warn!("Exiting HTLC VTXOs for lightning receive {}", recv.payment_hash);

		let mut vtxos = Vec::with_capacity(htlcs.vtxo_ids.len());
		for id in htlcs.vtxo_ids.iter() {
			vtxos.push(self.get_vtxo_by_id(*id).await?.vtxo);
		}
		let vtxo_refs = vtxos.iter().collect::<Vec<_>>();
		self.inner.exit.start_exit_for_vtxos(&vtxo_refs).await?;

		self.inner.movements.finish_movement_with_update(
			htlcs.movement_id,
			MovementStatus::Failed,
			MovementUpdate::new().exited_vtxos(vtxo_refs),
		).await?;

		// We only exit once the preimage has been revealed (Claiming phase), so
		// record it permanently: the exit subsystem needs it to witness the
		// on-chain HTLC-recv spend, possibly after this checkpoint is gone.
		let amount = recv.invoice.get_payment_amount(None).unwrap_or(Amount::ZERO);
		self.inner.db.record_settled_lightning_receive(
			recv.payment_hash, recv.payment_preimage, &recv.invoice, amount,
		).await?;

		Ok(())
	}

	/// Drive a lightning receive forward (e.g. to claim an inbound payment).
	/// `wait=true` keeps driving past parks until the action terminates.
	/// Returns the current state.
	pub async fn try_claim_lightning_receive(&self, hash: PaymentHash, wait: bool)
		-> anyhow::Result<LightningReceiveState>
	{
		if let Some(recv) = self.lightning_receive_checkpoint(hash).await? {
			let mode = if wait { DriveMode::UntilDone } else { DriveMode::UntilParkOrDone };
			self.drive_action(recv, mode).await?;
		}
		self.lightning_receive_state(hash).await
	}

	/// Drive every pending lightning receive forward, returning the resulting
	/// state of each. Errors on individual receives are logged, not returned,
	/// so one stuck receive doesn't block the others.
	pub async fn try_claim_all_lightning_receives(&self, wait: bool)
		-> anyhow::Result<Vec<LightningReceiveState>>
	{
		let pending = self.pending_lightning_receives().await?;
		let total = pending.len();

		if total == 0 {
			return Ok(vec![]);
		}

		let results: Vec<_> = tokio_stream::iter(pending)
			.map(|rcv| async move {
				self.try_claim_lightning_receive(rcv.invoice.into(), wait).await
			})
			.buffer_unordered(3)
			.collect()
			.await;

		let mut claimed = vec![];
		let mut failed = 0;

		for result in results {
			match result {
				Ok(receive) => claimed.push(receive),
				Err(e) => {
					error!("Error claiming lightning receive: {:#}", e);
					failed += 1;
				}
			}
		}

		if failed > 0 {
			info!(
				"Lightning receive claims: {} succeeded, {} failed out of {} pending",
				claimed.len(), failed, total
			);
		}

		if claimed.is_empty() {
			anyhow::bail!("All {} lightning receive claim(s) failed", failed);
		}

		Ok(claimed)
	}
}

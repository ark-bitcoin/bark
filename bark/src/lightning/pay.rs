use std::fmt;

use anyhow::Context;
use bitcoin::Amount;
use lightning::util::ser::Writeable;
use lnurllib::lightning_address::LightningAddress;
use lnurllib::lnurl::LnUrl;
use log::{info, warn};
use server_rpc::protos;

use ark::lightning::{Bolt12Invoice, Bolt12InvoiceExt, Invoice, Offer, PaymentHash, Preimage};

use crate::Wallet;
use crate::WalletVtxo;
use crate::actions::DriveMode;
use crate::actions::lightning::pay::ln_pay_action_id;
use crate::actions::lightning::pay::{
	Htlcs, LightningSend, LightningSendState, Progress, settle_lightning_send_payment,
	start_lightning_send,
};
use crate::lightning::{lnaddr_invoice, lnurlp_invoice};
use crate::movement::PaymentMethod;

impl Wallet {
	/// Returns every in-progress lightning send checkpoint.
	pub async fn pending_lightning_sends(&self) -> anyhow::Result<Vec<LightningSend>> {
		let mut result = Vec::new();
		for cp in self.inner.db.get_all_wallet_action_checkpoints().await? {
			if let Some(ls) = cp.into_lightning_send() {
				result.push(ls);
			}
		}
		Ok(result)
	}

	/// Returns every failed lightning payment currently stuck because revocation has failed. When
	/// HTLC VTXOs approach their expiry, the user should consider starting an exit for each VTXO.
	/// This will only happen automatically if the [Wallet::allow_lightning_send_to_exit] is called.
	pub async fn stuck_failed_lightning_sends(&self) -> anyhow::Result<Vec<LightningSend>> {
		let mut result = Vec::new();
		for send in self.pending_lightning_sends().await? {
			if send.has_failed_revocation() {
				result.push(send);
			}
		}
		Ok(result)
	}

	/// Opts the lightning send identified by `hash` into auto-exiting its
	/// HTLCs once they approach expiry, after revocation has failed.
	///
	/// The flag is persisted on the action checkpoint; the next drive
	/// (e.g. via [`Self::sync_pending_lightning_send_vtxos`] or
	/// [`Self::check_lightning_payment`]) picks it up and exits when
	/// HTLCs are near expiry. See [`LightningSend::has_failed_revocation`].
	pub async fn allow_lightning_send_to_exit(&self, hash: PaymentHash) -> anyhow::Result<()> {
		let key = ln_pay_action_id(hash);
		let _guard = self.inner.lock_manager.try_lock(&key).await
			.context("Payment operation already in progress for this invoice")?;

		let mut send = self.lightning_send_checkpoint(hash).await?
			.with_context(|| format!("no in-progress lightning send for payment hash {hash}"))?;
		send.allow_exit_of_htlcs = true;
		self.inner.db.upsert_wallet_action_checkpoint(&send.id(), &send.into()).await?;
		Ok(())
	}

	/// Returns the VTXOs currently held by any in-progress lightning send.
	pub async fn pending_lightning_send_vtxos(&self) -> anyhow::Result<Vec<WalletVtxo>> {
		let mut vtxos = Vec::new();
		for send in self.pending_lightning_sends().await? {
			let ids: Vec<_> = match &send.progress {
				Progress::Start => send.input_vtxo_ids.clone(),
				Progress::HtlcReceived(h) => h.vtxo_ids.clone(),
				Progress::PaymentInitiated(h) => h.vtxo_ids.clone(),
				Progress::RevocableHtlcs { htlcs, .. } => htlcs.vtxo_ids.clone(),
				Progress::RevocationStuck { htlcs, .. } => htlcs.vtxo_ids.clone(),
			};
			for id in ids {
				vtxos.push(self.get_vtxo_by_id(id).await?);
			}
		}
		Ok(vtxos)
	}

	/// Drives every pending lightning send forward by one step (or to
	/// completion if it's ready). Each action runs to its next park
	/// independently; errors on one don't stop the others.
	pub async fn sync_pending_lightning_send_vtxos(&self) -> anyhow::Result<()> {
		let pending = self.pending_lightning_sends().await?;
		if pending.is_empty() {
			return Ok(());
		}
		info!("Syncing {} pending lightning sends", pending.len());
		for send in pending {
			let id = send.id();
			if let Err(e) = self.drive_action(send, DriveMode::UntilParkOrDone).await {
				warn!("Failed to sync lightning send {}: {:#}", id, e);
			}
		}
		Ok(())
	}

	/// Fetches the current checkpoint for the given payment hash, if any.
	pub async fn lightning_send_checkpoint(&self, hash: PaymentHash)
		-> anyhow::Result<Option<LightningSend>>
	{
		Ok(self.inner.db.get_wallet_action_checkpoint(&ln_pay_action_id(hash)).await?
			.and_then(|cp| cp.into_lightning_send()))
	}

	/// Triage a payment hash: paid, in-progress, or unknown.
	pub async fn lightning_send_state(&self, hash: PaymentHash)
		-> anyhow::Result<LightningSendState>
	{
		if let Some(paid) = self.inner.db.get_paid_invoice(hash).await? {
			return Ok(LightningSendState::Paid(paid));
		}
		if let Some(cp) = self.lightning_send_checkpoint(hash).await? {
			return Ok(LightningSendState::InProgress(cp));
		}
		Ok(LightningSendState::Unknown)
	}

	/// Cheap "has this invoice ever been paid?" check.
	pub async fn is_invoice_paid(&self, hash: PaymentHash) -> anyhow::Result<bool> {
		Ok(self.inner.db.get_paid_invoice(hash).await?.is_some())
	}

	/// Drive a lightning send forward (e.g., to settle a pending one
	/// or revoke a failed one). `wait=true` keeps driving past parks
	/// until the action terminates. Returns the current state.
	pub async fn check_lightning_payment(&self, hash: PaymentHash, wait: bool)
		-> anyhow::Result<LightningSendState>
	{
		let send = match self.lightning_send_state(hash).await? {
			LightningSendState::InProgress(s) => s,
			s => return Ok(s),
		};

		let mode = if wait { DriveMode::UntilDone } else { DriveMode::UntilParkOrDone };
		self.drive_action(send, mode).await?;
		self.lightning_send_state(hash).await
	}

	/// Settle a payment using a preimage we already have (e.g. from a
	/// mailbox notification), skipping the server poll.
	pub(crate) async fn settle_lightning_send_with_preimage(
		&self,
		send: LightningSend,
		htlcs: Htlcs,
		preimage: Preimage,
	) -> anyhow::Result<()> {
		let payment_hash = send.invoice.payment_hash();
		if preimage.compute_payment_hash() != payment_hash {
			bail!("preimage mismatch for payment hash {}", payment_hash);
		}
		settle_lightning_send_payment(self, &send, &htlcs, preimage).await?;
		// Remove the in-progress row now that the paid_invoice record
		// is the source of truth.
		self.inner.db.remove_wallet_action_checkpoint(&ln_pay_action_id(payment_hash)).await?;
		Ok(())
	}

	/// Pays a Lightning [Invoice] using Ark VTXOs.
	///
	/// `wait=true` keeps the call open until the payment settles or
	/// fails; `wait=false` returns once the payment has been kicked off
	/// and lets the background sync drive it to completion. Returns the
	/// parsed [`Invoice`] in either case; callers wanting the preimage
	/// can look up the settled record via [`Self::lightning_send_state`].
	pub async fn pay_lightning_invoice<T>(
		&self,
		invoice: T,
		user_amount: Option<Amount>,
		wait: bool,
	) -> anyhow::Result<Invoice>
	where
		T: TryInto<Invoice>,
		T::Error: std::error::Error + fmt::Display + Send + Sync + 'static,
	{
		let invoice = invoice.try_into().context("failed to parse invoice")?;
		let amount = invoice.get_payment_amount(user_amount)?;
		info!("Sending bolt11 payment of {} to invoice {}", amount, invoice);
		self.make_lightning_payment(&invoice, invoice.clone().into(), user_amount, wait).await?;
		Ok(invoice)
	}

	/// Same as [`Self::pay_lightning_invoice`] but resolves the invoice
	/// from a [`LightningAddress`] first.
	pub async fn pay_lightning_address(
		&self,
		addr: &LightningAddress,
		amount: Amount,
		comment: Option<impl AsRef<str>>,
		wait: bool,
	) -> anyhow::Result<Invoice> {
		let comment = comment.as_ref();
		let invoice: Invoice = lnaddr_invoice(addr, amount, comment).await
			.context("lightning address error")?.into();
		info!("Sending {} to lightning address {}", amount, addr);
		self.make_lightning_payment(&invoice, addr.clone().into(), None, wait).await?;
		info!("Paid invoice {}", invoice);
		Ok(invoice)
	}

	/// Same as [`Self::pay_lightning_address`] but resolves the invoice from a
	/// raw LNURL-pay link (`lnurl1…`) first.
	///
	/// Errors if the link decodes to a non-pay LNURL (auth, withdraw, channel).
	pub async fn pay_lnurl(
		&self,
		lnurl: &LnUrl,
		amount: Amount,
		comment: Option<impl AsRef<str>>,
		wait: bool,
	) -> anyhow::Result<Invoice> {
		let invoice: Invoice = lnurlp_invoice(&lnurl.url, amount, comment).await
			.context("lnurl-pay error")?.into();
		info!("Sending {} to lnurl {}", amount, lnurl);
		self.make_lightning_payment(&invoice, lnurl.clone().into(), None, wait).await?;
		info!("Paid invoice {}", invoice);
		Ok(invoice)
	}

	/// Attempts to pay the given BOLT12 [`Offer`] using offchain funds.
	pub async fn pay_lightning_offer(
		&self,
		offer: Offer,
		user_amount: Option<Amount>,
		wait: bool,
	) -> anyhow::Result<Invoice> {
		let (mut srv, _) = self.require_server().await?;

		let offer_bytes = {
			let mut bytes = Vec::new();
			offer.write(&mut bytes).context("failed to serialize BOLT12 offer")?;
			bytes
		};

		let req = protos::FetchBolt12InvoiceRequest {
			offer: offer_bytes,
			amount_sat: user_amount.map(|a| a.to_sat()),
		};

		if let Some(amt) = user_amount {
			info!("Sending bolt12 payment of {} (user amount) to offer {}", amt, offer);
		} else if let Some(amt) = offer.amount() {
			info!("Sending bolt12 payment of {:?} (invoice amount) to offer {}", amt, offer);
		} else {
			warn!("Paying offer without amount nor user amount provided: {}", offer);
		}

		let resp = srv.client.fetch_bolt12_invoice(req).await?.into_inner();
		let invoice = Bolt12Invoice::try_from(resp.invoice)
			.map_err(|e| anyhow!("invalid invoice: {:?}", e))?;

		invoice.validate_issuance(&offer)
			.context("invalid BOLT12 invoice received from offer")?;

		let invoice: Invoice = invoice.into();
		self.make_lightning_payment(&invoice, offer.into(), None, wait).await?;
		info!("Paid invoice: {}", invoice);
		Ok(invoice)
	}

	/// Low-level lightning payment primitive. Exposed for
	/// [`PaymentMethod::Custom`] use cases (e.g. LNURL-pay).
	pub async fn make_lightning_payment(
		&self,
		invoice: &Invoice,
		original_payment_method: PaymentMethod,
		user_amount: Option<Amount>,
		wait: bool,
	) -> anyhow::Result<()> {
		if !original_payment_method.is_lightning() && !original_payment_method.is_custom() {
			bail!("Invalid original payment method for lightning payment");
		}

		let payment_hash = invoice.payment_hash();
		let mode = if wait { DriveMode::UntilDone } else { DriveMode::UntilParkOrDone };

		if self.is_invoice_paid(payment_hash).await? {
			bail!("Invoice has already been paid");
		}

		let key = ln_pay_action_id(payment_hash);
		let guard = self.inner.lock_manager.try_lock(&key).await
			.context("Payment operation already in progress for this invoice")?;

		// Resume an existing checkpoint, or build a fresh send.
		let action = match self.lightning_send_checkpoint(payment_hash).await? {
			Some(existing) => existing,
			None => {
				let start = start_lightning_send(
					self, invoice.clone(), user_amount, original_payment_method,
				).await?;

				self.inner.db.upsert_wallet_action_checkpoint(
					&start.id(), &start.clone().into()
				).await?;

				start
			},
		};

		self.drive_action_with_guard(action, mode, guard).await
	}
}

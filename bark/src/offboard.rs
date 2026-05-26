
use anyhow::Context;
use bitcoin::{Amount, Txid};
use log::{info, warn};

use ark::vtxo::VtxoRef;

use crate::Wallet;
use crate::actions::{DriveMode, WalletActionId};
use crate::actions::offboard::{Offboard, Progress, StartOffboardSpec, start_offboard};

impl Wallet {
	/// Returns every in-progress offboard checkpoint.
	pub async fn pending_offboards(&self) -> anyhow::Result<Vec<Offboard>> {
		let mut result = Vec::new();
		for cp in self.inner.db.get_all_wallet_action_checkpoints().await? {
			if let Some(o) = cp.into_offboard() {
				result.push(o);
			}
		}
		Ok(result)
	}

	/// Drives every pending offboard forward by one step (or to completion
	/// if it's ready). Each action runs to its next park independently;
	/// errors on one don't stop the others.
	pub async fn sync_pending_offboards(&self) -> anyhow::Result<()> {
		let pending = self.pending_offboards().await?;
		if pending.is_empty() {
			return Ok(());
		}
		info!("Syncing {} pending offboard(s)", pending.len());
		for action in pending {
			let id = action.id();
			if let Err(e) = self.drive_action(action, DriveMode::UntilParkOrDone).await {
				warn!("Failed to sync offboard {}: {:#}", id, e);
			}
		}
		Ok(())
	}

	/// Fetches the current checkpoint for the given action id, if any.
	pub async fn offboard_checkpoint(&self, id: &WalletActionId)
		-> anyhow::Result<Option<Offboard>>
	{
		Ok(self.inner.db.get_wallet_action_checkpoint(id).await?
			.and_then(|cp| cp.into_offboard()))
	}

	/// Send to an onchain address using your offchain balance.
	///
	/// We can only offboard whole VTXOs, so this kicks off an arkoor
	/// split first to produce an exact-sized vtxo plus change, then
	/// offboards the new vtxo.
	pub async fn send_onchain(
		&self,
		destination: bitcoin::Address,
		amount: Amount,
	) -> anyhow::Result<Txid> {
		let action = start_offboard(
			self, destination, StartOffboardSpec::SendOnchain { amount },
		).await?;
		self.run_offboard(action).await
	}

	/// Offboard all VTXOs to a given [bitcoin::Address].
	pub async fn offboard_all(&self, address: bitcoin::Address) -> anyhow::Result<Txid> {
		let input_vtxos = self.spendable_vtxos().await?;
		let action = start_offboard(
			self, address, StartOffboardSpec::OffboardWhole { vtxos: input_vtxos },
		).await?;
		self.run_offboard(action).await
	}

	/// Offboard the given VTXOs to a given [bitcoin::Address].
	pub async fn offboard_vtxos<V: VtxoRef>(
		&self,
		vtxos: impl IntoIterator<Item = V>,
		address: bitcoin::Address,
	) -> anyhow::Result<Txid> {
		let mut input_vtxos = vec![];
		for v in vtxos {
			let id = v.vtxo_id();
			let vtxo = match self.inner.db.get_wallet_vtxo(id).await? {
				Some(vtxo) => vtxo,
				_ => bail!("cannot find requested vtxo: {}", id),
			};
			input_vtxos.push(vtxo);
		}
		let action = start_offboard(
			self, address, StartOffboardSpec::OffboardWhole { vtxos: input_vtxos },
		).await?;
		self.run_offboard(action).await
	}

	async fn run_offboard(&self, action: Offboard) -> anyhow::Result<Txid> {
		let offboard_id = action.id();
		let guard = self.inner.lock_manager.try_lock(&offboard_id).await
			.context("offboard action already in progress")?;

		self.inner.db.upsert_wallet_action_checkpoint(&offboard_id, &action.clone().into()).await
			.context("failed to persist initial offboard checkpoint")?;

		// Drive once synchronously to get past the server interaction; the
		// rest (confirmation polling) is left to sync_pending_offboards.
		self.drive_action_with_guard(action, DriveMode::UntilParkOrDone, guard).await?;

		match self.offboard_checkpoint(&offboard_id).await? {
			Some(o) => match o.progress {
				Progress::AwaitingConfirmations { offboard_txid, .. } => Ok(offboard_txid),
				// A transient error parked the action before broadcast (the
				// executor logged the error itself). The checkpoint
				// survives, so the next wallet sync re-drives it.
				other => bail!(
					"offboard {} could not complete yet (parked in {:?}); \
					it remains pending and will be retried on wallet sync",
					offboard_id, other,
				),
			},
			None => bail!("offboard {} finished without producing a txid", offboard_id),
		}
	}
}

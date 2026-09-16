//! The wallet balance: which sats can be spent right now and which are held
//! by an operation in progress.

use std::collections::HashMap;

use bitcoin::Amount;
use bitcoin_ext::BlockHeight;
use log::{debug, warn};

use crate::Wallet;
use crate::exit::ExitStateKind;
use crate::vtxo::{VtxoState, VtxoStateKind};

/// The different balances of a Bark wallet.
#[derive(Debug, Clone)]
pub struct Balance {
	/// Coins that are spendable in the Ark, either in-round or out-of-round.
	pub spendable: Amount,
	/// Sats in VTXOs that can no longer be sent in an arkoor payment because
	/// they have expired or their exit depth has reached the server's limit.
	/// Nothing holds them, and they can still be offboarded, exited or
	/// refreshed, but they are kept out of [Balance::spendable] until
	/// maintenance has refreshed them. See [crate::WalletVtxo::needs_refresh].
	pub needs_refresh: Amount,
	/// Coins that are in the process of being sent over Lightning.
	pub pending_lightning_send: Amount,
	/// Coins that are in the process of being received over Lightning.
	pub claimable_lightning_receive: Amount,
	/// Coins locked in a round.
	pub pending_in_round: Amount,
	/// Sats in VTXOs whose unilateral exit has committed on-chain but which
	/// have not been claimed to the on-chain wallet yet. These VTXOs are
	/// [`crate::vtxo::VtxoStateKind::Exited`] and unusable in the Ark protocol.
	/// An exit that can still be canceled isn't counted here.
	pub pending_exit: Amount,
	/// Coins that are pending sufficient confirmations from board transactions.
	pub pending_board: Amount,
}

impl Wallet {
	/// Return the [Balance] of the wallet.
	///
	/// When not running the daemon, make sure you sync before calling this method.
	pub async fn balance(&self) -> anyhow::Result<Balance> {
		let tip = match self.inner.chain.tip().await {
			Ok(tip) => Some(tip),
			Err(e) => {
				debug!("Chain tip unavailable for the balance, using the last one seen: {:#}", e);
				self.inner.chain.last_observed_tip().await
			},
		};
		let max_exit_depth = match self.ark_info().await {
			Ok(info) => info.map(|i| i.max_vtxo_exit_depth),
			Err(e) => {
				debug!("Server info unavailable for the balance, judging expiry only: {:#}", e);
				None
			},
		};

		// Every VTXO the balance can count, read once.
		let vtxos = self.inner.db.get_vtxos_by_state(
			&[VtxoStateKind::Spendable, VtxoStateKind::Exited],
		).await?.into_iter().map(|v| (v.id(), v)).collect::<HashMap<_, _>>();

		let mut spendable = Amount::ZERO;
		let mut needs_refresh = Amount::ZERO;
		for vtxo in vtxos.values().filter(|v| v.state == VtxoState::Spendable) {
			// Without a tip only the depth can be judged; a tip of zero
			// expires nothing.
			if vtxo.needs_refresh(tip.unwrap_or(BlockHeight::ZERO), max_exit_depth) {
				needs_refresh += vtxo.amount();
			} else {
				spendable += vtxo.amount();
			}
		}

		let pending_lightning_send = self.pending_lightning_send_vtxos().await?.iter()
			.map(|v| v.amount())
			.sum::<Amount>();

		let claimable_lightning_receive = self.claimable_lightning_receive_balance().await?;

		let pending_board = self.pending_board_vtxos().await?.iter()
			.map(|v| v.amount())
			.sum::<Amount>();

		let pending_in_round = self.pending_round_balance().await?;

		// Read the exits from the database rather than the exit manager, whose
		// lock may be held for a while by an exit in progress.
		let exits = self.inner.db
			.get_exit_vtxo_entries_with_states(ExitStateKind::LIVE_STATES).await?;
		let mut pending_exit = Amount::ZERO;
		for exit in exits {
			if !exit.state.warrants_exited_vtxo() {
				continue;
			}
			match vtxos.get(&exit.vtxo_id) {
				Some(v) if v.state == VtxoState::Exited => pending_exit += v.amount(),
				Some(v) => warn!("Exit of VTXO {} has committed but the VTXO is {:?}",
					exit.vtxo_id, v.state,
				),
				None => warn!("Exit of VTXO {} has committed but the VTXO is spent or unknown",
					exit.vtxo_id,
				),
			}
		}

		Ok(Balance {
			spendable,
			needs_refresh,
			pending_in_round,
			pending_lightning_send,
			claimable_lightning_receive,
			pending_exit,
			pending_board,
		})
	}
}

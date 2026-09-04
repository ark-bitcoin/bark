//! The wallet balance: which sats can be spent right now and which are held
//! by an operation in progress.

use bitcoin::Amount;

use crate::Wallet;
use crate::vtxo::{FilterVtxos, VtxoStateKind};

/// The different balances of a Bark wallet.
#[derive(Debug, Clone)]
pub struct Balance {
	/// Coins that are spendable in the Ark, either in-round or out-of-round.
	pub spendable: Amount,
	/// Coins that are in the process of being sent over Lightning.
	pub pending_lightning_send: Amount,
	/// Coins that are in the process of being received over Lightning.
	pub claimable_lightning_receive: Amount,
	/// Coins locked in a round.
	pub pending_in_round: Amount,
	/// Coins held in VTXOs whose unilateral exit chain has confirmed onchain but which
	/// haven't yet been drained back to the onchain wallet. While in this state the
	/// VTXOs are [`crate::vtxo::VtxoStateKind::Exited`] and unusable in the Ark protocol; the
	/// drain transaction moves them to spendable onchain output.
	/// None if exit subsystem was unavailable
	pub pending_exit: Option<Amount>,
	/// Coins that are pending sufficient confirmations from board transactions.
	pub pending_board: Amount,
}

impl Wallet {
	/// Return the [Balance] of the wallet.
	///
	/// When not running the daemon, make sure you sync before calling this method.
	pub async fn balance(&self) -> anyhow::Result<Balance> {
		let vtxos = self.vtxos().await?;

		let spendable = {
			let mut v = vtxos.iter().collect();
			VtxoStateKind::Spendable.filter_vtxos(&mut v).await?;
			v.into_iter().map(|v| v.amount()).sum::<Amount>()
		};

		let pending_lightning_send = self.pending_lightning_send_vtxos().await?.iter()
			.map(|v| v.amount())
			.sum::<Amount>();

		let claimable_lightning_receive = self.claimable_lightning_receive_balance().await?;

		let pending_board = self.pending_board_vtxos().await?.iter()
			.map(|v| v.amount())
			.sum::<Amount>();

		let pending_in_round = self.pending_round_balance().await?;

		let pending_exit = self.exit_mgr().try_pending_total();

		Ok(Balance {
			spendable,
			pending_in_round,
			pending_lightning_send,
			claimable_lightning_receive,
			pending_exit,
			pending_board,
		})
	}
}

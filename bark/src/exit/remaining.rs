//! Read-only view of the exit transactions still awaiting confirmation.
//!
//! [Exit::remaining_exit_transactions] lists every exit transaction of the requested VTXOs not
//! yet confirmed onchain — without signing anything or touching the onchain wallet — so a third
//! party can broadcast the exits on the user's behalf. [Exit::presign_emergency_exit] signs
//! children for the same transactions.

use std::collections::HashMap;

use ark::VtxoId;
use bitcoin::Txid;

use crate::exit::{Exit, ExitError, TransactionInfo};

/// The exit transactions of a set of VTXOs still awaiting confirmation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemainingExitTransactions {
	/// The transactions each VTXO needs confirmed to be exited, in broadcast order.
	pub exits: HashMap<VtxoId, Vec<Txid>>,
	/// Every transaction referenced by `exits` exactly once, parents before children.
	pub transactions: Vec<TransactionInfo>,
}

impl Exit {
	/// Lists every exit transaction of the given VTXOs still awaiting confirmation.
	///
	/// Read-only: nothing is signed and the onchain wallet is never touched. Use
	/// [Exit::presign_emergency_exit] to sign the children. Works whether or not an exit has
	/// been started. Transaction statuses reflect the last exit sync — call
	/// [crate::Wallet::sync_exits] first for the current chain state.
	///
	/// # Errors
	/// - [ExitError::UnknownVtxo] if a VTXO id isn't known to the wallet.
	/// - [ExitError::VtxoAlreadyExited] if a VTXO has already completed its exit.
	/// - [ExitError::VtxoAlreadySpent] if a VTXO was already spent (e.g. forfeited in a round).
	pub async fn remaining_exit_transactions(
		&self,
		vtxos: &[VtxoId],
	) -> anyhow::Result<RemainingExitTransactions, ExitError> {
		let groups = self.collect_unconfirmed_exit_parents(vtxos).await?;

		// The collector lists a shared transaction only under the first VTXO referencing it, and
		// each chain is in broadcast order, so concatenating keeps parents before children.
		let mut exits = HashMap::with_capacity(groups.len());
		let mut transactions = Vec::with_capacity(groups.iter().map(|g| g.parents.len()).sum());
		for group in groups {
			transactions.extend(group.parents.into_iter()
				.map(|(tx, _)| TransactionInfo { txid: tx.compute_txid(), tx }));
			exits.insert(group.vtxo.id(), group.unconfirmed_txids);
		}

		Ok(RemainingExitTransactions { exits, transactions })
	}
}

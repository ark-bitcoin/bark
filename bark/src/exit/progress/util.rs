
use std::collections::HashMap;

use bitcoin::{Amount, FeeRate, Weight};

use ark::Vtxo;

use crate::exit::models::{ExitTx, ExitTxStatus};

/// Counts how many of the given ExitTx objects exist in either the mempool or the blockchain
pub(crate) fn count_broadcast(status: &[ExitTx]) -> usize {
	status.iter().filter(|s| match s.status {
		ExitTxStatus::BroadcastWithCpfp { .. } => true,
		ExitTxStatus::Confirmed { .. } => true,
		_ => false,
	}).count()
}


/// Counts how many of the given ExitTx objects are confirmed in the blockchain
pub(crate) fn count_confirmed(status: &[ExitTx]) -> usize {
	status.iter().filter(|s| match s.status {
		ExitTxStatus::Confirmed { .. } => true,
		_ => false,
	}).count()
}

/// Do a rudimentary check of the total exit cost for a set of vtxos.
/// We estimate the CPFP part by multiplying the exit tx weight by 2.
pub(crate) fn estimate_exit_cost<'a, I>(vtxos: I, fee_rate: FeeRate) -> Amount
where
	I: IntoIterator<Item = &'a Vtxo>
{
	let mut all_txs = HashMap::with_capacity(10);
	for vtxo in vtxos {
		for tx in vtxo.transactions() {
			all_txs.insert(tx.tx.compute_txid(), tx.tx);
		}
	}

	let total_weight = all_txs.values().map(|t| t.weight()).sum::<Weight>();
	// we multiply by two as a rough upper bound of all the CPFP txs
	fee_rate * total_weight * 2
}

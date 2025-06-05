use bdk_esplora::esplora_client::Amount;
use bitcoin::{FeeRate, Weight};

use ark::Vtxo;
use json::exit::states::{ExitTx, ExitTxStatus};

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
	let mut all_txs = Vec::with_capacity(10);
	for vtxo in vtxos {
		vtxo.collect_exit_txs(&mut all_txs);
	}
	let total_weight = all_txs.iter().map(|t| t.weight()).sum::<Weight>();
	// we multiply by two as a rough upper bound of all the CPFP txs
	fee_rate * total_weight * 2
}

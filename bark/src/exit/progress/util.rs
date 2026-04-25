
use bitcoin::{Amount, FeeRate, Weight};

use crate::exit::models::{ExitTx, ExitTxStatus};
use crate::WalletVtxo;

/// Counts how many of the given ExitTx objects exist in either the mempool or the blockchain
pub(crate) fn count_broadcast(status: &[ExitTx]) -> usize {
	status.iter().filter(|s| match s.status {
		ExitTxStatus::AwaitingConfirmation { .. } => true,
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
	I: IntoIterator<Item = &'a WalletVtxo>
{
	// we multiply by two as a rough upper bound of all the CPFP tx
	let total_weight = vtxos.into_iter().map(|vtxo| vtxo.exit_tx_weight).sum::<Weight>();
	fee_rate * total_weight * 2
}

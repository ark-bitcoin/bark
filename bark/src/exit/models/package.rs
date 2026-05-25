use bitcoin::{Amount, FeeRate, Transaction, Txid};

use ark::VtxoId;

use crate::exit::models::states::ExitTxOrigin;

/// Describes an exit transaction that needs a CPFP child to be confirmed.
///
/// Returned by [crate::exit::Exit::exits_needing_cpfp]. The caller creates a child
/// transaction spending the P2A anchor of [ExitCpfpRequest::exit_tx] and submits it
/// via [crate::exit::Exit::provide_cpfp_tx].
#[derive(Clone, Debug)]
pub struct ExitCpfpRequest {
	/// The VTXO being exited.
	pub vtxo_id: VtxoId,
	/// The exit transaction whose P2A anchor output must be spent by the CPFP child.
	pub exit_tx: Transaction,
	/// If set, a third-party CPFP is already in the mempool and the child must replace it
	/// via RBF. `None` means no CPFP exists yet and any valid fee is acceptable.
	pub rbf_requirement: Option<RbfRequirement>,
}

/// Constraints a CPFP replacement transaction must satisfy to evict an existing one via RBF.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RbfRequirement {
	/// The effective fee rate of the existing package. A replacement must exceed this.
	pub min_fee_rate: FeeRate,
	/// The total fee paid by the existing package. A replacement must pay strictly more.
	pub current_package_fee: Amount,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExitTransactionPackage {
	/// The actual unilateral exit transaction containing an anchor output and a spendable amount
	pub exit: TransactionInfo,
	/// The child transaction used to spend, and thus confirm, the exit anchor output
	pub child: Option<ChildTransactionInfo>,
}

/// An information struct used to pair the ID of a transaction with the full transaction for ease
/// of use and readability for the user
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransactionInfo {
	pub txid: Txid,
	pub tx: Transaction,
}

/// Represents a child transaction for an exit transaction package with information about the origin
/// of the transaction
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChildTransactionInfo {
	pub info: TransactionInfo,
	pub origin: ExitTxOrigin,
}

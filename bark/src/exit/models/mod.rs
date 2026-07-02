
mod error;
mod package;
mod states;

pub use self::package::{
	ChildTransactionInfo, ExitCpfpRequest, ExitTransactionPackage, FeeInfo, RbfRequirement,
	TransactionInfo,
};
pub use self::error::ExitError;
pub use self::states::{
	ExitTx, ExitTxStatus, ExitTxOrigin, ExitStartState, ExitProcessingState, ExitAwaitingDeltaState,
	ExitClaimableState, ExitClaimInProgressState, ExitClaimedState, ExitVtxoAlreadySpentState,
	ExitCanceledState,
};

use ark::VtxoId;
use bitcoin::Txid;

use bitcoin_ext::{BlockDelta, BlockHeight, BlockRef, TxStatus};

/// A utility type to wrap ExitState children so they can be easily serialized. This also helps with
/// debugging a lot!
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum ExitState {
	Start(ExitStartState),
	Processing(ExitProcessingState),
	AwaitingDelta(ExitAwaitingDeltaState),
	Claimable(ExitClaimableState),
	ClaimInProgress(ExitClaimInProgressState),
	/// Terminal state: the exit is fully complete, and the VTXO has been claimed by the user or
	/// spent by another user who owns a VTXO that is deeper in the tree than this one.
	///
	/// Note: The circumstances in which the latter can occur are typically when the user has stale
	/// data and is trying to exit an already-spent VTXO.
	Claimed(ExitClaimedState),
	/// Terminal state: the exit cannot proceed because the VTXO has already been spent offchain. A
	/// user can start a unilateral exit for a VTXO but later spend it via a refresh, arkoor, etc,
	/// in that situation an exit will enter this state.
	VtxoAlreadySpent(ExitVtxoAlreadySpentState),
	/// Resumable state: the user canceled the exit before its final transaction was broadcast;
	/// ancestor transactions may already be on-chain. The VTXO is untouched and stays spendable,
	/// so a new exit can be started later.
	Canceled(ExitCanceledState),
}

/// A flat, data-free discriminator for [ExitState]. Useful for filtering exits by state without
/// caring about the per-state payload — e.g.
/// [crate::persist::BarkPersister::get_exit_vtxo_entries_with_states].
///
/// The serde representation matches [ExitState]'s `type` tag (kebab-case), so the two stay in sync.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExitStateKind {
	Start,
	Processing,
	AwaitingDelta,
	Claimable,
	ClaimInProgress,
	Claimed,
	VtxoAlreadySpent,
	Canceled,
}

impl ExitStateKind {
	/// List of all the different states.
	pub const ALL: &[ExitStateKind] = &[
		ExitStateKind::Start,
		ExitStateKind::Processing,
		ExitStateKind::AwaitingDelta,
		ExitStateKind::Claimable,
		ExitStateKind::ClaimInProgress,
		ExitStateKind::Claimed,
		ExitStateKind::VtxoAlreadySpent,
		ExitStateKind::Canceled,
	];

	/// List of the states in which an exit is still live and actionable.
	pub const LIVE_STATES: &[ExitStateKind] = &[
		ExitStateKind::Start,
		ExitStateKind::Processing,
		ExitStateKind::AwaitingDelta,
		ExitStateKind::Claimable,
		ExitStateKind::ClaimInProgress,
	];

	/// List of the states in which an exit is finished and will never progress again. A canceled
	/// exit's VTXO stays spendable, so a fresh exit can be started for it later.
	pub const FINISHED_STATES: &[ExitStateKind] = &[
		ExitStateKind::Claimed,
		ExitStateKind::VtxoAlreadySpent,
		ExitStateKind::Canceled,
	];

	/// The stable string tag for this kind. It matches [ExitState]'s serde `type` discriminator,
	/// which is what's stored in the `state` JSON column — so it can be used directly to filter
	/// rows (e.g. `json_extract(state, '$.type')`). Kept in sync with serde by a unit test.
	pub fn as_str(&self) -> &'static str {
		match self {
			ExitStateKind::Start => "start",
			ExitStateKind::Processing => "processing",
			ExitStateKind::AwaitingDelta => "awaiting-delta",
			ExitStateKind::Claimable => "claimable",
			ExitStateKind::ClaimInProgress => "claim-in-progress",
			ExitStateKind::Claimed => "claimed",
			ExitStateKind::VtxoAlreadySpent => "vtxo-already-spent",
			ExitStateKind::Canceled => "canceled",
		}
	}
}

impl ExitState {
	/// Returns the data-free [ExitStateKind] discriminator for this state.
	pub fn kind(&self) -> ExitStateKind {
		match self {
			ExitState::Start(_) => ExitStateKind::Start,
			ExitState::Processing(_) => ExitStateKind::Processing,
			ExitState::AwaitingDelta(_) => ExitStateKind::AwaitingDelta,
			ExitState::Claimable(_) => ExitStateKind::Claimable,
			ExitState::ClaimInProgress(_) => ExitStateKind::ClaimInProgress,
			ExitState::Claimed(_) => ExitStateKind::Claimed,
			ExitState::VtxoAlreadySpent(_) => ExitStateKind::VtxoAlreadySpent,
			ExitState::Canceled(_) => ExitStateKind::Canceled,
		}
	}

	pub fn new_start(tip: BlockHeight) -> Self {
		ExitState::Start(ExitStartState { tip_height: tip })
	}

	pub fn new_processing<T: IntoIterator<Item = Txid>>(tip: BlockHeight, txids: T) -> Self {
		ExitState::Processing(ExitProcessingState {
			tip_height: tip,
			transactions: txids.into_iter()
				.map(|id| ExitTx {
					txid: id,
					status: ExitTxStatus::VerifyInputs,
				})
				.collect::<Vec<_>>(),
		})
	}

	pub fn new_processing_from_transactions(tip: BlockHeight, transactions: Vec<ExitTx>) -> Self {
		ExitState::Processing(ExitProcessingState {
			tip_height: tip,
			transactions,
		})
	}

	pub fn new_awaiting_delta(
		tip: BlockHeight,
		confirmed_block: BlockRef,
		wait_delta: BlockDelta
	) -> Self {
		debug_assert_ne!(wait_delta, 0, "wait delta must be non-zero");
		let claimable_height = confirmed_block.height + wait_delta as BlockHeight;
		ExitState::AwaitingDelta(ExitAwaitingDeltaState {
			tip_height: tip,
			confirmed_block,
			claimable_height,
		})
	}

	pub fn new_claimable(
		tip: BlockHeight,
		claimable_since: BlockRef,
		last_scanned_block: Option<BlockRef>
	) -> Self {
		ExitState::Claimable(ExitClaimableState {
			tip_height: tip,
			claimable_since,
			last_scanned_block,
		})
	}

	pub fn new_claim_in_progress(
		tip: BlockHeight,
		claimable_since: BlockRef,
		claim_txid: Txid
	) -> Self {
		ExitState::ClaimInProgress(ExitClaimInProgressState {
			tip_height: tip,
			claimable_since,
			claim_txid,
		})
	}

	pub fn new_claimed(tip: BlockHeight, txid: Txid, block: BlockRef) -> Self {
		ExitState::Claimed(ExitClaimedState {
			tip_height: tip,
			txid,
			block,
		})
	}

	pub fn new_vtxo_already_spent(tip: BlockHeight) -> Self {
		ExitState::VtxoAlreadySpent(ExitVtxoAlreadySpentState { tip_height: tip })
	}

	pub fn new_canceled(tip: BlockHeight) -> Self {
		ExitState::Canceled(ExitCanceledState { tip_height: tip })
	}

	/// Checks if the state is awaiting the confirmation of every exit transaction in the tree and
	/// the exit delta required for the VTXO to become claimable.
	///
	/// Note: This excludes the claimable state, use [ExitState::is_claimable] for that.
	pub fn is_pending(&self) -> bool {
		match self {
			ExitState::Start(_) => true,
			ExitState::Processing(_) => true,
			ExitState::AwaitingDelta(_) => true,
			_ => false,
		}
	}

	/// A simple helper for [ExitState::Claimable], at this point an exit can be spent on-chain
	/// and redeemed into a UTXO controlled by the user.
	pub fn is_claimable(&self) -> bool {
		match self {
			ExitState::Claimable(_) => true,
			_ => false,
		}
	}

	/// Whether the exit is still in its abortable window and can be canceled by the user. This is
	/// only possible until the final exit transaction is broadcast; ancestor transactions may
	/// already be on-chain.
	pub fn is_cancelable(&self) -> bool {
		match self {
			ExitState::Start(_) => true,
			ExitState::Processing(s) => s.transactions.last().map_or(true, |tx| matches!(
				tx.status,
				ExitTxStatus::VerifyInputs
				| ExitTxStatus::AwaitingInputConfirmation { .. }
				| ExitTxStatus::AwaitingCpfpBroadcast,
			)),
			_ => false,
		}
	}

	pub fn requires_confirmations(&self) -> bool {
		match self {
			ExitState::Processing(s) => {
				s.transactions.iter().any(|s| match s.status {
					ExitTxStatus::AwaitingInputConfirmation { .. } => true,
					ExitTxStatus::AwaitingConfirmation { .. } => true,
					_ => false,
				})
			},
			ExitState::AwaitingDelta(_) => true,
			ExitState::ClaimInProgress(_) => true,
			_ => false,
		}
	}

	pub fn claimable_height(&self) -> Option<BlockHeight> {
		match self {
			ExitState::AwaitingDelta(s) => Some(s.claimable_height),
			ExitState::Claimable(s) => Some(s.claimable_since.height),
			ExitState::ClaimInProgress(s) => Some(s.claimable_since.height),
			_ => None,
		}
	}

	/// True once every exit transaction has confirmed on-chain (i.e. the exit has reached
	/// at least [`ExitState::AwaitingDelta`]). At that point the VTXO can be considered
	/// [crate::vtxo::VtxoStateKind::Exited]: the underlying onchain outpoint is committed
	/// to the exit chain, the server can see it and will refuse to service the VTXO for
	/// any payment operations offchain, and there's nothing left to undo client-side.
	///
	/// Note: we deliberately don't flip the VTXO at `Processing` — even with every tx
	/// broadcast, mempool eviction is still possible until confirmation, so we hold off
	/// to keep `Exited` an accurate "this is gone" signal.
	pub fn warrants_exited_vtxo(&self) -> bool {
		match self {
			ExitState::Start(_) => false,
			ExitState::Processing(_) => false,
			ExitState::AwaitingDelta(_) => true,
			ExitState::Claimable(_) => true,
			ExitState::ClaimInProgress(_) => true,
			ExitState::Claimed(_) => true,
			ExitState::VtxoAlreadySpent(_) => false,
			ExitState::Canceled(_) => false,
		}
	}
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExitProgressStatus {
	/// The ID of the VTXO that is being unilaterally exited
	pub vtxo_id: VtxoId,
	/// The current state of the exit transaction
	pub state: ExitState,
	/// Any error that occurred during the exit process
	pub error: Option<ExitError>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExitTransactionStatus {
	/// The ID of the VTXO that is being unilaterally exited
	pub vtxo_id: VtxoId,
	/// The current state of the exit transaction
	pub state: ExitState,
	/// The history of each state the exit transaction has gone through
	pub history: Option<Vec<ExitState>>,
	/// Each exit transaction package required for the unilateral exit
	pub transactions: Vec<ExitTransactionPackage>,
}

#[derive(Clone, Copy, Debug,  Eq, PartialEq)]
pub struct ExitChildStatus {
	pub txid: Txid,
	pub status: TxStatus,
	pub origin: ExitTxOrigin,
	pub fee_info: Option<FeeInfo>,
}

#[cfg(test)]
mod test {
	use super::*;

	use bitcoin::hashes::Hash;

	fn txid(n: u8) -> Txid {
		Txid::from_byte_array([n; 32])
	}

	fn tx(n: u8, status: ExitTxStatus) -> ExitTx {
		ExitTx { txid: txid(n), status }
	}

	/// A status representing an exit tx that's been broadcast (its CPFP child is in the mempool).
	fn broadcast() -> ExitTxStatus {
		ExitTxStatus::AwaitingConfirmation { child_txid: txid(99), origin: ExitTxOrigin::Mempool }
	}

	/// One [ExitState] per variant, for tests that need to cover the whole enum.
	fn all_states() -> [ExitState; 8] {
		let block_ref = BlockRef { height: 1, hash: bitcoin::BlockHash::all_zeros() };
		[
			ExitState::new_start(1),
			ExitState::new_processing(1, [txid(1)]),
			ExitState::new_awaiting_delta(1, block_ref, 10),
			ExitState::new_claimable(1, block_ref, Some(block_ref)),
			ExitState::new_claim_in_progress(1, block_ref, txid(1)),
			ExitState::new_claimed(1, txid(1), block_ref),
			ExitState::new_vtxo_already_spent(1),
			ExitState::new_canceled(1),
		]
	}

	#[test]
	fn is_cancelable_only_checks_the_final_tx() {
		// Start is always cancellable — nothing has been built yet.
		assert!(ExitState::new_start(100).is_cancelable());

		// Processing with nothing broadcast.
		assert!(ExitState::new_processing_from_transactions(100, vec![
			tx(1, ExitTxStatus::VerifyInputs),
			tx(2, ExitTxStatus::AwaitingCpfpBroadcast),
		]).is_cancelable());

		// Ancestors broadcast but the final (leaf) tx is not — still cancellable, since only the
		// last transaction actually commits the VTXO on-chain.
		assert!(ExitState::new_processing_from_transactions(100, vec![
			tx(1, broadcast()),
			tx(2, ExitTxStatus::AwaitingCpfpBroadcast),
		]).is_cancelable());

		// The final tx has been broadcast — no longer cancellable.
		assert!(!ExitState::new_processing_from_transactions(100, vec![
			tx(1, broadcast()),
			tx(2, broadcast()),
		]).is_cancelable());

		// Terminal / post-broadcast states are never cancellable.
		assert!(!ExitState::new_canceled(100).is_cancelable());
		assert!(!ExitState::new_vtxo_already_spent(100).is_cancelable());
	}

	#[test]
	fn exit_state_kind_tag_matches_serde() {
		// ExitStateKind's serde tag must stay in lock-step with ExitState's `type` tag, since the
		// SQL/default filter relies on them matching.
		for state in all_states() {
			let state_tag = serde_json::to_value(&state).unwrap()
				.get("type").unwrap().as_str().unwrap().to_string();
			let kind_tag = serde_json::to_value(state.kind()).unwrap()
				.as_str().unwrap().to_string();
			assert_eq!(state_tag, kind_tag, "tag mismatch for {:?}", state.kind());
		}

		// ExitStateKind::as_str backs the SQL `json_extract(state, '$.type')` filter, so it must
		// equal the serde tag for every kind.
		for &kind in ExitStateKind::ALL {
			let serde_tag = serde_json::to_value(kind).unwrap().as_str().unwrap().to_string();
			assert_eq!(kind.as_str(), serde_tag, "as_str mismatch for {:?}", kind);
		}
	}

	#[test]
	fn exit_state_kind_all_is_exhaustive() {
		// When this match stops compiling, a variant was added: extend ALL, all_states(),
		// and LIVE_STATES or FINISHED_STATES.
		match ExitStateKind::Start {
			ExitStateKind::Start => {},
			ExitStateKind::Processing => {},
			ExitStateKind::AwaitingDelta => {},
			ExitStateKind::Claimable => {},
			ExitStateKind::ClaimInProgress => {},
			ExitStateKind::Claimed => {},
			ExitStateKind::VtxoAlreadySpent => {},
			ExitStateKind::Canceled => {},
		}

		// Every state's kind appears in ALL exactly once.
		assert_eq!(ExitStateKind::ALL.len(), all_states().len());
		for state in all_states() {
			let count = ExitStateKind::ALL.iter().filter(|&&k| k == state.kind()).count();
			assert_eq!(count, 1, "{:?} should appear exactly once in ALL", state.kind());
		}
	}

	#[test]
	fn exit_state_kind_live_and_finished_states_partition_all() {
		// Every kind belongs to exactly one of LIVE_STATES and FINISHED_STATES.
		for &kind in ExitStateKind::ALL {
			let live = !matches!(
				kind,
				ExitStateKind::Claimed
				| ExitStateKind::VtxoAlreadySpent
				| ExitStateKind::Canceled,
			);
			assert_eq!(
				ExitStateKind::LIVE_STATES.contains(&kind), live,
				"LIVE_STATES membership wrong for {:?}", kind,
			);
			assert_eq!(
				ExitStateKind::FINISHED_STATES.contains(&kind), !live,
				"FINISHED_STATES membership wrong for {:?}", kind,
			);
		}

		// Anything is_pending() must be live; the reverse doesn't hold since is_pending()
		// excludes Claimable and ClaimInProgress.
		for state in all_states() {
			if state.is_pending() {
				assert!(
					ExitStateKind::LIVE_STATES.contains(&state.kind()),
					"{:?} is_pending() but its kind is not in LIVE_STATES", state.kind(),
				);
			}
		}
	}
}

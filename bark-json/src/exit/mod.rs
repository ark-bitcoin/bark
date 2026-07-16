pub mod error;
pub mod package;
pub mod states;

#[cfg(feature = "utoipa")]
use utoipa::ToSchema;

use crate::exit::states::{
	ExitAwaitingDeltaState, ExitProcessingState, ExitClaimInProgressState, ExitClaimableState,
	ExitClaimedState, ExitStartState, ExitTx, ExitVtxoAlreadySpentState, ExitCanceledState,
};

/// A utility type to wrap ExitState children so they can be easily serialized. This also helps with
/// debugging a lot!
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum ExitState {
	Start(ExitStartState),
	Processing(ExitProcessingState),
	AwaitingDelta(ExitAwaitingDeltaState),
	Claimable(ExitClaimableState),
	ClaimInProgress(ExitClaimInProgressState),
	Claimed(ExitClaimedState),
	VtxoAlreadySpent(ExitVtxoAlreadySpentState),
	Canceled(ExitCanceledState),
}

impl From<bark::exit::ExitState> for ExitState {
	fn from(v: bark::exit::ExitState) -> Self {
		match v {
			bark::exit::ExitState::Start(s) => ExitState::Start(ExitStartState {
				tip_height: s.tip_height,
			}),
			bark::exit::ExitState::Processing(s) => ExitState::Processing(ExitProcessingState {
				tip_height: s.tip_height,
				transactions: s.transactions.into_iter().map(|t| ExitTx { txid: t.txid, status: t.status.into() }).collect(),
			}),
			bark::exit::ExitState::AwaitingDelta(s) => ExitState::AwaitingDelta(ExitAwaitingDeltaState {
				tip_height: s.tip_height,
				confirmed_block: s.confirmed_block.into(),
				claimable_height: s.claimable_height,
			}),
			bark::exit::ExitState::Claimable(s) => ExitState::Claimable(ExitClaimableState {
				tip_height: s.tip_height,
				claimable_since: s.claimable_since.into(),
				last_scanned_block: s.last_scanned_block.map(Into::into),
			}),
			bark::exit::ExitState::ClaimInProgress(s) => ExitState::ClaimInProgress(ExitClaimInProgressState {
				tip_height: s.tip_height,
				claimable_since: s.claimable_since.into(),
				claim_txid: s.claim_txid,
			}),
			bark::exit::ExitState::Claimed(s) => ExitState::Claimed(ExitClaimedState {
				tip_height: s.tip_height,
				txid: s.txid,
				block: s.block.into(),
			}),
			bark::exit::ExitState::VtxoAlreadySpent(s) => ExitState::VtxoAlreadySpent(
				ExitVtxoAlreadySpentState { tip_height: s.tip_height },
			),
			bark::exit::ExitState::Canceled(s) => ExitState::Canceled(
				ExitCanceledState { tip_height: s.tip_height },
			),
		}
	}
}

/// A flat, data-free discriminator for [ExitState]. The serde representation matches
/// [ExitState]'s `type` tag (kebab-case).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
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

impl From<bark::exit::ExitStateKind> for ExitStateKind {
	fn from(v: bark::exit::ExitStateKind) -> Self {
		match v {
			bark::exit::ExitStateKind::Start => ExitStateKind::Start,
			bark::exit::ExitStateKind::Processing => ExitStateKind::Processing,
			bark::exit::ExitStateKind::AwaitingDelta => ExitStateKind::AwaitingDelta,
			bark::exit::ExitStateKind::Claimable => ExitStateKind::Claimable,
			bark::exit::ExitStateKind::ClaimInProgress => ExitStateKind::ClaimInProgress,
			bark::exit::ExitStateKind::Claimed => ExitStateKind::Claimed,
			bark::exit::ExitStateKind::VtxoAlreadySpent => ExitStateKind::VtxoAlreadySpent,
			bark::exit::ExitStateKind::Canceled => ExitStateKind::Canceled,
		}
	}
}

impl std::fmt::Display for ExitStateKind {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		let s = match self {
			ExitStateKind::Start => "start",
			ExitStateKind::Processing => "processing",
			ExitStateKind::AwaitingDelta => "awaiting-delta",
			ExitStateKind::Claimable => "claimable",
			ExitStateKind::ClaimInProgress => "claim-in-progress",
			ExitStateKind::Claimed => "claimed",
			ExitStateKind::VtxoAlreadySpent => "vtxo-already-spent",
			ExitStateKind::Canceled => "canceled",
		};
		f.write_str(s)
	}
}

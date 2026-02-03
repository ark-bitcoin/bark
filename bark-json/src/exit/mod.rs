pub mod error;
pub mod package;
pub mod states;

#[cfg(feature = "utoipa")]
use utoipa::ToSchema;

use crate::exit::states::{
	ExitAwaitingDeltaState, ExitProcessingState, ExitClaimInProgressState, ExitClaimableState,
	ExitClaimedState, ExitStartState, ExitTx
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
		}
	}
}

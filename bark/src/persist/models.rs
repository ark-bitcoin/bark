//! Persistence-focused data models.
//!
//! This module defines serializable types that mirror core in-memory structures but are tailored
//! for durable storage and retrieval via a BarkPersister implementation.
//!
//! Intent
//! - Keep storage concerns decoupled from runtime types used by protocol logic.
//! - Provide stable, serde-friendly representations for database backends.
//! - Enable forward/backward compatibility when schema migrations occur.

use bdk_esplora::esplora_client::Amount;
use lightning_invoice::Bolt11Invoice;

use ark::{VtxoId, VtxoPolicy, VtxoRequest};
use ark::lightning::{Invoice, PaymentHash, Preimage};
use json::exit::ExitState;

use crate::exit::ExitVtxo;
use crate::vtxo_state::VtxoState;
use crate::WalletVtxo;

/// Persisted representation of a pending lightning send.
///
/// Stores the invoice and the amount being sent.
///
/// Note: the record should be removed when the payments is completed or failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingLightningSend {
	pub invoice: Invoice,
	pub amount: Amount,
	pub htlc_vtxos: Vec<WalletVtxo>,
}

/// Persisted representation of an incoming Lightning payment.
///
/// Stores the invoice and related cryptographic material (e.g., payment hash and preimage)
/// and tracks whether the preimage has been revealed.
///
/// Note: the record should be removed when the receive is completed or failed.
#[derive(Debug, Clone)]
pub struct LightningReceive {
	pub payment_hash: PaymentHash,
	pub payment_preimage: Preimage,
	pub invoice: Bolt11Invoice,
	pub preimage_revealed_at: Option<u64>,
	pub htlc_vtxos: Option<Vec<WalletVtxo>>,
}

/// Persistable view of an [ExitVtxo].
///
/// `StoredExit` is a lightweight data transfer object tailored for storage backends. It captures
/// the VTXO ID, the current state, and the full history of the unilateral exit.
pub struct StoredExit {
	/// Identifier of the VTXO being exited.
	pub vtxo_id: VtxoId,
	/// Current exit state.
	pub state: ExitState,
	/// Historical states for auditability.
	pub history: Vec<ExitState>,
}

impl StoredExit {
	/// Builds a persistable snapshot from an [ExitVtxo].
	pub fn new(exit: &ExitVtxo) -> Self {
		Self {
			vtxo_id: exit.id(),
			state: exit.state().clone(),
			history: exit.history().clone(),
		}
	}
}

/// Persisted request data used during round participation.
///
/// Captures the information required to rebuild or resume protocol state across attempts,
/// such as inputs, outputs, amounts, and metadata the server expects.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredVtxoRequest {
	#[serde(with = "ark::encode::serde")]
	pub request_policy: VtxoPolicy,
	pub amount: Amount,
	pub state: VtxoState
}

impl StoredVtxoRequest {
	pub fn from_parts(req: VtxoRequest, state: VtxoState) -> Self {
		Self {
			request_policy: req.policy,
			amount: req.amount,
			state,
		}
	}

	pub fn to_vtxo_request(&self) -> VtxoRequest {
		VtxoRequest {
			policy: self.request_policy.clone(),
			amount: self.amount,
		}
	}
}

#[cfg(test)]
mod test {
	use super::*;

	use json::exit::ExitState;
	use json::exit::states::ExitTxOrigin;
	use crate::movement::MovementRecipient;
	use crate::vtxo_state::VtxoState;

	#[test]
	/// Each struct stored as JSON in the database should have test to check for backwards compatibility
	/// Parsing can occur either in convert.rs or this file (query.rs)
	fn test_serialised_structs() {
		// Exit state
		let serialised = r#"{"type":"start","tip_height":119}"#;
		serde_json::from_str::<ExitState>(serialised).unwrap();
		let serialised = r#"{"type":"processing","tip_height":119,"transactions":[{"txid":"9fd34b8c556dd9954bda80ba2cf3474a372702ebc31a366639483e78417c6812","status":{"type":"awaiting-input-confirmation","txids":["ddfe11920358d1a1fae970dc80459c60675bf1392896f69b103fc638313751de"]}}]}"#;
		serde_json::from_str::<ExitState>(serialised).unwrap();
		let serialised = r#"{"type":"awaiting-delta","tip_height":122,"confirmed_block":{"height":122,"hash":"3cdd30fc942301a74666c481beb82050ccd182050aee3c92d2197e8cad427b8f"},"claimable_height":134}"#;
		serde_json::from_str::<ExitState>(serialised).unwrap();
		let serialised = r#"{"type":"claimable","tip_height":134,"claimable_since":{"height":134,"hash":"71fe28f4c803a4c46a3a93d0a9937507d7c20b4bd9586ba317d1109e1aebaac9"},"last_scanned_block":null}"#;
		serde_json::from_str::<ExitState>(serialised).unwrap();
		let serialised = r#"{"type":"claim-in-progress","tip_height":134,"claimable_since":{"height":134,"hash":"6585896bdda6f08d924bf45cc2b16418af56703b3c50930e4dccbc1728d3800a"},"claim_txid":"599347c35870bd36f7acb22b81f9ffa8b911d9b5e94834858aebd3ec09339f4c"}"#;
		serde_json::from_str::<ExitState>(serialised).unwrap();
		let serialised = r#"{"type":"claimed","tip_height":134,"txid":"599347c35870bd36f7acb22b81f9ffa8b911d9b5e94834858aebd3ec09339f4c","block":{"height":122,"hash":"3cdd30fc942301a74666c481beb82050ccd182050aee3c92d2197e8cad427b8f"}}"#;
		serde_json::from_str::<ExitState>(serialised).unwrap();

		// Exit child tx origins
		let serialized = r#"{"type":"wallet","confirmed_in":null}"#;
		serde_json::from_str::<ExitTxOrigin>(serialized).unwrap();
		let serialized = r#"{"type":"wallet","confirmed_in":{"height":134,"hash":"71fe28f4c803a4c46a3a93d0a9937507d7c20b4bd9586ba317d1109e1aebaac9"}}"#;
		serde_json::from_str::<ExitTxOrigin>(serialized).unwrap();
		let serialized = r#"{"type":"mempool","fee_rate_kwu":25000,"total_fee":27625}"#;
		serde_json::from_str::<ExitTxOrigin>(serialized).unwrap();
		let serialized = r#"{"type":"block","confirmed_in":{"height":134,"hash":"71fe28f4c803a4c46a3a93d0a9937507d7c20b4bd9586ba317d1109e1aebaac9"}}"#;
		serde_json::from_str::<ExitTxOrigin>(serialized).unwrap();

		// Movement recipient
		let serialised = r#"{"recipient":"03a4a6443868dbba406d03e43d7baf00d66809d57fba911616ccf90a4685de2bc1","amount_sat":150000}"#;
		serde_json::from_str::<MovementRecipient>(serialised).unwrap();

		// Vtxo state
		let serialised = r#""Spendable""#;
		serde_json::from_str::<VtxoState>(serialised).unwrap();
		let serialised = r#""Spent""#;
		serde_json::from_str::<VtxoState>(serialised).unwrap();
		let serialised = r#""Locked""#;
		serde_json::from_str::<VtxoState>(serialised).unwrap();

		let serialised = r#"{"request_policy":"0003a4a6443868dbba406d03e43d7baf00d66809d57fba911616ccf90a4685de2bc1","amount":300000,"state":"Spendable"}"#;
		serde_json::from_str::<StoredVtxoRequest>(serialised).unwrap();
	}
}

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
use ark::lightning::{PaymentHash, Preimage};
use json::exit::ExitState;

use crate::exit::ExitVtxo;
use crate::vtxo_state::VtxoState;

/// Persisted representation of an incoming Lightning payment.
///
/// Stores the invoice and related cryptographic material (e.g., payment hash and preimage)
/// and tracks whether the preimage has been revealed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LightningReceive {
	pub payment_hash: PaymentHash,
	pub payment_preimage: Preimage,
	pub invoice: Bolt11Invoice,
	pub preimage_revealed_at: Option<u64>,
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

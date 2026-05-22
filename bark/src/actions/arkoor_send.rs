//! Arkoor send wallet action.
//!
//! Identity (`id`, `destination`, `amount`) and immutable parameters live
//! on [`ArkoorSend`] as top-level fields; the mutable bit is the [`Progress`] enum.

use bitcoin::Amount;

use ark::Vtxo;
use ark::vtxo::{Full, VtxoId};

use crate::actions::WalletActionId;
use crate::movement::MovementId;

/// An in-flight arkoor payment to an [`ark::Address`], persisted
/// as a single checkpoint row and driven across crashes by the
/// executor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArkoorSend {
	// Immutable State:
	pub id: WalletActionId,
	pub destination: ark::Address,
	#[serde(with = "bitcoin::amount::serde::as_sat")]
	pub amount: Amount,
	pub input_vtxo_ids: Vec<VtxoId>,
	pub change_key_index: u32,

	// Mutable state:
	pub progress: Progress,
}

impl ArkoorSend {
	pub fn id(&self) -> WalletActionId {
		self.id.clone()
	}
}

/// The four phases of an outgoing arkoor send.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Progress {
	/// Inputs are locked and the change keypair is reserved.
	Cosigning,
	/// Cosign succeeded and the movement is recorded; pending registration of
	/// the signed vtxo transactions with the server.
	Registration {
		movement_id: MovementId,
		#[serde(with = "ark::encode::serde::vec")]
		signed_destination_vtxos: Vec<Vtxo<Full>>,
		#[serde(with = "ark::encode::serde::vec")]
		signed_change_vtxos: Vec<Vtxo<Full>>,
	},
	/// Registration succeeded; pending delivery of the signed vtxos to the
	/// recipient via the destination's mailbox mechanisms.
	Delivery {
		movement_id: MovementId,
		#[serde(with = "ark::encode::serde::vec")]
		signed_destination_vtxos: Vec<Vtxo<Full>>,
		#[serde(with = "ark::encode::serde::vec")]
		signed_change_vtxos: Vec<Vtxo<Full>>,
		/// Most recent reason a delivery pass parked. `None` until the first
		/// pass in which no mailbox accepted the post.
		last_park_error: Option<String>,
	},
	/// At least one delivery succeeded or the action was salvaged
	/// after retry exhaustion.
	Finalizing {
		movement_id: MovementId,
		#[serde(with = "ark::encode::serde::vec")]
		signed_change_vtxos: Vec<Vtxo<Full>>,
		/// `true` if at least one delivery mechanism acked the message,
		/// `false` if we are finalizing post-retry-exhaustion to salvage
		/// the change.
		delivery_succeeded: bool,
	},
}

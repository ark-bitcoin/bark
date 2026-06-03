//! State machine for incoming lightning payments.
//!
//! Identity (`invoice`, `payment_hash`, `payment_preimage`) and the
//! parameters fixed at invoice creation (htlc claim cltv delta, anti-dos
//! token) live on the action as top-level fields; the mutable bit is
//! [`Progress`], representing the current phase of the state machine.

use bitcoin::secp256k1::PublicKey;
use lightning_invoice::Bolt11Invoice;

use ark::VtxoId;
use ark::lightning::{PaymentHash, Preimage};
use bitcoin_ext::BlockDelta;

use crate::actions::WalletActionId;
use crate::movement::MovementId;

const LN_RECV_NAMESPACE: &str = "ln_recv";

pub(crate) fn ln_recv_action_id(payment_hash: PaymentHash) -> WalletActionId {
	format!("{LN_RECV_NAMESPACE}.{payment_hash}")
}

/// An incoming lightning payment, persisted as a single checkpoint row
/// stored at invoice creation time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LightningReceive {
	// Set at invoice creation, immutable thereafter:
	pub invoice: Bolt11Invoice,
	pub payment_hash: PaymentHash,
	pub payment_preimage: Preimage,
	pub htlc_recv_cltv_delta: BlockDelta,
	pub anti_dos_token: Option<String>,

	// Mutable state:
	pub progress: Progress,
}

impl LightningReceive {
	pub fn id(&self) -> WalletActionId {
		ln_recv_action_id(self.payment_hash)
	}
}

/// The phases of an incoming lightning receive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Progress {
	/// Invoice minted, waiting for an inbound HTLC. No money yet.
	AwaitingPayment,
	/// Server prepared HTLC-recv vtxos; we hold them locked and the
	/// movement is created. The preimage has NOT been revealed yet, so the
	/// receive is still cancellable.
	HtlcsReady(Htlcs),
	/// The preimage has been revealed via the claim RPC in
	/// exchange of pubkey VTXOs
	/// Past the point of no return — on failure we exit the
	/// HTLC vtxos on-chain rather than cancel.
	PreimageRevealed(Htlcs),
}

/// A handle for the HTLC-recv vtxos the server granted us
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Htlcs {
	/// The VTXO IDs of the HTLC-recv vtxos
	pub vtxo_ids: Vec<VtxoId>,
	/// The ID of the ongoing movement
	pub movement_id: MovementId,
	/// The pubkey to send claim outputs to
	pub claim_key: PublicKey,
}

//! Persisted state types for an outgoing lightning payment.
//!
//! Identity (`invoice`, `original_payment_method`) and the parameters
//! fixed at the start (inputs, amounts, htlc key, expiry) live on the
//! action as top-level fields; the mutable bit is [`Progress`], a small
//! enum that names the four phases of the state machine and only carries
//! the fields the phase actually has.
//!
//! Behaviour (transition functions and the
//! [`WalletAction`](crate::actions::WalletAction) impl) lands in
//! follow-up commits.

use ark::VtxoId;
use ark::lightning::Invoice;
use ark::mailbox::MailboxIdentifier;
use bitcoin::Amount;
use bitcoin::secp256k1::PublicKey;
use bitcoin_ext::BlockHeight;

use crate::actions::WalletActionId;
use crate::movement::{MovementId, PaymentMethod};

/// An outgoing lightning payment, persisted as a single checkpoint row
/// and driven across crashes by the executor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LightningSend {
	// Set at start, immutable thereafter:
	pub invoice: Invoice,
	pub original_payment_method: PaymentMethod,
	pub input_vtxo_ids: Vec<VtxoId>,
	pub payment_amount: Amount,
	pub fee: Amount,

	/// Used as both the HTLC output's locked pubkey and as the change
	/// pubkey (reused to avoid a second key derivation).
	pub htlc_key: PublicKey,
	pub htlc_expiry: BlockHeight,

	// Mutable state:
	pub progress: Progress,
}

impl LightningSend {
	pub fn id(&self) -> WalletActionId {
		self.invoice.payment_hash().to_string()
	}

	pub fn total_amount(&self) -> Amount {
		self.payment_amount + self.fee
	}
}

/// The four phases of an outgoing lightning send. The enum tag is the
/// phase; each variant carries only the data that exists by that
/// phase, so impossible combinations are unrepresentable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Progress {
	/// Inputs are locked, no server interaction yet.
	Start,
	/// Server cosigned the HTLC outputs; vtxos and movement persisted.
	HtlcReceived(Htlcs),
	/// Server has been told to pay; outcome is pending.
	PaymentInitiated(Htlcs),
	/// Payment failed; HTLCs must be revoked back to a spendable vtxo.
	RevocableHtlcs { htlcs: Htlcs, revocation: Revocation },
}

/// The HTLC vtxos the server cosigned for us, plus the movement they
/// belong to and the mailbox the server will push notifications to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Htlcs {
	pub vtxo_ids: Vec<VtxoId>,
	#[serde(with = "ark::encode::serde")]
	pub mailbox_id: MailboxIdentifier,
	pub movement_id: MovementId,
}

/// Revocation keypair derived when a payment is determined to have
/// failed; the public key is used to ask the server to cosign a claim
/// back to us.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Revocation {
	pub key: PublicKey,
}

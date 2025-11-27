
use std::fmt;
use std::str::FromStr;

use bitcoin::{taproot, Amount, ScriptBuf, TxOut};
use bitcoin::secp256k1::PublicKey;

use bitcoin_ext::{BlockDelta, BlockHeight, TaprootSpendInfoExt};

use crate::scripts;
use crate::lightning::{server_htlc_receive_taproot, server_htlc_send_taproot, PaymentHash};
use crate::vtxo::{checkpoint_taproot, exit_clause, exit_taproot};

/// Type enum of [VtxoPolicy].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum VtxoPolicyKind {
	/// Standard VTXO output protected with a public key.
	Pubkey,
	/// A public policy that grants bitcoin back to the server after expiry
	/// It is used to construct checkpoint transactions
	Checkpoint,
	/// A VTXO that represents an HTLC with the Ark server to send money.
	ServerHtlcSend,
	/// A VTXO that represents an HTLC with the Ark server to receive money.
	ServerHtlcRecv,
}

impl fmt::Display for VtxoPolicyKind {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
	    match self {
			Self::Pubkey => f.write_str("pubkey"),
			Self::Checkpoint => f.write_str("checkpoint"),
			Self::ServerHtlcSend => f.write_str("server-htlc-send"),
			Self::ServerHtlcRecv => f.write_str("server-htlc-receive"),
		}
	}
}

impl FromStr for VtxoPolicyKind {
	type Err = String;
	fn from_str(s: &str) -> Result<Self, Self::Err> {
		Ok(match s {
			"pubkey" => Self::Pubkey,
			"checkpoint" => Self::Checkpoint,
			"server-htlc-send" => Self::ServerHtlcSend,
			"server-htlc-receive" => Self::ServerHtlcRecv,
			_ => return Err(format!("unknown VtxoPolicyType: {}", s)),
		})
	}
}

impl serde::Serialize for VtxoPolicyKind {
	fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
		s.collect_str(self)
	}
}

impl<'de> serde::Deserialize<'de> for VtxoPolicyKind {
	fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
		struct Visitor;
		impl<'de> serde::de::Visitor<'de> for Visitor {
			type Value = VtxoPolicyKind;
			fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
				write!(f, "a VtxoPolicyType")
			}
			fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
				VtxoPolicyKind::from_str(v).map_err(serde::de::Error::custom)
			}
		}
		d.deserialize_str(Visitor)
	}
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PubkeyVtxoPolicy {
	pub user_pubkey: PublicKey,
}

impl From<PubkeyVtxoPolicy> for VtxoPolicy {
	fn from(policy: PubkeyVtxoPolicy) -> Self {
		Self::Pubkey(policy)
	}
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CheckpointVtxoPolicy {
	pub user_pubkey: PublicKey,
}

impl From<CheckpointVtxoPolicy> for VtxoPolicy {
	fn from(policy: CheckpointVtxoPolicy) -> Self {
		Self::Checkpoint(policy)
	}
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ServerHtlcSendVtxoPolicy {
	pub user_pubkey: PublicKey,
	pub payment_hash: PaymentHash,
	pub htlc_expiry: BlockHeight,
}

impl From<ServerHtlcSendVtxoPolicy> for VtxoPolicy {
	fn from(policy: ServerHtlcSendVtxoPolicy) -> Self {
		Self::ServerHtlcSend(policy)
	}
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ServerHtlcRecvVtxoPolicy {
	pub user_pubkey: PublicKey,
	pub payment_hash: PaymentHash,
	pub htlc_expiry_delta: BlockDelta,
	pub htlc_expiry: BlockHeight,
}

impl From<ServerHtlcRecvVtxoPolicy> for VtxoPolicy {
	fn from(policy: ServerHtlcRecvVtxoPolicy) -> Self {
		Self::ServerHtlcRecv(policy)
	}
}

/// The output policy of the VTXO.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum VtxoPolicy {
	/// Standard VTXO output protected with a public key.
	///
	/// This can be the result of either:
	/// - a board
	/// - a round
	/// - an arkoor tx
	/// - change from a LN payment
	Pubkey(PubkeyVtxoPolicy),
	/// A policy which returns all funds to the server after expiry
	Checkpoint(CheckpointVtxoPolicy),
	/// A VTXO that represents an HTLC with the Ark server to send money.
	ServerHtlcSend(ServerHtlcSendVtxoPolicy),
	/// A VTXO that represents an HTLC with the Ark server to receive money.
	ServerHtlcRecv(ServerHtlcRecvVtxoPolicy),
}

impl VtxoPolicy {
	pub fn new_pubkey(user_pubkey: PublicKey) -> Self {
		Self::Pubkey(PubkeyVtxoPolicy { user_pubkey })
	}

	pub fn new_checkpoint(user_pubkey: PublicKey) -> Self {
		Self::Checkpoint(CheckpointVtxoPolicy { user_pubkey })
	}

	pub fn new_server_htlc_send(
		user_pubkey: PublicKey,
		payment_hash: PaymentHash,
		htlc_expiry: BlockHeight,
	) -> Self {
		Self::ServerHtlcSend(ServerHtlcSendVtxoPolicy { user_pubkey, payment_hash, htlc_expiry })
	}

	/// Creates a new htlc from server to client
	/// - user_pubkey: A public key owned by the client
	/// - payment_hash: The payment hash, the client can claim the HTLC
	/// by revealing the corresponding pre-image
	/// - htlc_expiry: An absolute blockheight at which the HTLC expires
	/// - htlc_expiry_delta: A safety margin for the server. If the user
	/// tries to exit after time-out the server will have at-least
	/// `htlc_expiry_delta` blocks to claim the payment
	pub fn new_server_htlc_recv(
		user_pubkey: PublicKey,
		payment_hash: PaymentHash,
		htlc_expiry: BlockHeight,
		htlc_expiry_delta: BlockDelta,
	) -> Self {
		Self::ServerHtlcRecv(ServerHtlcRecvVtxoPolicy { user_pubkey, payment_hash, htlc_expiry, htlc_expiry_delta })
	}

	pub fn as_pubkey(&self) -> Option<&PubkeyVtxoPolicy> {
		match self {
			Self::Pubkey(v) => Some(v),
			_ => None,
		}
	}

	pub fn as_server_htlc_send(&self) -> Option<&ServerHtlcSendVtxoPolicy> {
		match self {
			Self::ServerHtlcSend(v) => Some(v),
			_ => None,
		}
	}

	pub fn as_server_htlc_recv(&self) -> Option<&ServerHtlcRecvVtxoPolicy> {
		match self {
			Self::ServerHtlcRecv(v) => Some(v),
			_ => None,
		}
	}

	/// The policy type id.
	pub fn policy_type(&self) -> VtxoPolicyKind {
		match self {
			Self::Pubkey { .. } => VtxoPolicyKind::Pubkey,
			Self::Checkpoint { .. } => VtxoPolicyKind::Checkpoint,
			Self::ServerHtlcSend { .. } => VtxoPolicyKind::ServerHtlcSend,
			Self::ServerHtlcRecv { .. } => VtxoPolicyKind::ServerHtlcRecv,
		}
	}

	/// Whether a [Vtxo] with this output can be spend in an arkoor tx.
	pub fn is_arkoor_compatible(&self) -> bool {
		match self {
			Self::Pubkey { .. } => true,
			Self::Checkpoint { .. } => true,
			Self::ServerHtlcSend { .. } => false,
			Self::ServerHtlcRecv { .. } => false,
		}
	}

	/// The public key used to cosign arkoor txs spending a [Vtxo] with this output.
	/// This will return [None] if [VtxoPolicy::is_arkoor_compatible] returns false.
	pub fn arkoor_pubkey(&self) -> Option<PublicKey> {
		match self {
			Self::Pubkey(PubkeyVtxoPolicy { user_pubkey }) => Some(*user_pubkey),
			Self::Checkpoint(CheckpointVtxoPolicy { user_pubkey }) => Some(*user_pubkey),
			Self::ServerHtlcSend(ServerHtlcSendVtxoPolicy { user_pubkey, .. }) => Some(*user_pubkey),
			Self::ServerHtlcRecv(ServerHtlcRecvVtxoPolicy { user_pubkey, .. }) => Some(*user_pubkey),
		}
	}

	/// Returns the user pubkey associated with a [Vtxo] with this output.
	pub fn user_pubkey(&self) -> PublicKey {
		match self {
			Self::Pubkey(PubkeyVtxoPolicy { user_pubkey }) => *user_pubkey,
			Self::Checkpoint(CheckpointVtxoPolicy { user_pubkey }) => *user_pubkey,
			Self::ServerHtlcSend(ServerHtlcSendVtxoPolicy { user_pubkey, .. }) => *user_pubkey,
			Self::ServerHtlcRecv(ServerHtlcRecvVtxoPolicy { user_pubkey, .. }) => *user_pubkey,
		}
	}

	pub(crate) fn taproot(
		&self,
		server_pubkey: PublicKey,
		exit_delta: BlockDelta,
		expiry_height: BlockHeight,
	) -> taproot::TaprootSpendInfo {
		match self {
			Self::Pubkey(PubkeyVtxoPolicy { user_pubkey }) => {
				exit_taproot(*user_pubkey, server_pubkey, exit_delta)
			},
			Self::Checkpoint(CheckpointVtxoPolicy {user_pubkey}) => {
				checkpoint_taproot(*user_pubkey, server_pubkey, expiry_height)
			}
			Self::ServerHtlcSend(ServerHtlcSendVtxoPolicy { user_pubkey, payment_hash, htlc_expiry }) => {
				server_htlc_send_taproot(*payment_hash, server_pubkey, *user_pubkey, exit_delta, *htlc_expiry)
			},
			Self::ServerHtlcRecv(ServerHtlcRecvVtxoPolicy {
				user_pubkey, payment_hash, htlc_expiry_delta, htlc_expiry
			}) => {
				server_htlc_receive_taproot(*payment_hash, server_pubkey, *user_pubkey, exit_delta, *htlc_expiry_delta, *htlc_expiry)
			},
		}
	}

	/// Generates a script based on the exit conditions for a given policy type.
	///
	/// Depending on the specific policy variant, this function produces an appropriate script
	/// that implements the user exit clause. The exit clause enforces specific rules for exiting
	/// the contract or completing a transaction based on the provided `exit_delta` parameter.
	pub fn user_exit_clause(&self, exit_delta: BlockDelta) -> ScriptBuf {
		match self {
			Self::Pubkey(PubkeyVtxoPolicy { user_pubkey }) => {
				exit_clause(*user_pubkey, exit_delta)
			},
			Self::Checkpoint(_) => {
				todo!("This clause cannot be exited by the user")
			},
			Self::ServerHtlcSend(ServerHtlcSendVtxoPolicy { user_pubkey, htlc_expiry, .. }) => {
				scripts::delay_timelock_sign(
					2 * exit_delta, *htlc_expiry, user_pubkey.x_only_public_key().0,
				)
			},
			Self::ServerHtlcRecv(ServerHtlcRecvVtxoPolicy {
				user_pubkey, payment_hash, htlc_expiry_delta, ..
			}) => {
				scripts::hash_delay_sign(
					payment_hash.to_sha256_hash(),
					exit_delta + *htlc_expiry_delta,
					user_pubkey.x_only_public_key().0,
				)
			},
		}
	}

	pub(crate) fn script_pubkey(
		&self,
		server_pubkey: PublicKey,
		exit_delta: BlockDelta,
		expiry_height: BlockHeight,
	) -> ScriptBuf {
		self.taproot(server_pubkey, exit_delta, expiry_height).script_pubkey()
	}

	pub(crate) fn txout(
		&self,
		amount: Amount,
		server_pubkey: PublicKey,
		exit_delta: BlockDelta,
		expiry_height: BlockHeight,
	) -> TxOut {
		TxOut {
			value: amount,
			script_pubkey: self.script_pubkey(server_pubkey, exit_delta, expiry_height),
		}
	}
}
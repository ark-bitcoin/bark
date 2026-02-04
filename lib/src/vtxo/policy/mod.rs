
pub mod clause;
pub mod signing;

use std::fmt;
use std::str::FromStr;

use bitcoin::{Amount, ScriptBuf, TxOut, taproot};
use bitcoin::secp256k1::PublicKey;

use bitcoin_ext::{BlockDelta, BlockHeight, TaprootSpendInfoExt};

use crate::{SECP, musig };
use crate::lightning::PaymentHash;
use crate::tree::signed::UnlockHash;
use crate::vtxo::TapScriptClause;
use crate::vtxo::policy::clause::{
	DelayedSignClause, DelayedTimelockSignClause, HashDelaySignClause, HashSignClause,
	TimelockSignClause, VtxoClause,
};

/// Trait for policy types that can be used in a Vtxo.
pub trait Policy: Clone + Send + Sync + 'static {
	fn policy_type(&self) -> VtxoPolicyKind;

	fn taproot(
		&self,
		server_pubkey: PublicKey,
		exit_delta: BlockDelta,
		expiry_height: BlockHeight,
	) -> taproot::TaprootSpendInfo;

	fn script_pubkey(
		&self,
		server_pubkey: PublicKey,
		exit_delta: BlockDelta,
		expiry_height: BlockHeight,
	) -> ScriptBuf {
		Policy::taproot(self, server_pubkey, exit_delta, expiry_height).script_pubkey()
	}

	fn txout(
		&self,
		amount: Amount,
		server_pubkey: PublicKey,
		exit_delta: BlockDelta,
		expiry_height: BlockHeight,
	) -> TxOut {
		TxOut {
			script_pubkey: Policy::script_pubkey(self, server_pubkey, exit_delta, expiry_height),
			value: amount,
		}
	}

	fn clauses(
		&self,
		exit_delta: u16,
		expiry_height: BlockHeight,
		server_pubkey: PublicKey,
	) -> Vec<VtxoClause>;
}

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
	/// Server-only policy where coins can only be swept by the server after expiry.
	Expiry,
	/// hArk leaf output policy (intermediate outputs spent by leaf txs).
	HarkLeaf,
}

impl fmt::Display for VtxoPolicyKind {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
	    match self {
			Self::Pubkey => f.write_str("pubkey"),
			Self::Checkpoint => f.write_str("checkpoint"),
			Self::ServerHtlcSend => f.write_str("server-htlc-send"),
			Self::ServerHtlcRecv => f.write_str("server-htlc-receive"),
			Self::Expiry => f.write_str("expiry"),
			Self::HarkLeaf => f.write_str("hark-leaf"),
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
			"expiry" => Self::Expiry,
			"hark-leaf" => Self::HarkLeaf,
			_ => return Err(format!("unknown VtxoPolicyKind: {}", s)),
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
				write!(f, "a VtxoPolicyKind")
			}
			fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
				VtxoPolicyKind::from_str(v).map_err(serde::de::Error::custom)
			}
		}
		d.deserialize_str(Visitor)
	}
}

/// Policy enabling VTXO protected with a public key.
///
/// This will build a taproot with 2 spending paths:
/// 1. The keyspend path allows Alice and Server to collaborate to spend
/// the VTXO.
///
/// 2. The script-spend path allows Alice to unilaterally spend the VTXO
/// after a delay.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PubkeyVtxoPolicy {
	pub user_pubkey: PublicKey,
}

impl From<PubkeyVtxoPolicy> for VtxoPolicy {
	fn from(policy: PubkeyVtxoPolicy) -> Self {
		Self::Pubkey(policy)
	}
}

impl PubkeyVtxoPolicy {
	/// Allows Alice to spend the VTXO after a delay.
	pub fn user_pubkey_claim_clause(&self, exit_delta: BlockDelta) -> DelayedSignClause {
		DelayedSignClause { pubkey: self.user_pubkey, block_delta: exit_delta }
	}

	pub fn clauses(&self, exit_delta: BlockDelta) -> Vec<VtxoClause> {
		vec![self.user_pubkey_claim_clause(exit_delta).into()]
	}

	pub fn taproot(
		&self,
		server_pubkey: PublicKey,
		exit_delta: BlockDelta,
	) -> taproot::TaprootSpendInfo {
		let combined_pk = musig::combine_keys([self.user_pubkey, server_pubkey])
			.x_only_public_key().0;

		let user_pubkey_claim_clause = self.user_pubkey_claim_clause(exit_delta);
		taproot::TaprootBuilder::new()
			.add_leaf(0, user_pubkey_claim_clause.tapscript()).unwrap()
			.finalize(&SECP, combined_pk).unwrap()
	}
}

/// Policy enabling server checkpoints
///
/// This will build a taproot with 2 clauses:
/// 1. The keyspend path allows Alice and Server to collaborate to spend
/// the checkpoint.
///
/// 2. The script-spend path allows Server to spend the checkpoint after
/// the expiry height.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CheckpointVtxoPolicy {
	pub user_pubkey: PublicKey,
}

impl From<CheckpointVtxoPolicy> for ServerVtxoPolicy {
	fn from(policy: CheckpointVtxoPolicy) -> Self {
		Self::Checkpoint(policy)
	}
}

impl CheckpointVtxoPolicy {
	/// Allows Server to spend the checkpoint after expiry height.
	pub fn server_sweeping_clause(
		&self,
		expiry_height: BlockHeight,
		server_pubkey: PublicKey,
	) -> TimelockSignClause {
		TimelockSignClause { pubkey: server_pubkey, timelock_height: expiry_height }
	}

	pub fn clauses(
		&self,
		expiry_height: BlockHeight,
		server_pubkey: PublicKey,
	) -> Vec<VtxoClause> {
		vec![self.server_sweeping_clause(expiry_height, server_pubkey).into()]
	}

	pub fn taproot(
		&self,
		server_pubkey: PublicKey,
		expiry_height: BlockHeight,
	) -> taproot::TaprootSpendInfo {
		let combined_pk = musig::combine_keys([self.user_pubkey, server_pubkey])
			.x_only_public_key().0;
		let server_sweeping_clause = self.server_sweeping_clause(expiry_height, server_pubkey);

		taproot::TaprootBuilder::new()
			.add_leaf(0, server_sweeping_clause.tapscript()).unwrap()
			.finalize(&SECP, combined_pk).unwrap()
	}
}

/// Server-only policy where coins can only be swept by the server after expiry.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ExpiryVtxoPolicy {
	pub internal_key: bitcoin::secp256k1::XOnlyPublicKey,
}

impl ExpiryVtxoPolicy {
	/// Creates a new expiry policy with the given internal key.
	pub fn new(internal_key: bitcoin::secp256k1::XOnlyPublicKey) -> Self {
		Self { internal_key }
	}

	/// Allows Server to spend after expiry height.
	pub fn server_sweeping_clause(
		&self,
		expiry_height: BlockHeight,
		server_pubkey: PublicKey,
	) -> TimelockSignClause {
		TimelockSignClause { pubkey: server_pubkey, timelock_height: expiry_height }
	}

	pub fn clauses(
		&self,
		expiry_height: BlockHeight,
		server_pubkey: PublicKey,
	) -> Vec<VtxoClause> {
		vec![self.server_sweeping_clause(expiry_height, server_pubkey).into()]
	}

	pub fn taproot(
		&self,
		server_pubkey: PublicKey,
		expiry_height: BlockHeight,
	) -> taproot::TaprootSpendInfo {
		let server_sweeping_clause = self.server_sweeping_clause(expiry_height, server_pubkey);

		taproot::TaprootBuilder::new()
			.add_leaf(0, server_sweeping_clause.tapscript()).unwrap()
			.finalize(&SECP, self.internal_key).unwrap()
	}
}

/// Policy for hArk leaf outputs (intermediate outputs spent by leaf txs).
///
/// These are the outputs that feed into the final leaf transactions in a signed
/// VTXO tree. They are locked by:
/// 1. An expiry clause allowing the server to sweep after expiry
/// 2. An unlock clause requiring a preimage and a signature from user+server
///
/// The internal key is set to the MuSig of user's VTXO key + server pubkey.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HarkLeafVtxoPolicy {
	pub user_pubkey: PublicKey,
	pub unlock_hash: UnlockHash,
}

impl HarkLeafVtxoPolicy {
	/// Creates the expiry clause allowing the server to sweep after expiry.
	pub fn expiry_clause(
		&self,
		expiry_height: BlockHeight,
		server_pubkey: PublicKey,
	) -> TimelockSignClause {
		TimelockSignClause { pubkey: server_pubkey, timelock_height: expiry_height }
	}

	/// Creates the unlock clause requiring a preimage and aggregate signature.
	pub fn unlock_clause(&self, server_pubkey: PublicKey) -> HashSignClause {
		let agg_pk = musig::combine_keys([self.user_pubkey, server_pubkey]);
		HashSignClause { pubkey: agg_pk, hash: self.unlock_hash }
	}

	/// Returns the clauses for this policy.
	pub fn clauses(
		&self,
		expiry_height: BlockHeight,
		server_pubkey: PublicKey,
	) -> Vec<VtxoClause> {
		vec![
			self.expiry_clause(expiry_height, server_pubkey).into(),
			self.unlock_clause(server_pubkey).into(),
		]
	}

	/// Build the taproot spend info for this policy.
	pub fn taproot(
		&self,
		server_pubkey: PublicKey,
		expiry_height: BlockHeight,
	) -> taproot::TaprootSpendInfo {
		let agg_pk = musig::combine_keys([self.user_pubkey, server_pubkey]);
		let expiry_clause = self.expiry_clause(expiry_height, server_pubkey);
		let unlock_clause = self.unlock_clause(server_pubkey);

		taproot::TaprootBuilder::new()
			.add_leaf(1, expiry_clause.tapscript()).unwrap()
			.add_leaf(1, unlock_clause.tapscript()).unwrap()
			.finalize(&SECP, agg_pk.x_only_public_key().0).unwrap()
	}
}

/// Policy enabling outgoing Lightning payments.
///
/// This will build a taproot with 3 clauses:
/// 1. The keyspend path allows Alice and Server to collaborate to spend
/// the HTLC. The Server can use this path to revoke the HTLC if payment
/// failed
///
/// 2. The script-spend path contains one leaf that allows Server to spend
/// the HTLC after the expiry, if it knows the preimage. Server can use
/// this path if Alice tries to spend using her clause.
///
/// 3. The second leaf allows Alice to spend the HTLC after its expiry
/// and with a delay. Alice must use this path if the server fails to
/// provide the preimage and refuse to revoke the HTLC. It will either
/// force the Server to reveal the preimage (by spending using her clause)
/// or give Alice her money back.
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

impl ServerHtlcSendVtxoPolicy {
	/// Allows Server to spend the HTLC after the delta, if it knows the
	/// preimage. Server can use this path if Alice tries to spend using her
	/// clause.
	pub fn server_reveals_preimage_clause(
		&self,
		server_pubkey: PublicKey,
		exit_delta: BlockDelta,
	) -> HashDelaySignClause {
		HashDelaySignClause {
			pubkey: server_pubkey,
			payment_hash: self.payment_hash,
			block_delta: exit_delta
		}
	}

	/// Allows Alice to spend the HTLC after its expiry and with a delay.
	/// Alice must use this path if the server fails to provide the preimage
	/// and refuse to revoke the HTLC. It will either force the server to
	/// reveal the preimage (by spending using its clause) or give Alice her
	/// money back.
	pub fn user_claim_after_expiry_clause(
		&self,
		exit_delta: BlockDelta,
	) -> DelayedTimelockSignClause {
		DelayedTimelockSignClause {
			pubkey: self.user_pubkey,
			timelock_height: self.htlc_expiry,
			block_delta: 2 * exit_delta
		}
	}


	pub fn clauses(&self, exit_delta: BlockDelta, server_pubkey: PublicKey) -> Vec<VtxoClause> {
		vec![
			self.server_reveals_preimage_clause(server_pubkey, exit_delta).into(),
			self.user_claim_after_expiry_clause(exit_delta).into(),
		]
	}

	pub fn taproot(&self, server_pubkey: PublicKey, exit_delta: BlockDelta) -> taproot::TaprootSpendInfo {
		let server_reveals_preimage_clause = self.server_reveals_preimage_clause(server_pubkey, exit_delta);
		let user_claim_after_expiry_clause = self.user_claim_after_expiry_clause(exit_delta);

		let combined_pk = musig::combine_keys([self.user_pubkey, server_pubkey])
			.x_only_public_key().0;
		bitcoin::taproot::TaprootBuilder::new()
			.add_leaf(1, server_reveals_preimage_clause.tapscript()).unwrap()
			.add_leaf(1, user_claim_after_expiry_clause.tapscript()).unwrap()
			.finalize(&SECP, combined_pk).unwrap()
	}
}


/// Policy enabling incoming Lightning payments.
///
/// This will build a taproot with 3 clauses:
/// 1. The keyspend path allows Alice and Server to collaborate to spend
/// the HTLC. This is the expected path to be used. Server should only
/// accept to collaborate if Alice reveals the preimage.
///
/// 2. The script-spend path contains one leaf that allows Server to spend
/// the HTLC after the expiry, with an exit delta delay. Server can use
/// this path if Alice tries to spend the HTLC using the 3rd path after
/// the HTLC expiry
///
/// 3. The second leaf allows Alice to spend the HTLC if she knows the
/// preimage, but with a greater exit delta delay than server's clause.
/// Alice must use this path if she revealed the preimage but Server
/// refused to collaborate.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ServerHtlcRecvVtxoPolicy {
	pub user_pubkey: PublicKey,
	pub payment_hash: PaymentHash,
	pub htlc_expiry_delta: BlockDelta,
	pub htlc_expiry: BlockHeight,
}

impl ServerHtlcRecvVtxoPolicy {
	/// Allows Alice to spend the HTLC if she knows the preimage, but with a
	/// greater exit delta delay than server's clause. Alice must use this
	/// path if she revealed the preimage but server refused to cosign
	/// claim VTXO.
	pub fn user_reveals_preimage_clause(&self, exit_delta: BlockDelta) -> HashDelaySignClause {
		HashDelaySignClause {
			pubkey: self.user_pubkey,
			payment_hash: self.payment_hash,
			block_delta: self.htlc_expiry_delta + exit_delta
		}
	}

	/// Allows Server to spend the HTLC after the HTLC expiry, with an exit
	/// delta delay. Server can use this path if Alice tries to spend the
	/// HTLC using her clause after the HTLC expiry.
	pub fn server_claim_after_expiry_clause(
		&self,
		server_pubkey: PublicKey,
		exit_delta: BlockDelta,
	) -> DelayedTimelockSignClause {
		DelayedTimelockSignClause {
			pubkey: server_pubkey,
			timelock_height: self.htlc_expiry,
			block_delta: exit_delta
		}
	}

	pub fn clauses(&self, exit_delta: BlockDelta, server_pubkey: PublicKey) -> Vec<VtxoClause> {
		vec![
			self.user_reveals_preimage_clause(exit_delta).into(),
			self.server_claim_after_expiry_clause(server_pubkey, exit_delta).into(),
		]
	}

	pub fn taproot(&self, server_pubkey: PublicKey, exit_delta: BlockDelta) -> taproot::TaprootSpendInfo {
		let server_claim_after_expiry_clause = self.server_claim_after_expiry_clause(server_pubkey, exit_delta);
		let user_reveals_preimage_clause = self.user_reveals_preimage_clause(exit_delta);

		let combined_pk = musig::combine_keys([self.user_pubkey, server_pubkey])
			.x_only_public_key().0;
		bitcoin::taproot::TaprootBuilder::new()
			.add_leaf(1, server_claim_after_expiry_clause.tapscript()).unwrap()
			.add_leaf(1, user_reveals_preimage_clause.tapscript()).unwrap()
			.finalize(&SECP, combined_pk).unwrap()
	}
}

impl From<ServerHtlcRecvVtxoPolicy> for VtxoPolicy {
	fn from(policy: ServerHtlcRecvVtxoPolicy) -> Self {
		Self::ServerHtlcRecv(policy)
	}
}

/// User-facing VTXO output policy.
///
/// All variants have an associated user public key, accessible via the infallible
/// `user_pubkey()` method. These policies are used in protocol messages and by clients.
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
	/// A VTXO that represents an HTLC with the Ark server to send money.
	ServerHtlcSend(ServerHtlcSendVtxoPolicy),
	/// A VTXO that represents an HTLC with the Ark server to receive money.
	ServerHtlcRecv(ServerHtlcRecvVtxoPolicy),
}

impl VtxoPolicy {
	pub fn new_pubkey(user_pubkey: PublicKey) -> Self {
		Self::Pubkey(PubkeyVtxoPolicy { user_pubkey })
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
		Self::ServerHtlcRecv(ServerHtlcRecvVtxoPolicy {
			user_pubkey, payment_hash, htlc_expiry, htlc_expiry_delta,
		})
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
			Self::ServerHtlcSend { .. } => VtxoPolicyKind::ServerHtlcSend,
			Self::ServerHtlcRecv { .. } => VtxoPolicyKind::ServerHtlcRecv,
		}
	}

	/// Whether a [Vtxo](crate::Vtxo) with this output can be spent in an arkoor tx.
	pub fn is_arkoor_compatible(&self) -> bool {
		match self {
			Self::Pubkey { .. } => true,
			Self::ServerHtlcSend { .. } => false,
			Self::ServerHtlcRecv { .. } => false,
		}
	}

	/// The public key used to cosign arkoor txs spending a [Vtxo](crate::Vtxo)
	/// with this output.
	/// Returns [None] for HTLC policies.
	pub fn arkoor_pubkey(&self) -> Option<PublicKey> {
		match self {
			Self::Pubkey(PubkeyVtxoPolicy { user_pubkey }) => Some(*user_pubkey),
			Self::ServerHtlcSend { .. } => None,
			Self::ServerHtlcRecv { .. } => None,
		}
	}

	/// Returns the user pubkey associated with this policy.
	pub fn user_pubkey(&self) -> PublicKey {
		match self {
			Self::Pubkey(PubkeyVtxoPolicy { user_pubkey }) => *user_pubkey,
			Self::ServerHtlcSend(ServerHtlcSendVtxoPolicy { user_pubkey, .. }) => *user_pubkey,
			Self::ServerHtlcRecv(ServerHtlcRecvVtxoPolicy { user_pubkey, .. }) => *user_pubkey,
		}
	}

	pub fn taproot(
		&self,
		server_pubkey: PublicKey,
		exit_delta: BlockDelta,
		expiry_height: BlockHeight,
	) -> taproot::TaprootSpendInfo {
		let _ = expiry_height; // not used by user-facing policies
		match self {
			Self::Pubkey(policy) => policy.taproot(server_pubkey, exit_delta),
			Self::ServerHtlcSend(policy) => policy.taproot(server_pubkey, exit_delta),
			Self::ServerHtlcRecv(policy) => policy.taproot(server_pubkey, exit_delta),
		}
	}

	pub fn script_pubkey(
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

	pub fn clauses(
		&self,
		exit_delta: u16,
		_expiry_height: BlockHeight,
		server_pubkey: PublicKey,
	) -> Vec<VtxoClause> {
		match self {
			Self::Pubkey(policy) => policy.clauses(exit_delta),
			Self::ServerHtlcSend(policy) => policy.clauses(exit_delta, server_pubkey),
			Self::ServerHtlcRecv(policy) => policy.clauses(exit_delta, server_pubkey),
		}
	}
}

/// Server-internal VTXO policy.
///
/// This is a superset of [VtxoPolicy] used by the server for internal tracking.
/// Includes policies without user public keys.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ServerVtxoPolicy {
	/// Wraps any user-facing policy.
	User(VtxoPolicy),
	/// A policy which returns all coins to the server after expiry.
	Checkpoint(CheckpointVtxoPolicy),
	/// Server-only policy where coins can only be swept by the server after expiry.
	Expiry(ExpiryVtxoPolicy),
	/// hArk leaf output policy (intermediate outputs spent by leaf txs).
	HarkLeaf(HarkLeafVtxoPolicy),
}

impl From<VtxoPolicy> for ServerVtxoPolicy {
	fn from(p: VtxoPolicy) -> Self {
		Self::User(p)
	}
}

impl From<HarkLeafVtxoPolicy> for ServerVtxoPolicy {
	fn from(p: HarkLeafVtxoPolicy) -> Self {
		Self::HarkLeaf(p)
	}
}

impl ServerVtxoPolicy {
	pub fn new_checkpoint(user_pubkey: PublicKey) -> Self {
		Self::Checkpoint(CheckpointVtxoPolicy { user_pubkey })
	}

	pub fn new_expiry(internal_key: bitcoin::secp256k1::XOnlyPublicKey) -> Self {
		Self::Expiry(ExpiryVtxoPolicy { internal_key })
	}

	pub fn new_hark_leaf(user_pubkey: PublicKey, unlock_hash: UnlockHash) -> Self {
		Self::HarkLeaf(HarkLeafVtxoPolicy { user_pubkey, unlock_hash })
	}

	/// The policy type id.
	pub fn policy_type(&self) -> VtxoPolicyKind {
		match self {
			Self::User(p) => p.policy_type(),
			Self::Checkpoint { .. } => VtxoPolicyKind::Checkpoint,
			Self::Expiry { .. } => VtxoPolicyKind::Expiry,
			Self::HarkLeaf { .. } => VtxoPolicyKind::HarkLeaf,
		}
	}

	/// Whether a [Vtxo](crate::Vtxo) with this output can be spent in an arkoor tx.
	pub fn is_arkoor_compatible(&self) -> bool {
		match self {
			Self::User(p) => p.is_arkoor_compatible(),
			Self::Checkpoint { .. } => true,
			Self::Expiry { .. } => false,
			Self::HarkLeaf { .. } => false,
		}
	}

	/// Returns the user pubkey if this policy has one.
	pub fn user_pubkey(&self) -> Option<PublicKey> {
		match self {
			Self::User(p) => Some(p.user_pubkey()),
			Self::Checkpoint(CheckpointVtxoPolicy { user_pubkey }) => Some(*user_pubkey),
			Self::Expiry { .. } => None,
			Self::HarkLeaf(HarkLeafVtxoPolicy { user_pubkey, .. }) => Some(*user_pubkey),
		}
	}

	pub fn taproot(
		&self,
		server_pubkey: PublicKey,
		exit_delta: BlockDelta,
		expiry_height: BlockHeight,
	) -> taproot::TaprootSpendInfo {
		let _ = exit_delta; // not used by server-only policies
		match self {
			Self::User(p) => p.taproot(server_pubkey, exit_delta, expiry_height),
			Self::Checkpoint(policy) => policy.taproot(server_pubkey, expiry_height),
			Self::Expiry(policy) => policy.taproot(server_pubkey, expiry_height),
			Self::HarkLeaf(policy) => policy.taproot(server_pubkey, expiry_height),
		}
	}

	pub fn script_pubkey(
		&self,
		server_pubkey: PublicKey,
		exit_delta: BlockDelta,
		expiry_height: BlockHeight,
	) -> ScriptBuf {
		self.taproot(server_pubkey, exit_delta, expiry_height).script_pubkey()
	}

	pub fn clauses(
		&self,
		exit_delta: u16,
		expiry_height: BlockHeight,
		server_pubkey: PublicKey,
	) -> Vec<VtxoClause> {
		let _ = exit_delta; // not used for server-only policies
		match self {
			Self::User(p) => p.clauses(exit_delta, expiry_height, server_pubkey),
			Self::Checkpoint(policy) => policy.clauses(expiry_height, server_pubkey),
			Self::Expiry(policy) => policy.clauses(expiry_height, server_pubkey),
			Self::HarkLeaf(policy) => policy.clauses(expiry_height, server_pubkey),
		}
	}

	/// Check whether this is a user policy
	pub fn is_user_policy(&self) -> bool {
		matches!(self, ServerVtxoPolicy::User(_))
	}

	/// Try to convert to a user policy if it is one
	pub fn into_user_policy(self) -> Option<VtxoPolicy> {
		match self {
			ServerVtxoPolicy::User(p) => Some(p),
			_ => None,
		}
	}
}

impl Policy for VtxoPolicy {
	fn policy_type(&self) -> VtxoPolicyKind {
		VtxoPolicy::policy_type(self)
	}

	fn taproot(
		&self,
		server_pubkey: PublicKey,
		exit_delta: BlockDelta,
		expiry_height: BlockHeight,
	) -> taproot::TaprootSpendInfo {
		VtxoPolicy::taproot(self, server_pubkey, exit_delta, expiry_height)
	}

	fn clauses(
		&self,
		exit_delta: u16,
		expiry_height: BlockHeight,
		server_pubkey: PublicKey,
	) -> Vec<VtxoClause> {
		VtxoPolicy::clauses(self, exit_delta, expiry_height, server_pubkey)
	}
}

impl Policy for ServerVtxoPolicy {
	fn policy_type(&self) -> VtxoPolicyKind {
		ServerVtxoPolicy::policy_type(self)
	}

	fn taproot(
		&self,
		server_pubkey: PublicKey,
		exit_delta: BlockDelta,
		expiry_height: BlockHeight,
	) -> taproot::TaprootSpendInfo {
		ServerVtxoPolicy::taproot(self, server_pubkey, exit_delta, expiry_height)
	}

	fn clauses(
		&self,
		exit_delta: u16,
		expiry_height: BlockHeight,
		server_pubkey: PublicKey,
	) -> Vec<VtxoClause> {
		ServerVtxoPolicy::clauses(self, exit_delta, expiry_height, server_pubkey)
	}
}

#[cfg(test)]
mod tests {
	use std::str::FromStr;

	use bitcoin::hashes::{sha256, Hash};
	use bitcoin::key::Keypair;
	use bitcoin::sighash::{self, SighashCache};
	use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, TxIn, TxOut, Txid, Witness};
	use bitcoin::taproot::{self, TapLeafHash};
	use bitcoin_ext::{TaprootSpendInfoExt, fee};

	use crate::{SECP, musig};
	use crate::test_util::verify_tx;
	use crate::vtxo::policy::clause::TapScriptClause;

	use super::*;

	lazy_static! {
		static ref USER_KEYPAIR: Keypair = Keypair::from_str("5255d132d6ec7d4fc2a41c8f0018bb14343489ddd0344025cc60c7aa2b3fda6a").unwrap();
		static ref SERVER_KEYPAIR: Keypair = Keypair::from_str("1fb316e653eec61de11c6b794636d230379509389215df1ceb520b65313e5426").unwrap();
	}

	fn transaction() -> bitcoin::Transaction {
		let address = bitcoin::Address::from_str("tb1q00h5delzqxl7xae8ufmsegghcl4jwfvdnd8530")
			.unwrap().assume_checked();

		bitcoin::Transaction {
			version: bitcoin::transaction::Version(3),
			lock_time: bitcoin::absolute::LockTime::ZERO,
			input: vec![],
			output: vec![TxOut {
				script_pubkey: address.script_pubkey(),
				value: Amount::from_sat(900_000),
			}, fee::fee_anchor()]
		}
	}

	#[test]
	fn test_hark_leaf_vtxo_policy_unlock_clause() {
		let preimage = [0u8; 32];
		let unlock_hash = sha256::Hash::hash(&preimage);

		let policy = HarkLeafVtxoPolicy {
			user_pubkey: USER_KEYPAIR.public_key(),
			unlock_hash,
		};

		let expiry_height = 100_000;

		// Build the taproot spend info using the policy
		let taproot = policy.taproot(SERVER_KEYPAIR.public_key(), expiry_height);
		let unlock_clause = policy.unlock_clause(SERVER_KEYPAIR.public_key());

		let tx_in = TxOut {
			script_pubkey: taproot.script_pubkey(),
			value: Amount::from_sat(1_000_000),
		};

		// Build the spending transaction
		let mut tx = transaction();
		tx.input.push(TxIn {
			previous_output: OutPoint::new(Txid::all_zeros(), 0),
			script_sig: ScriptBuf::default(),
			sequence: Sequence::ZERO,
			witness: Witness::new(),
		});

		// Get the control block for the unlock clause
		let cb = taproot
			.control_block(&(unlock_clause.tapscript(), taproot::LeafVersion::TapScript))
			.expect("script is in taproot");

		// Compute sighash
		let leaf_hash = TapLeafHash::from_script(
			&unlock_clause.tapscript(),
			taproot::LeafVersion::TapScript,
		);
		let mut shc = SighashCache::new(&tx);
		let sighash = shc.taproot_script_spend_signature_hash(
			0, &sighash::Prevouts::All(&[tx_in.clone()]), leaf_hash, sighash::TapSighashType::Default,
		).expect("all prevouts provided");

		// Create MuSig signature from user + server
		let (user_sec_nonce, user_pub_nonce) = musig::nonce_pair(&*USER_KEYPAIR);
		let (server_pub_nonce, server_part_sig) = musig::deterministic_partial_sign(
			&*SERVER_KEYPAIR,
			[USER_KEYPAIR.public_key()],
			&[&user_pub_nonce],
			sighash.to_byte_array(),
			None,
		);
		let agg_nonce = musig::nonce_agg(&[&user_pub_nonce, &server_pub_nonce]);

		let (_user_part_sig, final_sig) = musig::partial_sign(
			[USER_KEYPAIR.public_key(), SERVER_KEYPAIR.public_key()],
			agg_nonce,
			&*USER_KEYPAIR,
			user_sec_nonce,
			sighash.to_byte_array(),
			None,
			Some(&[&server_part_sig]),
		);
		let final_sig = final_sig.expect("should have final signature");

		tx.input[0].witness = unlock_clause.witness(&(final_sig, preimage), &cb);

		// Verify the transaction
		verify_tx(&[tx_in], 0, &tx).expect("unlock clause spending should be valid");
	}

	#[test]
	fn test_hark_leaf_vtxo_policy_expiry_clause() {
		let preimage = [0u8; 32];
		let unlock_hash = sha256::Hash::hash(&preimage);

		let policy = HarkLeafVtxoPolicy {
			user_pubkey: USER_KEYPAIR.public_key(),
			unlock_hash,
		};

		let expiry_height = 100;

		// Build the taproot spend info using the policy
		let taproot = policy.taproot(SERVER_KEYPAIR.public_key(), expiry_height);
		let expiry_clause = policy.expiry_clause(expiry_height, SERVER_KEYPAIR.public_key());

		let tx_in = TxOut {
			script_pubkey: taproot.script_pubkey(),
			value: Amount::from_sat(1_000_000),
		};

		// Build the spending transaction with locktime
		let mut tx = transaction();
		tx.lock_time = expiry_clause.locktime();
		tx.input.push(TxIn {
			previous_output: OutPoint::new(Txid::all_zeros(), 0),
			script_sig: ScriptBuf::default(),
			sequence: Sequence::ZERO,
			witness: Witness::new(),
		});

		// Get the control block for the expiry clause
		let cb = taproot
			.control_block(&(expiry_clause.tapscript(), taproot::LeafVersion::TapScript))
			.expect("script is in taproot");

		// Compute sighash
		let leaf_hash = TapLeafHash::from_script(
			&expiry_clause.tapscript(),
			taproot::LeafVersion::TapScript,
		);
		let mut shc = SighashCache::new(&tx);
		let sighash = shc.taproot_script_spend_signature_hash(
			0, &sighash::Prevouts::All(&[tx_in.clone()]), leaf_hash, sighash::TapSighashType::Default,
		).expect("all prevouts provided");

		// Server signs
		let signature = SECP.sign_schnorr(&sighash.into(), &*SERVER_KEYPAIR);

		tx.input[0].witness = expiry_clause.witness(&signature, &cb);

		// Verify the transaction
		verify_tx(&[tx_in], 0, &tx).expect("expiry clause spending should be valid");
	}
}

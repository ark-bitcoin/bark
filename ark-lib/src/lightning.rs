
use std::fmt;
use std::array::TryFromSliceError;
use std::str::FromStr;
use bitcoin::Amount ;
use bitcoin::hashes::{sha256, Hash};
use bitcoin::hex::{fmt_hex_exact, Case, FromHex};
use bitcoin::secp256k1::PublicKey;
use bitcoin::taproot::TaprootSpendInfo;
use hex_conservative::DisplayHex;
use bitcoin_ext::P2TR_DUST;

use crate::{musig, util};
use crate::util::SECP;


/// The minimum fee we consider for an HTLC transaction.
pub const HTLC_MIN_FEE: Amount = P2TR_DUST;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct PaymentHash([u8; 32]);

impl fmt::Debug for PaymentHash {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		fmt::Display::fmt(self, f)
	}
}

impl fmt::Display for PaymentHash {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		fmt_hex_exact!(f, 32, &self.0, Case::Lower)
	}
}

impl From<sha256::Hash> for PaymentHash {
	fn from(hash: sha256::Hash) -> Self {
		PaymentHash(hash.to_byte_array())
	}
}

impl From<&sha256::Hash> for PaymentHash {
	fn from(hash: &sha256::Hash) -> Self {
		PaymentHash(hash.to_byte_array())
	}
}

impl From<[u8; 32]> for PaymentHash {
	fn from(inner: [u8; 32]) -> Self {
		PaymentHash(inner)
	}
}

impl From<PaymentHash> for [u8; 32] {
	fn from(p: PaymentHash) -> Self {
		p.0
	}
}

impl TryFrom<Vec<u8>> for PaymentHash {
	type Error = TryFromSliceError;

	fn try_from(vec: Vec<u8>) -> Result<Self, Self::Error> {
		PaymentHash::try_from(vec.as_slice())
	}
}

impl TryFrom<&[u8]> for PaymentHash {
	type Error = TryFromSliceError;

	fn try_from(slice: &[u8]) -> Result<Self, Self::Error> {
		<&[u8; 32]>::try_from(slice).map(|arr| PaymentHash(*arr))
	}
}

impl AsRef<[u8]> for PaymentHash {
	fn as_ref(&self) -> &[u8] {
		&self.0
	}
}

impl FromStr for PaymentHash {
	type Err = bitcoin::hashes::hex::HexToArrayError;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		<[u8; 32]>::from_hex(s).map(PaymentHash)
	}
}

impl serde::Serialize for PaymentHash {
	fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
		if s.is_human_readable() {
			s.collect_str(self)
		} else {
			s.serialize_bytes(self.as_ref())
		}
	}
}

impl<'de> serde::Deserialize<'de> for PaymentHash {
	fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
		struct Visitor;
		impl<'de> serde::de::Visitor<'de> for Visitor {
			type Value = PaymentHash;
			fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
				write!(f, "a PaymentHash")
			}
			fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<Self::Value, E> {
				PaymentHash::from_slice(v).map_err(serde::de::Error::custom)
			}
			fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
				PaymentHash::from_str(v).map_err(serde::de::Error::custom)
			}
		}
		if d.is_human_readable() {
			d.deserialize_str(Visitor)
		} else {
			d.deserialize_bytes(Visitor)
		}
	}
}

impl PaymentHash {
	pub fn from_slice(bytes: &[u8]) -> Result<PaymentHash, bitcoin::hashes::FromSliceError> {
		sha256::Hash::from_slice(bytes).map(Into::into)
	}

	/// Returns the payment hash as a lowercase hex string.
	pub fn as_hex(&self) -> String {
		self.0.to_lower_hex_string()
	}

	/// Returns the payment hash as a `Vec<u8>`.
	pub fn to_vec(&self) -> Vec<u8> {
		self.0.to_vec()
	}

	pub fn from_preimage(preimage: Preimage) -> PaymentHash {
		sha256::Hash::hash(preimage.as_ref()).into()
	}

	/// Converts this PaymentHash into a `bitcoin::hashes::sha256::Hash`.
	pub fn to_sha256_hash(&self) -> bitcoin::hashes::sha256::Hash {
		bitcoin::hashes::sha256::Hash::from_slice(&self.0)
			.expect("PaymentHash must be 32 bytes, which is always valid for sha256::Hash")
	}
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Preimage([u8; 32]);

impl fmt::Debug for Preimage {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		fmt::Display::fmt(self, f)
	}
}

impl fmt::Display for Preimage {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		fmt_hex_exact!(f, 32, &self.0, Case::Lower)
	}
}

impl From<[u8; 32]> for Preimage {
	fn from(inner: [u8; 32]) -> Self {
		Preimage(inner)
	}
}

impl From<Preimage> for [u8; 32] {
	fn from(p: Preimage) -> Self {
		p.0
	}
}

impl TryFrom<Vec<u8>> for Preimage {
	type Error = TryFromSliceError;

	fn try_from(vec: Vec<u8>) -> Result<Self, Self::Error> {
		Preimage::try_from(vec.as_slice())
	}
}

impl TryFrom<&[u8]> for Preimage {
	type Error = TryFromSliceError;

	fn try_from(slice: &[u8]) -> Result<Self, Self::Error> {
		<&[u8; 32]>::try_from(slice).map(|arr| Preimage(*arr))
	}
}

impl AsRef<[u8]> for Preimage {
	fn as_ref(&self) -> &[u8] {
		&self.0
	}
}

impl Preimage {
	/// Returns the preimage as a lowercase hex string.
	pub fn as_hex(&self) -> String {
		self.0.to_lower_hex_string()
	}

	/// Returns the preimage as a `Vec<u8>`.
	pub fn to_vec(&self) -> Vec<u8> {
		self.0.to_vec()
	}

	pub fn random() -> Preimage {
		Preimage::from(rand::random::<[u8; 32]>())
	}
}
/// Build taproot spend info to build a VTXO to enable lightning send
///
/// This related to the [VtxoPolicy::ServerHtlcSend] policy.
///
/// This build a taproot with 3 clauses:
/// 1. The keyspend path allows Alice and Server to collaborate to spend
/// the HTLC. The Server can use this path to revoke the HTLC if payment
/// failed
///
/// 2. One leaf of the tree allows Server to spend the HTLC after the
/// expiry, if it knows the preimage. Server can use this path if Alice
/// tries to spend using 3rd path.
///
/// 3. The other leaf allows Alice to spend the HTLC after its expiry
/// and with a delay. Alice must use this path if the server fails to
/// provide the preimage and refuse to revoke the HTLC. It will either
/// force the Server to reveal the preimage (by spending using 2nd path)
/// or give Alice her money back.
pub fn server_htlc_send_taproot(
	payment_hash: PaymentHash,
	asp_pubkey: PublicKey,
	user_pubkey: PublicKey,
	exit_delta: u16,
	htlc_expiry: u32,
) -> TaprootSpendInfo {
	let asp_branch = util::hash_delay_sign(
		payment_hash.to_sha256_hash(), exit_delta, asp_pubkey.x_only_public_key().0,
	);
	let user_branch = util::delay_timelock_sign(
		2 * exit_delta, htlc_expiry, user_pubkey.x_only_public_key().0,
	);

	let combined_pk = musig::combine_keys([user_pubkey, asp_pubkey]);
	bitcoin::taproot::TaprootBuilder::new()
		.add_leaf(1, asp_branch).unwrap()
		.add_leaf(1, user_branch).unwrap()
		.finalize(&SECP, combined_pk).unwrap()
}

/// Build taproot spend info to build a VTXO for Alice lightning board
///
/// This related to the [VtxoPolicy::ServerHtlcRecv] policy.
///
/// This build a taproot with 3 clauses:
/// 1. The keyspend path allows Alice and Server to collaborate to spend
/// the HTLC. This is the expected path to be used. Server should only
/// accept to collaborate if Alice reveals the preimage.
///
/// 2. One leaf of the tree allows Server to spend the HTLC after the
/// expiry, with an exit delta delay. Server can use this path if Alice
/// tries to spend the HTLC using the 3rd path after the HTLC expiry
///
/// 3. The other leaf of the tree allows Alice to spend the HTLC if she
/// knows the preimage, but with a greater exit delta delay than Server.
/// Alice must use this path if she revealed the preimage but Server
/// refused to collaborate using the 1rst path.
pub fn server_htlc_receive_taproot(
	payment_hash: PaymentHash,
	asp_pubkey: PublicKey,
	user_pubkey: PublicKey,
	exit_delta: u16,
	htlc_expiry: u32,
) -> TaprootSpendInfo {
	let asp_branch =
		util::delay_timelock_sign(exit_delta, htlc_expiry, asp_pubkey.x_only_public_key().0);
	let user_branch = util::hash_delay_sign(
		payment_hash.to_sha256_hash(),
		2 * exit_delta,
		user_pubkey.x_only_public_key().0,
	);

	let combined_pk = musig::combine_keys([user_pubkey, asp_pubkey]);
	bitcoin::taproot::TaprootBuilder::new()
		.add_leaf(1, asp_branch).unwrap()
		.add_leaf(1, user_branch).unwrap()
		.finalize(&SECP, combined_pk).unwrap()
}


#[derive(Debug, Clone)]
pub enum PaymentStatus {
	Pending,
	Complete,
	Failed,
}

impl fmt::Display for PaymentStatus {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		fmt::Debug::fmt(self, f)
	}
}

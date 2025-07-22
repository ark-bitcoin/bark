
use bitcoin::{opcodes, ScriptBuf, TapSighash, TapTweakHash, Transaction};
use bitcoin::hashes::{sha256, ripemd160, Hash};
use bitcoin::secp256k1::{self, schnorr, PublicKey, XOnlyPublicKey};

use bitcoin_ext::{BlockHeight, TAPROOT_KEYSPEND_WEIGHT};

use crate::musig;

lazy_static! {
	/// Global secp context.
	pub static ref SECP: secp256k1::Secp256k1<secp256k1::All> = secp256k1::Secp256k1::new();
}

/// Create a tapscript that is a checksig and a relative timelock.
pub fn delayed_sign(delay_blocks: u16, pubkey: XOnlyPublicKey) -> ScriptBuf {
	let csv = bitcoin::Sequence::from_height(delay_blocks);
	bitcoin::Script::builder()
		.push_int(csv.to_consensus_u32() as i64)
		.push_opcode(opcodes::all::OP_CSV)
		.push_opcode(opcodes::all::OP_DROP)
		.push_x_only_key(&pubkey)
		.push_opcode(opcodes::all::OP_CHECKSIG)
		.into_script()
}

/// Create a tapscript that is a checksig and an absolute timelock.
pub fn timelock_sign(timelock_height: BlockHeight, pubkey: XOnlyPublicKey) -> ScriptBuf {
	let lt = bitcoin::absolute::LockTime::from_height(timelock_height).unwrap();
	bitcoin::Script::builder()
		.push_int(lt.to_consensus_u32() as i64)
		.push_opcode(opcodes::all::OP_CLTV)
		.push_opcode(opcodes::all::OP_DROP)
		.push_x_only_key(&pubkey)
		.push_opcode(opcodes::all::OP_CHECKSIG)
		.into_script()
}

/// Create a tapscript
pub fn delay_timelock_sign(delay_blocks: u16, timelock_height: u32, pubkey: XOnlyPublicKey) -> ScriptBuf {
	let csv = bitcoin::Sequence::from_height(delay_blocks);
	let lt = bitcoin::absolute::LockTime::from_height(timelock_height).unwrap();
	bitcoin::Script::builder()
		.push_int(lt.to_consensus_u32().try_into().unwrap())
		.push_opcode(opcodes::all::OP_CLTV)
		.push_opcode(opcodes::all::OP_DROP)
		.push_int(csv.to_consensus_u32().try_into().unwrap())
		.push_opcode(opcodes::all::OP_CSV)
		.push_opcode(opcodes::all::OP_DROP)
		.push_x_only_key(&pubkey)
		.push_opcode(opcodes::all::OP_CHECKSIG)
		.into_script()
}

pub fn hash_and_sign(hash: sha256::Hash, pubkey: XOnlyPublicKey) -> ScriptBuf {
	let hash_160 = ripemd160::Hash::hash(&hash[..]);

	bitcoin::Script::builder()
		.push_opcode(opcodes::all::OP_HASH160)
		.push_slice(hash_160.as_byte_array())
		.push_opcode(opcodes::all::OP_EQUALVERIFY)
		.push_x_only_key(&pubkey)
		.push_opcode(opcodes::all::OP_CHECKSIG)
		.into_script()
}

pub fn hash_delay_sign(hash: sha256::Hash, delay_blocks: u16, pubkey: XOnlyPublicKey) -> ScriptBuf {
	let hash_160 = ripemd160::Hash::hash(&hash[..]);
	let csv = bitcoin::Sequence::from_height(delay_blocks);

	bitcoin::Script::builder()
		.push_int(csv.to_consensus_u32().try_into().unwrap())
		.push_opcode(opcodes::all::OP_CSV)
		.push_opcode(opcodes::all::OP_DROP)
		.push_opcode(opcodes::all::OP_HASH160)
		.push_slice(hash_160.as_byte_array())
		.push_opcode(opcodes::all::OP_EQUALVERIFY)
		.push_x_only_key(&pubkey)
		.push_opcode(opcodes::all::OP_CHECKSIG)
		.into_script()
}

/// Fill in the signatures into the unsigned transaction.
///
/// Panics if the nb of inputs and signatures doesn't match or if some input
/// witnesses are not empty.
pub fn fill_taproot_sigs(tx: &mut Transaction, sigs: &[schnorr::Signature]) {
	assert_eq!(tx.input.len(), sigs.len());
	for (input, sig) in tx.input.iter_mut().zip(sigs.iter()) {
		assert!(input.witness.is_empty());
		input.witness.push(&sig[..]);
		debug_assert_eq!(TAPROOT_KEYSPEND_WEIGHT, input.witness.size());
	}
}

/// Verify a partial signature from either of the two parties cosigning a tx.
pub fn verify_partial_sig(
	sighash: TapSighash,
	tweak: TapTweakHash,
	signer: (PublicKey, &musig::PublicNonce),
	other: (PublicKey, &musig::PublicNonce),
	partial_signature: &musig::PartialSignature,
) -> bool {
	let agg_nonce = musig::nonce_agg(&[&signer.1, &other.1]);
	let agg_pk = musig::tweaked_key_agg([signer.0, other.0], tweak.to_byte_array()).0;

	let session = musig::Session::new(&musig::SECP, &agg_pk, agg_nonce, &sighash.to_byte_array());
	session.partial_verify(
		&musig::SECP, &agg_pk, partial_signature, signer.1, musig::pubkey_to(signer.0),
	)
}

/// Implement a bunch of useful traits for any newtype around 32 bytes.
macro_rules! impl_byte_newtype {
	($name:ident, $n:expr) => {
		impl std::fmt::Debug for $name {
			fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
				std::fmt::Display::fmt(self, f)
			}
		}

		impl std::fmt::Display for $name {
			fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
				let case = $crate::bitcoin::hex::Case::Lower;
				$crate::bitcoin::hex::fmt_hex_exact!(f, $n, &self.0, case)
			}
		}

		impl std::str::FromStr for $name {
			type Err = bitcoin::hashes::hex::HexToArrayError;

			fn from_str(s: &str) -> Result<Self, Self::Err> {
				$crate::bitcoin::hex::FromHex::from_hex(s).map($name)
			}
		}

		impl From<[u8; $n]> for $name {
			fn from(inner: [u8; $n]) -> Self {
				$name(inner)
			}
		}

		impl From<$name> for [u8; $n] {
			fn from(p: $name) -> Self {
				p.0
			}
		}

		impl std::convert::TryFrom<&[u8]> for $name {
			type Error = std::array::TryFromSliceError;

			fn try_from(slice: &[u8]) -> Result<Self, Self::Error> {
				<&[u8; $n]>::try_from(slice).map(|arr| $name(*arr))
			}
		}

		impl TryFrom<Vec<u8>> for $name {
			type Error = std::array::TryFromSliceError;

			fn try_from(vec: Vec<u8>) -> Result<Self, Self::Error> {
				$name::try_from(vec.as_slice())
			}
		}

		impl AsRef<[u8]> for $name {
			fn as_ref(&self) -> &[u8] {
				&self.0
			}
		}

		impl<'a> $crate::bitcoin::hex::DisplayHex for &'a $name {
			type Display = <&'a [u8; $n] as $crate::bitcoin::hex::DisplayHex>::Display;

			fn as_hex(self) -> Self::Display {
				$crate::bitcoin::hex::DisplayHex::as_hex(&self.0)
			}
		}

		impl serde::Serialize for $name {
			fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
				if s.is_human_readable() {
					s.collect_str(self)
				} else {
					s.serialize_bytes(self.as_ref())
				}
			}
		}

		impl<'de> serde::Deserialize<'de> for $name {
			fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
				struct Visitor;
				impl<'de> serde::de::Visitor<'de> for Visitor {
					type Value = $name;
					fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
						write!(f, concat!("a ", stringify!($name)))
					}
					fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<Self::Value, E> {
						TryFrom::try_from(v).map_err(serde::de::Error::custom)
					}
					fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
						std::str::FromStr::from_str(v).map_err(serde::de::Error::custom)
					}
				}

				if d.is_human_readable() {
					d.deserialize_str(Visitor)
				} else {
					d.deserialize_bytes(Visitor)
				}
			}
		}

		impl $name {
			/// Convert into underlying byte array.
			pub fn to_byte_array(self) -> [u8; $n] {
				self.0
			}

			/// Create from byte slice.
			pub fn from_slice(slice: &[u8]) -> Result<Self, std::array::TryFromSliceError> {
				Self::try_from(slice)
			}

			/// Convert into a byte vector.
			pub fn to_vec(&self) -> Vec<u8> {
				self.0.to_vec()
			}
		}
	};
}

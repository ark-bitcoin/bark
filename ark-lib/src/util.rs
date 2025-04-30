
use std::io;

use bitcoin::{opcodes, ScriptBuf, Transaction};
use bitcoin::hashes::{sha256, ripemd160, Hash};
use bitcoin::secp256k1::{self, schnorr, XOnlyPublicKey};

use bitcoin_ext::{BlockHeight, TAPROOT_KEYSPEND_WEIGHT};
use serde::de::DeserializeOwned;
use serde::Serialize;

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
		.push_slice(hash_160.as_byte_array())
		.push_opcode(opcodes::all::OP_SWAP)
		.push_opcode(opcodes::all::OP_HASH160)
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

pub trait Encodable: Serialize {
	fn encode(&self) -> Vec<u8> {
		let mut buf = Vec::new();
		ciborium::into_writer(self, &mut buf).unwrap();
		buf
	}
}

pub trait Decodable: DeserializeOwned {
	fn decode(bytes: &[u8]) -> Result<Self, ciborium::de::Error<io::Error>> {
		ciborium::from_reader(bytes)
	}
}

use std::borrow::Borrow;

use bitcoin::{opcodes, taproot, ScriptBuf};
use bitcoin::secp256k1::{self, Keypair, XOnlyPublicKey};

lazy_static::lazy_static! {
	/// Global secp context.
	pub static ref SECP: secp256k1::Secp256k1<secp256k1::All> = secp256k1::Secp256k1::new();
}

pub trait KeypairExt: Borrow<Keypair> {
	/// Adapt this key pair to be used in a key-spend-only taproot.
	fn for_keyspend(&self) -> Keypair {
		let tweak = taproot::TapTweakHash::from_key_and_tweak(
			self.borrow().x_only_public_key().0, None,
		).to_scalar();
		self.borrow().clone().add_xonly_tweak(&SECP, &tweak).expect("hashed values")
	}
}

impl KeypairExt for Keypair {}

/// Create a tapscript that is a checksig and a relative timelock.
pub fn delayed_sign(delay_blocks: u16, pubkey: XOnlyPublicKey) -> ScriptBuf {
	let csv = bitcoin::Sequence::from_height(delay_blocks);
	bitcoin::Script::builder()
		.push_int(csv.to_consensus_u32().try_into().unwrap())
		.push_opcode(opcodes::all::OP_CSV)
		.push_opcode(opcodes::all::OP_DROP)
		.push_x_only_key(&pubkey)
		.push_opcode(opcodes::all::OP_CHECKSIG)
		.into_script()
}

/// Create a tapscript that is a checksig and an absolute.
pub fn timelock_sign(timelock_height: u32, pubkey: XOnlyPublicKey) -> ScriptBuf {
	let lt = bitcoin::absolute::LockTime::from_height(timelock_height).unwrap();
	bitcoin::Script::builder()
		.push_int(lt.to_consensus_u32().try_into().unwrap())
		.push_opcode(opcodes::all::OP_CLTV)
		.push_opcode(opcodes::all::OP_DROP)
		.push_x_only_key(&pubkey)
		.push_opcode(opcodes::all::OP_CHECKSIG)
		.into_script()
}

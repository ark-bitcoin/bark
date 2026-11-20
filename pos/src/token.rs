//! Random bearer tokens and codes. Only their hashes are stored.

use bitcoin::hashes::{Hash, sha256};
use bitcoin::hex::DisplayHex;
use bitcoin::secp256k1::rand::{RngCore, thread_rng};


/// A new random token of 32 bytes, as hex.
pub fn new_token() -> String {
	random_hex(32)
}

/// A new pairing code. It is shorter than a token because people may type
/// it, and it is single-use and expires.
pub fn new_code() -> String {
	random_hex(12)
}

pub fn random_hex(len: usize) -> String {
	let mut bytes = vec![0u8; len];
	thread_rng().fill_bytes(&mut bytes);
	bytes.to_lower_hex_string()
}

pub fn hash(token: &str) -> String {
	sha256::Hash::hash(token.as_bytes()).to_string()
}

#[cfg(test)]
mod test {
	use super::*;

	#[test]
	fn tokens() {
		let a = new_token();
		assert_eq!(a.len(), 64);
		assert_ne!(a, new_token());
		assert_eq!(new_code().len(), 24);
		assert_eq!(hash("abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
	}
}

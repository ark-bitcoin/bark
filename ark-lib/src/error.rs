
use std::fmt;

use bitcoin::secp256k1::PublicKey;



/// Incorrect signing secret key was provided.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, thiserror::Error)]
#[error("incorrect signing key: required={required}, provided={provided}")]
pub struct IncorrectSigningKeyError {
	/// The public key of the key that was required the sign.
	pub required: PublicKey,
	/// The public key we got.
	pub provided: PublicKey,
}

impl fmt::Debug for IncorrectSigningKeyError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("IncorrectSigningKeyError")
			.field("required", &self.required.to_string())
			.field("provided", &self.provided.to_string())
			.finish()
	}
}


use bitcoin::hashes::sha256;


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DuplicateSecretHash {
	pub hash: sha256::Hash,
}
impl_slog!(DuplicateSecretHash, ERROR, "preimage-hash pair duplicate");

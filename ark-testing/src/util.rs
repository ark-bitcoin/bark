use rand::RngCore;

pub fn random_string() -> String {
	// Generate a few random bytes and base58 encode them
	// The entropy should be sufficient to generate unique test-names
	let mut entropy :[u8; 8] = [0; 8];
	rand::thread_rng().fill_bytes(&mut entropy);
	bitcoin::base58::encode(&entropy)
}

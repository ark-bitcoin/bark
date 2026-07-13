use ark::bitcoin::hashes::{sha256, Hash};

use bark_shinigami::v1::CAIRO_SOURCE_SHA256;

const CAIRO_SOURCE: &[u8] =
	include_bytes!("fixtures/ark_taproot_miniscript_claim_v1.cairo");

#[test]
fn cairo_source_matches_pinned_sha256() {
	let actual = sha256::Hash::hash(CAIRO_SOURCE);
	assert_eq!(actual.to_string(), CAIRO_SOURCE_SHA256);
}

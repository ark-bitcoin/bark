//! Version 1 of the experimental Cairo manifest-binding input ABI.
//!
//! This module reproduces the 25-field input and arithmetic used by the
//! `ArkTaprootMiniscriptClaim` Cairo demo whose LF-normalized source SHA-256 is
//! [`CAIRO_SOURCE_SHA256`]. It is an interoperability helper, not a security
//! boundary.
//!
//! [`ManifestBindingClaim::from_pubkey_vtxo_owner_exit`] derives the Bark-owned
//! amount, delay, TapLeaf hash, Merkle root, and control-block path from a
//! pubkey-policy VTXO. The caller remains responsible for validating the VTXO.
//! [`ManifestBindingClaim::from_manifest_fields`] is the lower-level ABI
//! encoder for external manifest producers and does not check that its opaque
//! fields describe a Bark VTXO.
//!
//! # What this does not verify
//!
//! The demo's `mix(left, right) = left * 31 + right * 17 + 7` operation is a
//! small algebraic binding over the Cairo field. It is not a cryptographic
//! hash. In particular, this module does **not**:
//!
//! - execute Bitcoin Script or Shinigami;
//! - generate or verify a STARK proof; or
//! - make caller-provided manifest data trustworthy.
//!
//! Callers must independently validate all Bitcoin and Taproot data. Never use
//! a binding produced here to authorize a bitcoin spend or other security-
//! sensitive action.

use std::fmt;

use ark::{ProtocolEncoding, Vtxo, VtxoPolicy};
use ark::bitcoin::hashes::{sha256, Hash, HashEngine};
use ark::bitcoin::taproot::{LeafVersion, TapLeafHash, TapNodeHash};
use ark::vtxo::{Full, TapScriptClause};

/// SHA-256 of the LF-normalized Cairo source defining this ABI.
pub const CAIRO_SOURCE_SHA256: &str =
	"ab422d117be16af2a2754a838769b4fa19b97f694af88309a82233669f59c472";

/// Number of fields accepted by the Cairo executable.
pub const CAIRO_INPUT_FIELD_COUNT: usize = 25;

/// Maximum sibling count supported by the fixed Cairo executable ABI.
pub const MAX_TAPROOT_PATH_DEPTH: usize = 3;

const BARK_MANIFEST_DOMAIN: &[u8] = b"bark/ark-taproot-miniscript-claim/v1/manifest";
const BARK_PATH_DOMAIN: &[u8] = b"bark/ark-taproot-miniscript-claim/v1/path";

/// The Cairo felt252 prime, represented as four little-endian `u64` limbs.
const CAIRO_FIELD_MODULUS: CairoFelt = CairoFelt([
	0x0000_0000_0000_0001,
	0x0000_0000_0000_0000,
	0x0000_0000_0000_0000,
	0x0800_0000_0000_0011,
]);

/// Errors returned while constructing a manifest-binding claim.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ManifestBindingError {
	#[error("expected a 32-byte hash encoded as 64 hexadecimal characters, got {length}")]
	InvalidHashLength { length: usize },

	#[error("invalid hexadecimal character '{character}' at position {index}")]
	InvalidHashCharacter { index: usize, character: char },

	#[error("unknown Cairo leaf role code {0}; expected a value from 1 through 5")]
	InvalidRole(u8),

	#[error("unknown Cairo sibling-side code {0}; expected 0 or 1")]
	InvalidSiblingSide(u8),

	#[error("Taproot path has depth {depth}; the Cairo ABI supports at most 3 siblings")]
	PathTooDeep { depth: usize },

	#[error("amount must be greater than zero")]
	ZeroAmount,

	#[error("exit delay must be greater than zero")]
	ZeroExitDelay,

	#[error("only pubkey-policy VTXOs have the Cairo v1 owner CSV exit shape")]
	UnsupportedVtxoPolicy,

	#[error("the VTXO Taproot output does not contain its owner exit clause")]
	OwnerExitClauseMissing,

	#[error("the VTXO owner exit Taproot output has no Merkle root")]
	OwnerExitRootMissing,

	#[error("the VTXO owner exit control-block path does not reconstruct its Merkle root")]
	OwnerExitRootMismatch,
}

/// An element of the Cairo felt252 field.
///
/// Values supplied as bytes are reduced modulo the Cairo prime. The internal
/// representation uses four little-endian `u64` limbs so this module does not
/// add a big-integer dependency to this interoperability crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct CairoFelt([u64; 4]);

impl CairoFelt {
	const ZERO: Self = Self([0; 4]);
	#[cfg(test)]
	const ONE: Self = Self([1, 0, 0, 0]);

	/// Reduce a big-endian 256-bit integer into the Cairo field.
	#[cfg(test)]
	#[allow(clippy::arithmetic_side_effects)]
	fn from_bytes_be(bytes: [u8; 32]) -> Self {
		let mut value = Self::ZERO;
		for byte in bytes {
			for bit in (0..8).rev() {
				value = value.add_mod(value);
				if byte & (1 << bit) != 0 {
					value = value.add_mod(Self::ONE);
				}
			}
		}
		value
	}

	const fn from_u64(value: u64) -> Self {
		Self([value, 0, 0, 0])
	}

	const fn from_u128(value: u128) -> Self {
		Self([value as u64, (value >> 64) as u64, 0, 0])
	}

	/// Return a fixed-width, big-endian representation.
	fn to_bytes_be(self) -> [u8; 32] {
		let mut bytes = [0u8; 32];
		for (chunk, limb) in bytes.chunks_exact_mut(8).zip(self.0.iter().rev()) {
			chunk.copy_from_slice(&limb.to_be_bytes());
		}
		bytes
	}

	/// Serialize using the lowercase `0x` format accepted by `scarb execute`.
	fn to_cairo_hex(self) -> String {
		let bytes = self.to_bytes_be();
		let first_nonzero = bytes.iter().position(|byte| *byte != 0);
		let Some(first_nonzero) = first_nonzero else {
			return "0x0".to_owned();
		};

		let mut encoded = String::from("0x");
		let mut significant_bytes = bytes[first_nonzero..].iter();
		let first_byte = significant_bytes.next()
			.expect("the first non-zero byte is present");
		encoded.push_str(&format!("{:x}", first_byte));
		for byte in significant_bytes {
			encoded.push_str(&format!("{:02x}", byte));
		}
		encoded
	}

	#[allow(clippy::arithmetic_side_effects)]
	fn add_mod(self, other: Self) -> Self {
		// Both operands are below p, so their sum is below 2p (< 2^253) and
		// always fits in four limbs.
		let mut sum = [0u64; 4];
		let mut carry = 0u128;
		for ((output, left), right) in sum.iter_mut().zip(self.0).zip(other.0) {
			let wide = u128::from(left) + u128::from(right) + carry;
			*output = wide as u64;
			carry = wide >> 64;
		}
		debug_assert_eq!(carry, 0, "sum of two Cairo field elements fits in 256 bits");

		let sum = Self(sum);
		if sum.cmp_limbs(CAIRO_FIELD_MODULUS) != std::cmp::Ordering::Less {
			sum.subtract(CAIRO_FIELD_MODULUS)
		} else {
			sum
		}
	}

	fn cmp_limbs(self, other: Self) -> std::cmp::Ordering {
		for (left, right) in self.0.iter().rev().zip(other.0.iter().rev()) {
			match left.cmp(right) {
				std::cmp::Ordering::Equal => {},
				ordering => return ordering,
			}
		}
		std::cmp::Ordering::Equal
	}

	fn subtract(self, other: Self) -> Self {
		debug_assert!(self.cmp_limbs(other) != std::cmp::Ordering::Less);

		let mut difference = [0u64; 4];
		let mut borrow = false;
		for ((output, left), right) in difference.iter_mut().zip(self.0).zip(other.0) {
			let (without_rhs, rhs_borrow) = left.overflowing_sub(right);
			let (with_borrow, carry_borrow) = without_rhs.overflowing_sub(u64::from(borrow));
			*output = with_borrow;
			borrow = rhs_borrow || carry_borrow;
		}
		debug_assert!(!borrow);
		Self(difference)
	}

	fn multiply_small(self, factor: u8) -> Self {
		let mut product = Self::ZERO;
		for _ in 0..factor {
			product = product.add_mod(self);
		}
		product
	}
}

impl fmt::Display for CairoFelt {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str(&self.to_cairo_hex())
	}
}

/// A 32-byte claim input.
///
/// This type deliberately calls the value a claim hash rather than asserting
/// how it was calculated. The manifest-binding circuit does not verify its
/// hash algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ClaimHash([u8; 32]);

impl ClaimHash {
	pub const ZERO: Self = Self([0; 32]);

	/// Construct an opaque claim hash from bytes in displayed big-endian order.
	pub const fn from_bytes_be(bytes: [u8; 32]) -> Self {
		Self(bytes)
	}

	/// Construct an opaque claim hash from a SHA-256 digest.
	pub fn from_sha256(hash: sha256::Hash) -> Self {
		Self(hash.to_byte_array())
	}

	/// Construct a hash from the two big-endian limbs used by the Cairo ABI.
	pub fn from_u128_limbs(high: u128, low: u128) -> Self {
		let mut bytes = [0u8; 32];
		bytes[..16].copy_from_slice(&high.to_be_bytes());
		bytes[16..].copy_from_slice(&low.to_be_bytes());
		Self(bytes)
	}

	/// Parse exactly 32 bytes of hexadecimal, with an optional `0x` prefix.
	#[allow(clippy::arithmetic_side_effects)]
	pub fn from_hex(encoded: &str) -> Result<Self, ManifestBindingError> {
		let encoded = encoded.strip_prefix("0x").unwrap_or(encoded);
		if encoded.len() != 64 {
			return Err(ManifestBindingError::InvalidHashLength { length: encoded.len() });
		}

		let mut bytes = [0u8; 32];
		for (index, pair) in encoded.as_bytes().chunks_exact(2).enumerate() {
			let high_index = index * 2;
			let low_index = high_index + 1;
			let high = decode_hex_nibble(pair[0]).ok_or_else(|| {
				ManifestBindingError::InvalidHashCharacter {
					index: high_index,
					character: char::from(pair[0]),
				}
			})?;
			let low = decode_hex_nibble(pair[1]).ok_or_else(|| {
				ManifestBindingError::InvalidHashCharacter {
					index: low_index,
					character: char::from(pair[1]),
				}
			})?;
			bytes[index] = (high << 4) | low;
		}
		Ok(Self(bytes))
	}

	pub const fn as_bytes(&self) -> &[u8; 32] {
		&self.0
	}

	pub fn to_hex(self) -> String {
		let mut encoded = String::with_capacity(64);
		for byte in self.0 {
			encoded.push_str(&format!("{:02x}", byte));
		}
		encoded
	}

	pub fn to_u128_limbs(self) -> (u128, u128) {
		let mut high = [0u8; 16];
		let mut low = [0u8; 16];
		high.copy_from_slice(&self.0[..16]);
		low.copy_from_slice(&self.0[16..]);
		(u128::from_be_bytes(high), u128::from_be_bytes(low))
	}
}

#[allow(clippy::arithmetic_side_effects)]
fn decode_hex_nibble(byte: u8) -> Option<u8> {
	match byte {
		b'0'..=b'9' => Some(byte - b'0'),
		b'a'..=b'f' => Some(byte - b'a' + 10),
		b'A'..=b'F' => Some(byte - b'A' + 10),
		_ => None,
	}
}

/// Leaf-role codes compiled into the Cairo executable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum ClaimRole {
	CooperativeRound = 1,
	OwnerCsvExit = 2,
	AspForfeitGuard = 3,
	DlcVirtualCetSettlement = 4,
	UtxorefChallengePublication = 5,
}

impl ClaimRole {
	pub const fn code(self) -> u8 {
		self as u8
	}
}

impl TryFrom<u8> for ClaimRole {
	type Error = ManifestBindingError;

	fn try_from(value: u8) -> Result<Self, Self::Error> {
		match value {
			1 => Ok(Self::CooperativeRound),
			2 => Ok(Self::OwnerCsvExit),
			3 => Ok(Self::AspForfeitGuard),
			4 => Ok(Self::DlcVirtualCetSettlement),
			5 => Ok(Self::UtxorefChallengePublication),
			_ => Err(ManifestBindingError::InvalidRole(value)),
		}
	}
}

/// Which side of the current path fold contains the sibling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum SiblingSide {
	Right = 0,
	Left = 1,
}

impl SiblingSide {
	pub const fn code(self) -> u8 {
		self as u8
	}
}

impl TryFrom<u8> for SiblingSide {
	type Error = ManifestBindingError;

	fn try_from(value: u8) -> Result<Self, Self::Error> {
		match value {
			0 => Ok(Self::Right),
			1 => Ok(Self::Left),
			_ => Err(ManifestBindingError::InvalidSiblingSide(value)),
		}
	}
}

/// One active sibling in the fixed-depth Cairo path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TaprootSibling {
	pub hash: ClaimHash,
	pub side: SiblingSide,
}

impl TaprootSibling {
	const PADDING: Self = Self { hash: ClaimHash::ZERO, side: SiblingSide::Right };

	pub const fn new(hash: ClaimHash, side: SiblingSide) -> Self {
		Self { hash, side }
	}

	pub fn from_side_code(hash: ClaimHash, side: u8) -> Result<Self, ManifestBindingError> {
		Ok(Self::new(hash, SiblingSide::try_from(side)?))
	}
}

/// A validated, ordered path of at most three siblings.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TaprootPath {
	siblings: Vec<TaprootSibling>,
}

impl TaprootPath {
	pub const fn empty() -> Self {
		Self { siblings: Vec::new() }
	}

	pub fn new(siblings: &[TaprootSibling]) -> Result<Self, ManifestBindingError> {
		if siblings.len() > MAX_TAPROOT_PATH_DEPTH {
			return Err(ManifestBindingError::PathTooDeep { depth: siblings.len() });
		}
		Ok(Self { siblings: siblings.to_vec() })
	}

	pub fn siblings(&self) -> &[TaprootSibling] {
		&self.siblings
	}

	pub fn len(&self) -> usize {
		self.siblings.len()
	}

	pub fn is_empty(&self) -> bool {
		self.siblings.is_empty()
	}

	fn depth(&self) -> u32 {
		u32::try_from(self.siblings.len()).unwrap_or(MAX_TAPROOT_PATH_DEPTH as u32)
	}

	fn padded_sibling(&self, index: usize) -> TaprootSibling {
		self.siblings.get(index).copied().unwrap_or(TaprootSibling::PADDING)
	}
}

/// Typed inputs for the experimental Cairo manifest-binding claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestBindingClaim {
	manifest_id: ClaimHash,
	taproot_root: ClaimHash,
	selected_leaf_hash: ClaimHash,
	selected_leaf_role: ClaimRole,
	taproot_path_commitment: ClaimHash,
	taproot_path: TaprootPath,
	settlement_hash: ClaimHash,
	amount_sats: u64,
	exit_delay: u32,
}

impl ManifestBindingClaim {
	/// Derive a v1 owner-exit claim from a pubkey-policy VTXO.
	///
	/// The caller must validate the VTXO before calling this constructor.
	/// [`Vtxo<Full>`] indicates that protocol fields are present; it does not
	/// establish that the VTXO is trusted or valid.
	///
	/// Bark's cooperative spend is a Taproot key-path spend and therefore has
	/// no leaf to export through this ABI. HTLC policies also do not have the
	/// simple owner-CSV shape represented by role code 2, so this constructor
	/// rejects them instead of inventing a mapping.
	///
	/// `settlement_hash` remains caller-provided because Bark has no canonical
	/// settlement commitment for this external program. All other claim data
	/// is derived deterministically from `vtxo`.
	///
	/// The manifest id is the untagged SHA-256 of the concatenation
	/// `bark/ark-taproot-miniscript-claim/v1/manifest ||
	/// ProtocolEncoding(vtxo)`. The path commitment is the untagged SHA-256 of
	/// `bark/ark-taproot-miniscript-claim/v1/path || root[32] || leaf[32] ||
	/// depth_u8 || (side_u8 || sibling[32])*`, with siblings ordered from leaf
	/// to root and side codes matching [`SiblingSide::code`]. These byte-level
	/// conventions are versioned by this module and locked by a golden vector.
	pub fn from_pubkey_vtxo_owner_exit(
		vtxo: &Vtxo<Full>,
		settlement_hash: ClaimHash,
	) -> Result<Self, ManifestBindingError> {
		let policy = match vtxo.policy() {
			VtxoPolicy::Pubkey(policy) => policy,
			VtxoPolicy::ServerHtlcSend(_) | VtxoPolicy::ServerHtlcRecv(_) => {
				return Err(ManifestBindingError::UnsupportedVtxoPolicy);
			},
		};
		let clause = policy.user_pubkey_claim_clause(vtxo.exit_delta());
		let tapscript = clause.tapscript();
		let taproot = vtxo.output_taproot();
		let leaf_version = LeafVersion::TapScript;
		let selected_leaf = TapLeafHash::from_script(&tapscript, leaf_version);
		let control_block = taproot.control_block(&(tapscript, leaf_version))
			.ok_or(ManifestBindingError::OwnerExitClauseMissing)?;
		let taproot_root = taproot.merkle_root()
			.ok_or(ManifestBindingError::OwnerExitRootMissing)?;

		let mut current = TapNodeHash::from(selected_leaf);
		let mut siblings = Vec::with_capacity(control_block.merkle_branch.len());
		for sibling in control_block.merkle_branch.iter() {
			let side = if *sibling < current {
				SiblingSide::Left
			} else {
				SiblingSide::Right
			};
			siblings.push(TaprootSibling::new(
				ClaimHash::from_bytes_be(sibling.to_byte_array()),
				side,
			));
			current = TapNodeHash::from_node_hashes(current, *sibling);
		}
		if current != taproot_root {
			return Err(ManifestBindingError::OwnerExitRootMismatch);
		}

		let taproot_path = TaprootPath::new(&siblings)?;
		let selected_leaf_hash = ClaimHash::from_bytes_be(selected_leaf.to_byte_array());
		let taproot_root = ClaimHash::from_bytes_be(taproot_root.to_byte_array());
		let encoded_vtxo = vtxo.serialize();
		let manifest_id = hash_domain(BARK_MANIFEST_DOMAIN, &encoded_vtxo);
		let taproot_path_commitment = path_commitment(
			taproot_root,
			selected_leaf_hash,
			&taproot_path,
		);

		Self::from_manifest_fields(
			manifest_id,
			taproot_root,
			selected_leaf_hash,
			ClaimRole::OwnerCsvExit,
			taproot_path_commitment,
			taproot_path,
			settlement_hash,
			vtxo.amount().to_sat(),
			u32::from(vtxo.exit_delta()),
		)
	}

	#[allow(clippy::too_many_arguments)]
	pub fn from_manifest_fields(
		manifest_id: ClaimHash,
		taproot_root: ClaimHash,
		selected_leaf_hash: ClaimHash,
		selected_leaf_role: ClaimRole,
		taproot_path_commitment: ClaimHash,
		taproot_path: TaprootPath,
		settlement_hash: ClaimHash,
		amount_sats: u64,
		exit_delay: u32,
	) -> Result<Self, ManifestBindingError> {
		let claim = Self {
			manifest_id,
			taproot_root,
			selected_leaf_hash,
			selected_leaf_role,
			taproot_path_commitment,
			taproot_path,
			settlement_hash,
			amount_sats,
			exit_delay,
		};
		claim.validate()?;
		Ok(claim)
	}

	pub const fn manifest_id(&self) -> ClaimHash {
		self.manifest_id
	}

	pub const fn taproot_root(&self) -> ClaimHash {
		self.taproot_root
	}

	pub const fn selected_leaf_hash(&self) -> ClaimHash {
		self.selected_leaf_hash
	}

	pub const fn selected_leaf_role(&self) -> ClaimRole {
		self.selected_leaf_role
	}

	pub const fn taproot_path_commitment(&self) -> ClaimHash {
		self.taproot_path_commitment
	}

	pub fn taproot_path(&self) -> &TaprootPath {
		&self.taproot_path
	}

	pub const fn settlement_hash(&self) -> ClaimHash {
		self.settlement_hash
	}

	pub const fn amount_sats(&self) -> u64 {
		self.amount_sats
	}

	pub const fn exit_delay(&self) -> u32 {
		self.exit_delay
	}

	fn validate(&self) -> Result<(), ManifestBindingError> {
		if self.amount_sats == 0 {
			return Err(ManifestBindingError::ZeroAmount);
		}
		if self.exit_delay == 0 {
			return Err(ManifestBindingError::ZeroExitDelay);
		}
		if self.taproot_path.len() > MAX_TAPROOT_PATH_DEPTH {
			return Err(ManifestBindingError::PathTooDeep { depth: self.taproot_path.len() });
		}
		Ok(())
	}

	fn taproot_path_fold(&self) -> CairoFelt {
		let mut current = mix_hash_limbs(self.selected_leaf_hash);
		for sibling in self.taproot_path.siblings() {
			let sibling_hash = mix_hash_limbs(sibling.hash);
			current = match sibling.side {
				SiblingSide::Left => mix(sibling_hash, current),
				SiblingSide::Right => mix(current, sibling_hash),
			};
		}
		current
	}

	fn binding_commitment(&self) -> CairoFelt {
		let manifest_id = mix_hash_limbs(self.manifest_id);
		let taproot_root = mix_hash_limbs(self.taproot_root);
		let selected_leaf_hash = mix_hash_limbs(self.selected_leaf_hash);
		let taproot_path_commitment = mix_hash_limbs(self.taproot_path_commitment);
		let settlement_hash = mix_hash_limbs(self.settlement_hash);

		let policy_pair = mix(manifest_id, taproot_root);
		let path_pair = mix(taproot_path_commitment, self.taproot_path_fold());
		let leaf_pair = mix(
			selected_leaf_hash,
			CairoFelt::from_u64(u64::from(self.selected_leaf_role.code())),
		);
		let policy_path = mix(policy_pair, path_pair);
		let policy_leaf = mix(policy_path, leaf_pair);
		let settlement_amount = mix(settlement_hash, CairoFelt::from_u64(self.amount_sats));
		let settlement_delay = mix(settlement_amount, CairoFelt::from_u64(u64::from(self.exit_delay)));

		mix(policy_leaf, settlement_delay)
	}

	/// Compile the claim into the exact 25-field Cairo executable ABI.
	pub fn to_cairo_input(&self) -> CairoManifestBindingInput {
		let (manifest_id_high, manifest_id_low) = self.manifest_id.to_u128_limbs();
		let (taproot_root_high, taproot_root_low) = self.taproot_root.to_u128_limbs();
		let (selected_leaf_high, selected_leaf_low) = self.selected_leaf_hash.to_u128_limbs();
		let (path_commitment_high, path_commitment_low) =
			self.taproot_path_commitment.to_u128_limbs();
		let (settlement_high, settlement_low) = self.settlement_hash.to_u128_limbs();
		let sibling_0 = self.taproot_path.padded_sibling(0);
		let sibling_1 = self.taproot_path.padded_sibling(1);
		let sibling_2 = self.taproot_path.padded_sibling(2);
		let (sibling_0_high, sibling_0_low) = sibling_0.hash.to_u128_limbs();
		let (sibling_1_high, sibling_1_low) = sibling_1.hash.to_u128_limbs();
		let (sibling_2_high, sibling_2_low) = sibling_2.hash.to_u128_limbs();

		CairoManifestBindingInput {
			fields: [
				CairoFelt::from_u128(manifest_id_high),
				CairoFelt::from_u128(manifest_id_low),
				CairoFelt::from_u128(taproot_root_high),
				CairoFelt::from_u128(taproot_root_low),
				CairoFelt::from_u128(selected_leaf_high),
				CairoFelt::from_u128(selected_leaf_low),
				CairoFelt::from_u64(u64::from(self.selected_leaf_role.code())),
				CairoFelt::from_u128(path_commitment_high),
				CairoFelt::from_u128(path_commitment_low),
				self.taproot_path_fold(),
				CairoFelt::from_u64(u64::from(self.taproot_path.depth())),
				CairoFelt::from_u128(sibling_0_high),
				CairoFelt::from_u128(sibling_0_low),
				CairoFelt::from_u64(u64::from(sibling_0.side.code())),
				CairoFelt::from_u128(sibling_1_high),
				CairoFelt::from_u128(sibling_1_low),
				CairoFelt::from_u64(u64::from(sibling_1.side.code())),
				CairoFelt::from_u128(sibling_2_high),
				CairoFelt::from_u128(sibling_2_low),
				CairoFelt::from_u64(u64::from(sibling_2.side.code())),
				CairoFelt::from_u128(settlement_high),
				CairoFelt::from_u128(settlement_low),
				CairoFelt::from_u64(self.amount_sats),
				CairoFelt::from_u64(u64::from(self.exit_delay)),
				self.binding_commitment(),
			],
		}
	}
}

fn hash_domain(domain: &[u8], bytes: &[u8]) -> ClaimHash {
	let mut engine = sha256::Hash::engine();
	engine.input(domain);
	engine.input(bytes);
	ClaimHash::from_sha256(sha256::Hash::from_engine(engine))
}

fn path_commitment(
	taproot_root: ClaimHash,
	selected_leaf_hash: ClaimHash,
	path: &TaprootPath,
) -> ClaimHash {
	let mut engine = sha256::Hash::engine();
	engine.input(BARK_PATH_DOMAIN);
	engine.input(taproot_root.as_bytes());
	engine.input(selected_leaf_hash.as_bytes());
	let depth = u8::try_from(path.len()).unwrap_or(u8::MAX);
	engine.input(&[depth]);
	for sibling in path.siblings() {
		engine.input(&[sibling.side.code()]);
		engine.input(sibling.hash.as_bytes());
	}
	ClaimHash::from_sha256(sha256::Hash::from_engine(engine))
}

fn mix_hash_limbs(hash: ClaimHash) -> CairoFelt {
	let (high, low) = hash.to_u128_limbs();
	mix(CairoFelt::from_u128(high), CairoFelt::from_u128(low))
}

fn mix(left: CairoFelt, right: CairoFelt) -> CairoFelt {
	left.multiply_small(31)
		.add_mod(right.multiply_small(17))
		.add_mod(CairoFelt::from_u64(7))
}

/// The compiled, fixed-width input to the Cairo executable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CairoManifestBindingInput {
	fields: [CairoFelt; CAIRO_INPUT_FIELD_COUNT],
}

impl CairoManifestBindingInput {
	pub fn to_cairo_args(self) -> [String; CAIRO_INPUT_FIELD_COUNT] {
		self.fields.map(CairoFelt::to_cairo_hex)
	}

	/// Serialize as deterministic, pretty JSON accepted by the prover scripts.
	pub fn to_cairo_json(self) -> String {
		let lines = self.to_cairo_args().map(|field| format!("  \"{}\"", field));
		format!("[\n{}\n]\n", lines.join(",\n"))
	}
}

#[cfg(test)]
mod tests {
	use ark::test_util::VTXO_VECTORS;
	use ark::bitcoin::hashes::Hash;
	use ark::bitcoin::taproot::{LeafVersion, TapLeafHash};
	use ark::vtxo::TapScriptClause;

	use super::{
		CairoFelt, ClaimHash, ClaimRole, ManifestBindingClaim, ManifestBindingError,
		SiblingSide, TaprootPath, TaprootSibling, CAIRO_INPUT_FIELD_COUNT,
	};

	const GOLDEN_INPUTS: [&str; 5] = [
		include_str!("../tests/vectors/cooperative_round.input.json"),
		include_str!("../tests/vectors/owner_csv_exit.input.json"),
		include_str!("../tests/vectors/asp_forfeit_guard.input.json"),
		include_str!("../tests/vectors/dlc_virtual_cet_settlement.input.json"),
		include_str!("../tests/vectors/utxoref_challenge_publication.input.json"),
	];
	const SETTLEMENT_HASH: &str =
		"8b8cd30852f4edbd86df233402d4ca881fab9e765c7669731c9c120db7946855";
	const BARK_OWNER_EXIT_INPUT: &str =
		include_str!("../tests/vectors/bark_pubkey_vtxo_owner_exit.input.json");

	fn hash(encoded: &str) -> ClaimHash {
		ClaimHash::from_hex(encoded).unwrap()
	}

	fn cairo_integer(encoded: &str) -> u128 {
		u128::from_str_radix(encoded.strip_prefix("0x").unwrap(), 16).unwrap()
	}

	fn hash_from_fields(args: &[String; CAIRO_INPUT_FIELD_COUNT], index: usize) -> ClaimHash {
		ClaimHash::from_u128_limbs(
			cairo_integer(&args[index]),
			cairo_integer(&args[index.checked_add(1).unwrap()]),
		)
	}

	fn claim_from_golden_input(
		json: &str,
	) -> (ManifestBindingClaim, [String; CAIRO_INPUT_FIELD_COUNT]) {
		let args: [String; CAIRO_INPUT_FIELD_COUNT] =
			serde_json::from_str::<Vec<String>>(json).unwrap().try_into().unwrap();
		let depth = usize::try_from(cairo_integer(&args[10])).unwrap();
		let mut siblings = Vec::with_capacity(depth);
		for index in 0..depth {
			let offset = index.checked_mul(3).and_then(|v| v.checked_add(11)).unwrap();
			siblings.push(TaprootSibling::from_side_code(
				hash_from_fields(&args, offset),
				u8::try_from(cairo_integer(&args[offset.checked_add(2).unwrap()])).unwrap(),
			).unwrap());
		}

		let claim = ManifestBindingClaim::from_manifest_fields(
			hash_from_fields(&args, 0),
			hash_from_fields(&args, 2),
			hash_from_fields(&args, 4),
			ClaimRole::try_from(u8::try_from(cairo_integer(&args[6])).unwrap()).unwrap(),
			hash_from_fields(&args, 7),
			TaprootPath::new(&siblings).unwrap(),
			hash_from_fields(&args, 20),
			u64::try_from(cairo_integer(&args[22])).unwrap(),
			u32::try_from(cairo_integer(&args[23])).unwrap(),
		).unwrap();
		(claim, args)
	}

	#[test]
	fn sample_claim_matches_cairo_demo() {
		let claim = ManifestBindingClaim::from_manifest_fields(
			ClaimHash::from_u128_limbs(0, 0x101),
			ClaimHash::from_u128_limbs(0, 0x202),
			ClaimHash::from_u128_limbs(0, 0x303),
			ClaimRole::DlcVirtualCetSettlement,
			ClaimHash::from_u128_limbs(0, 0x505),
			TaprootPath::empty(),
			ClaimHash::from_u128_limbs(0, 0x404),
			100_000,
			1008,
		).unwrap();

		assert_eq!(claim.taproot_path_fold().to_cairo_hex(), "0x333a");
		assert_eq!(claim.binding_commitment().to_cairo_hex(), "0x5b8d2b2be");
		let fields = claim.to_cairo_input().to_cairo_args();
		assert_eq!(fields[9], "0x333a");
		assert_eq!(fields[24], "0x5b8d2b2be");
	}

	#[test]
	fn pubkey_vtxo_owner_exit_derives_bark_owned_fields() {
		let vtxo = &VTXO_VECTORS.board_vtxo;
		let settlement = hash(SETTLEMENT_HASH);
		let claim = ManifestBindingClaim::from_pubkey_vtxo_owner_exit(vtxo, settlement)
			.unwrap();

		let policy = vtxo.policy().as_pubkey().unwrap();
		let tapscript = policy.user_pubkey_claim_clause(vtxo.exit_delta()).tapscript();
		let leaf = TapLeafHash::from_script(&tapscript, LeafVersion::TapScript);
		let root = vtxo.output_taproot().merkle_root().unwrap();

		assert_eq!(claim.selected_leaf_role(), ClaimRole::OwnerCsvExit);
		assert_eq!(claim.selected_leaf_hash(), ClaimHash::from_bytes_be(leaf.to_byte_array()));
		assert_eq!(claim.taproot_root(), ClaimHash::from_bytes_be(root.to_byte_array()));
		assert_eq!(claim.settlement_hash(), settlement);
		assert_eq!(claim.amount_sats(), vtxo.amount().to_sat());
		assert_eq!(claim.exit_delay(), u32::from(vtxo.exit_delta()));
		assert!(claim.taproot_path().is_empty());
		assert_ne!(claim.manifest_id(), ClaimHash::ZERO);
		assert_ne!(claim.taproot_path_commitment(), ClaimHash::ZERO);

		let duplicate = ManifestBindingClaim::from_pubkey_vtxo_owner_exit(vtxo, settlement)
			.unwrap();
		assert_eq!(claim, duplicate);
		assert_eq!(
			claim.to_cairo_input().to_cairo_json(),
			duplicate.to_cairo_input().to_cairo_json(),
		);
		assert_eq!(claim.to_cairo_input().to_cairo_json(), BARK_OWNER_EXIT_INPUT);
	}

	#[test]
	fn vtxo_owner_exit_rejects_htlc_policy() {
		let error = ManifestBindingClaim::from_pubkey_vtxo_owner_exit(
			&VTXO_VECTORS.arkoor_htlc_out_vtxo,
			hash(SETTLEMENT_HASH),
		).unwrap_err();
		assert_eq!(error, ManifestBindingError::UnsupportedVtxoPolicy);
	}

	#[test]
	fn settlement_hash_changes_only_external_fields_and_binding() {
		let vtxo = &VTXO_VECTORS.board_vtxo;
		let first = ManifestBindingClaim::from_pubkey_vtxo_owner_exit(
			vtxo,
			ClaimHash::from_u128_limbs(0, 1),
		).unwrap().to_cairo_input().to_cairo_args();
		let second = ManifestBindingClaim::from_pubkey_vtxo_owner_exit(
			vtxo,
			ClaimHash::from_u128_limbs(0, 2),
		).unwrap().to_cairo_input().to_cairo_args();

		for index in 0..CAIRO_INPUT_FIELD_COUNT {
			if ![20, 21, 24].contains(&index) {
				assert_eq!(first[index], second[index], "unexpected change at field {index}");
			}
		}
		assert_ne!(first[21], second[21]);
		assert_ne!(first[24], second[24]);
	}

	#[test]
	fn all_five_fixture_claims_match_golden_cairo_inputs() {
		for json in GOLDEN_INPUTS {
			let (claim, expected) = claim_from_golden_input(json);
			assert_eq!(claim.to_cairo_input().to_cairo_args(), expected);
		}
	}
	#[test]
	fn hash_limb_split_is_big_endian_and_roundtrips() {
		let original = hash(
			"00112233445566778899aabbccddeeffffeeddccbbaa99887766554433221100",
		);
		let (high, low) = original.to_u128_limbs();
		assert_eq!(high, 0x00112233445566778899aabbccddeeff);
		assert_eq!(low, 0xffeeddccbbaa99887766554433221100);
		assert_eq!(ClaimHash::from_u128_limbs(high, low), original);
	}

	#[test]
	fn felt_inputs_are_reduced_modulo_the_cairo_prime() {
		let modulus = *hash(
			"0800000000000011000000000000000000000000000000000000000000000001",
		).as_bytes();
		let modulus_plus_one = *hash(
			"0800000000000011000000000000000000000000000000000000000000000002",
		).as_bytes();

		assert_eq!(CairoFelt::from_bytes_be(modulus), CairoFelt::ZERO);
		assert_eq!(CairoFelt::from_bytes_be(modulus_plus_one), CairoFelt::ONE);
		assert_eq!(CairoFelt::ONE.to_cairo_hex(), "0x1");
	}

	#[test]
	fn path_fold_obeys_both_sibling_sides() {
		let selected_leaf = ClaimHash::from_u128_limbs(0, 1);
		let sibling_hash = ClaimHash::from_u128_limbs(0, 2);
		let right = ManifestBindingClaim::from_manifest_fields(
			ClaimHash::ZERO,
			ClaimHash::ZERO,
			selected_leaf,
			ClaimRole::OwnerCsvExit,
			ClaimHash::ZERO,
			TaprootPath::new(&[TaprootSibling::new(sibling_hash, SiblingSide::Right)]).unwrap(),
			ClaimHash::ZERO,
			1,
			1,
		).unwrap();
		let left = ManifestBindingClaim::from_manifest_fields(
			ClaimHash::ZERO,
			ClaimHash::ZERO,
			selected_leaf,
			ClaimRole::OwnerCsvExit,
			ClaimHash::ZERO,
			TaprootPath::new(&[TaprootSibling::new(sibling_hash, SiblingSide::Left)]).unwrap(),
			ClaimHash::ZERO,
			1,
			1,
		).unwrap();

		assert_eq!(right.taproot_path_fold().to_cairo_hex(), "0x5a8");
		assert_eq!(left.taproot_path_fold().to_cairo_hex(), "0x696");
		assert_ne!(right.taproot_path_fold(), left.taproot_path_fold());
	}

	#[test]
	fn invalid_claim_inputs_are_rejected() {
		let empty = TaprootPath::empty();
		let base = || {
			(
				ClaimHash::ZERO,
				ClaimHash::ZERO,
				ClaimHash::ZERO,
				ClaimRole::CooperativeRound,
				ClaimHash::ZERO,
				ClaimHash::ZERO,
			)
		};
		let (manifest, root, leaf, role, path_commitment, settlement) = base();
		let zero_amount = ManifestBindingClaim::from_manifest_fields(
			manifest, root, leaf, role, path_commitment, empty.clone(), settlement, 0, 1,
		);
		assert_eq!(zero_amount.unwrap_err(), ManifestBindingError::ZeroAmount);

		let (manifest, root, leaf, role, path_commitment, settlement) = base();
		let zero_delay = ManifestBindingClaim::from_manifest_fields(
			manifest, root, leaf, role, path_commitment, empty, settlement, 1, 0,
		);
		assert_eq!(zero_delay.unwrap_err(), ManifestBindingError::ZeroExitDelay);

		let sibling = TaprootSibling::new(ClaimHash::ZERO, SiblingSide::Right);
		assert_eq!(
			TaprootPath::new(&[sibling; 4]).unwrap_err(),
			ManifestBindingError::PathTooDeep { depth: 4 },
		);
		assert_eq!(
			TaprootSibling::from_side_code(ClaimHash::ZERO, 2).unwrap_err(),
			ManifestBindingError::InvalidSiblingSide(2),
		);
		assert_eq!(ClaimRole::try_from(0).unwrap_err(), ManifestBindingError::InvalidRole(0));
	}

	#[test]
	fn every_supported_path_depth_has_canonical_padding() {
		let sibling = TaprootSibling::new(
			ClaimHash::from_u128_limbs(0, 0x42),
			SiblingSide::Left,
		);
		for depth in 0..=3 {
			let siblings = vec![sibling; depth];
			let claim = ManifestBindingClaim::from_manifest_fields(
				ClaimHash::ZERO,
				ClaimHash::ZERO,
				ClaimHash::from_u128_limbs(0, 1),
				ClaimRole::OwnerCsvExit,
				ClaimHash::ZERO,
				TaprootPath::new(&siblings).unwrap(),
				ClaimHash::ZERO,
				1,
				1,
			).unwrap();
			let args = claim.to_cairo_input().to_cairo_args();
			assert_eq!(args[10], format!("0x{:x}", depth));
			for index in depth..3 {
				let offset = index.checked_mul(3).and_then(|v| v.checked_add(11)).unwrap();
				let end = offset.checked_add(3).unwrap();
				assert_eq!(&args[offset..end], &["0x0", "0x0", "0x0"]);
			}
		}
	}

	#[test]
	fn maximum_abi_integers_are_preserved() {
		let claim = ManifestBindingClaim::from_manifest_fields(
			ClaimHash::ZERO,
			ClaimHash::ZERO,
			ClaimHash::ZERO,
			ClaimRole::CooperativeRound,
			ClaimHash::ZERO,
			TaprootPath::empty(),
			ClaimHash::ZERO,
			u64::MAX,
			u32::MAX,
		).unwrap();
		let args = claim.to_cairo_input().to_cairo_args();
		assert_eq!(args[22], "0xffffffffffffffff");
		assert_eq!(args[23], "0xffffffff");
	}

	#[test]
	fn hash_parser_is_strict() {
		assert_eq!(
			ClaimHash::from_hex("00").unwrap_err(),
			ManifestBindingError::InvalidHashLength { length: 2 },
		);
		let mut invalid = "00".repeat(32);
		invalid.replace_range(17..18, "z");
		assert_eq!(
			ClaimHash::from_hex(&invalid).unwrap_err(),
			ManifestBindingError::InvalidHashCharacter { index: 17, character: 'z' },
		);
	}

	#[test]
	fn cairo_json_is_deterministic_and_pads_inactive_path_slots() {
		let (claim, expected_args) = claim_from_golden_input(GOLDEN_INPUTS[4]);
		let compiled = claim.to_cairo_input();
		let args = compiled.to_cairo_args();
		assert_eq!(args[10], "0x1");
		assert!(args[14..20].iter().all(|field| field == "0x0"));

		let expected_lines = expected_args.map(|field| format!("  \"{}\"", field));
		let expected_json = format!("[\n{}\n]\n", expected_lines.join(",\n"));
		assert_eq!(compiled.to_cairo_json(), expected_json);
		assert_eq!(compiled.to_cairo_json(), compiled.to_cairo_json());
	}
}

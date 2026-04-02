//! Raw VTXO representation with public fields for data migrations.
//!
//! Provides [`RawVtxo`], a view over a [`ServerVtxo<Full>`] with all
//! fields exposed as `pub` so they can be mutated from outside the crate.

use bitcoin::Amount;
use bitcoin::secp256k1::PublicKey;
use bitcoin::OutPoint;

use bitcoin_ext::BlockHeight;
use crate::encode::{ProtocolEncoding, ProtocolDecodingError};
use crate::vtxo::{Full, Vtxo};
use crate::vtxo::policy::ServerVtxoPolicy;

type ServerVtxoFull = Vtxo<Full, ServerVtxoPolicy>;

/// A VTXO with all fields public, for use in data migrations.
///
/// Convert from/to [`ServerVtxo<Full>`] via [`From`]/[`Into`].
pub struct RawVtxo {
	pub policy: ServerVtxoPolicy,
	pub amount: Amount,
	pub expiry_height: BlockHeight,
	pub server_pubkey: PublicKey,
	pub exit_delta: u16,
	pub anchor_point: OutPoint,
	pub genesis: Full,
	pub point: OutPoint,
}

impl From<Vtxo<Full, ServerVtxoPolicy>> for RawVtxo {
	fn from(v: Vtxo<Full, ServerVtxoPolicy>) -> Self {
		RawVtxo {
			policy: v.policy,
			amount: v.amount,
			expiry_height: v.expiry_height,
			server_pubkey: v.server_pubkey,
			exit_delta: v.exit_delta,
			anchor_point: v.anchor_point,
			genesis: v.genesis,
			point: v.point,
		}
	}
}

impl From<RawVtxo> for Vtxo<Full, ServerVtxoPolicy> {
	fn from(r: RawVtxo) -> Self {
		Vtxo {
			policy: r.policy,
			amount: r.amount,
			expiry_height: r.expiry_height,
			server_pubkey: r.server_pubkey,
			exit_delta: r.exit_delta,
			anchor_point: r.anchor_point,
			genesis: r.genesis,
			point: r.point,
		}
	}
}

impl RawVtxo {
	/// Deserialize from bytes encoded as a [`ServerVtxo<Full>`].
	pub fn deserialize(bytes: &[u8]) -> Result<Self, ProtocolDecodingError> {
		ServerVtxoFull::decode(&mut &*bytes).map(RawVtxo::from)
	}

	/// Serialize by converting back into a [`ServerVtxo<Full>`].
	pub fn serialize(self) -> Vec<u8> {
		let vtxo: ServerVtxoFull = self.into();
		ProtocolEncoding::serialize(&vtxo)
	}
}

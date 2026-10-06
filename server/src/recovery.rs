use std::collections::HashMap;
use std::ops::Range;

use anyhow::Context;
use bitcoin::bip32::{ChildNumber, Xpub};
use bitcoin::secp256k1::PublicKey;

use ark::{ProtocolEncoding, Vtxo, VtxoPolicy};
use ark::vtxo::Full;
use server_rpc::RECOVERY_XPUB_CHUNK_SIZE;

use crate::{Server, SECP};
use crate::database::SpendState;

/// A VTXO found by [Server::recover_vtxos_by_xpub].
#[derive(Debug, Clone)]
pub struct RecoveredVtxo {
	pub vtxo: Vtxo<Full>,
	/// The index of the non-hardened child of the xpub that owns the VTXO.
	pub derivation_index: u32,
	pub spend_state: SpendState,
}

/// The number of non-hardened child indices of an xpub.
pub const NB_NORMAL_CHILDREN: u32 = 1 << 31;

/// The serialized size of the VTXOs one [Server::recover_vtxos_by_xpub] call
/// returns at most, keeping a response well under the gRPC message limit.
///
/// The VTXOs of one key are never split over two calls, so a single key whose
/// VTXOs exceed it is returned whole.
pub const MAX_RECOVERY_RESPONSE_VTXO_BYTES: usize = 2 * 1024 * 1024;

/// derive the child pubkeys at indices
fn derive_child_pubkeys(xpub: &Xpub, indices: Range<u32>) -> anyhow::Result<Vec<PublicKey>> {
	indices.map(|idx| {
		let child = ChildNumber::from_normal_idx(idx)
			.with_context(|| format!("index {idx} is not a non-hardened child index"))?;
		Ok(xpub.ckd_pub(&SECP, child)
			.with_context(|| format!("failed to derive child {idx}"))?
			.public_key)
	}).collect()
}

/// The outcome of one [Server::recover_vtxos_by_xpub] call.
#[derive(Debug, Clone)]
pub struct XpubRecovery {
	pub vtxos: Vec<RecoveredVtxo>,
	/// The number of child indices scanned, from the requested start index.
	pub nb_keys_scanned: u32,
	/// More VTXOs may follow at higher indices: the scan stopped at
	/// [MAX_RECOVERY_RESPONSE_VTXO_BYTES], or it found VTXOs and ran to its end.
	pub have_more: bool,
}

impl Server {
	/// The recoverable VTXOs owned by the `recovery_xpub_nb_keys`
	/// non-hardened children of `xpub` starting at index `start_index`.
	///
	/// The range is cut short at the last non-hardened index, and at the last
	/// key whose VTXOs fit in [MAX_RECOVERY_RESPONSE_VTXO_BYTES].
	pub async fn recover_vtxos_by_xpub(
		&self,
		xpub: Xpub,
		start_index: u32,
	) -> anyhow::Result<XpubRecovery> {
		let end_index = start_index
			.saturating_add(self.config.recovery_xpub_nb_keys)
			.min(NB_NORMAL_CHILDREN);

		let mut found = Vec::new();
		let mut nb_bytes = 0;
		let mut start = start_index;
		let mut size_limited = false;
		while start < end_index {
			let end = start.saturating_add(RECOVERY_XPUB_CHUNK_SIZE).min(end_index);
			let pubkeys = tokio::task::spawn_blocking(move || {
				derive_child_pubkeys(&xpub, start..end)
			}).await.context("xpub derivation task panicked")??;
			let policies = pubkeys.iter().map(|pk| VtxoPolicy::new_pubkey(*pk)).collect::<Vec<_>>();
			let indices = pubkeys.into_iter().zip(start..end).collect::<HashMap<_, _>>();

			let rows = self.db.read(async |tx| {
				tx.get_vtxos_by_policy(&policies).await
			}).await?;

			let mut chunk = rows.into_iter().map(|state| {
				let vtxo = state.vtxo.try_into_user_vtxo().ok()
					.context("database returned a server vtxo for a user policy")?;
				let derivation_index = *indices.get(&vtxo.user_pubkey())
					.context("database returned a vtxo for a policy we didn't ask for")?;
				Ok(RecoveredVtxo { vtxo, derivation_index, spend_state: state.spend_state })
			}).collect::<anyhow::Result<Vec<_>>>()?;
			chunk.sort_by_key(|v| v.derivation_index);

			// Add the VTXOs one key at a time, so a call that stops at the size
			// limit resumes at the first key it left out.
			let mut chunk = chunk.into_iter().peekable();
			while let Some(first) = chunk.next() {
				let index = first.derivation_index;
				let mut key_vtxos = vec![first];
				while let Some(next) = chunk.next_if(|v| v.derivation_index == index) {
					key_vtxos.push(next);
				}

				let key_bytes = key_vtxos.iter().map(|v| v.vtxo.serialize().len()).sum::<usize>();
				if !found.is_empty() && nb_bytes + key_bytes > MAX_RECOVERY_RESPONSE_VTXO_BYTES {
					size_limited = true;
					start = index;
					break;
				}
				nb_bytes += key_bytes;
				found.extend(key_vtxos);
			}
			if size_limited {
				break;
			}
			start = end;
		}

		Ok(XpubRecovery {
			have_more: size_limited
				|| (!found.is_empty() && end_index < NB_NORMAL_CHILDREN),
			nb_keys_scanned: start - start_index,
			vtxos: found,
		})
	}
}
#[cfg(test)]
mod test {
	use super::*;

	#[test]
	fn derived_policies_match_xpriv_children() {
		use bitcoin::bip32::Xpriv;
		use bitcoin::NetworkKind;

		let xpriv = Xpriv::new_master(NetworkKind::Test, &[7u8; 32]).unwrap();
		let xpub = Xpub::from_priv(&SECP, &xpriv);

		let pubkeys = derive_child_pubkeys(&xpub, 0..5).unwrap();
		assert_eq!(pubkeys.len(), 5);
		for (idx, pubkey) in (0..5).zip(pubkeys) {
			let child = ChildNumber::from_normal_idx(idx).unwrap();
			let expected = xpriv.derive_priv(&SECP, &[child]).unwrap().to_keypair(&SECP).public_key();
			assert_eq!(pubkey, expected, "child {idx}");
		}

		// Hardened indices can't be derived from an xpub.
		assert!(derive_child_pubkeys(&xpub, (1 << 31)..((1 << 31) + 1)).is_err());
	}
}

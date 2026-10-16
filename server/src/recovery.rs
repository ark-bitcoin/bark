use std::collections::HashMap;
use std::ops::Range;

use anyhow::Context;
use bitcoin::bip32::{ChildNumber, Xpub};
use bitcoin::secp256k1::PublicKey;

use ark::{ProtocolEncoding, Vtxo, VtxoId, VtxoPolicy};
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
/// The VTXOs of one key are split over several calls when they exceed it, and
/// a single VTXO that exceeds it is returned on its own.
pub const MAX_RECOVERY_RESPONSE_VTXO_BYTES: usize = 2 * 1024 * 1024;

/// The number of VTXOs of a single key that one database query reads at most.
pub const RECOVERY_VTXO_PAGE_SIZE: usize = 1000;

/// The number of [Server::recover_vtxos_by_xpub] calls that wait at most for
/// a running scan to finish. Calls over the limit are rejected.
pub const XPUB_RECOVERY_QUEUE_SIZE: usize = 16;

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
	/// The last VTXO returned for the key at `start_index + nb_keys_scanned`,
	/// when the scan stopped inside the VTXOs of that key.
	pub cursor_vtxo_id: Option<VtxoId>,
}

impl Server {
	/// The recoverable VTXOs owned by the `recovery_xpub_nb_keys`
	/// non-hardened children of `xpub` starting at index `start_index`.
	///
	/// The range is cut short at the last non-hardened index, and at the last
	/// VTXO that fits in [MAX_RECOVERY_RESPONSE_VTXO_BYTES]. The VTXOs of the
	/// key at `start_index` start after the VTXO `cursor_vtxo_id` when given.
	pub async fn recover_vtxos_by_xpub(
		&self,
		xpub: Xpub,
		start_index: u32,
		cursor_vtxo_id: Option<VtxoId>,
	) -> anyhow::Result<XpubRecovery> {
		let end_index = start_index
			.saturating_add(self.config.recovery_xpub_nb_keys)
			.min(NB_NORMAL_CHILDREN);

		let mut found = Vec::new();
		let mut nb_bytes = 0;
		let mut start = start_index;
		let mut stopped_early = false;
		let mut size_limited = false;
		let mut next_cursor_vtxo_id = None;
		while start < end_index {
			let end = start.saturating_add(RECOVERY_XPUB_CHUNK_SIZE).min(end_index);
			let pubkeys = tokio::task::spawn_blocking(move || {
				derive_child_pubkeys(&xpub, start..end)
			}).await.context("xpub derivation task panicked")??;
			let policies = pubkeys.iter().map(|pk| VtxoPolicy::new_pubkey(*pk)).collect::<Vec<_>>();
			let indices = pubkeys.into_iter().zip(start..end).collect::<HashMap<_, _>>();

			let used = self.db.read(async |tx| {
				tx.get_used_vtxo_policies(&policies).await
			}).await?;

			// Stop early at an entire unused chunk (stop-gap). Keys are issued in
			// sequence, so this also ends the scan of an xpub without any VTXOs
			// after a single chunk.
			if used.is_empty() {
				stopped_early = true;
				start = end;
				break;
			}

			// Add the VTXOs in derivation order of their keys and in id order
			// within a key, so a call that stops at the size limit resumes at
			// the first VTXO it left out.
			let mut used = used.into_iter().map(|policy| {
				let index = *indices.get(&policy.user_pubkey())
					.context("database returned a policy we didn't ask for")?;
				Ok((index, policy))
			}).collect::<anyhow::Result<Vec<_>>>()?;
			used.sort_by_key(|(index, _)| *index);

			'keys: for (index, policy) in used {
				let mut after = if index == start_index { cursor_vtxo_id } else { None };
				loop {
					let page = self.db.read(async |tx| {
						tx.get_vtxos_by_policy_page(&policy, after, RECOVERY_VTXO_PAGE_SIZE).await
					}).await?;
					let is_last_page = page.len() < RECOVERY_VTXO_PAGE_SIZE;

					for state in page {
						let vtxo = state.vtxo.try_into_user_vtxo().ok()
							.context("database returned a server vtxo for a user policy")?;
						let vtxo_bytes = vtxo.serialize().len();
						if !found.is_empty() && nb_bytes + vtxo_bytes > MAX_RECOVERY_RESPONSE_VTXO_BYTES {
							size_limited = true;
							start = index;
							next_cursor_vtxo_id = after;
							break 'keys;
						}
						nb_bytes += vtxo_bytes;
						after = Some(state.vtxo_id);
						found.push(RecoveredVtxo { vtxo, derivation_index: index, spend_state: state.spend_state });
					}

					if is_last_page {
						break;
					}
				}
			}
			if size_limited {
				break;
			}
			start = end;
		}

		Ok(XpubRecovery {
			have_more: size_limited
				|| (!found.is_empty() && !stopped_early && end_index < NB_NORMAL_CHILDREN),
			nb_keys_scanned: start - start_index,
			vtxos: found,
			cursor_vtxo_id: next_cursor_vtxo_id,
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

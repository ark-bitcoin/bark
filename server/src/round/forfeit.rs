
use std::collections::HashSet;

use anyhow::Context;
use bitcoin::secp256k1::Keypair;

use ark::{musig, VtxoId};
use ark::forfeit::HashLockedForfeitBundle;
use ark::tree::signed::{UnlockHash, UnlockPreimage};

use crate::database::tree::VtxoTreeUpdate;
use crate::Server;
use crate::error::ContextExt;


pub struct HarkForfeitNonces {
	unlock_hash: UnlockHash,
	sec_nonce: musig::SecretNonce,
	pub_nonce: musig::PublicNonce,
}

impl HarkForfeitNonces {
	pub fn generate(key: &Keypair, unlock_hash: UnlockHash) -> Self {
		let (sec_nonce, pub_nonce) = musig::nonce_pair(key);
		Self { unlock_hash, sec_nonce, pub_nonce }
	}

	pub fn public_nonce(&self) -> musig::PublicNonce {
		self.pub_nonce
	}

	pub fn into_secret_nonce(self) -> musig::SecretNonce {
		self.sec_nonce
	}
}

impl Server {
	/// Generate forfeit nonces for the given vtxos
	///
	/// Returns one nonce package for each vtxo, in the same order.
	pub async fn generate_forfeit_nonces(
		&self,
		unlock_hash: UnlockHash,
		vtxos: &[VtxoId],
	) -> anyhow::Result<Vec<musig::PublicNonce>> {
		let mut ret = Vec::with_capacity(vtxos.len());
		for vtxo in vtxos {
			// nb this call is quite expensive computationally, so we don't want to
			// keep the lock while doing it
			let nonces = HarkForfeitNonces::generate(self.server_key.leak_ref(), unlock_hash);
			ret.push(nonces.public_nonce());
			self.forfeit_nonces.lock().insert_some(*vtxo, nonces);
		}
		Ok(ret)
	}

	pub async fn register_vtxo_forfeit(
		&self,
		forfeits: &[HashLockedForfeitBundle],
	) -> anyhow::Result<UnlockPreimage> {
		// validate bundles and collect vtxo ids before hitting the database,
		// so the batch fetch below sees a clean set of ids.
		let mut unlock_hash = None;
		let mut vtxo_ids = Vec::with_capacity(forfeits.len());
		let mut seen = HashSet::with_capacity(forfeits.len());
		for bundle in forfeits {
			if *unlock_hash.get_or_insert(bundle.unlock_hash) != bundle.unlock_hash {
				return badarg!("not all forfeit bundles have same unlock hash");
			}
			if !seen.insert(bundle.vtxo_id) {
				return badarg!("duplicate vtxo with id {}", bundle.vtxo_id);
			}
			vtxo_ids.push(bundle.vtxo_id);
		}

		let unlock_hash = unlock_hash.badarg("zero forfeit bundles provided")?;

		// fetch all input vtxos in a single query; result is in the same order as vtxo_ids
		let vtxos = self.db.get_user_vtxos_by_id(&vtxo_ids).await?;

		// fetch the round participation
		let part = self.db.get_round_participation_by_unlock_hash(unlock_hash).await?
			.badarg("unknown unlock hash")?;

		// if this participation was already forfeited, skip the expensive work
		// and return the preimage directly
		if part.forfeited_at.is_some() {
			return Ok(part.unlock_preimage.leak_owned());
		}

		// check that all inputs are present
		let mut input_set = part.inputs.iter().map(|i| i.vtxo_id).collect::<HashSet<_>>();
		for vtxo in forfeits {
			if !input_set.remove(&vtxo.vtxo_id) {
				return badarg!("vtxo with id {} is not part of this round participation",
					vtxo.vtxo_id);
			}
		}
		if !input_set.is_empty() {
			return badarg!("missing input vtxos: {:?}", input_set);
		}

		// then do the expensive verification and create final sigs
		let mut ff_txs = Vec::with_capacity(forfeits.len());
		let mut ff_txids = Vec::with_capacity(forfeits.len());
		let mut ff_vtxos = Vec::with_capacity(forfeits.len());
		let mut input_forfeit_pairs = Vec::with_capacity(forfeits.len());
		for (vtxo_ff, vtxo) in forfeits.iter().zip(&vtxos) {
			let input = part.inputs.iter().find(|i| i.vtxo_id == vtxo_ff.vtxo_id)
				.expect("checked this before");
			let nonces = self.forfeit_nonces.lock().take(&input.vtxo_id).with_badarg(||
				format!("no forfeit nonces generated for vtxo {}", input.vtxo_id),
			)?;
			if nonces.unlock_hash != unlock_hash {
				return badarg!("forfeit nonces were generated for unlock hash {} instead of {}",
					nonces.unlock_hash, unlock_hash,
				);
			}
			let pub_nonce = nonces.public_nonce();
			if let Err(e) = vtxo_ff.verify(&vtxo.vtxo, &pub_nonce) {
				return badarg!("forfeit validation failed for vtxo {}: {}", input.vtxo_id, e);
			}
			let (_ff_sig, ff_tx, ff_vtxo) = vtxo_ff.finish(
				&vtxo.vtxo,
				&pub_nonce,
				nonces.into_secret_nonce(),
				self.server_key.leak_ref(),
			);
			let ff_txid = ff_tx.compute_txid();

			ff_txs.push(ff_tx);
			ff_txids.push(ff_txid);
			ff_vtxos.push(ff_vtxo);
			input_forfeit_pairs.push((input.vtxo_id, ff_txid));
		}

		// Persist all signed forfeit txs in a single batch. Either all succeed or
		// none do; on a partial failure the user retries with the same bundles.
		self.db.set_forfeit_transactions(unlock_hash, &vtxo_ids, &ff_txs, &ff_txids).await
			.context("error storing signed forfeit txs")?;

		// Transition the round output vtxos from 'unclaimed' to 'spendable' and
		// record the forfeit txid on the round inputs.
		let round_id = part.round_id.context("round participation has no round_id")?;
		let round = self.db.get_round(round_id).await?
			.context("round not found for participation")?;
		let tree = round.signed_tree.into_cached_tree();
		let output_vtxo_ids = part.outputs.iter()
			.map(|output| {
				let idx = tree.spec.spec.leaf_idx_of_req(&output.vtxo_request)
					.with_context(|| format!("output req not in round {}", round_id))?;
				Ok(tree.build_vtxo(idx).id())
			})
			.collect::<anyhow::Result<Vec<_>>>()?;

		let update = VtxoTreeUpdate::new()
			.upsert_signed_tx(ff_txs)
			.insert_spendable_vtxos(ff_vtxos)
			.mark_vtxos_round_forfeited(input_forfeit_pairs)
			.mark_vtxos_claimed(output_vtxo_ids);
		self.db.execute_vtxo_tree_update(update).await
			.context("failed to execute vtxo tree update")?;

		self.db.mark_participation_forfeited(unlock_hash).await
			.context("failed to mark participation as forfeited")?;

		Ok(part.unlock_preimage.leak_owned())
	}
}

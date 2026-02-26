
use std::collections::{HashMap, HashSet};

use anyhow::Context;
use bitcoin::Amount;
use bitcoin::secp256k1::Keypair;

use ark::{musig, VtxoId};
use ark::forfeit::HashLockedForfeitBundle;
use ark::tree::signed::{UnlockHash, UnlockPreimage};

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
		// fetch vtxos and perform some checks on the bundles
		let mut total_amount = Amount::ZERO;
		let mut vtxos = HashMap::with_capacity(forfeits.len());
		let mut unlock_hash = None;
		for bundle in forfeits {
			let vtxo_id = bundle.vtxo_id;
			if *unlock_hash.get_or_insert(bundle.unlock_hash) != bundle.unlock_hash {
				return badarg!("not all forfeit bundles have same unlock hash");
			}

			let vtxo = self.db.get_user_vtxo_by_id(vtxo_id).await?;
			total_amount += vtxo.vtxo.amount();

			if vtxos.insert(vtxo_id, vtxo).is_some() {
				return badarg!("duplicate vtxo with id {}", vtxo_id);
			}
		}

		let unlock_hash = unlock_hash.badarg("zero forfeit bundles provided")?;

		// fetch the round participation
		let part = self.db.get_round_participation_by_unlock_hash(unlock_hash).await?
			.badarg("unknown unlock hash")?;

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
		for vtxo_ff in forfeits {
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
			let vtxo = self.db.get_user_vtxo_by_id(input.vtxo_id).await?;
			if let Err(e) = vtxo_ff.verify(&vtxo.vtxo, &pub_nonce) {
				return badarg!("forfeit validation failed for vtxo {}: {}", input.vtxo_id, e);
			}
			let (_ff_sig, ff_tx) = vtxo_ff.finish(
				&vtxo.vtxo,
				&pub_nonce,
				nonces.into_secret_nonce(),
				self.server_key.leak_ref(),
			);

			// NB if some succeed and others don't, we just don't respond the preimage and
			// the user has to do the same dance over again
			self.db.set_forfeit_transactions(unlock_hash, input.vtxo_id, &ff_tx).await
				.context("error storing signed forfeit txs")?;
		}

		// Mark transactions as having server-owned descendants after storing forfeits
		let txids = vtxos.values().flat_map(|v| v.vtxo.transactions().map(|i| i.tx.compute_txid()));
		self.db.mark_server_may_own_descendants(txids).await
			.context("failed to mark server_may_own_descendants")?;

		Ok(part.unlock_preimage.leak_owned())
	}
}

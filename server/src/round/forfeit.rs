
use std::collections::{HashMap, HashSet};

use anyhow::Context;
use bitcoin::secp256k1::Keypair;
use bitcoin::{Amount, OutPoint};

use ark::{musig, VtxoId};
use ark::forfeit::{HashLockedForfeitBundle, HashLockedForfeitNonces};
use ark::tree::signed::{UnlockHash, UnlockPreimage};

use crate::Server;
use crate::error::ContextExt;


pub struct HarkForfeitNonces {
	unlock_hash: UnlockHash,
	forfeit_tx_nonces: (musig::SecretNonce, musig::PublicNonce),
	claim_tx_nonces: (musig::SecretNonce, musig::PublicNonce),
}

impl HarkForfeitNonces {
	pub fn generate(key: &Keypair, unlock_hash: UnlockHash) -> Self {
		Self {
			unlock_hash,
			forfeit_tx_nonces: musig::nonce_pair(key),
			claim_tx_nonces: musig::nonce_pair(key),
		}
	}

	pub fn public_nonces(&self) -> HashLockedForfeitNonces {
		HashLockedForfeitNonces {
			forfeit_tx_nonce: self.forfeit_tx_nonces.1,
			forfeit_claim_tx_nonce: self.claim_tx_nonces.1,
		}
	}

	pub fn into_secret_nonces(self) -> [musig::SecretNonce; 2] {
		[
			self.forfeit_tx_nonces.0,
			self.claim_tx_nonces.0,
		]
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
	) -> anyhow::Result<Vec<HashLockedForfeitNonces>> {
		let mut ret = Vec::with_capacity(vtxos.len());
		for vtxo in vtxos {
			// nb this call is quite expensive computationally, so we don't want to
			// keep the lock while doing it
			let nonces = HarkForfeitNonces::generate(self.server_key.leak_ref(), unlock_hash);
			ret.push(nonces.public_nonces());
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
			let pub_nonces = nonces.public_nonces();
			let vtxo = self.db.get_user_vtxo_by_id(input.vtxo_id).await?;
			if let Err(e) = vtxo_ff.verify(&vtxo.vtxo, &pub_nonces) {
				return badarg!("forfeit validation failed for vtxo {}: {}", input.vtxo_id, e);
			}
			let [ff_sig, claim_sig] = vtxo_ff.finish(
				&vtxo.vtxo,
				&pub_nonces,
				nonces.into_secret_nonces(),
				self.server_key.leak_ref(),
			);
			let ff_tx = ark::forfeit::create_hark_forfeit_tx(
				&vtxo.vtxo, unlock_hash, Some(&ff_sig),
			);
			let ff_point = OutPoint::new(ff_tx.compute_txid(), 0);
			let witness = (&claim_sig, part.unlock_preimage.leak_owned());
			let claim_tx = ark::forfeit::create_hark_forfeit_claim_tx(
				&vtxo.vtxo, ff_point, unlock_hash, Some(witness),
			);

			// NB if some succeed and others don't, we just don't respond the preimage and
			// the user has to do the same dance over again
			self.db.set_forfeit_transactions(unlock_hash, input.vtxo_id, &ff_tx, &claim_tx).await
				.context("error storing signed forfeit txs")?;
		}

		// Mark transactions as having server-owned descendants after storing forfeits
		let txids = vtxos.values()
			.flat_map(|v| v.vtxo.transactions().map(|item| item.tx.compute_txid()))
			.collect::<Vec<_>>();
		self.db.mark_server_may_own_descendants(&txids).await
			.context("failed to mark server_may_own_descendants")?;

		Ok(part.unlock_preimage.leak_owned())
	}
}

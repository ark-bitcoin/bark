
use std::io;
use std::collections::HashSet;

use anyhow::Context;
use bitcoin::{sighash, taproot, Amount, OutPoint, Transaction, Witness};

use ark::{Vtxo, VtxoId, VtxoSpec};

use crate::{SECP, Wallet};
use crate::psbtext::PsbtInputExt;



const VTXO_CLAIM_INPUT_WEIGHT: usize = 138;

#[derive(Debug, Serialize, Deserialize)]
pub struct ClaimInput {
	pub utxo: OutPoint,
	//TODO(stevenroose) check how this is used because for OOR a pseudo spec is stored hre
	pub spec: VtxoSpec,
}

impl ClaimInput {
	pub fn encode(&self) -> Vec<u8> {
		let mut buf = Vec::new();
		ciborium::into_writer(self, &mut buf).unwrap();
		buf
	}

	pub fn decode(bytes: &[u8]) -> Result<Self, ciborium::de::Error<io::Error>> {
		ciborium::from_reader(bytes)
	}

	pub fn satisfaction_weight(&self) -> usize {
		// NB Better use a method for this because might be vtxo-dependent in the future.
		VTXO_CLAIM_INPUT_WEIGHT
	}
}

struct Exit {
	total_size: usize,
	started: Vec<VtxoId>,
	claim_inputs: Vec<ClaimInput>,
	fee_anchors: Vec<OutPoint>,
	broadcast: Vec<Transaction>,
}

impl Exit {
	fn new() -> Exit {
		Exit {
			total_size: 0,
			started: Vec::new(),
			claim_inputs: Vec::new(),
			fee_anchors: Vec::new(),
			broadcast: Vec::new(),
		}
	}

	fn add_vtxo(&mut self, vtxo: &Vtxo) {
		let id = vtxo.id();
		match vtxo {
			Vtxo::Onboard { .. } => {
				let reveal_tx = vtxo.vtxo_tx();
				self.broadcast.push(reveal_tx.clone());
				self.total_size += reveal_tx.vsize();
			},
			Vtxo::Round { exit_branch, .. } => {
				let mut branch_size = 0;
				for tx in exit_branch {
					self.broadcast.push(tx.clone());
					branch_size += tx.vsize();
				}
				self.total_size += branch_size;
			},
			Vtxo::Oor { inputs, oor_tx, .. } => {
				for input in inputs {
					self.add_vtxo(input);
				}
				self.broadcast.push(oor_tx.clone());
				self.total_size += oor_tx.vsize();
			},
		}
		self.started.push(id);
		self.fee_anchors.push(vtxo.fee_anchor());
		self.claim_inputs.push(ClaimInput { utxo: vtxo.point(), spec: vtxo.spec().clone() });
	}
}

impl Wallet {
	/// Exit all vtxo onto the chain.
	pub async fn start_unilateral_exit(&mut self) -> anyhow::Result<()> {
		self.onchain.sync().await.context("onchain sync error")?;
		if let Err(e) = self.sync_ark().await {
			warn!("Failed to sync incoming Ark payments, still doing exit: {}", e);
		}

		let vtxos = self.db.get_all_vtxos()?;

		//TODO(stevenroose) idea, each vtxo will have a fee anchor for us.
		// We should here
		// - collect all fee anchor outputs of broadcasted txs in a list
		// - add up the vsize of all txs we broadcasted
		// - create a new tx using our on-chain wallet that spends all anchors and
		// has an absolute fee that pays our feerate (also todo) for the entire
		// "package" vsize.

		info!("Starting unilateral exit of {} vtxos...", vtxos.len());
		let mut exit = Exit::new();
		for vtxo in vtxos {
			exit.add_vtxo(&vtxo);
		}

		//TODO(stevenroose) probably a good idea to store this exit struct in the db
		// so we can recover if anything fails

		// Broadcast exit txs.
		for tx in &exit.broadcast {
			trace!("Broadcasting tx {}: {}", tx.compute_txid(), bitcoin::consensus::encode::serialize_hex(tx));
			if let Err(e) = self.onchain.broadcast_tx(tx).await {
				error!("Error broadcasting exit tx {}: {}", tx.compute_txid(), e);
				error!("Tx {}: {}", tx.compute_txid(), bitcoin::consensus::encode::serialize_hex(tx));
			}
		}

		if exit.claim_inputs.len() == 0 {
			return Ok(());
		}

		info!("Got {} outputs to claim, {} fee anchors to spend and {} package vsize to cover",
			exit.claim_inputs.len(), exit.fee_anchors.len(), exit.total_size);

		// First we will store the claim inputs so we for sure don't forget about them.
		// We might already have some pending claim inputs.
		let mut claim_inputs = self.db.get_claim_inputs().context("db error getting existing claims")?;
		let mut claim_utxos = claim_inputs.iter().map(|i| i.utxo).collect::<HashSet<_>>();
		for new in exit.claim_inputs {
			if claim_utxos.insert(new.utxo) {
				claim_inputs.push(new);
			} else {
				warn!("A claim input for utxo {} already existed", new.utxo);
			}
		}
		self.db.store_claim_inputs(&claim_inputs).context("db error storing claim inputs")?;

		// Then we'll send a tx that will pay the fee for all the txs we made.
		let tx = self.onchain.spend_fee_anchors(&exit.fee_anchors, exit.total_size).await?;
		info!("Sent anchor spend tx: {}", tx.compute_txid());

		// After we succesfully stored the claim inputs, we can drop the vtxos.
		for id in exit.started {
			if let Err(e) = self.db.remove_vtxo(id) {
				// Don't error here so we can try remove the others.
				warn!("Error removing vtxo {} from db: {}", id, e);
			}
		}
		Ok(())
	}

	/// Returns all the pending exit claims, first the claimable ones and then
	/// the unclaimable ones.
	pub async fn unclaimed_exits(&self) -> anyhow::Result<(Vec<ClaimInput>, Vec<ClaimInput>)> {
		let all_inputs = self.db.get_claim_inputs()?;
		//TODO(stevenroose) we need to find a way of what to do with the inputs
		// that are already spent
		let mut claimable = Vec::with_capacity(all_inputs.len());
		let mut unclaimable = Vec::with_capacity(all_inputs.len());
		for input in all_inputs {
			match self.onchain.txout_confirmations(input.utxo).await {
				Ok(Some(confs)) => {
					if confs >= input.spec.exit_delta as u32 {
						claimable.push(input);
						continue;
					} else {
						trace!("Claim input {} has only {} confirmations (need {})",
							input.utxo, confs, input.spec.exit_delta);
					}
				},
				Ok(None) => warn!("Claim input {} not found in utxo set...", input.utxo),
				Err(e) => {
					trace!("Error from chain source: {}", e);
					warn!("Claim input {} not found in utxo set...", input.utxo);
				},
			}
			unclaimable.push(input);
		}
		Ok((claimable, unclaimable))
	}

	pub async fn claim_unilateral_exit(&mut self) -> anyhow::Result<()> {
		let (inputs, remaining) = self.unclaimed_exits().await?;

		if inputs.is_empty() {
			info!("No inputs we can claim.");
			return Ok(());
		}
		let total_amount = inputs.iter().map(|i| i.spec.amount).sum::<Amount>();
		debug!("Claiming the following exits with total value of {}: {:?}",
			total_amount, inputs.iter().map(|i| i.utxo.to_string()).collect::<Vec<_>>(),
		);

		let mut psbt = self.onchain.create_exit_claim_tx(&inputs).await?;

		// Sign all the claim inputs.
		let vtxo_key = self.vtxo_seed.to_keypair(&SECP);
		let lver = taproot::LeafVersion::TapScript;
		let prevouts = psbt.inputs.iter()
			.map(|i| i.witness_utxo.clone().unwrap())
			.collect::<Vec<_>>();
		let mut shc = sighash::SighashCache::new(&psbt.unsigned_tx);
		for (i, input) in psbt.inputs.iter_mut().enumerate() {
			let claim = if let Some(c) = input.get_claim_input() {
				c
			} else {
				continue;
			};

			// Now we need to sign for this.
			let exit_script = claim.spec.exit_clause();
			let leaf_hash = taproot::TapLeafHash::from_script(&exit_script, lver);
			let sighash = shc.taproot_script_spend_signature_hash(
				i, &sighash::Prevouts::All(&prevouts), leaf_hash, sighash::TapSighashType::Default,
			).expect("all prevouts provided");

			assert_eq!(vtxo_key.public_key(), claim.spec.user_pubkey);
			let sig = SECP.sign_schnorr(&sighash.into(), &vtxo_key);

			let cb = claim.spec.exit_taproot()
				.control_block(&(exit_script.clone(), lver))
				.expect("script is in taproot");

			let wit = Witness::from_slice(
				&[&sig[..], exit_script.as_bytes(), &cb.serialize()],
			);
			debug_assert_eq!(wit.size(), claim.satisfaction_weight());
			input.final_script_witness = Some(wit);
		}

		// Then sign the wallet's funding inputs.
		let tx = self.onchain.finish_tx(psbt).context("finishing claim psbt")?;
		if let Err(e) = self.onchain.broadcast_tx(&tx).await {
			bail!("Error broadcasting claim tx: {}", e);
		}

		// Then update the database and only set the remaining inputs as to do.
		self.db.store_claim_inputs(&remaining).context("failed db update")?;

		info!("Successfully claimed total value of {}", total_amount);
		Ok(())
	}
}

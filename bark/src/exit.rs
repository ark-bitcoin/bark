
use std::{cmp, io};
use std::collections::HashMap;

use anyhow::Context;
use bitcoin::{sighash, Amount, OutPoint, Transaction, Txid};

use ark::{Vtxo, VtxoSpec};

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
		// NB might be vtxo-dependent in the future.
		VTXO_CLAIM_INPUT_WEIGHT
	}
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub enum ExitTxStatus {
	/// Tx has not been broadcast.
	#[default]
	Pending,
	/// Has been been broadcast with
	BroadcastWithCpfp(Transaction),
	/// Has been confirmed.
	ConfirmedIn(u32),
}

#[derive(Debug, Deserialize, Serialize)]
pub struct VtxoExit {
	vtxo: Vtxo,
	exit_tx_status: HashMap<Txid, ExitTxStatus>,
}

impl VtxoExit {
	fn new(vtxo: Vtxo) -> VtxoExit {
		VtxoExit { vtxo, exit_tx_status: HashMap::new() }
	}

	fn exit_txs(&self) -> Vec<Transaction> {
		let mut ret = Vec::new();
		self.vtxo.collect_exit_txs(&mut ret);
		ret
	}

	//TODO(stevenroose) probably not needed
	fn claim(&self) -> ClaimInput {
		ClaimInput {
			utxo: self.vtxo.point(),
			spec: self.vtxo.spec().clone(),
		}
	}
}

#[derive(Debug, Default, Deserialize, Serialize)]
pub struct Exit {
	/// The vtxos in process of exit
	vtxos: Vec<VtxoExit>,

	// nb for now this seems just a vec, but later we will have txs
	// that cpfp multiple exits etc
}

impl Exit {
	fn add_vtxo(&mut self, vtxo: Vtxo) {
		if self.vtxos.iter().any(|v| v.vtxo.id() == vtxo.id()) {
			return;
		}
		self.vtxos.push(VtxoExit::new(vtxo));
	}

	pub fn is_empty(&self) -> bool {
		self.vtxos.is_empty()
	}

	pub fn vtxos(&self) -> impl ExactSizeIterator<Item = &Vtxo> {
		self.vtxos.iter().map(|v| &v.vtxo)
	}

	pub fn total_pending_amount(&self) -> Amount {
		self.vtxos.iter().map(|v| v.vtxo.spec().amount).sum()
	}
}

#[derive(Debug, PartialEq, Eq)]
pub enum ExitStatus {
	/// All txs were broadcast and we claimed all exits.
	Done,
	/// Not all txs were able to be broadcast and confirmed.
	NeedMoreTxs,
	/// All txs are broadcast and confirmed, but we need more confirmations.
	WaitingForHeight(u32),
}

impl Wallet {
	/// Add all vtxos in the current wallet to the exit process.
	pub async fn start_exit_for_entire_wallet(&mut self) -> anyhow::Result<()> {
		self.onchain.sync().await.context("onchain sync error")?;
		if let Err(e) = self.sync_ark().await {
			warn!("Failed to sync incoming Ark payments, still doing exit: {}", e);
		}
		let current_height = self.onchain.tip().await?;

		let vtxos = self.db.get_all_vtxos()?;
		let ids = vtxos.iter().map(|v| v.id()).collect::<Vec<_>>();

		// The idea is to convert all our vtxos into an exit process structure,
		// that we then store in the database and we can gradually proceed on.

		let mut exit = self.db.fetch_exit()?.unwrap_or_default();

		for vtxo in vtxos {
			exit.add_vtxo(vtxo);
		}

		self.db.store_exit(&exit)?;
		for id in ids {
			self.db.store_spent_vtxo(id, current_height).context("failed to mark vtxo as spent")?;
			self.db.remove_vtxo(id).context("failed to drop exited vtxo")?;
		}

		Ok(())
	}

	/// Get the pending exit tracking struct.
	//TODO(stevenroose) consider not exposing this and only expose a overview struct
	pub fn get_exit(&self) -> anyhow::Result<Option<Exit>> {
		Ok(self.db.fetch_exit()?)
	}

	/// Progress a unilateral exit progress.
	pub async fn progress_exit(&mut self) -> anyhow::Result<ExitStatus> {
		self.onchain.sync().await.context("onchain sync error")?;
		let mut exit = self.db.fetch_exit()?.unwrap_or_default();
		if exit.is_empty() {
			return Ok(ExitStatus::Done);
		}

		// Go over each tx and see if we can make progress on it.
		//
		// NB cpfp should be done on individual txs for now, because we will utilize 1p1c
		for vtxo in exit.vtxos.iter_mut() {
			'tx: for tx in vtxo.exit_txs() {
				let txid = tx.compute_txid();
				match vtxo.exit_tx_status.get(&txid) {
					Some(ExitTxStatus::ConfirmedIn(_)) => {}, // nothing to do
					Some(ExitTxStatus::BroadcastWithCpfp(_tx)) => {
						if let Ok(Some(h)) = self.onchain.tx_confirmed(txid).await {
							debug!("Exit tx {} is confirmed", txid);
							vtxo.exit_tx_status.insert(txid, ExitTxStatus::ConfirmedIn(h));
						}
					},
					None | Some(ExitTxStatus::Pending) => {
						// First check if it's already confirmed.
						if let Ok(Some(h)) = self.onchain.tx_confirmed(txid).await {
							debug!("Exit tx {} is confirmed", txid);
							vtxo.exit_tx_status.insert(txid, ExitTxStatus::ConfirmedIn(h));
							continue 'tx;
						}

						// Check if all the inputs are confirmed
						for inp in &tx.input {
							let res = self.onchain.tx_confirmed(inp.previous_output.txid).await;
							if res.is_err() || res.unwrap().is_none() {
								trace!("Can't include tx {} yet because input {} is not yet confirmed",
									txid, inp.previous_output,
								);
								continue 'tx;
							}
						}

						// Ok let's confirm this bastard.
						let cpfp = self.onchain.make_cpfp(&[&tx]).await?;
						if let Err(e) = self.onchain.broadcast_tx(&tx).await {
							warn!("Error broadcasting an exit tx, \
								hopefully means it already got broadcast before: {}", e);
						}
						if let Err(e) = self.onchain.broadcast_tx(&cpfp).await {
							error!("Error broadcasting CPFP tx: {}", e);
							//TODO(stevenroose) should we abort or still store the tx?
						} else {
							info!("Broadcast CPFP tx {} to confirm tx {}", cpfp.compute_txid(), txid);
						}
						vtxo.exit_tx_status.insert(txid, ExitTxStatus::BroadcastWithCpfp(cpfp));
					},
				}
			}
		}

		// Save the updated exit state.
		self.db.store_exit(&exit)?;

		// nb we wait until we can sweep all of them
		let mut all_confirmed = true;
		let mut highest_height = 0;
		for vtxo in exit.vtxos.iter_mut() {
			let status = vtxo.exit_tx_status.get(&vtxo.vtxo.vtxo_tx().compute_txid());
			if let Some(ExitTxStatus::ConfirmedIn(h)) = status {
				let height = h + vtxo.vtxo.spec().exit_delta as u32;
				highest_height = cmp::max(highest_height, height);
			} else {
				all_confirmed = false;
				break;
			}
		}
		let ret = if all_confirmed {
			let current_height = self.onchain.tip().await?;
			if highest_height <= current_height {
				let inputs = exit.vtxos.iter().map(|vtxo| {
					vtxo.claim()
				}).collect::<Vec<_>>();

				let total_amount = inputs.iter().map(|i| i.spec.amount).sum::<Amount>();
				debug!("Claiming the following exits with total value of {}: {:?}",
					total_amount, inputs.iter().map(|i| i.utxo.to_string()).collect::<Vec<_>>(),
				);

				let mut psbt = self.onchain.create_exit_claim_tx(&inputs).await?;

				// Sign all the claim inputs.
				let vtxo_key = self.vtxo_seed.to_keypair(&SECP);
				let prevouts = psbt.inputs.iter()
					.map(|i| i.witness_utxo.clone().unwrap())
					.collect::<Vec<_>>();
				let prevouts = sighash::Prevouts::All(&prevouts);
				let mut shc = sighash::SighashCache::new(&psbt.unsigned_tx);
				for (i, input) in psbt.inputs.iter_mut().enumerate() {
					input.try_sign_claim_input(&SECP, &mut shc, &prevouts, i, &vtxo_key);
				}

				// Then sign the wallet's funding inputs.
				let tx = self.onchain.finish_tx(psbt).context("finishing claim psbt")?;
				if let Err(e) = self.onchain.broadcast_tx(&tx).await {
					bail!("Error broadcasting claim tx: {}", e);
				}

				// Remove the exit record from the db.
				self.db.store_exit(&Exit::default())?;

				ExitStatus::Done
			} else {
				ExitStatus::WaitingForHeight(highest_height)
			}
		} else {
			ExitStatus::NeedMoreTxs
		};
		Ok(ret)
	}
}

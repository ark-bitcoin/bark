
use std::cmp;
use std::collections::HashMap;

use anyhow::Context;
use bdk_wallet::WalletPersister;
use bitcoin::{sighash, Amount, Transaction, Txid, Weight};
use serde::ser::StdError;

use ark::Vtxo;

use crate::persist::BarkPersister;
use crate::{SECP, Wallet};
use crate::psbtext::PsbtInputExt;



/// The input weight required to claim a VTXO.
const VTXO_CLAIM_INPUT_WEIGHT: Weight = Weight::from_wu(138);

#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize, Serialize)]
enum TxStatus {
	/// Tx has not been broadcast.
	#[default]
	Pending,
	/// Has been been broadcast with
	BroadcastWithCpfp(Transaction),
	/// Has been confirmed.
	ConfirmedIn(u32),
}

#[derive(Debug, Default, Deserialize, Serialize)]
pub struct Exit {
	/// The vtxos in process of exit
	vtxos: Vec<Vtxo>,
	/// The statuses of the various exit txs. Kept here because different
	/// exits might have overlapping txs.
	exit_tx_status: HashMap<Txid, TxStatus>,

	// nb for now this seems just a vec, but later we will have txs
	// that cpfp multiple exits etc
}

impl Exit {
	/// Add vtxo to the exit, if not already in
	/// 
	/// Returns the vtxo if it was added to the exit
	fn add_vtxo(&mut self, vtxo: Vtxo) -> Option<Vtxo> {
		if self.vtxos.iter().any(|v| v.id() == vtxo.id()) {
			return None
		}
		self.vtxos.push(vtxo.clone());
		Some(vtxo)
	}

	pub fn is_empty(&self) -> bool {
		self.vtxos.is_empty()
	}

	pub fn total_pending_amount(&self) -> Amount {
		self.vtxos.iter().map(|v| v.spec().amount).sum()
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

impl <P>Wallet<P> where 
	P: BarkPersister, 
	<P as WalletPersister>::Error: 'static + std::fmt::Debug + std::fmt::Display + Send + Sync + StdError
{
	/// Add all vtxos in the current wallet to the exit process.
	pub async fn start_exit_for_entire_wallet(&mut self) -> anyhow::Result<()> {
		if let Err(e) = self.sync_ark().await {
			warn!("Failed to sync incoming Ark payments, still doing exit: {}", e);
		}

		let vtxos = self.db.get_all_spendable_vtxos()?;

		// The idea is to convert all our vtxos into an exit process structure,
		// that we then store in the database and we can gradually proceed on.

		let mut exit = self.db.fetch_exit()?.unwrap_or_default();

		// We add vtxos to the exit, those already in exit are returned as `None`
		let added_vtxos = vtxos.into_iter().filter_map(|v| exit.add_vtxo(v)).collect::<Vec<_>>();

		self.db.store_exit(&exit)?;

		// TODO: later we might want to register each exit as separate exit (sent to different addresses)
		if !added_vtxos.is_empty() {
			// TODO: replace vtxo pubkey by something else
			self.db.register_send(&added_vtxos,  self.vtxo_pubkey().to_string(), None, None).context("Failed to register send")?;
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
				match exit.exit_tx_status.entry(txid).or_default() {
					TxStatus::ConfirmedIn(_) => {}, // nothing to do
					TxStatus::BroadcastWithCpfp(cpfp) => {
						// NB we don't care if our cpfp tx confirmed or
						// if it confirmed through other means
						if let Ok(Some(h)) = self.onchain.tx_confirmed(txid).await {
							debug!("Exit tx {} is confirmed after cpfp", txid);
							exit.exit_tx_status.insert(txid, TxStatus::ConfirmedIn(h));
							continue 'tx;
						}

						// Broadcast our cpfp again in case it got dropped.
						info!("Re-broadcasting package with CPFP tx {} to confirm tx {}",
							cpfp.compute_txid(), txid,
						);
						if let Err(e) = self.onchain.broadcast_package(&[&tx, &cpfp]).await {
							error!("Error broadcasting CPFP tx package: {}", e);
						}
					},
					TxStatus::Pending => {
						// First check if it's already confirmed.
						if let Ok(Some(h)) = self.onchain.tx_confirmed(txid).await {
							debug!("Exit tx {} is confirmed before cpfp", txid);
							exit.exit_tx_status.insert(txid, TxStatus::ConfirmedIn(h));
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
						let fee_rate = self.onchain.urgent_feerate();
						let cpfp = self.onchain.make_cpfp(&[&tx], fee_rate).await?;
						info!("Broadcasting package with CPFP tx {} to confirm tx {}",
							cpfp.compute_txid(), txid,
						);
						if let Err(e) = self.onchain.broadcast_package(&[&tx, &cpfp]).await {
							error!("Error broadcasting CPFP tx package: {}", e);
							// We won't abort the process because there are
							// various reasons why this can happen.
							// Many of them are not hurtful.
						}
						exit.exit_tx_status.insert(txid, TxStatus::BroadcastWithCpfp(cpfp));
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
			let status = exit.exit_tx_status.get(&vtxo.vtxo_tx().compute_txid());
			if let Some(TxStatus::ConfirmedIn(h)) = status {
				let height = h + vtxo.spec().exit_delta as u32;
				highest_height = cmp::max(highest_height, height);
			} else {
				all_confirmed = false;
				break;
			}
		}

		if !all_confirmed {
			return Ok(ExitStatus::NeedMoreTxs);
		}

		let current_height = self.onchain.tip().await?;
		if current_height < highest_height {
			return Ok(ExitStatus::WaitingForHeight(highest_height));
		}

		// Do the sweep
		self.sweep().await
	}

	async fn sweep(&mut self) -> anyhow::Result<ExitStatus> {
		let exit = self.db.fetch_exit()
			.context("Failed to retreive exit from db")?
			.context("Cannot sweep when no exit is in progress")?;
		let inputs = exit.vtxos.iter().collect::<Vec<_>>();

		let total_amount = inputs.iter().map(|i| i.amount()).sum::<Amount>();
		debug!("Claiming the following exits with total value of {}: {:?}",
			total_amount, inputs.iter().map(|i| i.point().to_string()).collect::<Vec<_>>(),
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
			input.try_sign_exit_claim_input(&SECP, &mut shc, &prevouts, i, &vtxo_key);
		}

		// Then sign the wallet's funding inputs.
		let tx = self.onchain.finish_tx(psbt).context("finishing claim psbt")?;
		if let Err(e) = self.onchain.broadcast_tx(&tx).await {
			bail!("Error broadcasting claim tx: {}", e);
		}

		// Remove the exit record from the db.
		self.db.store_exit(&Exit::default())?;

		Ok(ExitStatus::Done)		
	}
}


pub(crate) trait VtxoExt {
	fn satisfaction_weight(&self) -> Weight;
}

impl VtxoExt for Vtxo {
	fn satisfaction_weight(&self) -> Weight {
		// NB might be vtxo-dependent in the future
		VTXO_CLAIM_INPUT_WEIGHT
	}
}

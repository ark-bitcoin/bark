
use std::cmp;
use std::collections::HashMap;

use anyhow::Context;
use bdk_wallet::WalletPersister;
use bitcoin::consensus::encode::serialize_hex;
use bitcoin::params::Params;
use bitcoin::{Address, Amount, FeeRate, OutPoint, Transaction, Txid, Weight};
use bitcoin_ext::bdk::{CpfpError, WalletExt};
use serde::ser::StdError;

use ark::{BlockHeight, Vtxo, VtxoId};

use crate::movement::MovementArgs;
use crate::onchain::{self, ChainSource, ChainSourceClient};
use crate::persist::BarkPersister;

/// The confirmations needed to consider transaction
/// immutable in the chain
const DEEPLY_CONFIRMED: BlockHeight = 6;


#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SpendableVtxo {
	pub vtxo: Vtxo,
	pub spendable_at_height: u32
}

struct VtxoPartition {
	pub spendable: Vec<SpendableVtxo>,
	pub pending: Vec<Vtxo>,
	pub spent: Vec<Vtxo>
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize, Serialize)]
enum OutputStatus {
	/// Exit output is available and not been spent yet
	#[default]
	Available,
	/// Output has been spent in tx, but not confirmed yet
	SpentIn(Txid),
	/// Transaction spending the output has been confirmed in block
	ConfirmedIn(u32),
}

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
pub struct ExitIndex {
	/// The vtxos in process of exit
	vtxos: Vec<Vtxo>,
	/// The status of the exit outputs, kept to know when it's ok to remove vtxo from exit index
	exit_output_status: HashMap<OutPoint, OutputStatus>,
	/// The statuses of the various exit txs. Kept here because different
	/// exits might have overlapping txs.
	exit_tx_status: HashMap<Txid, TxStatus>,

	// nb for now this seems just a vec, but later we will have txs
	// that cpfp multiple exits etc
}

impl ExitIndex {
	/// Add vtxo to the exit, if not already in
	///
	/// Returns the vtxo if it was added to the exit
	pub fn add_vtxo(&mut self, vtxo: Vtxo) -> Option<Vtxo> {
		if self.vtxos.iter().any(|v| v.id() == vtxo.id()) {
			return None
		}
		self.vtxos.push(vtxo.clone());
		Some(vtxo)
	}

	pub fn remove_vtxo(&mut self, vtxoid: VtxoId) {
		if let Some((idx, _v)) = self.vtxos.iter().enumerate().find(|(_i, v)| v.id() == vtxoid) {
			self.vtxos.remove(idx);
		}
	}

	pub fn is_empty(&self) -> bool {
		self.vtxos.is_empty()
	}

	/// Returns the height at which VTXO output will be spendable
	///
	/// If the exit txs have not been fully confirmed yet, it will return `None`
	pub (crate) fn spendable_at_height(&self, vtxo: &Vtxo) -> Option<u32> {
		let txid = vtxo.point().txid;
		match self.exit_tx_status.get(&txid) {
			Some(TxStatus::ConfirmedIn(height)) => Some(height + vtxo.spec().exit_delta as u32),
			_ => None
		}
	}
}

/// Handle to process and keep track of ongoing VTXO exits
pub struct Exit<P: BarkPersister> {
	/// The vtxos in process of exit
	index: ExitIndex,

	db: P,
	chain_source: ChainSourceClient,
}


impl <P>Exit<P> where
	P: BarkPersister,
	<P as WalletPersister>::Error: 'static + std::fmt::Debug + std::fmt::Display + Send + Sync + StdError
{
	pub (crate) fn new(db: P, chain_source: ChainSource) -> anyhow::Result<Exit<P>> {
		let chain_source = ChainSourceClient::new(chain_source)?;
		let index = db.fetch_exit()?.unwrap_or_default();

		Ok(Exit {
			index,
			db,
			chain_source
		})
	}

	fn persist_exit(&self) -> anyhow::Result<()> {
		Ok(self.db.store_exit(&self.index)?)
	}

	/// Add all vtxos in the current wallet to the exit process.
	///
	/// It is recommended to sync with ASP before calling this
	pub async fn start_exit_for_entire_wallet(
		&mut self,
		onchain: &mut onchain::Wallet<P>,
	) -> anyhow::Result<()> {
		let vtxos = self.db.get_all_spendable_vtxos()?;

		// The idea is to convert all our vtxos into an exit process structure,
		// that we then store in the database and we can gradually proceed on.
		self.start_exit_for_vtxos(&vtxos, onchain).await?;

		Ok(())
	}

	/// Add provided vtxo to the exit process.
	pub async fn start_exit_for_vtxos(
		&mut self,
		vtxos: &[Vtxo],
		onchain: &mut onchain::Wallet<P>,
	) -> anyhow::Result<()> {
		// To avoid starting an exit we can't afford, let's do some napkin math.
		let fee_rate = self.chain_source.urgent_feerate();
		let total_fee = estimate_exit_weight(vtxos, fee_rate);
		let balance = onchain.balance();
		if balance < total_fee {
			bail!("total exit fee estimate is {total_fee}, wallet only has {balance}")
		}

		for vtxo in vtxos {
			let added = self.index.add_vtxo(vtxo.clone());
			if let Some(added) = added {
				let params = Params::new(onchain.wallet.network());
				let address = Address::from_script(&added.spec().vtxo_spk(), params)?;
				self.db.register_movement(MovementArgs {
					spends: vec![&added],
					receives: None,
					recipients: vec![
						(address.to_string(), added.amount())
					],
					fees: None
				}).context("Failed to register send")?;
			}
		}

		self.persist_exit()?;
		Ok(())
	}

	/// Returns the total amount of all VTXOs requiring more txs to be confirmed
	pub async fn pending_total(&self) -> anyhow::Result<Amount> {
		let VtxoPartition { pending, .. } = self.partition_vtxos().await?;

		let amount = pending.into_iter().map(|v| v.spec().amount).sum();
		Ok(amount)
	}

	/// Reset exit to an empty state. Should be called when dropping VTXOs
	///
	/// Note: _This method is **dangerous** and can lead to funds loss. Be cautious._
	pub (crate) fn clear_exit(&mut self) -> anyhow::Result<()> {
		self.index = ExitIndex::default();
		self.persist_exit()?;
		Ok(())
	}

	/// Iterates over all pending unilateral exits to check it is
	/// confirmed and rebroadcast the exit cpfp tx if needed
	///
	/// ### Arguments
	///
	/// - `onchain` is a mutable reference to an onchain wallet
	/// used to build the cpfp transaction
	///
	/// ### Return
	///
	/// Return exit status if there are vtxos to exit, else `None`
	pub async fn progress_exit(&mut self, onchain: &mut onchain::Wallet<P>) -> anyhow::Result<()> {
		if self.index.is_empty() {
			return Ok(());
		}

		// Go over each tx and see if we can make progress on it.
		//
		// NB cpfp should be done on individual txs for now, because we will utilize 1p1c
		for vtxo in self.index.vtxos.iter_mut() {
			trace!("exiting vtxo: {} / {:?}", vtxo.id(), vtxo);

			let txs = vtxo.exit_txs();
			'tx: for tx in txs {
				trace!("broadcasting transaction: {} / {}", tx.compute_txid(), serialize_hex(&tx));

				let txid = tx.compute_txid();
				match self.index.exit_tx_status.entry(txid).or_default() {
					TxStatus::ConfirmedIn(_) => {
						if let Ok(None) = self.chain_source.tx_confirmed(txid).await {
							debug!("Chain has been reorged, tx {} is back unconfirmed", txid);
							self.index.exit_tx_status.insert(txid, TxStatus::Pending);
						}
					},
					TxStatus::BroadcastWithCpfp(cpfp) => {
						// NB we don't care if our cpfp tx confirmed or
						// if it confirmed through other means
						if let Ok(Some(h)) = self.chain_source.tx_confirmed(txid).await {
							debug!("Exit tx {} is confirmed after cpfp", txid);
							self.index.exit_tx_status.insert(txid, TxStatus::ConfirmedIn(h));
							continue 'tx;
						}

						// Broadcast our cpfp again in case it got dropped.
						info!("Re-broadcasting package with CPFP tx {} to confirm tx {}",
							cpfp.compute_txid(), txid,
						);
						if let Err(e) = self.chain_source.broadcast_package(&[&tx, &cpfp]).await {
							error!("Error broadcasting CPFP tx package: {}", e);
						}
					},
					TxStatus::Pending => {
						// First check if it's already confirmed.
						if let Ok(Some(h)) = self.chain_source.tx_confirmed(txid).await {
							debug!("Exit tx {} is confirmed before cpfp", txid);
							self.index.exit_tx_status.insert(txid, TxStatus::ConfirmedIn(h));
							continue 'tx;
						}

						// Check if all the inputs are confirmed
						for inp in &tx.input {
							let res = self.chain_source.tx_confirmed(inp.previous_output.txid).await;
							if res.is_err() || res.unwrap().is_none() {
								trace!("Can't include tx {} yet because input {} is not yet confirmed",
									txid, inp.previous_output,
								);
								continue 'tx;
							}
						}

						// Ok let's confirm this bastard.
						let fee_rate = self.chain_source.urgent_feerate();
						let cpfp_psbt = match onchain.wallet.make_cpfp(&[&tx], fee_rate) {
							Ok(psbt) => psbt,
							Err(CpfpError::NeedConfirmations(e)) => {
								info!("On-chain funds need more confirmations \
									to make progress on exit: {}", e);
								return Ok(());
							},
							Err(e) => return Err(e.into()),
						};
						let cpfp = onchain.finish_tx(cpfp_psbt)?;
						info!("Broadcasting package with CPFP tx {} to confirm tx {}",
							cpfp.compute_txid(), txid,
						);
						if let Err(e) = self.chain_source.broadcast_package(&[&tx, &cpfp]).await {
							error!("Error broadcasting CPFP tx package: {}", e);
							// We won't abort the process because there are
							// various reasons why this can happen.
							// Many of them are not hurtful.
						}
						self.index.exit_tx_status.insert(txid, TxStatus::BroadcastWithCpfp(cpfp));
					},
				}
			}
		}

		// Save the updated exit state.
		self.persist_exit()?;

		Ok(())
	}

	/// Partition VTXOs by their exit output's status
	/// - pending -> needs more confirmation to reach `exit_delta`
	/// - spendable -> confirmed and reached `exit_delta`
	/// - spent -> already spent
	async fn partition_vtxos(&self) -> anyhow::Result<VtxoPartition> {
		let current_height = self.chain_source.tip().await?;

		let mut pending = vec![];
		let mut spent = vec![];
		let mut spendable = vec![];

		for vtxo in self.index.vtxos.iter() {
			if let Some(spendable_at_height) = self.index.spendable_at_height(vtxo) {
				if let Some(status) = self.index.exit_output_status.get(&vtxo.point()) {
					if matches!(status, OutputStatus::ConfirmedIn(_) | OutputStatus::SpentIn(_)) {
						spent.push(vtxo.clone());
						continue;
					}
				}

				if current_height >= spendable_at_height  {
					spendable.push(SpendableVtxo {
						vtxo: vtxo.clone(),
						spendable_at_height: spendable_at_height,
					});
					continue
				}
			}

			pending.push(vtxo.clone());
		}

		Ok(VtxoPartition { spendable, spent, pending })
	}

	pub async fn list_spendable_exits(&self) -> anyhow::Result<Vec<SpendableVtxo>> {
		Ok(self.partition_vtxos().await?.spendable)
	}

	pub async fn list_pending_exits(&self) -> anyhow::Result<Vec<Vtxo>> {
		Ok(self.partition_vtxos().await?.pending)
	}

	/// The height at which all exits will be spendable.
	///
	/// If None, this means some exit txs are not confirmed yet
	pub async fn all_spendable_at_height(&self) -> Option<u32> {
		let mut highest_spendable_height = None;
		for vtxo in self.index.vtxos.iter() {
			match self.index.spendable_at_height(vtxo) {
				Some(spendable_at_height) => {
					highest_spendable_height = cmp::max(highest_spendable_height, Some(spendable_at_height));
				},
				None => {
					highest_spendable_height = None;
					// If at least one of the VTXO exits is not confirmed yet,
					// highest_height should remain `None`: we break the loop
					break;
				}
			}
		}

		highest_spendable_height
	}

	/// Sync to check if spendable vtxos have been spent
	///
	/// If so, it removes the VTXO from the exit
	///
	/// Note: this does not sync exit txs, only exit outputs.
	/// To sync exit txs, see [`Exit::progress_exit`]
	pub (crate) async fn sync_exit(&mut self, onchain: &mut onchain::Wallet<P>) -> anyhow::Result<()> {
		let VtxoPartition { spendable, spent, .. } = self.partition_vtxos().await?;
		let vtxos = spendable.into_iter().map(|v| v.vtxo).chain(spent.into_iter()).collect::<Vec<_>>();

		let current_height = self.chain_source.tip().await?;

		// we compute the lowest confirmation height from which we can start syncing
		// we don't need to sync before because outputs weren't spendable
		let lowest_confirm_height = vtxos.iter()
			.map(|v| self.index.spendable_at_height(v).expect("vtxo must be spendable here"))
			.min();

		if let Some(lowest_confirm_height) = lowest_confirm_height {
			let (tx_by_outpoint, unconfirmed_tx_by_outpoint) = self.chain_source.txs_spending_inputs(
				vtxos.iter().map(|v| v.point()).collect::<Vec<_>>(),
				lowest_confirm_height as u64
			).await?;

			for vtxo in vtxos {
				let point = vtxo.point();

				// Tracking output on chain
				if let Some((height, _txid)) = tx_by_outpoint.get(&point) {
					self.index.exit_output_status.insert(point, OutputStatus::ConfirmedIn(*height as u32));
					continue
				}

				// Tracking output in mempool
				if let Some(txid) = unconfirmed_tx_by_outpoint.get(&point) {
					self.index.exit_output_status.insert(point, OutputStatus::SpentIn(*txid));
					continue
				}

				// If transaction spending output has been sufficiently deep,
				// we can safely remove the VTXO from the index
				if let Some(exit_output_status) = self.index.exit_output_status.get(&point) {
					match exit_output_status {
						OutputStatus::ConfirmedIn(height)
							if current_height > (height + DEEPLY_CONFIRMED as u32) =>
						{
							self.index.remove_vtxo(vtxo.id());
							continue;
						}
						_ => {}
					}
				}

				// Default to move back output to available status
				self.index.exit_output_status.insert(point,  OutputStatus::Available);
			}

			self.persist_exit()?;

			let outputs = self.list_spendable_exits().await?;
			onchain.exit_outputs = outputs;
		}

		Ok(())
	}
}

/// Do a rudimentary check of the total exit cost for a set of vtxos.
/// We estimate the CPCP part by multiplying the exit tx weight by 2.
fn estimate_exit_weight(vtxos: &[Vtxo], fee_rate: FeeRate) -> Amount {
	let mut all_txs = Vec::with_capacity(vtxos.len() * 2);
	for vtxo in vtxos {
		vtxo.collect_exit_txs(&mut all_txs);
	}
	let total_weight = all_txs.iter().map(|t| t.weight()).sum::<Weight>();
	// we multiply by two as a rough upper bound of all the CPFP txs
	fee_rate * total_weight * 2
}

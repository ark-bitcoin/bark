use std::ops::{Deref, DerefMut};
use std::sync::Arc;

use anyhow::Context;
use ark::time::timestamp_secs;
use bdk_esplora::EsploraAsyncExt;
use bdk_wallet::chain::{ChainPosition, CheckPoint};
use bdk_wallet::Wallet as BdkWallet;
use bdk_wallet::coin_selection::DefaultCoinSelectionAlgorithm;
use bdk_wallet::{Balance, KeychainKind, LocalOutput, TxBuilder, TxOrdering};
use bitcoin::{
	Address, Amount, FeeRate, Network, OutPoint, Psbt, Sequence, Transaction, TxOut, Txid, Weight, bip32, psbt
};
use log::{debug, error, info, trace, warn};

use ark::vtxo::policy::signing::VtxoSigner;
use bitcoin_ext::{BlockHeight, BlockRef};
use bitcoin_ext::bdk::{CpfpInternalError, WalletExt};
use bitcoin_ext::cpfp::CpfpError;

use crate::chain::{ChainSource, ChainSourceClient};
use crate::exit::{ExitVtxo, ExitState};
use crate::onchain::{
	ChainSync, GetBalance, GetSpendingTx, GetWalletTx, LocalUtxo,
	MakeCpfp, MakeCpfpFees, PreparePsbt, SignPsbt, Utxo, WalletTxInfo,
};
use crate::persist::BarkPersister;
use crate::psbtext::PsbtInputExt;
use crate::Wallet;

const STOP_GAP: usize = 50;
const PARALLEL_REQS: usize = 4;
const GENESIS_HEIGHT: u32 = 0;

impl From<LocalOutput> for LocalUtxo {
	fn from(value: LocalOutput) -> Self {
		LocalUtxo {
			outpoint: value.outpoint,
			amount: value.txout.value,
			confirmation_height: value.chain_position.confirmation_height_upper_bound(),
		}
	}
}

/// Trait extension for TxBuilder to add exit outputs
///
/// When used, the resulting PSBT should be signed using
/// [crate::exit::Exit::sign_exit_claim_inputs].
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait TxBuilderExt: Send + Sync {
	async fn add_exit_claim_inputs(
		&mut self,
		wallet: &Wallet,
		exit_outputs: &[&ExitVtxo],
	) -> anyhow::Result<()>;
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl<Cs: Send + Sync> TxBuilderExt for TxBuilder<'_, Cs> {
	async fn add_exit_claim_inputs(
		&mut self,
		wallet: &Wallet,
		exit_outputs: &[&ExitVtxo],
	) -> anyhow::Result<()> {
		self.version(2);

		for input in exit_outputs {
			if !matches!(input.state(), ExitState::Claimable(..)) {
				bail!("VTXO exit is not spendable");
			}

			let vtxo = wallet.db.get_wallet_vtxo(input.id()).await?
				.context(format!("Unable to load VTXO for exit: {}", input.id()))?;
			let mut psbt_in = psbt::Input::default();
			psbt_in.set_exit_claim_input(&vtxo);
			psbt_in.witness_utxo = Some(TxOut {
				script_pubkey: vtxo.output_script_pubkey(),
				value: vtxo.amount(),
			});

			let clause = wallet.find_signable_clause(&vtxo).await
				.context("Cannot sign vtxo")?;

			let witness_weight = {
				let witness_size = clause.witness_size(&vtxo);
				Weight::from_witness_data_size(witness_size as u64)
			};

			self.add_foreign_utxo_with_sequence(
				vtxo.point(),
				psbt_in,
				witness_weight,
				clause.sequence().unwrap_or(Sequence::ZERO),
			).expect("error adding foreign utxo for claim input");
		}

		Ok(())
	}
}

impl <W: Deref<Target = BdkWallet>> GetBalance for W {
	fn get_balance(&self) -> Amount {
		self.deref().balance().total()
	}
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl SignPsbt for BdkWallet {
	async fn finish_psbt(&mut self, mut psbt: Psbt) -> anyhow::Result<Psbt> {
		#[allow(deprecated)]
		let opts = bdk_wallet::SignOptions {
			trust_witness_utxo: true,
			..Default::default()
		};

		let finalized = self.sign(&mut psbt, opts).context("signing error")?;
		assert!(finalized);
		let tx = psbt.clone().extract_tx()?;
		self.apply_unconfirmed_txs([(tx, timestamp_secs())]);
		Ok(psbt)
	}

}

impl <W: Deref<Target = BdkWallet>> GetWalletTx for W {
	/// Retrieves a transaction from the wallet
	///
	/// This method will only check the database and will not
	/// use a chain-source to find the transaction
	fn get_wallet_tx(&self, txid: Txid) -> Option<Arc<Transaction>> {
		self.deref().get_tx(txid).map(|tx| tx.tx_node.tx)
	}

	fn get_wallet_tx_confirmed_block(&self, txid: Txid) -> anyhow::Result<Option<BlockRef>> {
		match self.deref().get_tx(txid) {
			Some(tx) => match tx.chain_position {
				ChainPosition::Confirmed { anchor, .. } => Ok(Some(anchor.block_id.into())),
				ChainPosition::Unconfirmed { .. } => Ok(None),
			},
			None => Err(anyhow!("Tx {} does not exist in the wallet", txid)),
		}
	}
}

impl <W: DerefMut<Target = BdkWallet>> PreparePsbt for W {
	fn prepare_tx(
		&mut self,
		destinations: &[(Address, Amount)],
		fee_rate: FeeRate,
	) -> anyhow::Result<Psbt> {
		let mut b = self.deref_mut().build_tx();
		b.ordering(TxOrdering::Untouched);
		for (dest, amount) in destinations {
			b.add_recipient(dest.script_pubkey(), *amount);
		}
		b.fee_rate(fee_rate);
		b.finish().context("error building tx")
	}

	fn prepare_drain_tx(
		&mut self,
		destination: Address,
		fee_rate: FeeRate,
	) -> anyhow::Result<Psbt> {
		let mut b = self.deref_mut().build_tx();
		b.drain_to(destination.script_pubkey());
		b.fee_rate(fee_rate);
		b.drain_wallet();
		b.finish().context("error building tx")
	}
}

impl <W: Deref<Target = BdkWallet>> GetSpendingTx for W {
	fn get_spending_tx(&self, outpoint: OutPoint) -> Option<Arc<Transaction>> {
		for transaction in self.deref().transactions() {
			if transaction.tx_node.tx.input.iter().any(|i| i.previous_output == outpoint) {
				return Some(transaction.tx_node.tx);
			}
		}
		None
	}
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl MakeCpfp for BdkWallet {
	fn make_signed_p2a_cpfp(
		&mut self,
		tx: &Transaction,
		fees: MakeCpfpFees,
	) -> Result<Transaction, CpfpError> {
		 WalletExt::make_signed_p2a_cpfp(self, tx, fees)
			 .inspect_err(|e| error!("Error creating signed P2A CPFP: {}", e))
			 .map_err(|e| match e {
				 CpfpInternalError::General(s) => CpfpError::InternalError(s),
				 CpfpInternalError::Create(e) => CpfpError::CreateError(e.to_string()),
				 CpfpInternalError::Extract(e) => CpfpError::FinalizeError(e.to_string()),
				 CpfpInternalError::Fee() => CpfpError::InternalError(e.to_string()),
				 CpfpInternalError::FinalizeError(s) => CpfpError::FinalizeError(s),
				 CpfpInternalError::InsufficientConfirmedFunds(f) => {
					 CpfpError::InsufficientConfirmedFunds {
						 needed: f.needed, available: f.available,
					 }
				 },
				 CpfpInternalError::NoFeeAnchor(txid) => CpfpError::NoFeeAnchor(txid),
				 CpfpInternalError::Signer(e) => CpfpError::SigningError(e.to_string()),
			 })
	}

	async fn store_signed_p2a_cpfp(&mut self, tx: &Transaction) -> anyhow::Result<(), CpfpError> {
		self.apply_unconfirmed_txs([(tx.clone(), timestamp_secs())]);
		trace!("Unconfirmed txs: {:?}", self.unconfirmed_txids().collect::<Vec<_>>());
		Ok(())
	}
}

/// A basic wrapper around the bdk wallet to showcase
/// how to use bark with an external onchain wallet.
///
/// Note: BDK wallet already implements all the traits
/// to be used as an onboard and exit wallet, so that
/// wrapper only needs to proxy the methods.
pub struct OnchainWallet {
	pub inner: BdkWallet,
	db: Arc<dyn BarkPersister>,
}

impl Deref for OnchainWallet {
	type Target = BdkWallet;

	fn deref(&self) -> &Self::Target {
		&self.inner
	}
}

impl DerefMut for OnchainWallet {
	fn deref_mut(&mut self) -> &mut Self::Target {
		&mut self.inner
	}
}

impl OnchainWallet {
	pub async fn load_or_create(network: Network, seed: [u8; 64], db: Arc<dyn BarkPersister>) -> anyhow::Result<Self> {
		let xpriv = bip32::Xpriv::new_master(network, &seed).expect("valid seed");
		let desc = bdk_wallet::template::Bip86(xpriv, KeychainKind::External);

		let changeset = db.initialize_bdk_wallet().await.context("error reading bdk wallet state")?;
		let wallet_opt = bdk_wallet::Wallet::load()
			.descriptor(bdk_wallet::KeychainKind::External, Some(desc.clone()))
			.extract_keys()
			.check_network(network)
			.load_wallet_no_persist(changeset)?;

		let wallet = match wallet_opt {
			Some(wallet) => wallet,
			None => bdk_wallet::Wallet::create_single(desc)
				.network(network)
				.create_wallet_no_persist()?,
		};

		Ok(Self { inner: wallet, db })
	}
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl MakeCpfp for OnchainWallet {
	fn make_signed_p2a_cpfp(
		&mut self,
		tx: &Transaction,
		fees: MakeCpfpFees,
	) -> Result<Transaction, CpfpError> {
		MakeCpfp::make_signed_p2a_cpfp(&mut self.inner, tx, fees)
	}

	async fn store_signed_p2a_cpfp(&mut self, tx: &Transaction) -> anyhow::Result<(), CpfpError> {
		self.inner.store_signed_p2a_cpfp(tx).await?;
		self.persist().await
			.map_err(|e| CpfpError::StoreError(e.to_string()))
	}
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl SignPsbt for OnchainWallet {
	async fn finish_psbt(&mut self, psbt: Psbt) -> anyhow::Result<Psbt> {
		let psbt = self.inner.finish_psbt(psbt).await?;
		self.persist().await?;
		Ok(psbt)
	}
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl ChainSync for OnchainWallet {
	async fn sync(&mut self, chain: &ChainSource) -> anyhow::Result<()> {
		debug!("Starting wallet sync...");
		debug!("Starting balance: {}", self.inner.balance());
		trace!("Starting unconfirmed txs: {:?}", self.unconfirmed_txids().collect::<Vec<_>>());

		match chain.inner() {
			#[cfg(feature = "bitcoind-rpc")]
			ChainSourceClient::Bitcoind { sync, .. } => {
				let prev_tip = self.inner.latest_checkpoint();
				self.inner_sync_bitcoind(sync, prev_tip).await?;
			},
			ChainSourceClient::Esplora(client) => {
				debug!("Syncing with esplora...");
				let request = self.inner.start_sync_with_revealed_spks_at(timestamp_secs())
					.outpoints(self.list_unspent().iter().map(|o| o.outpoint).collect::<Vec<_>>())
					.txids(self.inner.transactions().map(|tx| tx.tx_node.txid).collect::<Vec<_>>());

				let update = client.sync(request, PARALLEL_REQS).await?;
				self.inner.apply_update(update)?;
				self.persist().await?;
				debug!("Finished syncing with esplora");
			},
		}

		debug!("Current balance: {}", self.inner.balance());
		trace!("Current unconfirmed txs: {:?}", self.unconfirmed_txids().collect::<Vec<_>>());
		self.rebroadcast_txs(chain, timestamp_secs()).await?;

		Ok(())
	}
}

impl OnchainWallet {
	pub fn balance(&self) -> Balance {
		self.inner.balance()
	}

	pub fn list_unspent(&self) -> Vec<LocalOutput> {
		self.inner.list_unspent().collect()
	}

	pub fn list_transactions(&self) -> Vec<Arc<Transaction>> {
		self.inner.transactions().map(|tx| tx.tx_node.tx).collect()
	}

	/// List every wallet transaction with fee, balance change, and confirmation.
	///
	/// Fees are `None` for txs whose foreign prevouts BDK has not indexed: see
	/// [`WalletTxInfo::onchain_fees`].
	pub fn list_transaction_infos(&self) -> anyhow::Result<Vec<WalletTxInfo>> {
		let mut out = Vec::new();
		for canon in self.inner.transactions() {
			let txid = canon.tx_node.txid;
			let tx = canon.tx_node.tx.clone();

			let confirmation = match canon.chain_position {
				ChainPosition::Confirmed { anchor, .. } => Some(anchor.block_id.into()),
				ChainPosition::Unconfirmed { .. } => None,
			};

			let (sent, received) = self.inner.sent_and_received(&tx);
			let balance_change = received.to_signed().context("received overflow")?
				- sent.to_signed().context("sent overflow")?;

			let onchain_fees = self.inner.calculate_fee(&tx).ok();

			out.push(WalletTxInfo {
				txid,
				tx,
				onchain_fees,
				balance_change,
				confirmation,
			});
		}
		Ok(out)
	}

	pub async fn address(&mut self) -> anyhow::Result<Address> {
		let ret = self.inner.reveal_next_address(bdk_wallet::KeychainKind::External).address;
		self.persist().await?;
		Ok(ret)
	}

	pub fn utxos(&self) -> Vec<Utxo> {
		self.list_unspent().into_iter().map(|o| Utxo::Local(o.into())).collect()
	}

	pub async fn send(&mut self, chain: &ChainSource, dest: Address, amount: Amount, fee_rate: FeeRate
	)	-> anyhow::Result<Txid> {
		let psbt = self.prepare_tx(&[(dest, amount)], fee_rate)?;
		let tx = self.finish_psbt(psbt).await?.extract_tx()?;
		chain.broadcast_tx(&tx).await?;
		Ok(tx.compute_txid())
	}

	pub async fn send_many(
		&mut self,
		chain: &ChainSource,
		destinations: &[(Address, Amount)],
		fee_rate: FeeRate,
	) -> anyhow::Result<Txid> {
		let pbst = self.prepare_tx(destinations, fee_rate)?;
		let tx = self.finish_psbt(pbst).await?.extract_tx()?;
		chain.broadcast_tx(&tx).await?;
		Ok(tx.compute_txid())
	}


	pub async fn drain(
		&mut self,
		chain: &ChainSource,
		destination: Address,
		fee_rate: FeeRate,
	) -> anyhow::Result<Txid> {
		let psbt = self.prepare_drain_tx(destination, fee_rate)?;
		let tx = self.finish_psbt(psbt).await?.extract_tx()?;
		chain.broadcast_tx(&tx).await?;
		Ok(tx.compute_txid())
	}

	pub fn build_tx(&mut self) -> TxBuilder<'_, DefaultCoinSelectionAlgorithm> {
		self.inner.build_tx()
	}

	#[cfg(feature = "bitcoind-rpc")]
	async fn inner_sync_bitcoind(
		&mut self,
		bitcoind_sync: &bitcoin_ext::rpc::BitcoinRpcClient,
		prev_tip: CheckPoint,
	) -> anyhow::Result<()> {
		debug!("Syncing with bitcoind, starting at block height {}...", prev_tip.height());
		// `bdk_bitcoind_rpc::Emitter` is sync-only upstream. Run it on a
		// blocking thread and stream blocks back over a channel so we can
		// persist progress incrementally and yield to the runtime.
		// NB We pass start_height=0 so the Emitter never skips blocks.
		// Using prev_tip.height() would cause the Emitter to jump from the
		// agreement point directly to prev_tip on the new chain after a deep
		// reorg, producing a gap that BDK cannot merge.
		let sync_rpc = bitcoind_sync.clone();
		let prev_tip_clone = prev_tip.clone();
		// Materialize the unconfirmed-tx iterator before crossing the thread
		// boundary; bdk's iterator borrows wallet state and is not Send.
		let unconfirmed: Vec<_> = self.unconfirmed_txs().collect();
		let (block_tx, mut block_rx) =
			tokio::sync::mpsc::channel::<bdk_bitcoind_rpc::BlockEvent<bitcoin::Block>>(8);
		let (mempool_tx, mempool_rx) =
			tokio::sync::oneshot::channel::<bdk_bitcoind_rpc::MempoolEvent>();
		let emitter_handle = tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
			let mut emitter = bdk_bitcoind_rpc::Emitter::new(
				&sync_rpc, prev_tip_clone, 0, unconfirmed,
			);
			while let Some(em) = emitter.next_block()? {
				if block_tx.blocking_send(em).is_err() {
					return Ok(());
				}
			}
			drop(block_tx);
			let _ = mempool_tx.send(emitter.mempool()?);
			Ok(())
		});

		let mut count = 0;
		while let Some(em) = block_rx.recv().await {
			self.inner.apply_block_connected_to(
				&em.block, em.block_height(), em.connected_to(),
			)?;
			count += 1;

			if count % 10_000 == 0 {
				self.persist().await?;
				info!("Synced until block height {}", em.block_height());
			}
		}
		emitter_handle.await.context("wallet sync blocking task panicked")??;

		if let Ok(mempool) = mempool_rx.await {
			self.inner.apply_evicted_txs(mempool.evicted);
			self.inner.apply_unconfirmed_txs(mempool.update);
		}
		self.persist().await?;
		debug!("Finished syncing with bitcoind");

		Ok(())
	}

	async fn rebroadcast_txs(&mut self, chain: &ChainSource, sync_start: u64) -> anyhow::Result<Amount> {
		let balance = self.inner.balance();

		// Ultimately, let's try to rebroadcast all our unconfirmed txs.
		let transactions = self.inner.transactions().filter(|tx| {
			if let ChainPosition::Unconfirmed { last_seen, .. } = tx.chain_position {
				match last_seen {
					Some(last_seen) => last_seen < sync_start,
					None => true,
				}
			} else {
				false
			}
		}).collect::<Vec<_>>();

		for tx in transactions {
			if let Err(e) = chain.broadcast_tx(&tx.tx_node.tx).await {
				warn!("Error broadcasting tx {}: {}", tx.tx_node.txid, e);
			}
		}

		Ok(balance.total())
	}

	pub async fn initial_wallet_scan(
		&mut self,
		chain: &ChainSource,
		start_height: Option<BlockHeight>,
	) -> anyhow::Result<Amount> {
		info!("Starting initial wallet sync...");
		debug!("Starting balance: {}", self.inner.balance());

		match chain.inner() {
			#[cfg(feature = "bitcoind-rpc")]
			ChainSourceClient::Bitcoind { rpc, sync } => {
				use bitcoind_async_client::traits::Reader;
				// Make sure we include the given start_height in the scan
				let height = start_height.unwrap_or(GENESIS_HEIGHT).saturating_sub(1);
				let block_hash = rpc.get_block_hash(height as u64).await?;
				self.inner.set_checkpoint(height, block_hash);
				self.inner_sync_bitcoind(sync, self.inner.latest_checkpoint()).await?;
			},
			// Esplora can't do a full scan from a given block height, so we can ignore start_height
			ChainSourceClient::Esplora(client) => {
				debug!("Starting full scan with esplora...");
				let request = self.inner.start_full_scan_at(timestamp_secs());
				let update = client.full_scan(request, STOP_GAP, PARALLEL_REQS).await?;
				self.inner.apply_update(update)?;
				self.persist().await?;
				debug!("Finished scanning with esplora");
			},
		}

		debug!("Current balance: {}", self.inner.balance());
		self.rebroadcast_txs(chain, timestamp_secs()).await
	}


	async fn persist(&mut self) -> anyhow::Result<()> {
		if let Some(stage) = self.inner.staged() {
			self.db.store_bdk_wallet_changeset(&*stage).await?;
			let _ = self.inner.take_staged();
		}
		Ok(())
	}
}

use std::collections::HashSet;
use std::ops::{Deref, DerefMut};
use std::sync::Arc;

use anyhow::Context;
use bdk_esplora::EsploraAsyncExt;
use bdk_wallet::chain::{Anchor, ChainPosition, CheckPoint, ConfirmationBlockTime, Indexer, TxUpdate};
use bdk_wallet::Wallet as BdkWallet;
use bdk_wallet::coin_selection::DefaultCoinSelectionAlgorithm;
use bdk_wallet::signer::SignerOrdering;
use bdk_wallet::{Balance, KeychainKind, LoadError, LocalOutput, TxBuilder, TxOrdering, Update};
use bitcoin::{
	Address, Amount, FeeRate, Network, Psbt, Script, Sequence, Transaction, TxOut,
	Txid, Weight, bip32, psbt,
};
use log::{debug, error, info, trace, warn};

use ark::vtxo::policy::signing::VtxoSigner;
use bitcoin_ext::{BlockHeight, DEEPLY_CONFIRMED, TransactionExt};
use bitcoin_ext::bdk::{CpfpInternalError, WalletExt};
use bitcoin_ext::cpfp::CpfpError;

use crate::Wallet;
use crate::chain::{ChainSource, ChainSourceClient};
use crate::exit::{ExitVtxo, ExitState};
use crate::onchain::{
	CpfpWalkEstimate, FundingShortfall, LocalUtxo, MakeCpfpFees, Utxo, OnchainWalletTrait,
	WalletTxInfo,
};
use crate::persist::BarkPersister;
use crate::psbtext::PsbtInputExt;

const STOP_GAP: usize = 50;
const PARALLEL_REQS: usize = 4;
const GENESIS_HEIGHT: u32 = 0;
/// Minimum age (by `last_seen`) a locally-unconfirmed tx must reach before a
/// sync is allowed to evict it for being absent from the node's mempool.
///
/// A tx is marked seen (`apply_unconfirmed_txs`) as soon as it's signed, not
/// once it's actually reached the node: e.g. a board's funding tx is applied
/// locally in `finish_psbt`, then only broadcast after a cosign round-trip
/// with the Ark server. Without this grace period, a sync landing in that gap
/// would see the tx as absent from the node's mempool and evict it, handing
/// its inputs back to the next coin selection while the "evicted" tx is still
/// in flight and about to land in the mempool anyway -- a self-inflicted
/// double-spend. A tx that's genuinely gone just gets evicted one sync later.
const ONCHAIN_EVICTION_GRACE_SECS: u64 = 30;

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

			// Claiming an exit needs the full vtxo: the PSBT input embeds the
			// serialized full bytes (including the genesis chain) so the
			// claim signer can reconstruct the spend.
			let vtxo = wallet.inner.db.get_full_vtxo(input.id()).await?
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

/// Map the internal BDK CPFP error onto the public [CpfpError] surface.
fn cpfp_internal_to_error(e: CpfpInternalError) -> CpfpError {
	match e {
		CpfpInternalError::General(s) => CpfpError::InternalError(s),
		CpfpInternalError::Create(e) => CpfpError::CreateError(e.to_string()),
		CpfpInternalError::Extract(e) => CpfpError::FinalizeError(e.to_string()),
		CpfpInternalError::Fee() => CpfpError::InternalError(CpfpInternalError::Fee().to_string()),
		CpfpInternalError::FinalizeError(s) => CpfpError::FinalizeError(s),
		CpfpInternalError::InsufficientConfirmedFunds(f) => {
			CpfpError::InsufficientConfirmedFunds {
				needed: f.needed, available: f.available,
			}
		},
		CpfpInternalError::NoFeeAnchor(txid) => CpfpError::NoFeeAnchor(txid),
		CpfpInternalError::Signer(e) => CpfpError::SigningError(e.to_string()),
	}
}

/// A throwaway, in-memory replica of a wallet, used only for fee estimation.
///
/// The broadcast-walk estimate inserts CPFP children as *confirmed*, which BDK can't undo. Running
/// it on a replica keeps that mutation off the live wallet.
pub struct EstimationWallet {
	inner: BdkWallet,
}

impl EstimationWallet {
	/// Build a replica from a snapshot of `wallet`'s live components (chain, tx graph, keychain
	/// index and locked outpoints — staged changes included), reusing its signers so the replica
	/// builds and signs transactions exactly like the original would.
	pub fn new(wallet: &BdkWallet) -> Result<EstimationWallet, LoadError> {
		let mut changeset = bdk_wallet::ChangeSet {
			network: Some(wallet.network()),
			local_chain: wallet.local_chain().initial_changeset(),
			tx_graph: wallet.tx_graph().initial_changeset(),
			indexer: wallet.spk_index().initial_changeset(),
			..Default::default()
		};
		for (keychain, descriptor) in wallet.keychains() {
			match keychain {
				KeychainKind::External => changeset.descriptor = Some(descriptor.clone()),
				KeychainKind::Internal => changeset.change_descriptor = Some(descriptor.clone()),
			}
		}
		changeset.locked_outpoints.outpoints = wallet.list_locked_outpoints()
			.map(|outpoint| (outpoint, true))
			.collect();

		let mut inner = BdkWallet::load()
			.check_network(wallet.network())
			.load_wallet_no_persist(changeset)?
			.expect("changeset carries a descriptor");

		// The changeset only carries public descriptors, so hand the original's signers over.
		for keychain in [KeychainKind::External, KeychainKind::Internal] {
			for signer in wallet.get_signers(keychain).signers() {
				inner.add_signer(keychain, SignerOrdering::default(), Arc::clone(signer));
			}
		}

		Ok(EstimationWallet { inner })
	}

	/// Insert a CPFP child into the replica as confirmed, anchored at its tip, so the next child
	/// can spend its change.
	fn apply_cpfp_child(&mut self, child: &Transaction) {
		let mut tx_update = TxUpdate::default();
		tx_update.txs.push(Arc::new(child.clone()));

		tx_update.anchors.insert((
			ConfirmationBlockTime {
				block_id: self.inner.latest_checkpoint().block_id(),
				confirmation_time: 0,
			},
			child.compute_txid(),
		));

		self.inner.apply_update(Update { tx_update, ..Default::default() })
			.expect("anchor block is the replica's own tip");
	}

	/// Build one CPFP child per parent, funding each from confirmed coins and recycling each
	/// child's change into the next (the serial order the packages really confirm in). Each child
	/// is returned with the exact package fee it commits, which an RBF minimum can push above
	/// rate × weight. Stops early when confirmed funds run out, reporting the shortfall.
	pub fn estimate_p2a_cpfp_walk(
		&mut self,
		parents: &[(Transaction, MakeCpfpFees)],
	) -> Result<CpfpWalkEstimate, CpfpInternalError> {
		let mut children = Vec::with_capacity(parents.len());
		for (parent, fees) in parents {
			let child = match self.inner.make_signed_p2a_cpfp(parent, *fees) {
				Ok(child) => child,
				Err(CpfpInternalError::InsufficientConfirmedFunds(e)) => {
					return Ok(CpfpWalkEstimate {
						children,
						shortfall: Some(FundingShortfall {
							needed: e.needed,
							available: e.available,
						}),
					});
				},
				Err(e) => return Err(e),
			};

			let (_, anchor_txout) = parent.fee_anchor()
				.expect("make_signed_p2a_cpfp succeeded on this parent");
			// The replica wallet knows all inputs but the anchor
			let funding_value = anchor_txout.value + child.input.iter()
				.filter_map(|input| {
					self.inner.tx_graph().get_txout(input.previous_output)
						.map(|txout| txout.value)
				})
				.sum::<Amount>();
			// The parent is zero-fee, so the child pays the whole package fee: everything its
			// inputs bring in beyond its own outputs.
			let fee = funding_value.checked_sub(child.output_value())
				.unwrap_or_default();

			self.apply_cpfp_child(&child);

			children.push((child, fee));
		}

		Ok(CpfpWalkEstimate { children, shortfall: None })
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
impl OnchainWalletTrait for OnchainWallet {
	async fn balance(&self) -> Amount {
		self.inner.balance().total()
	}

	async fn address(&mut self) -> anyhow::Result<Address> {
		let ret = self.inner.reveal_next_address(bdk_wallet::KeychainKind::External).address;
		self.persist().await?;
		Ok(ret)
	}

	async fn sync(&mut self, chain: &ChainSource) -> anyhow::Result<()> {
		OnchainWallet::sync(self, chain).await
	}

	async fn is_mine(&self, spk: &Script) -> anyhow::Result<bool> {
		Ok(self.inner.is_mine(spk.to_owned()))
	}

	async fn register_tx(&mut self, tx: &Transaction) -> anyhow::Result<()> {
		self.inner.apply_unconfirmed_txs([(tx.clone(), bark_runtime::timestamp_secs())]);
		self.persist().await
	}

	async fn prepare_tx(
		&mut self,
		destinations: &[(Address, Amount)],
		fee_rate: FeeRate,
	) -> anyhow::Result<Psbt> {
		let mut b = self.inner.build_tx();
		b.ordering(TxOrdering::Untouched);
		for (dest, amount) in destinations {
			b.add_recipient(dest.script_pubkey(), *amount);
		}
		b.fee_rate(fee_rate);
		b.finish().context("error building tx")
	}

	async fn prepare_drain_tx(
		&mut self,
		destination: Address,
		fee_rate: FeeRate,
	) -> anyhow::Result<Psbt> {
		let mut b = self.inner.build_tx();
		b.drain_to(destination.script_pubkey());
		b.fee_rate(fee_rate);
		b.drain_wallet();
		b.finish().context("error building tx")
	}

	async fn finish_psbt(&mut self, mut psbt: Psbt) -> anyhow::Result<Psbt> {
		#[allow(deprecated)]
		let opts = bdk_wallet::SignOptions {
			trust_witness_utxo: true,
			..Default::default()
		};
		let finalized = self.inner.sign(&mut psbt, opts).context("signing error")?;
		ensure!(finalized, "failed to succesfully sign the tx");
		let tx = psbt.clone().extract_tx()?;
		self.inner.apply_unconfirmed_txs([(tx, bark_runtime::timestamp_secs())]);
		self.persist().await?;
		Ok(psbt)
	}

	async fn make_signed_p2a_cpfp(
		&mut self,
		tx: &Transaction,
		fees: MakeCpfpFees,
	) -> Result<Transaction, CpfpError> {
		WalletExt::make_signed_p2a_cpfp(&mut self.inner, tx, fees)
			.inspect_err(|e| error!("Error creating signed P2A CPFP: {}", e))
			.map_err(cpfp_internal_to_error)
	}

	fn estimate_p2a_cpfp_walk(
		&self,
		parents: &[(Transaction, MakeCpfpFees)],
	) -> Result<CpfpWalkEstimate, CpfpError> {
		EstimationWallet::new(&self.inner)
			.map_err(|e| CpfpError::InternalError(format!("failed to build estimation wallet: {}", e)))
			.and_then(|mut w| w.estimate_p2a_cpfp_walk(parents).map_err(cpfp_internal_to_error))
			.inspect_err(|e| error!("Error estimating P2A CPFP walk: {}", e))
	}

	async fn store_signed_p2a_cpfp(&mut self, tx: &Transaction) -> anyhow::Result<(), CpfpError> {
		self.inner.apply_unconfirmed_txs([(tx.clone(), bark_runtime::timestamp_secs())]);
		trace!("Unconfirmed txs: {:?}", self.unconfirmed_txids().collect::<Vec<_>>());
		self.persist().await
			.map_err(|e| CpfpError::StoreError(e.to_string()))
	}
}

impl OnchainWallet {
	pub async fn sync(&mut self, chain: &ChainSource) -> anyhow::Result<()> {
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

				// Don't sync the entire transaction history of the wallet. We can safely filter out
				// anything deeply confirmed.
				let min_height = self.inner.latest_checkpoint()
					.height()
					.checked_sub(DEEPLY_CONFIRMED)
					.unwrap_or(0);

				let request = self.inner.start_sync_with_revealed_spks_at(bark_runtime::timestamp_secs())
					.outpoints(self.list_unspent().iter().map(|o| o.outpoint))
					.txids(self.inner.transactions().filter_map(|tx| {
						let fresh = match tx.chain_position {
							ChainPosition::Unconfirmed { .. } => true,
							ChainPosition::Confirmed { anchor, .. } => {
								anchor.anchor_block().height >= min_height
							},
						};
						if fresh {
							Some(tx.tx_node.txid)
						} else {
							None
						}
					}));

				let update = client.sync(request, PARALLEL_REQS).await?;
				self.inner.apply_update(update)?;
				self.persist().await?;
				debug!("Finished syncing with esplora");
			},
		}

		debug!("Current balance: {}", self.inner.balance());
		trace!("Current unconfirmed txs: {:?}", self.unconfirmed_txids().collect::<Vec<_>>());
		self.rebroadcast_txs(chain, bark_runtime::timestamp_secs()).await?;

		Ok(())
	}

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

			// A P2A fee anchor is anyone-can-spend (BIP-431), so its spend
			// carries no signature: both witness and script_sig are empty.
			let is_cpfp = tx.input.iter()
				.any(|i| i.witness.is_empty() && i.script_sig.is_empty());

			out.push(WalletTxInfo {
				txid,
				tx,
				onchain_fees,
				balance_change,
				confirmation,
				is_cpfp,
			});
		}
		Ok(out)
	}

	pub fn utxos(&self) -> Vec<Utxo> {
		self.list_unspent().into_iter().map(|o| Utxo::Local(o.into())).collect()
	}

	pub async fn send(&mut self, chain: &ChainSource, dest: Address, amount: Amount, fee_rate: FeeRate
	)	-> anyhow::Result<Txid> {
		let psbt = self.prepare_tx(&[(dest, amount)], fee_rate).await?;
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
		let pbst = self.prepare_tx(destinations, fee_rate).await?;
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
		let psbt = self.prepare_drain_tx(destination, fee_rate).await?;
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
			let now = bark_runtime::timestamp_secs();
			let recently_seen: HashSet<Txid> = self.inner.transactions()
				.filter_map(|tx| match tx.chain_position {
					ChainPosition::Unconfirmed { last_seen: Some(seen), .. }
						if now.saturating_sub(seen) < ONCHAIN_EVICTION_GRACE_SECS => {
						Some(tx.tx_node.txid)
					},
					_ => None,
				})
				.collect();
			let evicted = mempool.evicted.into_iter().filter(|(txid, _)| {
				if recently_seen.contains(txid) {
					debug!("Not evicting recently-seen tx {} still within grace period", txid);
					false
				} else {
					true
				}
			});
			self.inner.apply_evicted_txs(evicted);
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
				let request = self.inner.start_full_scan_at(bark_runtime::timestamp_secs());
				let update = client.full_scan(request, STOP_GAP, PARALLEL_REQS).await?;
				self.inner.apply_update(update)?;
				self.persist().await?;
				debug!("Finished scanning with esplora");
			},
		}

		debug!("Current balance: {}", self.inner.balance());
		self.rebroadcast_txs(chain, bark_runtime::timestamp_secs()).await
	}


	async fn persist(&mut self) -> anyhow::Result<()> {
		if let Some(stage) = self.inner.staged() {
			self.db.store_bdk_wallet_changeset(&*stage).await?;
			let _ = self.inner.take_staged();
		}
		Ok(())
	}
}

#[cfg(test)]
mod test {
	use super::*;

	use std::collections::HashSet;

	use bdk_wallet::chain::BlockId;
	use bdk_wallet::test_utils::{get_test_wpkh, insert_checkpoint, receive_output_in_latest_block};
	use bitcoin::{BlockHash, OutPoint};
	use bitcoin::hashes::Hash;

	/// A wallet with one confirmed UTXO per given amount.
	fn funded_wallet(amounts: &[Amount]) -> BdkWallet {
		let mut wallet = BdkWallet::create_single(get_test_wpkh())
			.network(Network::Regtest)
			.create_wallet_no_persist()
			.unwrap();
		insert_checkpoint(&mut wallet, BlockId { height: 1_000, hash: BlockHash::all_zeros() });
		for amount in amounts {
			receive_output_in_latest_block(&mut wallet, *amount);
		}
		wallet
	}

	/// A zero-fee v3 parent carrying a P2A fee anchor; `tag` makes its txid unique.
	fn p2a_parent(tag: u8) -> Transaction {
		Transaction {
			version: bitcoin::transaction::Version(3),
			lock_time: bitcoin::absolute::LockTime::ZERO,
			input: vec![bitcoin::TxIn {
				previous_output: OutPoint::new(Txid::from_byte_array([tag; 32]), 0),
				..Default::default()
			}],
			output: vec![bitcoin_ext::fee::fee_anchor()],
		}
	}

	#[test]
	fn estimation_wallet_replicates_and_isolates() {
		let wallet = funded_wallet(&[Amount::from_sat(1_000), Amount::from_sat(1_001)]);
		let mut replica = EstimationWallet::new(&wallet).unwrap();

		assert_eq!(wallet.balance(), replica.inner.balance());
		assert_eq!(
			wallet.list_unspent().map(|u| u.outpoint).collect::<Vec<_>>(),
			replica.inner.list_unspent().map(|u| u.outpoint).collect::<Vec<_>>(),
		);
		assert_eq!(
			wallet.next_derivation_index(KeychainKind::External),
			replica.inner.next_derivation_index(KeychainKind::External),
		);

		// The replica must sign with the original's keys, and mutating it must not leak into
		// the original wallet.
		let parent = p2a_parent(1);
		let fees = MakeCpfpFees::Effective(FeeRate::from_sat_per_vb(1).unwrap());
		let child = replica.inner.make_signed_p2a_cpfp(&parent, fees).unwrap();
		assert_eq!(wallet.balance().confirmed, Amount::from_sat(2_001));
		assert!(wallet.get_tx(child.compute_txid()).is_none());
	}

	/// With a single-coin wallet, every CPFP child after the first can only be funded by the
	/// previous child's change: the walk must model that serial recycling.
	#[test]
	fn cpfp_walk_recycles_change_serially() {
		let wallet = funded_wallet(&[Amount::from_sat(50_000)]);
		let fees = MakeCpfpFees::Effective(FeeRate::from_sat_per_vb(10).unwrap());
		let parents = (1..=3).map(|tag| (p2a_parent(tag), fees)).collect::<Vec<_>>();

		let walk = EstimationWallet::new(&wallet).unwrap().estimate_p2a_cpfp_walk(&parents).unwrap();
		assert!(walk.shortfall.is_none());
		assert_eq!(walk.children.len(), 3);

		for (i, (child, fee)) in walk.children.iter().enumerate() {
			let anchor_point = parents[i].0.fee_anchor().unwrap().0;
			assert!(child.input.iter().any(|input| input.previous_output == anchor_point));
			assert_eq!(child.input.len(), 2, "anchor spend plus a single funding input");
			assert_eq!(child.output.len(), 1, "drain output only");
			// The parent is zero-fee, so the effective-rate child pays exactly the package fee.
			assert_eq!(*fee, fees.effective() * (parents[i].0.weight() + child.weight()));
			if i > 0 {
				let (prev_child, _) = &walk.children[i - 1];
				let prev_change = OutPoint::new(prev_child.compute_txid(), 0);
				assert!(
					child.input.iter().any(|input| input.previous_output == prev_change),
					"child {} must be funded by the previous child's change", i,
				);
				// Funded solely by the previous change, so the reported fee must be exactly
				// the value that change lost.
				assert_eq!(*fee, prev_child.output[0].value - child.output[0].value);
			}
		}

		// The walk runs against a replica; the wallet itself stays untouched.
		assert_eq!(wallet.balance().confirmed, Amount::from_sat(50_000));
		assert!(wallet.get_tx(walk.children[0].0.compute_txid()).is_none());
	}

	/// Whatever coins each child selects, no coin may fund two children: earlier estimation
	/// re-ran selection against the same unchanged wallet, double-counting the same UTXO.
	#[test]
	fn cpfp_walk_never_double_spends_across_children() {
		// NB identical amounts would produce identical funding txids and collapse into one UTXO.
		// No coin covers a ~1150-sat package fee plus non-dust change alone, so children have to
		// combine coins.
		let amounts = (0..5).map(|i| Amount::from_sat(1_000 + i)).collect::<Vec<_>>();
		let wallet = funded_wallet(&amounts);
		let original_coins = wallet.list_unspent()
			.map(|u| u.outpoint)
			.collect::<HashSet<_>>();
		let fees = MakeCpfpFees::Effective(FeeRate::from_sat_per_vb(4).unwrap());
		let parents = (1..=2).map(|tag| (p2a_parent(tag), fees)).collect::<Vec<_>>();

		let walk = EstimationWallet::new(&wallet).unwrap().estimate_p2a_cpfp_walk(&parents).unwrap();
		assert!(walk.shortfall.is_none());
		assert_eq!(walk.children.len(), 2);

		let change_outputs = walk.children.iter()
			.map(|(child, _)| OutPoint::new(child.compute_txid(), 0))
			.collect::<HashSet<_>>();
		let mut spent = HashSet::new();
		for ((child, _), (parent, _)) in walk.children.iter().zip(&parents) {
			let anchor_point = parent.fee_anchor().unwrap().0;
			for input in &child.input {
				if input.previous_output == anchor_point {
					continue;
				}
				let coin = input.previous_output;
				assert!(
					original_coins.contains(&coin) || change_outputs.contains(&coin),
					"funding input {} must be a wallet coin or an earlier child's change", coin,
				);
				assert!(spent.insert(coin), "coin {} funds two children", coin);
			}
		}
	}

	#[test]
	fn cpfp_walk_reports_shortfall() {
		// 3000 sats fund the first ~2200-sat package but its change can't fund the second.
		let wallet = funded_wallet(&[Amount::from_sat(3_000)]);
		let fees = MakeCpfpFees::Effective(FeeRate::from_sat_per_vb(10).unwrap());
		let parents = (1..=2).map(|tag| (p2a_parent(tag), fees)).collect::<Vec<_>>();

		let walk = EstimationWallet::new(&wallet).unwrap().estimate_p2a_cpfp_walk(&parents).unwrap();
		assert_eq!(walk.children.len(), 1);
		let (first_child, first_fee) = &walk.children[0];
		// The single coin funds the first child entirely, so wallet value splits exactly into
		// the reported fee and the change.
		assert_eq!(*first_fee + first_child.output[0].value, Amount::from_sat(3_000));
		let shortfall = walk.shortfall.expect("second bump must exceed the remaining change");
		assert!(shortfall.needed > shortfall.available);
		assert_eq!(shortfall.available, first_child.output[0].value);
	}
}

use std::collections::HashSet;
use std::ops::{Deref, DerefMut};
use std::sync::Arc;

use anyhow::Context;
use bdk_esplora::EsploraAsyncExt;
use bdk_wallet::chain::{Anchor, ChainPosition, CheckPoint, ConfirmationBlockTime, Indexer, TxUpdate};
use bdk_wallet::Wallet as BdkWallet;
use bdk_wallet::coin_selection::DefaultCoinSelectionAlgorithm;
use bdk_wallet::signer::SignersContainer;
use bdk_wallet::{Balance, KeychainKind, LoadError, LocalOutput, TxBuilder, TxOrdering, Update};
use bitcoin::{
	Address, Amount, FeeRate, Network, Psbt, Script, Sequence, Transaction, TxOut,
	Txid, Weight, bip32, psbt,
};
use log::{debug, error, info, trace, warn};

use ark::vtxo::policy::signing::VtxoSigner;
use bitcoin_ext::{BlockDelta, BlockHeight, DEEPLY_CONFIRMED, TransactionExt};
use bitcoin_ext::bdk::{CpfpInternalError, WalletExt, KEYCHAIN};
use bitcoin_ext::cpfp::CpfpError;

use crate::Wallet;
use crate::chain::{ChainSource, ChainSourceClient};
use crate::exit::{ExitVtxo, ExitState};
use crate::onchain::{
	LocalUtxo, MakeCpfpFees, Utxo, OnchainWalletTrait,
	WalletTxInfo,
};
use crate::persist::BarkPersister;
use crate::psbtext::PsbtInputExt;

const STOP_GAP: usize = 50;
const PARALLEL_REQS: usize = 4;
const GENESIS_HEIGHT: BlockHeight = BlockHeight::ZERO;
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
			confirmation_height: value.chain_position.confirmation_height_upper_bound()
				.map(BlockHeight::new),
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

/// A throwaway, in-memory replica of a wallet, used only for presigning CPFP children.
///
/// The broadcast walk inserts CPFP children into the wallet, which BDK can't undo. Running it on
/// a replica keeps that mutation off the live wallet.
pub struct WalletReplica {
	inner: BdkWallet,
}

impl WalletReplica {
	/// Build a replica from a snapshot of `wallet`'s live components (chain, tx graph, keychain
	/// index and locked outpoints — staged changes included), so the replica builds transactions
	/// exactly like the original would. It holds no keys.
	pub fn new(wallet: &BdkWallet) -> Result<WalletReplica, LoadError> {
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

		let inner = BdkWallet::load()
			.check_network(wallet.network())
			.load_wallet_no_persist(changeset)?
			.expect("changeset carries a descriptor");

		Ok(WalletReplica { inner })
	}

	/// Mark the given wave's children as confirmed at the replica tip, so the next wave can
	/// spend their change.
	fn confirm_cpfp_children(&mut self, txids: impl IntoIterator<Item = Txid>) {
		let mut tx_update = TxUpdate::default();
		let block = ConfirmationBlockTime {
			block_id: self.inner.latest_checkpoint().block_id(),
			confirmation_time: 0,
		};
		for txid in txids {
			tx_update.anchors.insert((block, txid));
		}
		self.inner.apply_update(Update { tx_update, ..Default::default() })
			.expect("anchor block is the replica's own tip");
	}

	/// The package fee a signed child commits: everything its inputs bring in beyond its own
	/// outputs (the parent is zero-fee).
	fn package_fee(&self, parent: &Transaction, child: &Transaction) -> Amount {
		let (_, anchor_txout) = parent.fee_anchor()
			.expect("make_signed_p2a_cpfp succeeded on this parent");
		// The replica wallet knows all inputs but the anchor.
		let funding_value = anchor_txout.value + child.input.iter()
			.filter_map(|input| {
				self.inner.tx_graph().get_txout(input.previous_output)
					.map(|txout| txout.value)
			})
			.sum::<Amount>();
		funding_value.checked_sub(child.output_value()).unwrap_or_default()
	}

	/// Sign a CPFP child per parent, grouped into broadcast waves; see
	/// [OnchainWalletTrait::presign_p2a_cpfp_walk] for the wave semantics.
	///
	/// A wave models one block: children signed within it spend only coins confirmed before it
	/// and are inserted unconfirmed, so BDK's own coin selection keeps concurrent chains funded
	/// disjointly. At wave end the children confirm and the next wave begins. Stops when no
	/// chain can advance (funds ran out), returning a leading run per exit. An RBF minimum can
	/// push a child's fee above rate × weight.
	///
	/// `relayed` transactions confirm with the first wave, which may sign nothing. Children are
	/// signed with `signers`.
	pub fn sign_p2a_cpfp_walk(
		&mut self,
		exits: &[Vec<(Transaction, MakeCpfpFees)>],
		relayed: &[Txid],
		signers: &SignersContainer,
	) -> Result<Vec<Vec<(Transaction, Amount)>>, CpfpInternalError> {
		let all_parents = exits.iter().flatten()
			.map(|(parent, _)| parent.compute_txid())
			.chain(relayed.iter().copied())
			.collect::<HashSet<_>>();
		let mut confirmed = HashSet::new();
		let mut cursors = vec![0usize; exits.len()];
		let mut waves = Vec::new();
		loop {
			let mut wave = Vec::new();
			for (parents, cursor) in exits.iter().zip(cursors.iter_mut()) {
				let Some((parent, fees)) = parents.get(*cursor) else {
					continue;
				};
				// A package can only broadcast once every in-set parent its exit tx spends has
				// confirmed, which includes this exit's own previous package.
				let gated = parent.input.iter().any(|input| {
					let prev = input.previous_output.txid;
					all_parents.contains(&prev) && !confirmed.contains(&prev)
				});
				if gated {
					continue;
				}
				let child = match self.inner.make_signed_p2a_cpfp(parent, *fees, signers) {
					Ok(child) => child,
					// Skip for now; the next wave's confirmed change may cover it.
					Err(CpfpInternalError::InsufficientConfirmedFunds(_)) => continue,
					Err(e) => return Err(e),
				};
				let fee = self.package_fee(parent, &child);
				self.inner.apply_unconfirmed_txs([(child.clone(), 0)]);
				wave.push((parent.compute_txid(), child, fee));
				*cursor += 1;
			}
			let first_wave = waves.is_empty();
			if wave.is_empty() && !(first_wave && !relayed.is_empty()) {
				// No chain advanced: another wave can't change anything.
				break;
			}
			self.confirm_cpfp_children(wave.iter().map(|(_, child, _)| child.compute_txid()));
			confirmed.extend(wave.iter().map(|(parent_txid, _, _)| *parent_txid));
			if first_wave {
				confirmed.extend(relayed.iter().copied());
			}
			waves.push(wave.into_iter().map(|(_, child, fee)| (child, fee)).collect());
		}

		if waves.iter().all(Vec::is_empty) {
			waves.clear();
		}
		Ok(waves)
	}

	/// The highest drain-keychain index this replica revealed, covering the change addresses of
	/// the children it signed, or `None` if it revealed none.
	///
	/// Presigning reveals the real wallet up to this index; that is a no-op when the walk signed
	/// nothing, since the replica starts from the real wallet's own index.
	fn revealed_change_index(&self) -> Option<u32> {
		self.inner.derivation_index(KEYCHAIN)
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
	signers: SignersContainer,
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
			.check_network(network)
			.load_wallet_no_persist(changeset)?;

		let wallet = match wallet_opt {
			Some(wallet) => wallet,
			None => bdk_wallet::Wallet::create_single(desc.clone())
				.network(network)
				.create_wallet_no_persist()?,
		};
		let signers = wallet.build_signers(desc).context("error building wallet signers")?;

		Ok(Self { inner: wallet, signers, db })
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

	async fn evict_tx(&mut self, txid: Txid) -> anyhow::Result<()> {
		self.inner.apply_evicted_txs([(txid, bark_runtime::timestamp_secs())]);
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

	async fn sign_psbt(&mut self, psbt: Psbt) -> anyhow::Result<Psbt> {
		OnchainWallet::sign_psbt(self, psbt).await
	}

	async fn finish_psbt(&mut self, mut psbt: Psbt) -> anyhow::Result<Psbt> {
		#[allow(deprecated)]
		let opts = bdk_wallet::SignOptions {
			trust_witness_utxo: true,
			..Default::default()
		};
		let finalized = self.inner.sign_with_signers(&mut psbt, &[&self.signers], opts)
			.context("signing error")?;
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
		WalletExt::make_signed_p2a_cpfp(&mut self.inner, tx, fees, &self.signers)
			.inspect_err(|e| error!("Error creating signed P2A CPFP: {}", e))
			.map_err(cpfp_internal_to_error)
	}

	async fn presign_p2a_cpfp_walk(
		&mut self,
		exits: &[Vec<(Transaction, MakeCpfpFees)>],
		relayed: &[Txid],
	) -> Result<Vec<Vec<(Transaction, Amount)>>, CpfpError> {
		let mut replica = WalletReplica::new(&self.inner)
			.map_err(|e|
				CpfpError::InternalError(format!("failed to build wallet replica: {}", e)),
			)?;
		let waves = replica.sign_p2a_cpfp_walk(exits, relayed, &self.signers)
			.map_err(cpfp_internal_to_error)?;

		// The children pay change to addresses only the replica derived, so reveal them here or
		// the wallet would discover the broadcast chain one child per sync.
		if let Some(index) = replica.revealed_change_index() {
			let _ = self.inner.reveal_addresses_to(KEYCHAIN, index).last();
			self.persist().await.map_err(|e| CpfpError::StoreError(e.to_string()))?;
		}
		Ok(waves)
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
					.checked_sub(DEEPLY_CONFIRMED.to_u32())
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

				let mut update = client.sync(request, PARALLEL_REQS).await?;

				// Esplora's indexer runs behind the mempool: a tx broadcast
				// moments ago can still be absent from its response and BDK
				// will report it as evicted. Drop such evictions here so we
				// don't hand a freshly-spent UTXO back to coin selection
				// before the tx actually confirms; see ONCHAIN_EVICTION_GRACE_SECS.
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
				update.tx_update.evicted_ats.retain(|(txid, _)| {
					if recently_seen.contains(txid) {
						debug!("Not evicting recently-seen tx {} still within grace period", txid);
						false
					} else {
						true
					}
				});

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

	/// Sign a psbt. Wallet-graph application is deferred to
	/// [`Self::record_broadcast_tx`].
	async fn sign_psbt(&mut self, mut psbt: Psbt) -> anyhow::Result<Psbt> {
		#[allow(deprecated)]
		let opts = bdk_wallet::SignOptions {
			trust_witness_utxo: true,
			..Default::default()
		};
		let finalized = self.inner.sign_with_signers(&mut psbt, &[&self.signers], opts)
			.context("signing error")?;
		ensure!(finalized, "failed to succesfully sign the tx");
		Ok(psbt)
	}

	async fn record_broadcast_tx(&mut self, tx: Transaction) -> anyhow::Result<()> {
		self.inner.apply_unconfirmed_txs([(tx, bark_runtime::timestamp_secs())]);
		self.persist().await
	}

	pub async fn send(&mut self, chain: &ChainSource, dest: Address, amount: Amount, fee_rate: FeeRate
	)	-> anyhow::Result<Txid> {
		let psbt = self.prepare_tx(&[(dest, amount)], fee_rate).await?;
		let tx = self.sign_psbt(psbt).await?.extract_tx()?;
		let txid = tx.compute_txid();
		self.record_broadcast_tx(tx.clone()).await?;
		if let Err(e) = chain.broadcast_tx(&tx).await {
			warn!("broadcast for {txid} returned error, will retry on next sync: {e:#}");
		}
		Ok(txid)
	}

	pub async fn send_many(
		&mut self,
		chain: &ChainSource,
		destinations: &[(Address, Amount)],
		fee_rate: FeeRate,
	) -> anyhow::Result<Txid> {
		let pbst = self.prepare_tx(destinations, fee_rate).await?;
		let tx = self.sign_psbt(pbst).await?.extract_tx()?;
		let txid = tx.compute_txid();
		self.record_broadcast_tx(tx.clone()).await?;
		if let Err(e) = chain.broadcast_tx(&tx).await {
			warn!("broadcast for {txid} returned error, will retry on next sync: {e:#}");
		}
		Ok(txid)
	}


	pub async fn drain(
		&mut self,
		chain: &ChainSource,
		destination: Address,
		fee_rate: FeeRate,
	) -> anyhow::Result<Txid> {
		let psbt = self.prepare_drain_tx(destination, fee_rate).await?;
		let tx = self.sign_psbt(psbt).await?.extract_tx()?;
		let txid = tx.compute_txid();
		self.record_broadcast_tx(tx.clone()).await?;
		if let Err(e) = chain.broadcast_tx(&tx).await {
			warn!("broadcast for {txid} returned error, will retry on next sync: {e:#}");
		}
		Ok(txid)
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
				let height = start_height.unwrap_or(GENESIS_HEIGHT).saturating_sub(BlockDelta::new(1));
				let block_hash = rpc.get_block_hash(height.into()).await?;
				self.inner.set_checkpoint(height.into(), block_hash);
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
	use bdk_wallet::test_utils::{
		get_test_tr_single_sig_xprv, get_test_wpkh, insert_checkpoint, insert_tx,
		receive_output_in_latest_block,
	};
	use bitcoin::{BlockHash, OutPoint};
	use bitcoin::hashes::Hash;

	/// A wallet with one confirmed UTXO per given amount, and its signers.
	fn funded_wallet(amounts: &[Amount]) -> (BdkWallet, SignersContainer) {
		let mut wallet = BdkWallet::create_single(get_test_wpkh())
			.network(Network::Regtest)
			.create_wallet_no_persist()
			.unwrap();
		insert_checkpoint(&mut wallet, BlockId { height: 1_000, hash: BlockHash::all_zeros() });
		for amount in amounts {
			receive_output_in_latest_block(&mut wallet, *amount);
		}
		let signers = wallet.build_signers(get_test_wpkh()).unwrap();
		(wallet, signers)
	}

	/// A zero-fee v3 parent spending the given prevout, carrying a P2A fee anchor.
	fn p2a_parent_spending(prev: OutPoint) -> Transaction {
		Transaction {
			version: bitcoin::transaction::Version(3),
			lock_time: bitcoin::absolute::LockTime::ZERO,
			input: vec![bitcoin::TxIn { previous_output: prev, ..Default::default() }],
			output: vec![bitcoin_ext::fee::fee_anchor()],
		}
	}

	/// A zero-fee v3 parent carrying a P2A fee anchor; `tag` makes its txid unique.
	fn p2a_parent(tag: u8) -> Transaction {
		p2a_parent_spending(OutPoint::new(Txid::from_byte_array([tag; 32]), 0))
	}

	#[test]
	fn wallet_replica_replicates_and_isolates() {
		let (wallet, signers) = funded_wallet(&[Amount::from_sat(1_000), Amount::from_sat(1_001)]);
		let mut replica = WalletReplica::new(&wallet).unwrap();

		assert_eq!(wallet.balance(), replica.inner.balance());
		assert_eq!(
			wallet.list_unspent().map(|u| u.outpoint).collect::<Vec<_>>(),
			replica.inner.list_unspent().map(|u| u.outpoint).collect::<Vec<_>>(),
		);
		assert_eq!(
			wallet.next_derivation_index(KeychainKind::External),
			replica.inner.next_derivation_index(KeychainKind::External),
		);

		// Mutating the replica must not leak into the original wallet.
		let parent = p2a_parent(1);
		let fees = MakeCpfpFees::Effective(FeeRate::from_sat_per_vb(1).unwrap());
		let child = replica.inner.make_signed_p2a_cpfp(&parent, fees, &signers).unwrap();
		assert_eq!(wallet.balance().confirmed, Amount::from_sat(2_001));
		assert!(wallet.get_tx(child.compute_txid()).is_none());
	}

	/// With a single-coin wallet, every CPFP child after the first can only be funded by the
	/// previous child's change: the walk must model that serial recycling.
	#[test]
	fn cpfp_walk_recycles_change_serially() {
		let (wallet, signers) = funded_wallet(&[Amount::from_sat(50_000)]);
		let fees = MakeCpfpFees::Effective(FeeRate::from_sat_per_vb(10).unwrap());
		let parents = (1..=3).map(|tag| (p2a_parent(tag), fees)).collect::<Vec<_>>();

		let waves = WalletReplica::new(&wallet).unwrap()
			.sign_p2a_cpfp_walk(&[parents.clone()], &[], &signers).unwrap();
		// One exit advances one package per wave.
		assert!(waves.iter().all(|wave| wave.len() == 1), "{:?}", waves);
		let children = waves.into_iter().flatten().collect::<Vec<_>>();
		assert_eq!(children.len(), 3);

		for (i, (child, fee)) in children.iter().enumerate() {
			let anchor_point = parents[i].0.fee_anchor().unwrap().0;
			assert!(child.input.iter().any(|input| input.previous_output == anchor_point));
			assert_eq!(child.input.len(), 2, "anchor spend plus a single funding input");
			assert_eq!(child.output.len(), 1, "drain output only");
			// The parent is zero-fee, so the effective-rate child pays exactly the package fee.
			assert_eq!(*fee, fees.effective() * (parents[i].0.weight() + child.weight()));
			if i > 0 {
				let (prev_child, _) = &children[i - 1];
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
		assert!(wallet.get_tx(children[0].0.compute_txid()).is_none());
	}

	/// Whatever coins each child selects, no coin may fund two children: earlier estimation
	/// re-ran selection against the same unchanged wallet, double-counting the same UTXO.
	#[test]
	fn cpfp_walk_never_double_spends_across_children() {
		// NB identical amounts would produce identical funding txids and collapse into one UTXO.
		// No coin covers a ~1150-sat package fee plus non-dust change alone, so children have to
		// combine coins.
		let amounts = (0..5).map(|i| Amount::from_sat(1_000 + i)).collect::<Vec<_>>();
		let (wallet, signers) = funded_wallet(&amounts);
		let original_coins = wallet.list_unspent()
			.map(|u| u.outpoint)
			.collect::<HashSet<_>>();
		let fees = MakeCpfpFees::Effective(FeeRate::from_sat_per_vb(4).unwrap());
		let parents = (1..=2).map(|tag| (p2a_parent(tag), fees)).collect::<Vec<_>>();

		let waves = WalletReplica::new(&wallet).unwrap()
			.sign_p2a_cpfp_walk(&[parents.clone()], &[], &signers).unwrap();
		let children = waves.into_iter().flatten().collect::<Vec<_>>();
		assert_eq!(children.len(), 2);

		let change_outputs = children.iter()
			.map(|(child, _)| OutPoint::new(child.compute_txid(), 0))
			.collect::<HashSet<_>>();
		let mut spent = HashSet::new();
		for ((child, _), (parent, _)) in children.iter().zip(&parents) {
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
	fn cpfp_walk_signs_leading_run_when_funds_run_out() {
		// 3000 sats fund the first ~2200-sat package but its change can't fund the second.
		let (wallet, signers) = funded_wallet(&[Amount::from_sat(3_000)]);
		let fees = MakeCpfpFees::Effective(FeeRate::from_sat_per_vb(10).unwrap());
		let parents = (1..=2).map(|tag| (p2a_parent(tag), fees)).collect::<Vec<_>>();

		let waves = WalletReplica::new(&wallet).unwrap()
			.sign_p2a_cpfp_walk(&[parents], &[], &signers).unwrap();
		let children = waves.into_iter().flatten().collect::<Vec<_>>();
		assert_eq!(children.len(), 1, "only the first package is fundable");
		let (first_child, first_fee) = &children[0];
		// The single coin funds the first child entirely, so wallet value splits exactly into
		// the reported fee and the change.
		assert_eq!(*first_fee + first_child.output[0].value, Amount::from_sat(3_000));
	}

	/// Two exits with their own confirmed UTXOs advance in the same wave, funded disjointly:
	/// unconfirmed wave siblings are unselectable, so BDK cannot cross-fund them.
	#[test]
	fn cpfp_walk_funds_exits_concurrently() {
		let (wallet, signers) = funded_wallet(&[Amount::from_sat(50_000), Amount::from_sat(50_001)]);
		let fees = MakeCpfpFees::Effective(FeeRate::from_sat_per_vb(10).unwrap());
		let exits = (1..=2).map(|tag| vec![(p2a_parent(tag), fees)]).collect::<Vec<_>>();

		let waves = WalletReplica::new(&wallet).unwrap().sign_p2a_cpfp_walk(&exits, &[], &signers).unwrap();
		assert_eq!(waves.len(), 1, "{:?}", waves);
		assert_eq!(waves[0].len(), 2);

		let funding = |child: &Transaction, exit: usize| child.input.iter()
			.map(|input| input.previous_output)
			.filter(|point| *point != exits[exit][0].0.fee_anchor().unwrap().0)
			.collect::<HashSet<_>>();
		let first = funding(&waves[0][0].0, 0);
		let second = funding(&waves[0][1].0, 1);
		assert!(first.is_disjoint(&second), "{:?} vs {:?}", first, second);
	}

	/// With a single UTXO, a second exit waits a wave and then funds itself from the first
	/// exit's change, which has confirmed by then.
	#[test]
	fn cpfp_walk_chains_onto_other_exit_change_when_utxos_run_out() {
		let (wallet, signers) = funded_wallet(&[Amount::from_sat(50_000)]);
		let fees = MakeCpfpFees::Effective(FeeRate::from_sat_per_vb(10).unwrap());
		let exits = (1..=2).map(|tag| vec![(p2a_parent(tag), fees)]).collect::<Vec<_>>();

		let waves = WalletReplica::new(&wallet).unwrap().sign_p2a_cpfp_walk(&exits, &[], &signers).unwrap();
		assert_eq!(waves.len(), 2, "{:?}", waves);
		assert_eq!(waves[0].len(), 1);
		assert_eq!(waves[1].len(), 1);

		let first_change = OutPoint::new(waves[0][0].0.compute_txid(), 0);
		assert!(
			waves[1][0].0.input.iter().any(|input| input.previous_output == first_change),
			"second exit's child must be funded by the first child's change",
		);
	}

	/// An exit transaction spending another exit's still-unsigned transaction cannot broadcast
	/// before it confirms, so its package must land in a later wave no matter the funds.
	#[test]
	fn cpfp_walk_gates_shared_ancestry() {
		let (wallet, signers) = funded_wallet(&[Amount::from_sat(50_000), Amount::from_sat(50_001)]);
		let fees = MakeCpfpFees::Effective(FeeRate::from_sat_per_vb(10).unwrap());
		let shared = p2a_parent(1);
		// Both exits descend from `shared`, which is listed under the first exit only.
		let own_a = p2a_parent_spending(OutPoint::new(shared.compute_txid(), 1));
		let own_b = p2a_parent_spending(OutPoint::new(shared.compute_txid(), 2));
		let exits = vec![
			vec![(shared, fees), (own_a.clone(), fees)],
			vec![(own_b.clone(), fees)],
		];

		let waves = WalletReplica::new(&wallet).unwrap().sign_p2a_cpfp_walk(&exits, &[], &signers).unwrap();
		assert_eq!(waves.len(), 2, "{:?}", waves);
		assert_eq!(waves[0].len(), 1, "only the shared prefix can broadcast first");
		// Once the prefix confirmed, both descendants advance in the same wave.
		assert_eq!(waves[1].len(), 2);
		let anchors = waves[1].iter().flat_map(|(child, _)| &child.input)
			.map(|input| input.previous_output)
			.collect::<HashSet<_>>();
		assert!(anchors.contains(&own_a.fee_anchor().unwrap().0));
		assert!(anchors.contains(&own_b.fee_anchor().unwrap().0));
	}

	/// A relayed parent gates its dependents until the second wave.
	#[test]
	fn cpfp_walk_gates_relayed_parents() {
		let (wallet, signers) = funded_wallet(&[Amount::from_sat(50_000), Amount::from_sat(50_001)]);
		let fees = MakeCpfpFees::Effective(FeeRate::from_sat_per_vb(10).unwrap());
		let relayed = p2a_parent(1);
		let dependent = p2a_parent_spending(OutPoint::new(relayed.compute_txid(), 1));
		let independent = p2a_parent(2);
		let relayed = [relayed.compute_txid()];

		let exits = vec![vec![(dependent.clone(), fees)], vec![(independent.clone(), fees)]];
		let waves = WalletReplica::new(&wallet).unwrap()
			.sign_p2a_cpfp_walk(&exits, &relayed, &signers).unwrap();
		assert_eq!(waves.len(), 2, "{:?}", waves);
		let anchor_of = |wave: &[(Transaction, Amount)]| wave.iter()
			.flat_map(|(child, _)| &child.input)
			.map(|input| input.previous_output)
			.collect::<HashSet<_>>();
		assert_eq!(waves[0].len(), 1);
		assert!(anchor_of(&waves[0]).contains(&independent.fee_anchor().unwrap().0));
		assert_eq!(waves[1].len(), 1);
		assert!(anchor_of(&waves[1]).contains(&dependent.fee_anchor().unwrap().0));

		// Nothing else to sign: the first wave is empty.
		let waves = WalletReplica::new(&wallet).unwrap()
			.sign_p2a_cpfp_walk(&[vec![(dependent, fees)]], &relayed, &signers).unwrap();
		assert_eq!(waves.len(), 2, "{:?}", waves);
		assert!(waves[0].is_empty());
		assert_eq!(waves[1].len(), 1);

		// Nothing to sign: no waves.
		let waves = WalletReplica::new(&wallet).unwrap()
			.sign_p2a_cpfp_walk(&[], &relayed, &signers).unwrap();
		assert!(waves.is_empty(), "{:?}", waves);
	}

	/// A derivable single-keychain wallet (the real onchain wallet's shape) with one confirmed
	/// UTXO per given amount, and its signers.
	fn derivable_wallet(amounts: &[Amount]) -> (BdkWallet, SignersContainer) {
		let mut wallet = BdkWallet::create_single(get_test_tr_single_sig_xprv())
			.network(Network::Regtest)
			.create_wallet_no_persist()
			.unwrap();
		insert_checkpoint(&mut wallet, BlockId { height: 1_000, hash: BlockHash::all_zeros() });
		for amount in amounts {
			receive_output_in_latest_block(&mut wallet, *amount);
		}
		let signers = wallet.build_signers(get_test_tr_single_sig_xprv()).unwrap();
		(wallet, signers)
	}

	/// The replica must report the change index it derived, so presigning can reveal the real
	/// wallet up to it, and must leave the real wallet's own derivation state untouched.
	#[test]
	fn cpfp_walk_reports_change_index() {
		let (wallet, signers) = derivable_wallet(&[Amount::from_sat(50_000)]);
		let fees = MakeCpfpFees::Effective(FeeRate::from_sat_per_vb(10).unwrap());
		let parents = (1..=3).map(|tag| (p2a_parent(tag), fees)).collect::<Vec<_>>();

		let next = wallet.next_derivation_index(KEYCHAIN);
		let mut replica = WalletReplica::new(&wallet).unwrap();
		let children = replica.sign_p2a_cpfp_walk(&[parents.clone()], &[], &signers).unwrap()
			.into_iter().flatten().collect::<Vec<_>>();
		assert_eq!(children.len(), 3);

		// One fresh change address per child, derived in order past the wallet's tip.
		assert_eq!(replica.revealed_change_index(), Some(next + 2));
		for (i, (child, _)) in children.iter().enumerate() {
			assert_eq!(
				child.output[0].script_pubkey,
				wallet.peek_address(KEYCHAIN, next + i as u32).address.script_pubkey(),
			);
		}
		assert_eq!(wallet.next_derivation_index(KEYCHAIN), next);
	}

	/// Revealing the walk's change indices must never leave a gap a recovery full scan could stop
	/// short of: change allocation takes the lowest unused index, so revealed-but-unbroadcast
	/// indices get reused rather than skipped, and a broadcast chain uses every revealed index.
	#[test]
	fn revealed_walk_change_leaves_no_address_gap() {
		let (mut wallet, signers) = derivable_wallet(&[Amount::from_sat(50_000)]);
		let fees = MakeCpfpFees::Effective(FeeRate::from_sat_per_vb(10).unwrap());
		let parents = (1..=3).map(|tag| (p2a_parent(tag), fees)).collect::<Vec<_>>();

		let mut replica = WalletReplica::new(&wallet).unwrap();
		let children = replica.sign_p2a_cpfp_walk(&[parents.clone()], &[], &signers).unwrap()
			.into_iter().flatten().collect::<Vec<_>>();
		let change_index = replica.revealed_change_index().unwrap();
		let _ = wallet.reveal_addresses_to(KEYCHAIN, change_index).last();
		assert_eq!(wallet.next_derivation_index(KEYCHAIN), change_index + 1);

		// The allocator still points at the first revealed-unused index, so ordinary wallet
		// activity fills the presign indices before consuming new ones.
		assert_eq!(
			wallet.next_unused_address(KEYCHAIN).address.script_pubkey(),
			children[0].0.output[0].script_pubkey,
		);

		// A repeat walk re-derives the same addresses: an un-broadcast chain never consumes
		// more than one chain's worth of address space, no matter how often it is re-signed.
		let mut repeat_replica = WalletReplica::new(&wallet).unwrap();
		let repeat = repeat_replica.sign_p2a_cpfp_walk(&[parents.clone()], &[], &signers).unwrap()
			.into_iter().flatten().collect::<Vec<_>>();
		assert_eq!(repeat_replica.revealed_change_index(), Some(change_index));
		let change_spks = |children: &[(Transaction, Amount)]| children.iter()
			.map(|(child, _)| child.output[0].script_pubkey.clone())
			.collect::<Vec<_>>();
		assert_eq!(change_spks(&repeat), change_spks(&children));

		// Once the chain is onchain, the used run is contiguous: no gap for a full scan.
		for (child, _) in &children {
			insert_tx(&mut wallet, child.clone());
		}
		assert_eq!(wallet.list_unused_addresses(KEYCHAIN).count(), 0);
		assert_eq!(wallet.next_unused_address(KEYCHAIN).index, change_index + 1);
	}
}

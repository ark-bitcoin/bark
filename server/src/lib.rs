#[macro_use] extern crate anyhow;
#[macro_use] extern crate async_trait;
#[macro_use] extern crate serde;
#[macro_use] extern crate server_log;

#[macro_use]
mod error;

mod bitcoind;
pub mod config;
pub mod database;
pub mod rpcserver;
pub mod forfeits;
pub mod secret;
pub mod sweeps;
pub mod tip_fetcher;
pub mod vtxopool;
pub mod wallet;
pub mod watchman;

pub(crate) mod flux;
pub(crate) mod system;

mod intman;
mod ln;
mod psbtext;
mod round;
mod serde_util;
mod telemetry;
mod txindex;
pub mod filters;

pub use crate::config::Config;

use std::borrow::Borrow;
use std::collections::HashSet;
use std::fs;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;
use std::task::Poll;
use std::time::Duration;

use anyhow::Context;
use bitcoin::{bip32, Address, Amount, OutPoint};
use bitcoin::secp256k1::{self, rand, schnorr, Keypair, PublicKey};
use futures::Stream;
use log::{info, trace, warn};
use tokio::sync::{broadcast, mpsc, oneshot};
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::wrappers::errors::BroadcastStreamRecvError;

use ark::{Vtxo, VtxoId, VtxoRequest};
use ark::arkoor::{ArkoorBuilder, ArkoorCosignResponse, ArkoorPackageBuilder};
use ark::board::BoardBuilder;
use ark::musig::{self, PublicNonce};
use ark::rounds::RoundEvent;
use ark::tree::signed::builder::{SignedTreeBuilder, SignedTreeCosignResponse};
use bitcoin_ext::{BlockHeight, BlockRef, TransactionExt, TxStatus, P2TR_DUST};
use bitcoin_ext::rpc::{BitcoinRpcClient, BitcoinRpcExt, RpcApi};

use crate::bitcoind::BitcoinRpcClientExt;
use crate::error::ContextExt;
use crate::flux::VtxosInFlux;
use crate::forfeits::ForfeitWatcher;
use crate::ln::cln::ClnManager;
use crate::round::RoundInput;
use crate::secret::Secret;
use crate::sweeps::VtxoSweeper;
use crate::system::RuntimeManager;
use crate::tip_fetcher::TipFetcher;
use crate::txindex::TxIndex;
use crate::txindex::broadcast::TxNursery;
use crate::vtxopool::VtxoPool;
use crate::wallet::{PersistedWallet, WalletKind, MNEMONIC_FILE};

lazy_static::lazy_static! {
	/// Global secp context.
	static ref SECP: secp256k1::Secp256k1<secp256k1::All> = secp256k1::Secp256k1::new();
}

/// The HD keypath to use for the server key.
const SERVER_KEY_PATH: &str = "m/2'/0'";

/// The HD keypath used to generate ephemeral keys
const EPHEMERAL_KEY_PATH: &str = "m/30'";


/// Return type for the round event RPC stream.
///
/// It contains a first item that is yielded first and then it refers to the stream.
pub struct RoundEventStream {
	first: Option<Arc<RoundEvent>>,
	events: BroadcastStream<Arc<RoundEvent>>,
}

impl Stream for RoundEventStream {
	type Item = Arc<RoundEvent>;

	fn poll_next(
		mut self: Pin<&mut Self>,
		cx: &mut std::task::Context,
	) -> Poll<Option<Self::Item>> {
		if let Some(e) = self.first.take() {
			return Poll::Ready(Some(e));
		}

		loop {
			match Pin::new(&mut self.events).poll_next(cx) {
				// We lagged behind, we continue which will give us new messages
				Poll::Ready(Some(Err(BroadcastStreamRecvError::Lagged(_)))) => continue,
				Poll::Ready(Some(Ok(e))) => break Poll::Ready(Some(e)),
				Poll::Ready(None) => break Poll::Ready(None),
				Poll::Pending => break Poll::Pending,
			}
		}
	}
}

pub struct RoundHandle {
	round_event_tx: broadcast::Sender<Arc<RoundEvent>>,
	last_round_event: parking_lot::Mutex<Option<Arc<RoundEvent>>>,
	round_input_tx: mpsc::UnboundedSender<(RoundInput, oneshot::Sender<anyhow::Error>)>,
	round_trigger_tx: mpsc::Sender<()>,
}

impl RoundHandle {
	pub fn events(&self) -> RoundEventStream {
		// If we keep the lock just as long as we create a new receiver,
		// we will never miss any messages.
		let guard = self.last_round_event.lock();
		let events = BroadcastStream::new(self.round_event_tx.subscribe());
		let first = guard.clone();
		RoundEventStream { first, events }
	}

	pub fn last_event(&self) -> Option<Arc<RoundEvent>> {
		self.last_round_event.lock().clone()
	}
}

impl RoundHandle {
	/// Broadcast a new event and store it as the last sent event.
	fn broadcast_event(&self, event: RoundEvent) {
		let event = Arc::new(event);
		let mut last_lock = self.last_round_event.lock();
		let _ = self.round_event_tx.send(event.clone());
		*last_lock = Some(event);
	}
}

pub struct Server {
	config: Config,
	db: database::Db,
	server_key: Secret<Keypair>,
	server_pubkey: PublicKey, // public key part of former
	/// The keypair used to generate ephemeral keys using tweaks
	ephemeral_master_key: Secret<Keypair>,
	// NB this needs to be an Arc so we can take a static guard
	rounds_wallet: Arc<tokio::sync::Mutex<PersistedWallet>>,
	bitcoind: BitcoinRpcClient,
	tip_fetcher: TipFetcher,
	rtmgr: RuntimeManager,
	tx_nursery: TxNursery,
	vtxo_sweeper: Option<VtxoSweeper>,
	rounds: RoundHandle,
	forfeits: Option<ForfeitWatcher>,
	/// All vtxos that are currently being processed in any way.
	/// (Plus a small buffer to optimize allocations.)
	vtxos_in_flux: VtxosInFlux,
	cln: ClnManager,
	vtxopool: VtxoPool,
}

impl Server {
	pub async fn create(cfg: Config) -> anyhow::Result<()> {
		// Check for a mnemonic file to see if the server was already initialized.
		if cfg.data_dir.join(MNEMONIC_FILE).exists() {
			bail!("Found an existing mnemonic file in datadir, the server is probably already initialized!");
		}

		let bitcoind = BitcoinRpcClient::new(&cfg.bitcoind.url, cfg.bitcoind.auth())
			.context("failed to create bitcoind rpc client")?;
		// Check if our bitcoind is on the expected network.
		let chain_info = bitcoind.get_blockchain_info()?;
		if chain_info.chain != cfg.network {
			bail!("Our bitcoind is running on network {} while we are configured for network {}",
				chain_info.chain, cfg.network,
			);
		}
		let deep_tip = bitcoind.deep_tip()
			.context("failed to fetch deep tip from bitcoind")?;

		info!("Creating server at {}", cfg.data_dir.display());

		// create dir if not exit, but check that it's empty
		fs::create_dir_all(&cfg.data_dir).context("can't create dir")?;

		let db = database::Db::create(&cfg.postgres).await?;

		// Initiate key material.
		let seed = {
			let mnemonic = bip39::Mnemonic::generate(12).expect("12 is valid");

			fs::write(cfg.data_dir.join(MNEMONIC_FILE), mnemonic.to_string().as_bytes())
				.context("failed to store mnemonic")?;

			mnemonic.to_seed("")
		};
		let seed_xpriv = bip32::Xpriv::new_master(cfg.network, &seed).unwrap();

		// Store initial wallet states to avoid full chain sync.
		for wallet in [WalletKind::Rounds, WalletKind::Forfeits] {
			let wallet_xpriv = seed_xpriv.derive_priv(&*SECP, &[wallet.child_number()])
				.expect("can't error");
			let _wallet = PersistedWallet::load_from_xpriv(
				db.clone(), cfg.network, &wallet_xpriv, wallet, deep_tip,
			);
		}

		Ok(())
	}

	pub fn server_pubkey(&self) -> PublicKey {
		self.server_pubkey
	}

	pub fn ark_info(&self) -> ark::ArkInfo {
		ark::ArkInfo {
			network: self.config.network,
			server_pubkey: self.server_pubkey,
			round_interval: self.config.round_interval,
			nb_round_nonces: self.config.nb_round_nonces,
			vtxo_exit_delta: self.config.vtxo_exit_delta,
			vtxo_expiry_delta: self.config.vtxo_lifetime,
			htlc_send_expiry_delta: self.config.htlc_send_expiry_delta,
			htlc_expiry_delta: self.config.htlc_expiry_delta,
			max_vtxo_amount: self.config.max_vtxo_amount,
			max_arkoor_depth: self.config.max_arkoor_depth,
			required_board_confirmations: self.config.required_board_confirmations,
			max_user_invoice_cltv_delta: self.config.max_user_invoice_cltv_delta,
			min_board_amount: self.config.min_board_amount,
		}
	}

	pub fn database(&self) -> &database::Db {
		&self.db
	}

	pub async fn open_round_wallet(
		cfg: &Config,
		db: database::Db,
		master_xpriv: &bip32::Xpriv,
		deep_tip: BlockRef,
	) -> anyhow::Result<PersistedWallet> {
		let wallet_xpriv = master_xpriv.derive_priv(&*SECP, &[WalletKind::Rounds.child_number()])
			.expect("can't error");
		Ok(PersistedWallet::load_from_xpriv(
			db, cfg.network, &wallet_xpriv, WalletKind::Rounds, deep_tip,
		).await?)
	}

	/// Start the server.
	pub async fn start(cfg: Config) -> anyhow::Result<Arc<Self>> {
		info!("Starting server at {}", cfg.data_dir.display());

		info!("Connecting to db at {}:{}", cfg.postgres.host, cfg.postgres.port);
		let db = database::Db::connect(&cfg.postgres)
			.await
			.context("failed to connect to db")?;

		let bitcoind = BitcoinRpcClient::new(&cfg.bitcoind.url, cfg.bitcoind.auth())
			.context("failed to create bitcoind rpc client")?;
		bitcoind.require_network(cfg.network)?;
		bitcoind.require_version()?;
		bitcoind.require_txindex()?;

		// Check if our bitcoind is on the expected network.
		let chain_info = bitcoind.get_blockchain_info()?;
		if chain_info.chain != cfg.network {
			bail!("Our bitcoind is running on network {} while we are configured for network {}",
				chain_info.chain, cfg.network,
			);
		}

		let seed = wallet::read_mnemonic_from_datadir(&cfg.data_dir)?.to_seed("");
		let master_xpriv = bip32::Xpriv::new_master(cfg.network, &seed).unwrap();

		let deep_tip = bitcoind.deep_tip().context("failed to query node for deep tip")?;
		let mut rounds_wallet = Self::open_round_wallet(&cfg, db.clone(), &master_xpriv, deep_tip)
			.await.context("error loading wallet")?;

		let server_key = {
			let path = bip32::DerivationPath::from_str(SERVER_KEY_PATH).unwrap();
			let xpriv = master_xpriv.derive_priv(&SECP, &path).unwrap();
			Keypair::from_secret_key(&SECP, &xpriv.private_key)
		};

		let ephemeral_master_key = {
			let path = bip32::DerivationPath::from_str(EPHEMERAL_KEY_PATH).unwrap();
			let xpriv = master_xpriv.derive_priv(&SECP, &path).unwrap();
			Keypair::from_secret_key(&SECP, &xpriv.private_key)
		};

		if let Some(ref endpoint) = cfg.otel_collector_endpoint {
			telemetry::init_telemetry::<telemetry::Captaind>(
				endpoint,
				cfg.otel_tracing_sampler,
				cfg.network,
				cfg.round_interval,
				cfg.max_vtxo_amount,
				server_key.public_key(),
			);
		}

		// *******************
		// * START PROCESSES *
		// *******************

		let rtmgr = RuntimeManager::new();
		let _startup_worker = rtmgr.spawn("Bootstrapping");
		rtmgr.run_shutdown_signal_listener(Duration::from_secs(60));

		let txindex = TxIndex::start(
			deep_tip,
			rtmgr.clone(),
			bitcoind.clone(),
			cfg.txindex_check_interval,
			db.clone(),
		);

		let tx_nursery = TxNursery::start(
			rtmgr.clone(),
			txindex.clone(),
			bitcoind.clone(),
			cfg.transaction_rebroadcast_interval,
		);

		let vtxo_sweeper = if let Some(c) = cfg.vtxo_sweeper.enabled() {
			let s = VtxoSweeper::start(
				rtmgr.clone(),
				c.clone(),
				cfg.network,
				bitcoind.clone(),
				db.clone(),
				txindex.clone(),
				tx_nursery.clone(),
				server_key.clone(),
				rounds_wallet.reveal_next_address(
					bdk_wallet::KeychainKind::External,
				).address,
			).await.context("failed to start VtxoSweeper")?;
			Some(s)
		} else {
			None
		};

		let forfeits = if let Some(c) = cfg.forfeit_watcher.enabled() {
			let s = ForfeitWatcher::start(
				rtmgr.clone(),
				c.clone(),
				cfg.network,
				bitcoind.clone(),
				db.clone(),
				txindex.clone(),
				tx_nursery.clone(),
				master_xpriv.derive_priv(&*SECP, &[WalletKind::Forfeits.child_number()])
					.expect("can't error"),
				server_key.clone(),
			).await.context("failed to start ForfeitWatcher")?;
			Some(s)
		} else {
			None
		};

		let tip_fetcher = TipFetcher::start(
			rtmgr.clone(),
			bitcoind.clone(),
		).await.context("Failed to start TipFetcher")?;

		let cln = ClnManager::start(
			rtmgr.clone(),
			&cfg,
			db.clone(),
		).await.context("failed to start ClnManager")?;

		let vtxopool = VtxoPool::new(cfg.vtxopool.clone(), &db).await
			.context("failed to initiate vtxopool")?;

		let (round_event_tx, _rx) = broadcast::channel(8);
		let (round_input_tx, round_input_rx) = tokio::sync::mpsc::unbounded_channel();
		let (round_trigger_tx, round_trigger_rx) = tokio::sync::mpsc::channel(1);

		let srv = Server {
			rounds_wallet: Arc::new(tokio::sync::Mutex::new(rounds_wallet)),
			rounds: RoundHandle {
				round_event_tx,
				last_round_event: parking_lot::Mutex::new(None),
				round_input_tx,
				round_trigger_tx,
			},
			vtxos_in_flux: VtxosInFlux::new(),
			config: cfg.clone(),
			db,
			server_pubkey: server_key.public_key(),
			server_key: Secret::new(server_key),
			ephemeral_master_key: Secret::new(ephemeral_master_key),
			bitcoind,
			tip_fetcher,
			rtmgr,
			tx_nursery: tx_nursery.clone(),

			vtxo_sweeper: vtxo_sweeper,
			forfeits: forfeits,
			cln,
			vtxopool,
		};

		let srv = Arc::new(srv);

		let srv2 = srv.clone();
		tokio::spawn(async move {
			let res = round::run_round_coordinator(
				&srv2,
				round_input_rx,
				round_trigger_rx,
			)
				.await.context("error from round scheduler");
			info!("Round coordinator exited with {:?}", res);
		});

		// VtxoPool
		srv.vtxopool.start(srv.clone());

		// RPC

		let srv2 = srv.clone();
		tokio::spawn(async move {
			let res = rpcserver::ark::run_rpc_server(srv2)
				.await.context("error running public gRPC server");
			info!("RPC server exited with {:?}", res);
		});

		if cfg.rpc.admin_address.is_some() {
			let srv2 = srv.clone();
			tokio::spawn(async move {
				let res = rpcserver::admin::run_rpc_server(srv2)
					.await.context("error running admin gRPC server");
				info!("Admin RPC server exited with {:?}", res);
			});
		}

		if cfg.rpc.integration_address.is_some() {
			let srv2 = srv.clone();
			tokio::spawn(async move {
				let res = rpcserver::intman::run_rpc_server(srv2)
					.await.context("error running integration gRPC server");
				info!("Integration RPC server exited with {:?}", res);
			});
		}

		Ok(srv)
	}

	/// Waits for server to terminate.
	pub async fn wait(&self) {
		self.rtmgr.wait().await;
		slog!(ServerTerminated);
	}

	/// Starts the server and waits until it terminates.
	///
	/// This is equivalent to calling [Server::start] and [Server::wait] in one go.
	pub async fn run(cfg: Config) -> anyhow::Result<()> {
		let srv = Server::start(cfg).await?;
		srv.wait().await;
		Ok(())
	}

	pub fn chain_tip(&self) -> BlockRef {
		self.tip_fetcher.tip()
	}

	/// Sync all the system's wallets.
	///
	/// This includes the rounds wallet sending new funds to the forfeits
	/// wallet if it's running low.
	pub async fn sync_wallets(&self) -> anyhow::Result<()> {
		// First sync both wallets.
		let (rounds_balance, _) = tokio::try_join!(
			async {
				self.rounds_wallet.lock().await.sync(&self.bitcoind, false).await
			},
			async {
				if let Some(ref fw) = self.forfeits {
					fw.wallet_sync().await
				} else {
					Ok(())
				}
			},
		)?;

		// Then try rebalance.
		if let Some(ref forfeits) = self.forfeits {
			let forfeit_wallet = forfeits.wallet_status().await?;
			if forfeit_wallet.total_balance < self.config.forfeit_watcher_min_balance {
				let amount = self.config.forfeit_watcher_min_balance * 2;
				if rounds_balance.total() < amount {
					warn!("Rounds wallet doesn't have sufficient funds to fund forfeit watcher.");
				} else {
					let mut wallet = self.rounds_wallet.lock().await;
					let addr = forfeit_wallet.address.assume_checked();
					let feerate = self.config.round_tx_feerate; //TODO(stevenroose) fix this
					info!("Sending {amount} to forfeit wallet address {addr}...");
					let tx = match wallet.send(addr.script_pubkey(), amount, feerate).await {
						Ok(tx) => tx,
						Err(e) => {
							warn!("Error sending from round to forfeit wallet: {:?}", e);
							return Err(e).context("error sending tx from round to forfeit wallet");
						},
					};
					drop(wallet);

					let tx = self.tx_nursery.broadcast_tx(tx).await
						.context("Failed to broadcast transaction")?;

					// wait until it's actually broadcast
					tokio::time::timeout(Duration::from_millis(5_000), async {
						loop {
							if tx.status().seen() {
								break;
							}
							tokio::time::sleep(Duration::from_millis(500)).await;
						}
					}).await.context("waiting for tx broadcast timed out")?;

					// then re-sync
					forfeits.wallet_sync().await?;
				}
			}
		}

		Ok(())
	}

	pub async fn new_onchain_address(&self) -> anyhow::Result<Address> {
		let mut wallet = self.rounds_wallet.lock().await;
		let ret = wallet.reveal_next_address(bdk_wallet::KeychainKind::External).address;
		wallet.persist().await?;
		Ok(ret)
	}

	/// Fetch all the utxos in our wallet that are being spent or created by txs
	/// from the VtxoSweeper.
	pub async fn pending_sweep_utxos(&self) -> anyhow::Result<HashSet<OutPoint>> {
		let ret = self.db.fetch_pending_sweeps().await?.values()
			.map(|tx| tx.all_related_utxos())
			.flatten().collect();
		Ok(ret)
	}

	pub async fn cosign_board(
		&self,
		amount: Amount,
		user_pubkey: PublicKey,
		expiry_height: BlockHeight,
		utxo: OutPoint,
		user_pub_nonce: PublicNonce,
	) -> anyhow::Result<ark::board::BoardCosignResponse> {
		let min_amount = self.config.min_board_amount.max(P2TR_DUST);

		if amount < min_amount {
			return badarg!("board amount must be at least {}", min_amount);
		}

		if let Some(max) = self.config.max_vtxo_amount {
			if amount > max {
				return badarg!("board amount exceeds limit of {max}");
			}
		}

		//TODO(stevenroose) make this more robust
		let tip = self.chain_tip();
		if expiry_height < tip.height {
			bail!("vtxo already expired: {} (tip = {})", expiry_height, tip.height);
		}

		let builder = BoardBuilder::new_for_cosign(
			user_pubkey,
			expiry_height,
			self.server_pubkey,
			self.config.vtxo_exit_delta,
			amount,
			utxo,
			user_pub_nonce,
		);

		info!("Cosigning board request for utxo {}", utxo);
		let resp = builder.server_cosign(self.server_key.leak_ref());

		slog!(CosignedBoard, utxo, amount);

		Ok(resp)
	}

	/// Registers a board vtxo in the database
	///
	/// Errors if the board vtxo is not sufficiently confirmed.
	pub async fn register_board(&self, vtxo: Vtxo) -> anyhow::Result<()> {
		//TODO(stevenroose) validate board vtxo

		// All boards must be sufficiently confirmed before we will register them.
		match self.bitcoind.custom_get_raw_transaction_info(&vtxo.chain_anchor().txid, None) {
			Ok(Some(txinfo)) => {
				let confs = txinfo.confirmations.unwrap_or(0) as usize;
				if confs < self.config.required_board_confirmations {
					slog!(UnconfirmedBoardRegisterAttempt, vtxo: vtxo.id(), confirmations: confs);
					return badarg!("board vtxo tx not sufficiently confirmed (has {confs} confs, \
						but requires {}): {}", self.config.required_board_confirmations, vtxo.id(),
					);
				}
			},
			Ok(None) => return badarg!("board transaction not found"),
			Err(e) => bail!("error fetching tx info for board tx: {e}"),
		}

		trace!("Board tx {} is sufficiently confirmed, registering board", vtxo.chain_anchor().txid);

		// Accepted, let's register
		self.db.upsert_board(&vtxo).await.context("db error")
			.context("Failed to upsert board into database")?;

		slog!(RegisteredBoard, onchain_utxo: vtxo.chain_anchor(), vtxo: vtxo.point(),
			amount: vtxo.amount(),
		);

		Ok(())
	}

	pub async fn check_vtxos_not_exited(&self, vtxos: &[Vtxo]) -> anyhow::Result<()> {
		for vtxo in vtxos {
			// NB: we only care about the first exit tx, because next ones are descendants of it
			let tx = vtxo.transactions().first_exit().expect("branch should have exit tx");
			let status = self.bitcoind.tx_status(&tx.compute_txid())?;

			match status {
				TxStatus::Confirmed(_) => {
					// TODO: should we mark vtxo as spent here?
					return badarg!("cannot spend vtxo that is already exited: {}", vtxo.id());
				},
				TxStatus::Mempool => {
					return badarg!("cannot spend vtxo that is being exited: {}", vtxo.id());
				},
				TxStatus::NotFound => {},
			}
		}

		Ok(())
	}

	/// Validate all arkoor inputs are not too deep
	fn validate_arkoor_inputs<V: Borrow<Vtxo>>(
		&self,
		inputs: impl IntoIterator<Item = V>,
	) -> anyhow::Result<()> {
		for input in inputs {
			if input.borrow().arkoor_depth() >= self.config.max_arkoor_depth {
				return badarg!("OOR depth reached maximum of {}, please refresh your VTXO: {}",
					self.config.max_arkoor_depth, input.borrow().id());
			}
		}

		Ok(())
	}

	/// Perform the arkoor cosign from the builder.
	/// Assumes that sanity checks on the input have been performed.
	/// Will lock the input vtxo in flux.
	async fn cosign_oor_package_with_builder(
		&self,
		builder: &ArkoorPackageBuilder<'_, VtxoRequest>,
	) -> anyhow::Result<Vec<ArkoorCosignResponse>> {
		let inputs = builder.inputs();
		let input_ids = inputs.iter().map(|input| input.id()).collect::<Vec<_>>();
		let _lock = match self.vtxos_in_flux.lock(&input_ids) {
			Ok(l) => l,
			Err(id) => {
				slog!(ArkoorInputAlreadyInFlux, vtxo: id);
				return badarg!("attempted to sign arkoor tx for vtxo already in flux: {}", id);
			},
		};

		match self.db.check_set_vtxo_oor_spent_package(&builder).await {
			Ok(Some(dup)) => {
				badarg!("attempted to sign arkoor tx for already spent vtxo {}", dup)
			},
			Ok(None) => {
				let output_ids = builder.new_vtxos().into_iter().flatten()
					.map(|v| v.id()).collect::<Vec<_>>();
				slog!(ArkoorCosign, input_ids, output_ids);
				// let's sign the tx
				Ok(builder.server_cosign(&self.server_key.leak_ref()))
			},
			Err(e) => Err(e),
		}
	}

	async fn cosign_oor_package(
		&self,
		arkoor_args: Vec<(VtxoId, musig::PublicNonce, Vec<VtxoRequest>)>,
	) -> anyhow::Result<Vec<ArkoorCosignResponse>> {
		let ids = arkoor_args.iter().map(|(id, _, _)| *id).collect::<Vec<_>>();
		let input_vtxos = self.db.get_vtxos_by_id(&ids).await?
			.into_iter().map(|s| s.vtxo).collect::<Vec<_>>();

		let arkoors = arkoor_args.iter().zip(input_vtxos.iter())
			.map(|((_, user_nonce, outputs), vtxo)| {
				ArkoorBuilder::new(
					&vtxo,
					&user_nonce,
					outputs,
				).badarg("invalid arkoor")
			})
			.collect::<anyhow::Result<Vec<_>>>()?;

		self.check_vtxos_not_exited(&input_vtxos).await?;

		self.validate_arkoor_inputs(&input_vtxos)?;

		let builder = ArkoorPackageBuilder::from_arkoors(arkoors)
			.badarg("error creating arkoor package")?;

		self.cosign_oor_package_with_builder(&builder).await
	}

	pub async fn generate_ephemeral_cosign_key(
		&self,
		lifetime: Duration,
	) -> anyhow::Result<Keypair> {
		let secret = rand::random::<[u8; 32]>();
		let tweak = secp256k1::Scalar::from_be_bytes(secret).expect("very improbable");
		let seckey = self.ephemeral_master_key.leak_ref().secret_key()
			.add_tweak(&tweak).expect("tweak error");
		let key = Keypair::from_secret_key(&*SECP, &seckey);
		self.db.store_ephemeral_tweak(key.public_key(), tweak, lifetime).await?;
		Ok(key)
	}

	pub async fn get_ephemeral_cosign_key(&self, pubkey: PublicKey) -> anyhow::Result<Keypair> {
		let tweak = self.db.fetch_ephemeral_tweak(pubkey).await?
			.context("ephemeral pubkey unknown")?;
		let seckey = self.ephemeral_master_key.leak_ref().secret_key()
			.add_tweak(&tweak).expect("tweak error");
		Ok(Keypair::from_secret_key(&*SECP, &seckey))
	}

	pub async fn drop_ephemeral_cosign_key(&self, pubkey: PublicKey) -> anyhow::Result<Keypair> {
		let tweak = self.db.drop_ephemeral_tweak(pubkey).await?
			.context("ephemeral pubkey unknown")?;
		let seckey = self.ephemeral_master_key.leak_ref().secret_key()
			.add_tweak(&tweak).expect("tweak error");
		Ok(Keypair::from_secret_key(&*SECP, &seckey))
	}

	pub async fn cosign_vtxo_tree(
		&self,
		vtxos: impl IntoIterator<Item = VtxoRequest>,
		cosign_pubkey: PublicKey,
		server_cosign_pubkey: PublicKey,
		expiry_height: BlockHeight,
		utxo: OutPoint,
		pub_nonces: Vec<musig::PublicNonce>,
	) -> anyhow::Result<SignedTreeCosignResponse> {
		// NB we don't drop yet cuz we need to verify it was our key
		// in the [Server::register_cosigned_vtxo_tree] step.
		let cosign_key = self.get_ephemeral_cosign_key(server_cosign_pubkey).await?;

		let builder = SignedTreeBuilder::new_for_cosign(
			vtxos,
			cosign_pubkey,
			expiry_height,
			self.server_key.leak_ref().public_key(),
			server_cosign_pubkey,
			self.config.vtxo_exit_delta,
			utxo,
			pub_nonces,
		);
		Ok(builder.server_cosign(&cosign_key))
	}

	/// Register the VTXOs in the signed vtxo tree
	///
	/// This should only be called once we trust that the root of the tree
	/// will confirm.
	pub async fn register_cosigned_vtxo_tree(
		&self,
		vtxos: impl IntoIterator<Item = VtxoRequest>,
		cosign_pubkey: PublicKey,
		server_cosign_pubkey: PublicKey,
		expiry_height: BlockHeight,
		utxo: OutPoint,
		signatures: Vec<schnorr::Signature>,
	) -> anyhow::Result<()> {
		let tree = SignedTreeBuilder::construct_tree_spec(
			vtxos,
			cosign_pubkey,
			expiry_height,
			self.server_key.leak_ref().public_key(),
			server_cosign_pubkey,
			self.config.vtxo_exit_delta,
		).into_unsigned_tree(utxo);

		if let Err(pk) = tree.verify_cosign_sigs(&signatures) {
			bail!("invalid cosign signatures for xonly pk {}", pk);
		}

		// Now we're done and we can drop the key.
		let _ = self.drop_ephemeral_cosign_key(server_cosign_pubkey).await?;

		//TODO(stevenroose) some sanity check on expiry?

		let tree = tree.into_signed_tree(signatures).into_cached_tree();
		self.db.upsert_vtxos(tree.all_vtxos()).await.context("db error occurred")?;

		Ok(())
	}
}

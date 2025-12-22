#[macro_use] extern crate anyhow;
#[macro_use] extern crate async_trait;
#[macro_use] extern crate serde;
#[macro_use] extern crate server_log;

#[macro_use]
mod error;

pub mod arkoor;
pub mod sync;
pub mod config;
pub mod database;
pub mod filters;
pub mod forfeits;
pub mod mailbox_manager;
pub mod rpcserver;
pub mod secret;
pub mod sweeps;
pub mod vtxopool;
pub mod wallet;
pub mod watchman;

pub(crate) mod flux;
pub(crate) mod system;

mod bitcoind;
mod intman;
mod ln;
mod psbtext;
mod round;
pub mod telemetry;
mod txindex;
mod utils;


pub use crate::intman::{CAPTAIND_API_KEY, CAPTAIND_CLI_API_KEY};
pub use crate::config::Config;
use crate::utils::TimedEntryMap;

use std::borrow::Borrow;
use std::collections::HashSet;
use std::fs;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;
use std::task::Poll;
use std::time::Duration;

use anyhow::Context;
use bitcoin::{bip32, Address, Amount, OutPoint, Transaction};
use bitcoin::secp256k1::{self, rand, Keypair, PublicKey};
use futures::Stream;
use tokio::sync::{broadcast, mpsc, oneshot};
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::wrappers::errors::BroadcastStreamRecvError;
use tracing::{info, warn, trace};

use ark::{Vtxo, VtxoId, VtxoRequest};
use ark::vtxo::VtxoRef;
use ark::arkoor::{ArkoorBuilder, ArkoorCosignResponse, ArkoorPackageBuilder};
use ark::board::BoardBuilder;
use ark::mailbox::{BlindedMailboxIdentifier, MailboxIdentifier};
use ark::musig::{self, PublicNonce};
use ark::rounds::{RoundEvent, RoundId};
use ark::tree::signed::{LeafVtxoCosignRequest, LeafVtxoCosignResponse, UnlockPreimage};
use ark::tree::signed::builder::{SignedTreeBuilder, SignedTreeCosignResponse};
use bitcoin_ext::{BlockHeight, BlockRef, TransactionExt, TxStatus, P2TR_DUST};
use bitcoin_ext::rpc::{BitcoinRpcClient, BitcoinRpcExt, RpcApi};

use crate::bitcoind::BitcoinRpcClientExt;
use crate::sync::SyncManager;
use crate::error::ContextExt;
use crate::flux::VtxosInFlux;
use crate::forfeits::ForfeitWatcher;
use crate::ln::cln::ClnManager;
use crate::mailbox_manager::MailboxManager;
use crate::round::RoundInput;
use crate::round::forfeit::HarkForfeitNonces;
use crate::secret::Secret;
use crate::sweeps::VtxoSweeper;
use crate::system::RuntimeManager;
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

/// The HD keypath to use for the mailbox key.
const MAILBOX_KEY_PATH: &str = "m/2'/1'";

/// The HD keypath used to generate ephemeral keys
const EPHEMERAL_KEY_PATH: &str = "m/30'";


/// Return type for the round event RPC stream.
///
/// It contains a first item that is yielded first and then it refers to the stream.
pub struct RoundEventStream {
	events: BroadcastStream<Arc<RoundEvent>>,
}

impl Stream for RoundEventStream {
	type Item = Arc<RoundEvent>;

	fn poll_next(
		mut self: Pin<&mut Self>,
		cx: &mut std::task::Context,
	) -> Poll<Option<Self::Item>> {
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
		let events = BroadcastStream::new(self.round_event_tx.subscribe());
		RoundEventStream { events }
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
	/// The key used for unblinding unified mailbox ids
	mailbox_key: Secret<Keypair>,
	mailbox_pubkey: PublicKey, // public key part of former
	mailbox_manager: Arc<MailboxManager>,
	/// The keypair used to generate ephemeral keys using tweaks
	ephemeral_master_key: Secret<Keypair>,
	// NB this needs to be an Arc so we can take a static guard
	rounds_wallet: Arc<tokio::sync::Mutex<PersistedWallet>>,
	bitcoind: BitcoinRpcClient,
	sync_manager: SyncManager,
	rtmgr: RuntimeManager,
	tx_nursery: TxNursery,
	vtxo_sweeper: Option<VtxoSweeper>,
	rounds: RoundHandle,
	// nb we store Option because remove is costly, we take the option and clean up later
	forfeit_nonces: parking_lot::Mutex<TimedEntryMap<VtxoId, Option<HarkForfeitNonces>>>,
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

	pub fn mailbox_pubkey(&self) -> PublicKey {
		self.mailbox_pubkey
	}

	pub fn ark_info(&self) -> ark::ArkInfo {
		ark::ArkInfo {
			network: self.config.network,
			server_pubkey: self.server_pubkey,
			mailbox_pubkey: self.mailbox_pubkey,
			round_interval: self.config.round_interval,
			nb_round_nonces: self.config.nb_round_nonces,
			vtxo_exit_delta: self.config.vtxo_exit_delta,
			vtxo_expiry_delta: self.config.vtxo_lifetime,
			htlc_send_expiry_delta: self.config.htlc_send_expiry_delta,
			htlc_expiry_delta: self.config.htlc_expiry_delta,
			max_vtxo_amount: self.config.max_vtxo_amount,
			required_board_confirmations: self.config.required_board_confirmations,
			max_user_invoice_cltv_delta: self.config.max_user_invoice_cltv_delta,
			min_board_amount: self.config.min_board_amount,
			offboard_feerate: self.config.offboard_feerate,
			offboard_fixed_fee_vb: self.config.offboard_fixed_fee_vb,
			ln_receive_anti_dos_required: self.config.ln_receive_anti_dos_required,
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
		let seed = wallet::read_mnemonic_from_datadir(&cfg.data_dir)?.to_seed("");
		let master_xpriv = bip32::Xpriv::new_master(cfg.network, &seed).unwrap();

		let server_key = {
			let path = bip32::DerivationPath::from_str(SERVER_KEY_PATH).unwrap();
			let xpriv = master_xpriv.derive_priv(&SECP, &path).unwrap();
			Keypair::from_secret_key(&SECP, &xpriv.private_key)
		};

		let mailbox_key = {
			let path = bip32::DerivationPath::from_str(MAILBOX_KEY_PATH).unwrap();
			let xpriv = master_xpriv.derive_priv(&SECP, &path).unwrap();
			Keypair::from_secret_key(&SECP, &xpriv.private_key)
		};

		telemetry::init_telemetry::<telemetry::Captaind>(
			cfg.otel_collector_endpoint.clone(),
			cfg.otel_tracing_sampler,
			cfg.otel_deployment_name.as_str(),
			cfg.network,
			cfg.round_interval,
			cfg.max_vtxo_amount,
			server_key.public_key(),
		);
		info!("Running with config: {:#?}", cfg);

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

		let deep_tip = bitcoind.deep_tip().context("failed to query node for deep tip")?;
		let mut rounds_wallet = Self::open_round_wallet(&cfg, db.clone(), &master_xpriv, deep_tip)
			.await.context("error loading wallet")?;

		let ephemeral_master_key = {
			let path = bip32::DerivationPath::from_str(EPHEMERAL_KEY_PATH).unwrap();
			let xpriv = master_xpriv.derive_priv(&SECP, &path).unwrap();
			Keypair::from_secret_key(&SECP, &xpriv.private_key)
		};

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

		let sync_manager = SyncManager::start(
			rtmgr.clone(),
			bitcoind.clone(),
			db.clone(),
			vec![],
			deep_tip,
			cfg.sync_manager_block_poll_interval,
		).await.context("Failed to start SyncManager")?;

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
		let mailbox_manager = Arc::new(MailboxManager::new());

		let srv = Server {
			rounds_wallet: Arc::new(tokio::sync::Mutex::new(rounds_wallet)),
			rounds: RoundHandle {
				round_event_tx,
				last_round_event: parking_lot::Mutex::new(None),
				round_input_tx,
				round_trigger_tx,
			},
			forfeit_nonces: parking_lot::Mutex::new(TimedEntryMap::new()),
			vtxos_in_flux: VtxosInFlux::new(),
			config: cfg.clone(),
			db,
			server_pubkey: server_key.public_key(),
			server_key: Secret::new(server_key),
			mailbox_pubkey: mailbox_key.public_key(),
			mailbox_key: Secret::new(mailbox_key),
			mailbox_manager,
			ephemeral_master_key: Secret::new(ephemeral_master_key),
			bitcoind,
			sync_manager,
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
		self.sync_manager.chain_tip()
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

		slog!(RegisteredBoard,
			onchain_utxo: vtxo.chain_anchor(),
			vtxo: vtxo.point(),
			amount: vtxo.amount(),
		);

		Ok(())
	}

	pub async fn check_vtxos_not_exited<V: VtxoRef>(
		&self,
		vtxos: impl IntoIterator<Item=V>
	) -> anyhow::Result<()> {
		for vtxo in vtxos {
			let vtxo_id = vtxo.vtxo_id();
			let txid = vtxo_id.utxo().txid;
			let status = self.bitcoind.tx_status(&txid)?;

			match status {
				TxStatus::Confirmed(_) => {
					// TODO: should we mark vtxo as spent here?
					return badarg!("cannot spend vtxo that is already exited: {}", vtxo_id);
				},
				TxStatus::Mempool => {
					return badarg!("cannot spend vtxo that is being exited: {}", vtxo_id);
				},
				TxStatus::NotFound => {},
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
		let _guard = self.vtxos_in_flux.lock(&input_ids)
			.map_err(|e| { slog!(ArkoorInputAlreadyInFlux, vtxo: e.id); e })
			.badarg("attempted to sign arkoor tx for VTXO already locked")?;

		match self.db.check_set_vtxo_oor_spent_package(&builder).await {
			Ok(Some(dup)) => {
				badarg!("attempted to sign arkoor tx for already spent vtxo {}", dup)
			},
			Ok(None) => {
				let output_vtxo_ids = builder.new_vtxos().into_iter().flatten()
					.map(|v| v.id()).collect::<Vec<_>>();
				let input_vtxo_ids = input_ids.into_iter().map(|id| id).collect::<Vec<_>>();
				slog!(ArkoorCosign, input_ids: input_vtxo_ids, output_ids: output_vtxo_ids);
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

		let builder = ArkoorPackageBuilder::from_arkoors(arkoors)
			.badarg("error creating arkoor package")?;

		self.cosign_oor_package_with_builder(&builder).await
	}

	/// Unblind a [BlindedMailboxIdentifier]
	pub fn unblind_mailbox_id(
		&self,
		blinded: BlindedMailboxIdentifier,
		vtxo_pubkey: PublicKey,
	) -> MailboxIdentifier {
		MailboxIdentifier::from_blinded(blinded, vtxo_pubkey, self.mailbox_key.leak_ref())
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
		unlock_preimage: UnlockPreimage,
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
			unlock_preimage,
			expiry_height,
			self.server_key.leak_ref().public_key(),
			server_cosign_pubkey,
			self.config.vtxo_exit_delta,
			utxo,
			pub_nonces,
		)?;
		Ok(builder.server_cosign(&cosign_key))
	}

	/// Cosign the hArk leaf VTXO
	pub fn cosign_hashlocked_leaf(
		&self,
		request: &LeafVtxoCosignRequest,
		vtxo: &Vtxo,
		funding_tx: &Transaction,
	) -> LeafVtxoCosignResponse {
		// NB there is no danger in doing this multiple times
		// because user needs the preimage alongside the signature

		trace!("Signing hArk leaf for VTXO {}", request.vtxo_id);
		let ret = LeafVtxoCosignResponse::new_cosign(
			request, vtxo, funding_tx, self.server_key.leak_ref(),
		);
		slog!(HarkLeafSigned, vtxo_id: request.vtxo_id, funding_txid: funding_tx.compute_txid());
		ret
	}

	/// Cosign the hArk leaf VTXO from a known round
	pub async fn cosign_hashlocked_leaf_round(
		&self,
		request: &LeafVtxoCosignRequest,
	) -> anyhow::Result<LeafVtxoCosignResponse> {
		let [vtxo] = self.db.get_vtxos_by_id(&[request.vtxo_id]).await?
			.try_into().expect("one argument one response");
		let round_id = RoundId::new(vtxo.vtxo.chain_anchor().txid);
		let round = self.db.get_round(round_id).await?
			.badarg("VTXO's chain anchor is not a known round")?;
		Ok(self.cosign_hashlocked_leaf(request, &vtxo.vtxo, &round.funding_tx))
	}

	/// Register a set of new VTXOs
	///
	/// This should only be called once we trust that the root of the tree
	/// will confirm.
	pub async fn register_vtxos<V: Borrow<Vtxo>>(
		&self,
		vtxos: impl IntoIterator<Item = V>,
	) -> anyhow::Result<()> {
		self.db.upsert_vtxos(vtxos).await.context("db error occurred")
	}
}

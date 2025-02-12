

#[macro_use] extern crate anyhow;
#[macro_use] extern crate log;
#[macro_use] extern crate serde;
#[macro_use] extern crate aspd_log;

mod bitcoind;
mod database;
mod lightning;
mod psbtext;
mod serde_util;
mod vtxo_sweeper;
mod rpcserver;
mod round;
mod txindex;
mod telemetry;

use std::borrow::Borrow;
use std::collections::HashSet;
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use bitcoin::{bip32, Address, Amount, FeeRate, Network, Transaction};
use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::{self, Keypair, PublicKey};
use lightning_invoice::Bolt11Invoice;
use opentelemetry::KeyValue;
use tokio::time::MissedTickBehavior;
use tokio::sync::{broadcast, Mutex};
use tokio_stream::{StreamExt, Stream};
use tokio_stream::wrappers::{BroadcastStream, IntervalStream};

use ark::{musig, BlockHeight, BlockRef, OnboardVtxo, Vtxo, VtxoId, VtxoSpec};
use ark::lightning::Bolt11Payment;
use ark::rounds::RoundEvent;
use aspd_rpc as rpc;
use bark_cln::subscribe_sendpay::SendpaySubscriptionItem;

use crate::bitcoind::{BitcoinRpcClient, BitcoinRpcErrorExt, BitcoinRpcExt, RpcApi};
use crate::round::RoundInput;
use crate::telemetry::init_telemetry;
use crate::txindex::TxIndex;

lazy_static::lazy_static! {
	/// Global secp context.
	static ref SECP: secp256k1::Secp256k1<secp256k1::All> = secp256k1::Secp256k1::new();
}

/// The number of confirmations after which we consider the odds of a reorg
/// happening negligible.
const DEEPLY_CONFIRMED: BlockHeight = 12;

/// The HD keypath to use for the ASP key.
const ASP_KEY_PATH: &str = "m/2'/0'";

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
	pub network: bitcoin::Network,
	pub public_rpc_address: SocketAddr,
	pub admin_rpc_address: Option<SocketAddr>,
	pub bitcoind_url: String,
	pub bitcoind_cookie: Option<PathBuf>,
	pub bitcoind_rpc_user: Option<String>,
	pub bitcoind_rpc_pass: Option<String>,
	pub otel_collector_endpoint: Option<String>,

	// vtxo spec
	pub vtxo_expiry_delta: u16,
	pub vtxo_exit_delta: u16,

	// ln
	pub htlc_delta: u16,
	pub htlc_expiry_delta: u16,

	pub round_interval: Duration,
	pub round_submit_time: Duration,
	pub round_sign_time: Duration,
	pub nb_round_nonces: usize,
	/// Number of confirmations needed for onboard vtxos to be spend in rounds.
	pub round_onboard_confirmations: usize,
	//TODO(stevenroose) get these from a fee estimator service
	/// Fee rate used for the round tx.
	pub round_tx_feerate: FeeRate,
	/// Fallback feerate for sweep txs.
	pub sweep_tx_fallback_feerate: FeeRate,

	/// Interval at which to sweep expired rounds.
	pub round_sweep_interval: Duration,
	/// Don't make sweep txs for amounts lower than this amount.
	pub sweep_threshold: Amount,

	// limits
	#[serde(rename = "max_onboard_value_sat", with = "bitcoin::amount::serde::as_sat::opt")]
	pub max_onboard_value: Option<Amount>,

	// lightning
	#[serde(skip_serializing_if = "Option::is_none")]
	#[serde(default)]
	pub cln_config: Option<ClnConfig>
}

// NB some random defaults to have something
impl Default for Config {
	fn default() -> Config {
		Config {
			network: bitcoin::Network::Regtest,
			public_rpc_address: "0.0.0.0:3535".parse().unwrap(),
			admin_rpc_address: Some("127.0.0.1:3536".parse().unwrap()),
			bitcoind_url: "http://127.0.0.1:38332".into(),
			bitcoind_cookie: Some("~/.bitcoin/signet/.cookie".into()),
			bitcoind_rpc_user: None,
			bitcoind_rpc_pass: None,
			otel_collector_endpoint: Some("http://127.0.0.1:4317".parse().unwrap()),
			vtxo_expiry_delta: 1 * 24 * 6, // 1 day
			vtxo_exit_delta: 2 * 6, // 2 hrs
			htlc_delta: 1 * 6, // 1 hr
			htlc_expiry_delta: 1 * 6, // 1 hr
			round_interval: Duration::from_secs(10),
			round_submit_time: Duration::from_secs(2),
			round_sign_time: Duration::from_secs(2),
			nb_round_nonces: 10,
			round_onboard_confirmations: 12,
			round_tx_feerate: FeeRate::from_sat_per_vb(10).unwrap(),
			sweep_tx_fallback_feerate: FeeRate::from_sat_per_vb(10).unwrap(),
			round_sweep_interval: Duration::from_secs(1 * 60 * 60), // 1 hr
			sweep_threshold: Amount::from_sat(1_000_000),
			max_onboard_value: None,
			cln_config: None,
		}
	}
}

impl Config {
	fn bitcoind_auth(&self) -> bdk_bitcoind_rpc::bitcoincore_rpc::Auth {
		match (&self.bitcoind_rpc_user, &self.bitcoind_rpc_pass) {
			(Some(user), Some(pass)) => {
				return bdk_bitcoind_rpc::bitcoincore_rpc::Auth::UserPass(user.into(), pass.into());
			},
			(Some(_), None) => panic!("Missing configuration for bitcoind_rpc_pass."),
			(None, Some(_)) => panic!("Missing configurationfor bitcoind_rpc_user."),
			(None, None) => {} // Do nothing,
		};

		let bitcoind_cookie_file = self.bitcoind_cookie.as_ref()
			.expect("The bitcoind-cookie must be set if username and password aren't provided");
		bdk_bitcoind_rpc::bitcoincore_rpc::Auth::CookieFile(bitcoind_cookie_file.into())
	}
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ClnConfig {
	#[serde(with = "serde_util::uri")]
	pub grpc_uri: tonic::transport::Uri,
	pub grpc_server_cert_path: PathBuf,
	pub grpc_client_cert_path: PathBuf,
	pub grpc_client_key_path: PathBuf,
}

impl Config {
	pub fn read_from_datadir<P: AsRef<Path>>(datadir: P) -> anyhow::Result<Self> {
		let path = datadir.as_ref().join("config.json");
		trace!("Reading configuraton from file {}", path.display());
		let bytes = fs::read(&path)
			.with_context(|| format!("failed to read config file: {}", path.display()))?;

		serde_json::from_slice::<Self>(&bytes).context("invalid config file")
	}

	pub fn write_to_datadir<P: AsRef<Path>>(&self, datadir: P) -> anyhow::Result<()> {
		let path = datadir.as_ref().join("config.json");
		trace!("Dumping configuration from file {}", path.display());

		// write the config to disk
		let config_str = serde_json::to_string_pretty(&self)?;
		fs::write(path, config_str.as_bytes())
			.context("failed to write config file")?;

			Ok(())
	}

	pub fn create_backup_in_datadir<P: AsRef<Path>>(datadir: P) -> anyhow::Result<()> {
		let mut index = 0;
		let source = datadir.as_ref().join("config.json");

		// Create the destination file-path
		// We don't delete data
		let mut destination = datadir.as_ref().join(format!("config.backup.json.v{}", index));
		while destination.exists() {
			index+=1;
			destination = datadir.as_ref().join(format!("config.backup.json.v{}", index))
		}

		// Create the copy
		fs::copy(source, destination).context("Failed to create back-up")?;
		Ok(())
	}
}

pub struct RoundHandle {
	round_event_tx: tokio::sync::broadcast::Sender<RoundEvent>,
	round_input_tx: tokio::sync::mpsc::UnboundedSender<RoundInput>,
	round_trigger_tx: tokio::sync::mpsc::Sender<()>,
}

pub struct SendpayHandle {
	sendpay_rx: tokio::sync::broadcast::Receiver<SendpaySubscriptionItem>
}

pub struct App {
	config: Config,
	db: database::Db,
	shutdown_channel: broadcast::Sender<()>,
	asp_key: Keypair,
	// NB this needs to be an Arc so we can take a static guard
	wallet: Arc<Mutex<bdk_wallet::Wallet>>,
	bitcoind: BitcoinRpcClient,
	chain_tip: Mutex<BlockRef>,
	txindex: TxIndex,

	rounds: Option<RoundHandle>,
	/// All vtxos that are currently being processed in any way.
	/// (Plus a small buffer to optimize allocations.)
	vtxos_in_flux: Mutex<VtxosInFlux>,
	sendpay_updates: Option<SendpayHandle>,
	trigger_round_sweep_tx: Option<tokio::sync::mpsc::Sender<()>>,
}

impl App {
	/// Return the bdk wallet struct and the ASP keypair.
	fn wallet_from_seed(
		network: Network,
		seed: &[u8],
		state: Option<bdk_wallet::ChangeSet>,
	) -> anyhow::Result<(bdk_wallet::Wallet, Keypair)> {
		let seed_xpriv = bip32::Xpriv::new_master(network, &seed).unwrap();

		let desc = format!("tr({}/84'/0'/0'/0/*)", seed_xpriv);
		let wallet = if let Some(changeset) = state {
			bdk_wallet::Wallet::load()
				.descriptor(bdk_wallet::KeychainKind::External, Some(desc))
				.check_network(network)
				.extract_keys()
				.load_wallet_no_persist(changeset)?
				.expect("wallet should be loaded")
		} else {
			bdk_wallet::Wallet::create_single(desc)
				.network(network)
				.create_wallet_no_persist()?
		};

		let asp_path = bip32::DerivationPath::from_str(ASP_KEY_PATH).unwrap();
		let asp_xpriv = seed_xpriv.derive_priv(&SECP, &asp_path).unwrap();
		let asp_key = Keypair::from_secret_key(&SECP, &asp_xpriv.private_key);

		Ok((wallet, asp_key))
	}

	pub async fn create(datadir: &Path, config: Config) -> anyhow::Result<()> {
		info!("Creating aspd server at {}", datadir.display());
		trace!("Config: {:?}", config);

		// create dir if not exit, but check that it's empty
		fs::create_dir_all(&datadir).context("can't create dir")?;
		if fs::read_dir(&datadir).context("can't read dir")?.next().is_some() {
			bail!("dir is not empty");
		}

		let bitcoind = BitcoinRpcClient::new(&config.bitcoind_url, config.bitcoind_auth())
			.context("failed to create bitcoind rpc client")?;
		let deep_tip = (|| {
			let tip = bitcoind.get_block_count()?;
			let deep = tip.saturating_sub(DEEPLY_CONFIRMED);
			let hash = bitcoind.get_block_hash(deep)?;
			let header = bitcoind.get_block_header_info(&hash)?;
			let block_id = bdk_wallet::chain::BlockId {
				height: header.height as u32,
				hash: header.hash,
			};
			Ok::<_, anyhow::Error>(block_id)
		})().context("failed to fetch deep tip from bitcoind")?;

		// write the config to disk
		let config_str = serde_json::to_string_pretty(&config)
			.expect("serialization can't error");
		fs::write(datadir.join("config.json"), config_str.as_bytes())
			.context("failed to write config file")?;

		// create mnemonic and store in empty db
		let db_path = datadir.join("aspd_db");
		info!("Loading db at {}", db_path.display());
		let db = database::Db::open(&db_path).context("failed to open db")?;

		// Initiate key material.
		let mnemonic = bip39::Mnemonic::generate(12).expect("12 is valid");
		db.store_master_mnemonic_and_seed(&mnemonic)
			.context("failed to store mnemonic")?;

		// Store initial wallet state to avoid full chain sync.
		let seed = mnemonic.to_seed("");
		let (mut wallet, _) = Self::wallet_from_seed(config.network, &seed, None)
			.expect("shouldn't fail on empty state");
		wallet.apply_update(bdk_wallet::Update {
			chain: Some(wallet.latest_checkpoint().insert(deep_tip)),
			..Default::default()
		}).expect("should work, might fail if tip is genesis");
		let cs = wallet.take_staged().expect("should have stored tip");
		ensure!(db.read_aggregate_changeset().await.context("db error")?.is_none(), "db not empty");
		db.store_changeset(&cs).await.context("error storing initial wallet state")?;

		Ok(())
	}

	pub async fn open(datadir: &Path) -> anyhow::Result<Arc<Self>> {
		info!("Starting aspd at {}", datadir.display());

		let config = Config::read_from_datadir(datadir)?;
		trace!("Config: {:?}", config);

		let db_path = datadir.join("aspd_db");
		info!("Loading db at {}", db_path.display());
		let db = database::Db::open(&db_path).context("failed to open db")?;

		let seed = db.get_master_seed()
			.context("db error")?
			.context("db doesn't contain seed")?;
		let init = db.read_aggregate_changeset().await?;
		let (wallet, asp_key) = Self::wallet_from_seed(config.network, &seed, init)
			.context("error loading wallet")?;

		let bitcoind = BitcoinRpcClient::new(&config.bitcoind_url, config.bitcoind_auth())
			.context("failed to create bitcoind rpc client")?;

		let (shutdown_channel, _) = broadcast::channel::<()>(1);
		Ok(Arc::new(App {
			wallet: Arc::new(Mutex::new(wallet)),
			txindex: TxIndex::new(),
			chain_tip: Mutex::new(bitcoind.tip().context("failed to fetch tip")?),
			rounds: None,
			vtxos_in_flux: Mutex::new(VtxosInFlux::default()),
			trigger_round_sweep_tx: None,
			sendpay_updates: None,
			config,
			db,
			shutdown_channel,
			asp_key,
			bitcoind,
		}))
	}

	/// Load all relevant txs from the database into the tx index.
	pub async fn fill_txindex(self: &Arc<Self>) -> anyhow::Result<()> {
		// Load all round txs into the txindex.
		for res in self.db.fetch_all_rounds() {
			let round = res?;
			trace!("Adding txs for round {} to txindex", round.id());
			self.txindex.register(round.tx).await;
			self.txindex.register_batch(round.signed_tree.all_signed_txs()).await;
		}

		// Load all onboard reveal txs into the txindex.
		for res in self.db.get_expired_onboards(BlockHeight::MAX) {
			let onboard = res?;
			trace!("Adding onboard vtxo {} to txindex", onboard.id());
			self.txindex.register(onboard.reveal_tx()).await;
		}
		Ok(())
	}

	/// Perform all startup processes.
	async fn startup(self: &Arc<Self>) -> anyhow::Result<()> {
		// Check if our bitcoind is on the expected network.
		let chain_info = self.bitcoind.get_blockchain_info()?;
		if chain_info.chain != self.config.network {
			bail!("Our bitcoind is running on network {} while we are configured for network {}",
				chain_info.chain, self.config.network,
			);
		}

		// Start loading txindex.
		self.fill_txindex().await.context("error filling txindex")?;

		Ok(())
	}

	pub async fn start(self: &mut Arc<Self>) -> anyhow::Result<()> {
		let (round_event_tx, _rx) = tokio::sync::broadcast::channel(8);
		let (round_input_tx, round_input_rx) = tokio::sync::mpsc::unbounded_channel();
		let (round_trigger_tx, round_trigger_rx) = tokio::sync::mpsc::channel(1);
		let (sweep_trigger_tx, sweep_trigger_rx) = tokio::sync::mpsc::channel(1);
		let (sendpay_tx, sendpay_rx) = broadcast::channel(1024);

		let mut_self = Arc::get_mut(self).context("can only start if we are unique Arc")?;
		mut_self.rounds = Some(RoundHandle { round_event_tx, round_input_tx, round_trigger_tx });
		mut_self.sendpay_updates = Some(SendpayHandle { sendpay_rx });
		mut_self.trigger_round_sweep_tx = Some(sweep_trigger_tx);
		let jh_txindex = mut_self.txindex.start(
			mut_self.bitcoind.clone(),
			Duration::from_secs(2),
			mut_self.shutdown_channel.subscribe(),
		);


		// First perform all startup tasks...
		info!("Starting startup tasks...");
		self.startup().await.context("startup error")?;
		info!("Startup tasks done");


		// Then start all our subprocesses
		let spawn_counter = init_telemetry(self)?;

		// Spawn a task to handle Ctrl+C
		let shutdown_channel = self.shutdown_channel.clone();
		tokio::spawn(async move {
			tokio::signal::ctrl_c()
				.await
				.expect("Failed to listen for Ctrl+C");
			info!("Ctrl+C received! Sending shutdown signal...");
			let _ = shutdown_channel.send(());
			for i in (1..=60).rev() {
				info!("Forced exit in {} seconds...", i);
				tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
			}
			std::process::exit(0);
		});

		let app = self.clone();
		let jh_rpc_public = tokio::spawn(async move {
			let ret = rpcserver::run_public_rpc_server(app)
				.await.context("error running public gRPC server");
			info!("RPC server exited with {:?}", ret);
			ret
		});
		spawn_counter.as_ref().map(|sc| {
			sc.add(1, &[KeyValue::new("spawn", "rpcserver::run_public_rpc_server")])
		});

		let app = self.clone();
		let jh_round_coord = tokio::spawn(async move {
			let ret = round::run_round_coordinator(&app, round_input_rx, round_trigger_rx)
				.await.context("error from round scheduler");
			info!("Round coordinator exited with {:?}", ret);
			ret
		});
		spawn_counter.as_ref().map(|sc| {
			sc.add(1, &[KeyValue::new("spawn", "round::run_round_coordinator")])
		});

		let app = self.clone();
		let jh_round_sweeper = tokio::spawn(async move {
			let ret = vtxo_sweeper::run_vtxo_sweeper(&app, sweep_trigger_rx)
				.await.context("error from round sweeper");
			info!("Round sweeper exited with {:?}", ret);
			ret
		});
		spawn_counter.as_ref().map(|sc| {
			sc.add(1, &[KeyValue::new("spawn", "vtxo_sweeper::run_vtxo_sweeper")])
		});

		let app = self.clone();
		let mut shutdown = app.shutdown_channel.clone().subscribe();
		let jh_tip_fetcher = tokio::spawn(async move {
			loop {
				tokio::select! {
					// Periodic interval for chain tip fetch
					() = tokio::time::sleep(Duration::from_secs(1)) => {},
					_ = shutdown.recv() => {
						info!("Shutdown signal received. Exiting fetch_tip loop...");
						break;
					}
				}

				match app.bitcoind.tip() {
					Ok(t) => {
						let mut lock = app.chain_tip.lock().await;
						if t != *lock {
							*lock = t;
							slog!(TipUpdated, height: t.height, hash: t.hash);
						}
					}
					Err(e) => {
						warn!("Error getting chain tip from bitcoind: {}", e);
					},
				}
			}

			info!("Chain tip loop terminated gracefully.");

			Ok(())
		});
		spawn_counter.as_ref().map(|sc| sc.add(1, &[KeyValue::new("spawn", "fetch_tip")]));

		// The tasks that always run
		let mut jhs = vec![
			jh_txindex,
			jh_rpc_public,
			jh_round_coord,
			jh_round_sweeper,
			jh_tip_fetcher,
		];

		// These tasks do only run if the config is provided
		if self.config.admin_rpc_address.is_some() {
			let app = self.clone();
			let jh_rpc_admin = tokio::spawn(async move {
				let ret = rpcserver::run_admin_rpc_server(app)
					.await.context("error running admin gRPC server");
				info!("Admin RPC server exited with {:?}", ret);
				ret
			});
			spawn_counter.as_ref().map(|sc| {
				sc.add(1, &[KeyValue::new("spawn", "rpcserver::run_admin_rpc_server")])
			});

			jhs.push(jh_rpc_admin)
		}

		let app = self.clone();
		if self.config.cln_config.is_some() {
			let cln_config = self.config.cln_config.clone().unwrap();
			let jh_sendpay = tokio::spawn(async move {
				let shutdown = app.shutdown_channel.clone();
				let ret = lightning::run_process_sendpay_updates(shutdown, &cln_config, sendpay_tx)
					.await.context("error processing sendpays");
				info!("Sendpay updater process exited with {:?}", ret);
				ret
			});
			spawn_counter.as_ref().map(|sc| {
				sc.add(1, &[KeyValue::new("spawn", "lightning::run_process_sendpay_updates")])
			});

			jhs.push(jh_sendpay)
		}

		// Wait until the first task finishes
		futures::future::try_join_all(jhs).await
			.context("one of our background processes errored")?;

		slog!(AspdTerminated);

		Ok(())
	}

	pub async fn chain_tip(&self) -> BlockRef {
		self.chain_tip.lock().await.clone()
	}

	pub fn try_rounds(&self) -> anyhow::Result<&RoundHandle> {
		self.rounds.as_ref().context("no round scheduler started yet")
	}

	pub fn rounds(&self) -> &RoundHandle {
		self.try_rounds().expect("should only call this in round scheduler code")
	}

	pub async fn new_onchain_address(&self) -> anyhow::Result<Address> {
		let mut wallet = self.wallet.lock().await;
		let ret = wallet.reveal_next_address(bdk_wallet::KeychainKind::External).address;
		if let Some(change) = wallet.take_staged() {
			self.db.store_changeset(&change).await?;
		}
		Ok(ret)
	}

	pub async fn sync_onchain_wallet(&self) -> anyhow::Result<Amount> {
		let mut wallet = self.wallet.lock().await;
		let prev_tip = wallet.latest_checkpoint();
		let prev_balance = wallet.balance();
		// let keychain_spks = self.wallet.spks_of_all_keychains();

		slog!(WalletSyncStarting, block_height: prev_tip.height());
		let mut emitter = bdk_bitcoind_rpc::Emitter::new(
			&self.bitcoind, prev_tip.clone(), prev_tip.height(),
		);
		while let Some(em) = emitter.next_block()? {
			wallet.apply_block_connected_to(&em.block, em.block_height(), em.connected_to())?;

			if em.block_height() % 10_000 == 0 {
				slog!(WalletSyncCommittingProgress, block_height: prev_tip.height());
				if let Some(change) = wallet.take_staged() {
					self.db.store_changeset(&change).await?;
				}
			}
		}

		// mempool
		let mempool = emitter.mempool()?;
		wallet.apply_unconfirmed_txs(mempool.into_iter().map(|(tx, time)| (tx, time)));
		if let Some(change) = wallet.take_staged() {
			self.db.store_changeset(&change).await?;
		}

		// rebroadcast unconfirmed txs
		// NB during some round failures we commit a tx but fail to broadcast it,
		// so this ensures we still broadcast them afterwards
		for tx in wallet.transactions() {
			if !tx.chain_position.is_confirmed() {
				if let Err(e) = self.bitcoind.broadcast_tx(&*tx.tx_node.tx) {
					slog!(WalletTransactionBroadcastFailure, error: e.to_string(), txid: tx.tx_node.txid);
				}
			}
		}

		let checkpoint = wallet.latest_checkpoint();
		slog!(WalletSyncComplete, new_block_height: checkpoint.height(), previous_block_height: prev_tip.height());

		let balance = wallet.balance();
		if balance != prev_balance {
			slog!(WalletBalanceUpdated, balance: balance.clone(), network: wallet.network(), block_height: checkpoint.height());
		} else {
			slog!(WalletBalanceUnchanged, balance: balance.clone(), network: wallet.network(), block_height: checkpoint.height());
		}
		Ok(balance.total())
	}

	pub async fn drain(
		&self,
		address: Address<bitcoin::address::NetworkUnchecked>,
	) -> anyhow::Result<Transaction> {
		//TODO(stevenroose) also claim all expired round vtxos here!

		let addr = address.require_network(self.config.network)?;

		let mut wallet = self.wallet.lock().await;
		let mut b = wallet.build_tx();
		b.drain_to(addr.script_pubkey());
		b.drain_wallet();
		let mut psbt = b.finish().context("error building tx")?;
		let finalized = wallet.sign(&mut psbt, bdk_wallet::SignOptions::default())?;
		assert!(finalized);
		let tx = psbt.extract_tx()?;
		if let Some(change) = wallet.take_staged() {
			self.db.store_changeset(&change).await?;
		}
		drop(wallet);

		if let Err(e) = self.bitcoind.broadcast_tx(&tx) {
			error!("Error broadcasting tx: {}", e);
			error!("Try yourself: {}", bitcoin::consensus::encode::serialize_hex(&tx));
		}

		Ok(tx)
	}

	/// Atomically store either all vtxos as being in flux, or none of them.
	///
	/// If one of them is already in flux, an error is returned containing it,
	/// and none of the other ones are stored as in flux.
	pub async fn atomic_check_put_vtxo_in_flux<V: Borrow<VtxoId>>(
		&self,
		ids: impl IntoIterator<Item = V>,
	) -> Result<(), VtxoId> {
		self.vtxos_in_flux.lock().await.atomic_check_put(ids)
	}

	/// Release the vtxos from flux.
	pub async fn release_vtxos_in_flux<V: Borrow<VtxoId>>(
		&self,
		ids: impl IntoIterator<Item = V>,
	) {
		self.vtxos_in_flux.lock().await.release(ids)
	}

	pub fn cosign_onboard(&self, user_part: ark::onboard::UserPart) -> ark::onboard::AspPart {
		info!("Cosigning onboard request for utxo {}", user_part.utxo);
		let ret = ark::onboard::new_asp(&user_part, &self.asp_key);
		slog!(CosignedOnboard, utxo: user_part.utxo, amount: user_part.spec.amount,
			reveal_txid: ark::onboard::create_reveal_tx(&user_part.spec, user_part.utxo, None).compute_txid(),
		);
		ret
	}

	pub fn validate_onboard_spec(&self, spec: &VtxoSpec) -> anyhow::Result<()> {
		let tip = self.bitcoind.get_block_count()? as u32;

		if spec.asp_pubkey != self.asp_key.public_key() {
			bail!("invalid asp pubkey: {} != {}", spec.asp_pubkey, self.asp_key.public_key());
		}

		//TODO(stevenroose) make this more robust
		if spec.expiry_height < tip {
			bail!("vtxo already expired: {} (tip = {})", spec.expiry_height, tip);
		}

		if spec.exit_delta != self.config.vtxo_exit_delta {
			bail!("invalid exit delta: {} != {}", spec.exit_delta, self.config.vtxo_exit_delta);
		}

		Ok(())
	}

	pub async fn register_onboard(
		&self,
		vtxo: OnboardVtxo,
		tx: Transaction,
	) -> anyhow::Result<()> {
		self.validate_onboard_spec(&vtxo.spec).context("invalid onboard vtxo spec")?;
		vtxo.validate_tx(&tx).context("onboard tx doesn't match vtxo spec")?;

		// Since the user might have just created and broadcast this tx very recently,
		// it's very likely that we won't have it in our mempool yet.
		// We will first check if we have it, if not, try to broadcast it.
		match self.bitcoind.get_raw_transaction_info(&vtxo.onchain_output.txid, None) {
			Ok(txinfo) => {
				let conf = txinfo.confirmations.unwrap_or(0);
				trace!("Onboard tx {} has {} confirmations", vtxo.onchain_output.txid, conf);
			},
			Err(e) if e.is_not_found() => {
				// First check if the tx is actually standard and inputs are unspent.
				let ret = self.bitcoind.test_mempool_accept(&[&tx])?
					.into_iter().next().expect("we submitted one");
				if !ret.allowed {
					bail!("Tx not allowed in mempool: {}",
						ret.reject_reason.as_ref().map(|s| s.as_str()).unwrap_or("unknown"),
					);
				}

				// Then broadcast to our own mempool and peers.
				if let Err(e) = self.bitcoind.broadcast_tx(&tx) {
					if !e.is_already_in_mempool() {
						bail!("onboard tx not accepted in mempool");
					}
				}
				trace!("We submitted onboard tx with txid {} to mempool", vtxo.onchain_output.txid);
			},
			Err(e) => return Err(anyhow!("error fetching tx info for onboard tx: {e}")),
		}

		// Accepted, let's register
		self.txindex.register(vtxo.reveal_tx()).await;
		self.db.insert_onboard_vtxos(&[&vtxo]).context("db error")?;

		slog!(RegisteredOnboard, onchain_utxo: vtxo.onchain_output, vtxo: vtxo.point(),
			amount: vtxo.spec.amount,
		);

		Ok(())
	}

	pub async fn cosign_oor(
		&self,
		payment: &ark::oor::OorPayment,
		user_nonces: &[musig::MusigPubNonce],
	) -> anyhow::Result<(Vec<musig::MusigPubNonce>, Vec<musig::MusigPartialSignature>)> {
		let ids = payment.inputs.iter().map(|v| v.id()).collect::<Vec<_>>();

		if let Err(id) = self.atomic_check_put_vtxo_in_flux(&ids).await {
			bail!("attempted to sign OOR for vtxo already in flux: {}", id);
		}

		let txid = payment.txid();
		let new_vtxos = payment.unsigned_output_vtxos();
		let ret = match self.db.check_set_vtxo_oor_spent(&ids, txid, &new_vtxos) {
			Ok(Some(dup)) => {
				Err(anyhow!("attempted to sign OOR for already spent vtxo {}", dup))
			},
			Ok(None) => {
				info!("Cosigning OOR tx {} with inputs: {:?}", txid, ids);
				let (nonces, sigs) = payment.sign_asp(&self.asp_key, &user_nonces);
				Ok((nonces, sigs))
			},
			Err(e) => Err(e),
		};

		self.release_vtxos_in_flux(ids).await;

		ret
	}

	// lightning

	pub fn start_bolt11(
		&self,
		invoice: Bolt11Invoice,
		amount: Amount,
		input_vtxos: Vec<Vtxo>,
		user_pk: PublicKey,
		user_nonces: &[musig::MusigPubNonce],
	) -> anyhow::Result<(
		Bolt11Payment,
		Vec<musig::MusigPubNonce>,
		Vec<musig::MusigPartialSignature>,
	)> {
		//TODO(stevenroose) check that vtxos are valid

		//TODO(stevenroose) sanity check that inputs match up to the amount

		let expiry = {
			//TODO(stevenroose) bikeshed this
			let tip = self.bitcoind.get_block_count()? as u32;
			tip + 7 * 18
		};
		let details = Bolt11Payment {
			invoice,
			inputs: input_vtxos,
			asp_pubkey: self.asp_key.public_key(),
			user_pubkey: user_pk,
			payment_amount: amount,
			forwarding_fee: Amount::from_sat(350), //TODO(stevenroose) set fee schedule
			htlc_delta: self.config.htlc_delta,
			htlc_expiry_delta: self.config.htlc_expiry_delta,
			htlc_expiry: expiry,
			exit_delta: self.config.vtxo_exit_delta,
		};
		if !details.check_amounts() {
			bail!("invalid amounts");
		}

		// let's sign the tx
		let (nonces, part_sigs) = details.sign_asp(
			&self.asp_key,
			user_nonces,
		);

		Ok((details, nonces, part_sigs))
	}


	/// Returns a stream of updates related to the payment with hash
	fn get_payment_update_stream(&self, payment_hash: sha256::Hash) -> impl Stream<Item = rpc::Bolt11PaymentUpdate> {
		// A progress update is sent every five seconds to give the user an nidication of progress
		let mut interval = tokio::time::interval(Duration::from_secs(5));
		interval.set_missed_tick_behavior(MissedTickBehavior::Delay);

		let heartbeat_stream = IntervalStream::new(interval).map(move |_| {
				rpc::Bolt11PaymentUpdate {
					progress_message: String::from("Your payment is being routed through the lightning network..."),
					payment_hash: payment_hash.as_byte_array().to_vec(),
					status: rpc::PaymentStatus::Pending as i32,
					payment_preimage: None
				}
		});


		// Let event-stream
		let rx = self.sendpay_updates.as_ref().unwrap().sendpay_rx.resubscribe();
		let event_stream = BroadcastStream::new(rx).filter_map(move |v| match v {
			Ok(v) => {
				Some(rpc::Bolt11PaymentUpdate {
					status: rpc::PaymentStatus::from(v.status.clone()) as i32,
					progress_message: format!(
						"{} payment-part for hash {:?} - Attempt {} part {} to status {}",
						v.kind, v.payment_hash, v.group_id, v.part_id, v.status,
					),
					payment_hash: payment_hash.as_byte_array().to_vec(),
					payment_preimage: v.payment_preimage.map(|h| h.as_byte_array().to_vec())
				})
			},
			Err(_) => None,
		});

		heartbeat_stream.merge(event_stream)
	}

	// ** SOME ADMIN COMMANDS **

	pub fn get_master_mnemonic(&self) -> anyhow::Result<String> {
		Ok(self.db.get_master_mnemonic()?.expect("app running"))
	}
}

/// Simple locking structure to keep track of vtxos that are currently in flux.
#[derive(Default)]
struct VtxosInFlux {
	vtxos: HashSet<VtxoId>,
	buf: Vec<VtxoId>,
}

impl VtxosInFlux {
	pub fn atomic_check_put<V: Borrow<VtxoId>>(
		&mut self,
		ids: impl IntoIterator<Item = V>,
	) -> Result<(), VtxoId> {
		let ids_iter = ids.into_iter();
		let min_nb_vtxos = ids_iter.size_hint().0;
		self.buf.clear();
		self.vtxos.reserve(min_nb_vtxos);
		self.buf.reserve(min_nb_vtxos);
		for id in ids_iter {
			let id = *id.borrow();
			if !self.vtxos.insert(id) {
				// abort
				for take in &self.buf {
					self.vtxos.remove(&take);
				}
				return Err(id);
			}
			self.buf.push(id);
		}
		Ok(())
	}

	pub fn release<V: Borrow<VtxoId>>(&mut self, ids: impl IntoIterator<Item = V>) {
		for id in ids {
			self.vtxos.remove(id.borrow());
		}
	}
}

#[cfg(test)]
mod test {
	use super::*;
	use std::iter;
	use bitcoin::secp256k1::rand;

	fn random_vtxoid() -> VtxoId {
		let mut b = [0u8; 36];
		rand::Fill::try_fill(&mut b[..], &mut rand::thread_rng()).unwrap();
		VtxoId::from_slice(&b).unwrap()
	}

	#[test]
	fn test_in_flux() {
		let mut flux = VtxosInFlux::default();
		let vtxos = iter::from_fn(|| Some(random_vtxoid())).take(10).collect::<Vec<_>>();

		flux.atomic_check_put(&[vtxos[0], vtxos[1]]).unwrap();
		flux.atomic_check_put(&[vtxos[2], vtxos[3]]).unwrap();
		assert_eq!(4, flux.vtxos.len());
		flux.atomic_check_put(&[vtxos[0], vtxos[4]]).unwrap_err();
		assert_eq!(4, flux.vtxos.len());
		flux.release(&[vtxos[0]]);
		assert_eq!(3, flux.vtxos.len());
		flux.atomic_check_put(&[vtxos[0], vtxos[4]]).unwrap();
		assert_eq!(5, flux.vtxos.len());

		flux.atomic_check_put(&[vtxos[1], vtxos[5]]).unwrap_err();
		assert_eq!(5, flux.vtxos.len());
		assert!(!flux.vtxos.contains(&vtxos[5]));
	}
}

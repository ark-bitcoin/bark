//!
//! This module defines an alternate server struct that can be used to complement
//! captaind or the main [crate::Server] struct.
//!
//! It runs a subset of the server services, namely those that are not required
//! for user functionality:
//!
//! - the [ForfeitWatcher]
//! - the [VtxoSweeper]
//!

use std::fs;
use std::str::FromStr;
use std::time::Duration;

use anyhow::Context;
use bitcoin::bip32;
use bitcoin::secp256k1::Keypair;
use tracing::info;
use bitcoin_ext::rpc::{BitcoinRpcClient, BitcoinRpcExt, RpcApi};

use crate::{database, fee_estimator, telemetry, wallet, SECP};
use crate::sync::SyncManager;
use crate::config::watchman::Config;
use crate::forfeits::ForfeitWatcher;
use crate::system::RuntimeManager;
use crate::txindex::TxIndex;
use crate::txindex::broadcast::TxNursery;
use crate::sweeps::VtxoSweeper;
use crate::wallet::{PersistedWallet, WalletKind, MNEMONIC_FILE};


/// The HD keypath to use for the server key.
const SERVER_KEY_PATH: &str = "m/2'/0'";


/// Server struct that runs all non-user-facing background services
pub struct Watchman {
	rtmgr: RuntimeManager,
	#[allow(unused)]
	sync_manager: SyncManager,
	pub txindex: TxIndex,
	pub tx_nursery: TxNursery,
	pub forfeit_watcher: ForfeitWatcher,
	pub vtxo_sweeper: VtxoSweeper,
}

impl Watchman {
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
		let wallet_xpriv = seed_xpriv.derive_priv(&*SECP, &[WalletKind::Forfeits.child_number()])
			.expect("can't error");
		let _wallet = PersistedWallet::load_from_xpriv(
			db.clone(), cfg.network, &wallet_xpriv, WalletKind::Forfeits, deep_tip,
		);

		Ok(())
	}

	/// Start the server.
	pub async fn start(cfg: Config) -> anyhow::Result<Self> {
		let seed = wallet::read_mnemonic_from_datadir(&cfg.data_dir)?.to_seed("");
		let master_xpriv = bip32::Xpriv::new_master(cfg.network, &seed).unwrap();
		let server_key_path = bip32::DerivationPath::from_str(SERVER_KEY_PATH).unwrap();
		let server_key_xpriv = master_xpriv.derive_priv(&SECP, &server_key_path).unwrap();
		let server_key = Keypair::from_secret_key(&SECP, &server_key_xpriv.private_key);

		telemetry::init_telemetry::<telemetry::Watchmand>(
			cfg.otel_collector_endpoint.clone(),
			cfg.otel_tracing_sampler,
			cfg.otel_deployment_name.as_str(),
			cfg.network,
			Duration::ZERO,
			None,
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
		// Check if our bitcoind is on the expected network.
		let chain_info = bitcoind.get_blockchain_info()?;
		if chain_info.chain != cfg.network {
			bail!("Our bitcoind is running on network {} while we are configured for network {}",
				chain_info.chain, cfg.network,
			);
		}

		let deep_tip = bitcoind.deep_tip().context("failed to query node for deep tip")?;


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

		let fee_estimator = fee_estimator::start(
			rtmgr.clone(),
			cfg.fee_estimator.clone(),
			bitcoind.clone(),
		);

		let vtxo_sweeper = VtxoSweeper::start(
			rtmgr.clone(),
			cfg.vtxo_sweeper.clone(),
			cfg.network,
			bitcoind.clone(),
			db.clone(),
			txindex.clone(),
			tx_nursery.clone(),
			server_key.clone(),
			cfg.sweep_address.clone().context("no sweep address config set")?
				.require_network(cfg.network).context("sweep address for wrong network")?,
			fee_estimator.clone(),
		).await.context("failed to start VtxoSweeper")?;

		let forfeit_watcher = ForfeitWatcher::start(
			rtmgr.clone(),
			cfg.forfeit_watcher.clone(),
			cfg.network,
			bitcoind.clone(),
			db.clone(),
			txindex.clone(),
			tx_nursery.clone(),
			master_xpriv.derive_priv(&*SECP, &[WalletKind::Forfeits.child_number()])
				.expect("can't error"),
			server_key.clone(),
			fee_estimator.clone(),
		).await.context("failed to start VtxoSweeper")?;

		let sync_manager = SyncManager::start(
			rtmgr.clone(),
			bitcoind.clone(),
			db.clone(),
			vec![],
			deep_tip,
			cfg.sync_manager_block_poll_interval,
		).await.context("Failed to start SyncManager")?;

		Ok(Self { rtmgr, sync_manager, txindex, tx_nursery, forfeit_watcher, vtxo_sweeper })
	}

	/// Waits for server to terminate.
	pub async fn wait(&self) {
		self.rtmgr.wait().await;
		slog!(ServerTerminated);
	}

	/// Starts the server and waits until it terminates.
	///
	/// This is equivalent to calling [crate::Server::start] and [crate::Server::wait] in one go.
	pub async fn run(cfg: Config) -> anyhow::Result<()> {
		let srv = Self::start(cfg).await?;
		srv.wait().await;
		Ok(())
	}

	pub async fn stop(self) {
		self.rtmgr.shutdown();
		self.wait().await;
	}
}

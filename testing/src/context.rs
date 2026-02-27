use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ark::fees::{
	BoardFees, FeeSchedule, LightningReceiveFees, LightningSendFees, OffboardFees, PpmFeeRate,
	RefreshFees,
};
use bark::BarkNetwork;
use bitcoin::{Amount, FeeRate, Network, Txid};
use bitcoincore_rpc::RpcApi;
use futures::future::join_all;
use log::{debug, info, trace};
use server::vtxopool::VtxoTarget;
use server::Server;
use tokio::{fs, join};
use tonic::transport::Uri;
use server::config::{self, Config, HodlInvoiceClnPlugin};
use server_rpc as rpc;

use crate::daemon::captaind::proxy::ArkRpcProxyServer;
use crate::postgres::{self, PostgresDatabaseManager};
use crate::util::{
	get_bark_chain_source_from_env, test_data_directory, FutureExt, TestContextChainSource,
};
use crate::{
	btc, constants, sat, Bark, Bitcoind, BitcoindConfig, Captaind, Electrs, ElectrsConfig,
	Lightningd, LightningdConfig,
};
use crate::daemon::bitcoind::BitcoindRpcHandle;

pub struct LightningPaymentSetup {
	pub receiver: Lightningd,
	pub sender: Lightningd,
}

impl LightningPaymentSetup {
	pub async fn sync(&self) {
		tokio::join!(
			self.receiver.wait_for_block_sync(),
			self.sender.wait_for_block_sync(),
		);
	}
}

pub trait ToArkUrl {
	fn ark_url(&self) -> String;
}
impl ToArkUrl for Captaind {
	fn ark_url(&self) -> String { self.ark_url() }
}
impl ToArkUrl for String {
	fn ark_url(&self) -> String { self.clone() }
}
impl ToArkUrl for str {
	fn ark_url(&self) -> String { self.to_owned() }
}
impl ToArkUrl for ArkRpcProxyServer {
	fn ark_url(&self) -> String { self.address.clone() }
}

pub struct TestContext {
	pub test_name: String,
	pub datadir: PathBuf,

	pub bitcoind: Option<Bitcoind>,

	/// RPC handles for secondary bitcoind nodes that are p2p-connected to the
	/// central one. Used by [`await_block_count_sync`] to ensure blocks have
	/// propagated to all nodes.
	secondary_bitcoinds: Mutex<Vec<BitcoindRpcHandle>>,

	// use a central Electrs for the Esplora and mempool.space API if necessary
	pub electrs: Option<Electrs>,

	// ensures postgres daemon, if any, stays alive the TestContext's lifetime
	postgres_manager: Option<postgres::PostgresDatabaseManager>,
}

impl TestContext {
	pub async fn new_minimal(test_name: impl AsRef<str>) -> Self {
		crate::util::init_logging();

		let test_name = test_name.as_ref().to_owned();
		let datadir = test_data_directory().await.join(&test_name);

		if datadir.exists() {
			fs::remove_dir_all(&datadir).await.unwrap();
		}
		fs::create_dir_all(&datadir).await.unwrap();

		TestContext {
			test_name,
			datadir,
			bitcoind: None,
			secondary_bitcoinds: Mutex::new(Vec::new()),
			electrs: None,
			postgres_manager: None,
		}
	}

	pub async fn new(test_name: impl AsRef<str>) -> Self {
		let mut ctx = Self::new_minimal(test_name).await;

		ctx.init_central_bitcoind().await;
		ctx.init_central_electrs().await;
		ctx.init_central_postgres().await;

		ctx
	}

	pub fn bitcoind_default_cfg(&self, name: impl AsRef<str>) -> BitcoindConfig {
		let datadir = self.datadir.join(name.as_ref());
		BitcoindConfig {
			datadir,
			wallet: false,
			txindex: true,
			network: Network::Regtest,
			fallback_fee: FeeRate::from_sat_per_vb(1).unwrap(),
			relay_fee: None,
		}
	}

	pub async fn init_central_bitcoind(&mut self) {
		let bitcoind = {
			let mut bitcoind = Bitcoind::new(
				"bitcoind".to_string(),
				BitcoindConfig {
					datadir: self.datadir.join("bitcoind"),
					wallet: true,
					txindex: true,
					network: Network::Regtest,
					fallback_fee: FeeRate::from_sat_per_vb(1).unwrap(),
					relay_fee: None,
				},
				None
			);
			bitcoind.start().await.unwrap();
			bitcoind
		};

		bitcoind.init_wallet().await;
		bitcoind.prepare_funds().await;

		self.bitcoind = Some(bitcoind);
	}

	pub async fn init_central_electrs(&mut self) {
		let electrs = match get_bark_chain_source_from_env() {
			TestContextChainSource::BitcoinCore => None,
			TestContextChainSource::ElectrsRest(electrs_type) => {
				let cfg = ElectrsConfig {
					network: Network::Regtest,
					bitcoin_dir: self.bitcoind().datadir(),
					bitcoin_rpc_port: self.bitcoind().rpc_port(),
					bitcoin_zmq_port: self.bitcoind().zmq_port(),
					electrs_dir: self.datadir.join("electrs"),
				};
				let mut electrs = Electrs::new(&self.test_name, cfg, electrs_type);
				electrs.start().await.unwrap();
				Some(electrs)
			},
		};

		self.electrs = electrs;
		self.await_block_count_sync().await
	}

	pub fn postgres_manager(&self) -> &PostgresDatabaseManager {
		self.postgres_manager.as_ref().unwrap()
	}

	pub async fn init_central_postgres(&mut self) {
		if self.postgres_manager.is_none() {
			let datadir = self.datadir.join("postgres");
			self.postgres_manager = Some(PostgresDatabaseManager::init(datadir).await);
		}
	}

	/// Returns the `Bitcoind` which is central to this `TextContext`
	/// Will panic if no central `BitcoinD` is present
	pub fn bitcoind(&self) -> &Bitcoind {
		self.bitcoind.as_ref()
			.expect("The central bitcoind hasn't been initialized. Call init_central_bitcoind first")
	}

	pub async fn new_bitcoind(&self, name: impl AsRef<str>) -> Bitcoind {
		self.new_bitcoind_with_cfg(name.as_ref(), self.bitcoind_default_cfg(name.as_ref())).await
	}

	pub async fn new_bitcoind_with_cfg(&self, name: impl AsRef<str>, cfg: BitcoindConfig) -> Bitcoind {
		let wallet = cfg.wallet;
		let mut bitcoind = Bitcoind::new(name.as_ref().to_string(), cfg, Some(self.bitcoind().p2p_url()));
		bitcoind.start().await.unwrap();
		if wallet {
			bitcoind.init_wallet().await;
		}
		self.secondary_bitcoinds.lock().unwrap().push(bitcoind.rpc_handle());
		bitcoind
	}

	pub async fn new_postgres(&self, db_name: &str) -> server::config::Postgres {
		self.postgres_manager.as_ref().unwrap()
			.request_database(db_name).await
	}

	async fn captaind_default_cfg(
		&self,
		name: impl AsRef<str>,
		bitcoind: &Bitcoind,
		lightningd: Option<&Lightningd>,
	) -> Config {
		let name = name.as_ref();
		let data_dir = self.datadir.join(name);

		let cln_array = if let Some(lnd) = lightningd {
			let grpc_details = lnd.grpc_details().await;
			let hold_details = lnd.hold_details().await;

			let lightningd = config::Lightningd {
				uri: Uri::from_str(&grpc_details.uri).expect("failed to parse cln grpc uri"),
				priority: 1,
				server_cert_path: grpc_details.server_cert_path,
				client_cert_path: grpc_details.client_cert_path,
				client_key_path: grpc_details.client_key_path,
				hold_invoice: Some(HodlInvoiceClnPlugin {
					uri: Uri::from_str(&hold_details.uri).expect("failed to parse hold plugin uri"),
					server_cert_path: hold_details.server_cert_path,
					client_cert_path: hold_details.client_cert_path,
					client_key_path: hold_details.client_key_path,
				})
			};

			let mut cln_array = Vec::new();
			cln_array.push(lightningd);

			cln_array
		} else {
			Vec::new()
		};

		// Create a new postgres database with the name of the test and database
		let db_name = format!("{}/{}", self.test_name, name);
		let postgres_cfg = self.new_postgres(&db_name).await;

		// NB we don't auto-complete `..Default::default()` here
		// to force us to evaluate every value in test context.
		Config {
			data_dir: data_dir.clone(),
			network: Network::Regtest,
			vtxo_lifetime: 144,
			vtxo_exit_delta: 12,
			round_interval: Duration::from_secs(3600),
			round_submit_time: Duration::from_millis(5000),
			// this one can be long cuz in most tests all users are ready and we don't wait
			round_sign_time: Duration::from_millis(5000),
			nb_round_nonces: 8,
			round_forfeit_nonces_timeout: Duration::from_secs(30),
			required_board_confirmations: constants::BOARD_CONFIRMATIONS as usize,
			round_tx_untrusted_input_confirmations: 1,
			max_vtxo_amount: None,
			max_arkoor_depth: 5,
			max_arkoor_fanout: 4,
			rpc_rich_errors: true,
			txindex_check_interval: Duration::from_millis(500),
			sync_manager_block_poll_interval: Duration::from_millis(100),
			handshake_psa: None,
			otel_collector_endpoint: None,
			otel_tracing_sampler: Some(1f64),
			otel_deployment_name: db_name,
			watchman: config::OptionalService::Disabled,
			watchman_min_balance: Amount::from_sat(1_000_000),
			vtxopool: server::vtxopool::Config {
				vtxo_targets: vec![
					VtxoTarget { count: 3, amount: sat(10_000) },
					VtxoTarget { count: 3, amount: btc(1) },
				],
				vtxo_target_issue_threshold: 50,
				vtxo_lifetime: 144,
				vtxo_pre_expiry: 12,
				max_vtxo_arkoor_depth: 3,
				issue_interval: Duration::from_secs(3),
			},
			offboard_feerate: FeeRate::from_sat_per_vb_unchecked(7),
			offboard_session_timeout: Duration::from_secs(30),
			fee_estimator: server::fee_estimator::Config {
				update_interval: Duration::from_secs(60),
				fallback_fee_rate_fast: FeeRate::from_sat_per_vb_unchecked(25),
				fallback_fee_rate_regular: FeeRate::from_sat_per_vb_unchecked(10),
				fallback_fee_rate_slow: FeeRate::from_sat_per_vb_unchecked(5),
			},
			transaction_rebroadcast_interval: std::time::Duration::from_secs(2),
			rpc: config::Rpc {
				// these will be overwritten on start, but can't be empty
				public_address: SocketAddr::from_str("127.0.0.1:3535").unwrap(),
				admin_address: None,
				integration_address: None,
			},
			bitcoind: config::Bitcoind {
				url: bitcoind.rpc_url(),
				cookie: Some(bitcoind.rpc_cookie()),
				rpc_user: None,
				rpc_pass: None,
			},
			postgres: postgres_cfg,
			cln_array,
			cln_reconnect_interval: Duration::from_secs(10),
			invoice_check_interval: Duration::from_secs(3),
			invoice_recheck_delay: Duration::from_secs(2),
			invoice_check_base_delay: Duration::from_secs(2),
			max_invoice_check_delay: Duration::from_secs(10),
			invoice_poll_interval: Duration::from_secs(10),
			track_all_base_delay: Duration::from_secs(1),
			max_track_all_delay: Duration::from_secs(60),
			htlc_expiry_delta: 6,
			htlc_send_expiry_delta: 258,
			max_user_invoice_cltv_delta: 58,
			invoice_expiry: Duration::from_secs(10 * 60),
			receive_htlc_forward_timeout: Duration::from_secs(30),
			min_board_amount: Amount::from_sat(20_000),
			ln_receive_anti_dos_required: false,
			max_read_mailbox_items: 100,
			fees: FeeSchedule {
				board: BoardFees {
					min_fee: Amount::ZERO,
					base_fee: Amount::ZERO,
					ppm: PpmFeeRate::ZERO,
				},
				offboard: OffboardFees {
					base_fee: Amount::ZERO,
					fixed_additional_vb: 100,
					ppm_expiry_table: vec![],
				},
				refresh: RefreshFees {
					base_fee: Amount::ZERO,
					ppm_expiry_table: vec![],
				},
				lightning_receive: LightningReceiveFees {
					base_fee: Amount::ZERO,
					ppm: PpmFeeRate::ZERO,
				},
				lightning_send: LightningSendFees {
					min_fee: Amount::ZERO,
					base_fee: Amount::ZERO,
					ppm_expiry_table: vec![],
				},
			},
		}
	}

	pub async fn new_captaind_with_cfg(
		&self,
		name: impl AsRef<str>,
		lightningd: Option<&Lightningd>,
		mod_cfg: impl FnOnce(&mut server::Config),
	) -> Captaind {
		let bitcoind = self.new_bitcoind(format!("{}_bitcoind", name.as_ref())).await;
		let mut cfg = self.captaind_default_cfg(name.as_ref(), &bitcoind, lightningd).await;
		mod_cfg(&mut cfg);

		let mut ret = Captaind::new(name, bitcoind, cfg);
		ret.start().await.unwrap();

		ret
	}

	/// Creates new captaind without any funds.
	pub async fn new_captaind(
		&self,
		name: impl AsRef<str>,
		lightningd: Option<&Lightningd>,
	) -> Captaind {
		self.new_captaind_with_cfg(name, lightningd, |_| {}).await
	}

	/// Creates new captaind and immediately funds it. Waits until the captaind's bitcoind
	/// receives funding transaction.
	pub async fn new_captaind_with_funds(
		&self,
		name: impl AsRef<str>,
		lightningd: Option<&Lightningd>,
		amount: Amount
	) -> Captaind {
		let srv = self.new_captaind(name, lightningd).await;
		let _txid = self.fund_captaind(&srv, amount).await;
		srv
	}

	pub async fn new_server_with_cfg(
		&self,
		name: impl AsRef<str>,
		lightningd: Option<&Lightningd>,
		mod_cfg: impl FnOnce(&mut server::Config),
	) -> Arc<Server> {
		// using context bitcoind because we don't have a place to store the bitcoind
		let mut cfg = self.captaind_default_cfg(name.as_ref(), self.bitcoind(), lightningd).await;
		mod_cfg(&mut cfg);

		Server::create(cfg.clone()).await.expect("error creating server");
		Server::start(cfg).await.expect("error starting server")
	}

	pub fn bark_default_cfg(
		&self,
		srv: &dyn ToArkUrl,
		bitcoind: Option<&Bitcoind>,
	) -> bark::Config {
		bark::Config {
			server_address: srv.ark_url(),
			esplora_address: if bitcoind.is_none() {
				Some(self.electrs.as_ref().expect("need either bitcoind or electrs").rest_url())
			} else {
				None
			},
			bitcoind_address: bitcoind.map(|b| b.rpc_url()),
			bitcoind_cookiefile: bitcoind.map(|b| b.rpc_cookie()),
			bitcoind_user: None,
			bitcoind_pass: None,

			vtxo_refresh_expiry_threshold: 24,
			vtxo_exit_margin: 12,
			htlc_recv_claim_delta: 18,
			fallback_fee_rate: Some(FeeRate::from_sat_per_vb_unchecked(5)),
			round_tx_required_confirmations: constants::ROUND_CONFIRMATIONS,
		}
	}

	pub async fn try_new_bark_with_cfg(
		&self,
		name: impl AsRef<str>,
		srv: &dyn ToArkUrl,
		mod_cfg: impl FnOnce(&mut bark::Config),
	) -> anyhow::Result<Bark> {
		let bitcoind = if self.electrs.is_none() {
			Some(self.new_bitcoind(format!("{}_bitcoind", name.as_ref())).await)
		} else {
			None
		};

		let mut cfg = self.bark_default_cfg(srv, bitcoind.as_ref());
		mod_cfg(&mut cfg);

		let datadir = self.datadir.join(name.as_ref());
		Bark::try_new(name, datadir, BarkNetwork::Regtest, cfg, bitcoind).await
	}

	pub async fn try_new_bark(
		&self,
		name: impl AsRef<str>,
		srv: &dyn ToArkUrl,
	) -> anyhow::Result<Bark> {
		self.try_new_bark_with_cfg(name, srv, |_| {}).await
	}

	/// Creates new bark without any funds.
	pub async fn new_bark(&self, name: impl AsRef<str>, srv: &dyn ToArkUrl) -> Bark {
		self.try_new_bark(name, srv).await.unwrap()
	}

	/// Creates new bark and immediately funds it. Waits until the bark's bitcoind
	/// receives funding transaction.
	pub async fn new_bark_with_funds(&self, name: impl AsRef<str>, srv: &dyn ToArkUrl, amount: Amount) -> Bark {
		let bark = self.try_new_bark(name, srv).await.unwrap();
		let _txid = self.fund_bark(&bark, amount).await;
		bark
	}

	pub async fn new_lightningd(&self, name: impl AsRef<str>) -> Lightningd {
		let datadir = self.datadir.join(name.as_ref());

		let bitcoind = self.new_bitcoind(format!("{}_bitcoind", name.as_ref())).await;

		let cfg = LightningdConfig {
			network: String::from("regtest"),
			bitcoin_dir: bitcoind.datadir(),
			bitcoin_rpcport: bitcoind.rpc_port(),
			lightning_dir: datadir.clone()
		};

		let mut ret = Lightningd::new(name, bitcoind, cfg);
		ret.start().await.unwrap();
		// wait for grpc to be available
		async {
			loop {
				if ret.try_grpc_client().await.is_ok() {
					break;
				} else {
					tokio::time::sleep(Duration::from_millis(200)).await;
				}
			}
		}.wait_millis(5000).await;
		ret
	}


	/// Creates one sender and one receiver lightningd node and funds sender,
	/// but does not create a channel between them.
	pub async fn new_lightning_setup_no_channel(&self, name: impl AsRef<str>) -> LightningPaymentSetup {
		trace!("Start receiver and sender lightningd nodes");
		let receiver = self.new_lightningd(format!("{}_receiver", name.as_ref())).await;
		let sender = self.new_lightningd(format!("{}_sender", name.as_ref())).await;

		trace!("Funding all lightning-nodes");
		self.fund_lightning(&sender, btc(10)).await;
		let height = self.generate_blocks(6).await;
		sender.wait_for_block(height).await;

		LightningPaymentSetup { receiver, sender }
	}

	/// Creates one sender and one receiver lightningd node and funds sender,
	/// and creates a channel between them.
	pub async fn new_lightning_setup(&self, name: impl AsRef<str>) -> LightningPaymentSetup {
		let lightning = self.new_lightning_setup_no_channel(name).await;

		trace!("Creating channel between lightning nodes");
		lightning.sender.connect(&lightning.receiver).await;
		let funding_txid = lightning.sender.fund_channel(&lightning.receiver, btc(8)).await;

		// We need to await the channel funding transaction or else we get
		// infinite 'Waiting for gossip...' below.
		self.await_transaction(funding_txid).await;
		// Default depth before channel_ready
		self.generate_blocks(6).await;

		lightning.sender.wait_for_gossip(1).await;

		lightning
	}

	pub async fn fund_captaind(&self, srv: &Captaind, amount: Amount) {
		info!("Fund {} {}", srv.name, amount);
		let rounds_address = srv.get_rounds_funding_address().await;
		self.bitcoind().fund_addr(rounds_address, amount).await;
		tokio::time::sleep(Duration::from_millis(1000)).await;
		self.bitcoind().generate(1).await;
		tokio::time::sleep(Duration::from_millis(1000)).await;
		srv.get_wallet_rpc().await.wallet_sync(rpc::protos::Empty {}).await
			.expect("error calling wallet status after funding server");
	}

	/// Send `amount` to an onchain address of this Bark client.
	pub async fn fund_bark(&self, bark: &Bark, amount: Amount) -> Txid {
		info!("Fund {} {}", bark.name(), amount);
		let address = bark.get_onchain_address().await;
		let txid = self.bitcoind().fund_addr(address, amount).await;
		self.bitcoind().generate(1).await;
		self.await_block_count_sync().await;
		txid
	}

	pub async fn fund_lightning(&self, lightning: &Lightningd, amount: Amount) -> Txid {
		info!("Fund {} {}", lightning.name, amount);
		let address = lightning.get_onchain_address().await;

		let client = self.bitcoind().sync_client();
		client.send_to_address(
			&address, amount, None, None, None, None, None, None,
		).unwrap()
	}

	/// Wait until all secondary bitcoind nodes and electrs have synced to
	/// the central bitcoind's current tip.
	///
	/// For electrs, polls the Prometheus `tip_height` metric rather than
	/// the REST API height, because the REST height can update before the
	/// history (address) index is ready — causing BDK wallet syncs to miss txs.
	pub async fn await_block_count_sync(&self) {
		let Some(bitcoind) = self.bitcoind.as_ref() else { return };
		let height = bitcoind.get_block_count().await;

		// Wait for all secondary bitcoind nodes to reach the same height.
		let handles: Vec<_> = self.secondary_bitcoinds.lock().unwrap()
			.iter()
			.map(|h| (h.name.clone(), h.client()))
			.collect();
		for (name, client) in &handles {
			loop {
				match client.get_block_count() {
					Ok(current) if current >= height => break,
					Ok(current) => {
						trace!("Waiting for {} to reach height {} (at {})", name, height, current);
					}
					// Node was shut down mid-test (e.g. server restart tests).
					Err(e) => {
						debug!("Skipping sync for {} (node unreachable: {})", name, e);
						break;
					}
				}
				tokio::time::sleep(Duration::from_millis(100)).await;
			}
		}

		if let Some(electrs) = self.electrs.as_ref() {
			electrs.await_tip_synced(height as u32).await;
		}
	}

	/// Waits for the given transaction ID to be available in both the central bitcoind and electrs
	pub async fn await_transaction(&self, txid: Txid) {
		let bitcoin = async move {
			if let Some(bitcoind) = &self.bitcoind {
				bitcoind.await_transaction(txid).await;
			}
		};
		let electrs = async move {
			if let Some(electrs) = &self.electrs {
				electrs.await_transaction(txid).await;
			}
		};
		join!(bitcoin, electrs);
	}

	/// Waits for the given transaction ID to be available in the central bitcoin and electrs, as
	/// well as each given bitcoin node.
	pub async fn await_transactions_across_nodes(
		&self,
		txids: impl IntoIterator<Item = Txid>,
		nodes: impl IntoIterator<Item = &Bitcoind>,
	) {
		let txids = txids.into_iter().collect::<Vec<_>>();
		let central_futures = async {
			join_all(txids.iter().map(|txid| self.await_transaction(*txid))).await;
		};
		let nodes_future = async {
			join_all(nodes.into_iter().flat_map(|b| {
				txids.iter().map(|txid| b.await_transaction(*txid))
			})).await
		};
		join!(central_futures, nodes_future);
	}

	/// Generated a block using the central bitcoind and ensures that electrs is synced with it.
	/// Returns the new block height.
	pub async fn generate_blocks(&self, block_num: u32) -> u64 {
		// Give transactions time to propagate
		tokio::time::sleep(Duration::from_millis(1000)).await;

		self.bitcoind().generate(block_num).await;

		// Wait untill all blocks are propagated
		self.await_block_count_sync().await;

		let height = self.bitcoind().get_block_count().await;
		info!("New chain tip: {}", height);
		height
	}

	/// Generated a block using the central bitcoind without waiting for propagation
	pub async fn generate_blocks_unsynced(&self, block_num: u32) {
		self.bitcoind().generate(block_num).await;
	}

	/// Triggers a round and refreshes all given barks concurrently.
	pub async fn refresh_all(&self, srv: &Captaind, barks: &[Bark]) {
		let futures = barks.iter().map(|b| b.try_refresh_all_no_retry());
		let (results, _) = tokio::join!(
			join_all(futures),
			srv.trigger_round(),
		);
		for r in results {
			r.expect("refresh failed");
		}
	}
}

impl Drop for TestContext {
	fn drop(&mut self) {
		log::info!("TestContext: Datadir is located at {:?}", self.datadir);

		if std::thread::panicking() {
			log::info!("Leave test directory intact");
			// do nothing
		} else {
			let keep_all_data = std::env::var_os(constants::env::KEEP_ALL_TEST_DATA)
				.map(|v| v == "true" || v == "1")
				.unwrap_or(false);
			if keep_all_data {
				log::info!("Keep test data intact because {} is set", constants::env::KEEP_ALL_TEST_DATA);
			} else {
				match std::fs::remove_dir_all(&self.datadir) {
					Ok(_) => log::info!("Cleaned up {:?}", self.datadir),
					Err(e) => log::warn!("Failed to clean up datadir {:?} because {:?}", self.datadir, e)

				}
			}
		}
	}
}

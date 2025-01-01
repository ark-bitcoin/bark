
use std::fmt;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

use anyhow::Context;
use bitcoin::address::NetworkUnchecked;
use bitcoin::{Address, Amount, FeeRate, Network, Txid};
use bitcoincore_rpc::{Client as BitcoindClient, Auth, RpcApi};

use tokio::process::Command;
use crate::constants::bitcoind::BITCOINRPC_TEST_AUTH;
use crate::constants::env::{BITCOIND_EXEC, BITCOINRPC_TIMEOUT_SECS};
use crate::daemon::{Daemon, DaemonHelper};
use crate::util::{FeeRateExt, resolve_path};

pub struct BitcoindHelper {
	name : String,
	exec: PathBuf,
	config: BitcoindConfig,
	state: BitcoindState,
	add_node: Option<String>
}

pub struct BitcoindConfig {
	pub datadir: PathBuf,
	pub txindex: bool,
	pub network: Network,
	pub fallback_fee: FeeRate,
	pub relay_fee: Option<FeeRate>
}

#[derive(Default)]
pub struct BitcoindState {
	rpc_port: Option<u16>,
	p2p_port: Option<u16>,
	zmq_port: Option<u16>,
}

pub type Bitcoind = Daemon<BitcoindHelper>;

impl std::fmt::Debug for Bitcoind {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "bitcoind in {}", self.inner.datadir().display())
	}
}

impl Bitcoind {
	fn exec() -> PathBuf {
		if let Ok(e) = std::env::var(&BITCOIND_EXEC) {
			resolve_path(e).expect("failed to resolve BITCOIND_EXEC")
		} else if let Ok(e) = which::which("bitcoind") {
			e.into()
		} else {
			panic!("BITCOIND_EXEC env not set")
		}
	}

	pub fn new(name: String, config: BitcoindConfig, add_node: Option<String>) -> Self {
		let state = BitcoindState::default();
		let exec = Bitcoind::exec();
		Daemon::wrap(BitcoindHelper { name, exec, config, state, add_node })
	}

	pub fn sync_client(&self) -> BitcoindClient {
		self.inner.sync_client().unwrap()
	}

	pub fn rpc_cookie(&self) -> PathBuf {
		self.inner.rpc_cookie()
	}

	pub fn rpc_url(&self) -> String {
		self.inner.rpc_url()
	}

	pub fn auth(&self) -> Auth {
		self.inner.auth()
	}

	pub fn rpc_port(&self) -> u16 {
		self.inner.rpc_port()

	}

	pub fn zmq_url(&self) -> String {
		self.inner.zmq_url()
	}

	pub fn zmq_port(&self) -> u16 {
		self.inner.zmq_port()
	}

	pub fn p2p_url(&self) -> String {
		self.inner.p2p_url()
	}

	pub fn datadir(&self) -> PathBuf {
		self.inner.config.datadir.clone()
	}

	pub async fn init_wallet(&self) {
		info!("Initializing a wallet");
		let client = self.sync_client();
		if client.get_wallet_info().is_err() {
			client.create_wallet("", None, None, None, None).expect("failed to create new wallet");
		}
	}

	pub async fn generate_to_wallet(&self, block_num: u64) {
		self.init_wallet().await;

		let client = self.sync_client();
		let address = client.get_new_address(None, None).unwrap()
			.require_network(Network::Regtest).unwrap();
		client.generate_to_address(block_num, &address).unwrap();
	}

	pub async fn generate(&self, block_num: u64) {
		let client = self.sync_client();
		lazy_static! {
			static ref RANDOM_ADDR: Address = Address::<NetworkUnchecked>::from_str(
				"mzU8XRVhUdXtdxmSA3Vw8XeU2FDV4iBDRW"
			).unwrap().assume_checked();
		}
		client.generate_to_address(block_num, &*RANDOM_ADDR).unwrap();
	}

	pub async fn prepare_funds(&self) {
		self.generate_to_wallet(4).await;
		self.generate(100).await;
	}

	pub async fn fund_addr(&self, address: impl fmt::Display, amount: Amount) -> Txid {
		let addr = Address::<NetworkUnchecked>::from_str(&address.to_string()).unwrap().assume_checked();
		let client = self.sync_client();
		client.send_to_address(
			&addr, amount, None, None, None, None, None, None,
		).unwrap()
	}

	pub async fn get_block_count(&self) -> u64 {
		let client = self.sync_client();
		client.get_block_count().unwrap()
	}

	pub fn get_new_address(&self) -> Address {
		let client = self.sync_client();
		client.get_new_address(None, None).unwrap().assume_checked()
	}

	pub fn get_received_by_address(&self, address: &Address) -> Amount {
		let client = self.sync_client();
		client.get_received_by_address(address, Some(1)).unwrap()
	}
}

impl BitcoindHelper {
	pub fn auth(&self) -> Auth {
			Auth::CookieFile(self.rpc_cookie())
	}

	pub fn rpc_cookie(&self) -> PathBuf {
		let cookie = self.config.datadir
			.join(self.config.network.to_string())
			.join(".cookie");

		cookie
	}

	pub fn rpc_port(&self) -> u16 {
		self.state.rpc_port.expect("A port has been picked. Is bitcoind running?")
	}

	pub fn rpc_url(&self) -> String {
		format!("http://127.0.0.1:{}", self.state.rpc_port.expect("A port has been picked. Is bitcoind running?"))
	}

	pub fn p2p_url(&self) -> String {
		format!("127.0.0.1:{}", self.state.p2p_port.expect("A P2P port has been assigned."))
	}

	pub fn sync_client(&self) -> anyhow::Result<BitcoindClient> {
		let url = self.rpc_url();
		let auth = self.auth();
		let (user, pass) = auth.get_user_pass()?;

		let timeout_str = std::env::var(BITCOINRPC_TIMEOUT_SECS).unwrap_or_else(|_| String::from("15"));
		let timeout = std::time::Duration::from_secs(timeout_str.parse::<u64>().expect("BITCOINRPC_TIMEOUT_SECS is not a number"));

		let transport = bitcoincore_rpc::jsonrpc::http::simple_http::Builder::new()
			.url(&url).with_context(|| format!("Invalid rpc-url: {}", url))?
			.auth(user.expect("A user is defined"), pass)
			.timeout(timeout)
			.build();

		let jsonrpc = bitcoincore_rpc::jsonrpc::client::Client::with_transport(transport);
		let client = BitcoindClient::from_jsonrpc(jsonrpc);
		Ok(client)
	}

	pub fn zmq_port(&self) -> u16 {
		self.state.zmq_port.expect("A port has been picked. Is bitcoind running?")
	}

	pub fn zmq_url(&self) -> String {
		format!("tcp://127.0.0.1:{}", self.zmq_port())
	}
}

impl DaemonHelper for BitcoindHelper {
	fn name(&self) -> &str {
		&self.name
	}

	fn datadir(&self) -> PathBuf {
		self.config.datadir.clone()
	}

	async fn make_reservations(&mut self) -> anyhow::Result<()> {
		self.state.rpc_port = Some(portpicker::pick_unused_port().expect("A port is free"));
		self.state.p2p_port = Some(portpicker::pick_unused_port().expect("A port is free"));
		self.state.zmq_port = Some(portpicker::pick_unused_port().expect("A port is free"));

		Ok(())
	}
	async fn prepare(&self) -> anyhow::Result<()> {
		debug!("Creating bitcoind datadir in {:?}", self.config.datadir.clone());
		std::fs::create_dir_all(self.config.datadir.clone())?;
		Ok(())
	}

	async fn get_command(&self) -> anyhow::Result<Command> {
		let mut cmd = Command::new(self.exec.clone());
		if self.config.network != Network::Bitcoin {
			cmd.arg(format!("-{}", self.config.network));
		}
		cmd.args(&[
			"-unsafesqlitesync",
			"-debug=1",
			"-debugexclude=libevent",
			&format!("-rpcauth={}", BITCOINRPC_TEST_AUTH),
			&format!("-datadir={}", self.config.datadir.display()),
			&format!("-txindex={}", self.config.txindex as u8),
			&format!("-rpcport={}", self.state.rpc_port.expect("A port has been picked")),
			&format!("-bind=127.0.0.1:{}", self.state.p2p_port.expect("A port has been picked")),
			&format!("-zmqpubhashblock={}", self.zmq_url()),
			&format!("-zmqpubhashtx={}", self.zmq_url()),
			&format!("-zmqpubrawblock={}", self.zmq_url()),
			&format!("-zmqpubrawtx={}", self.zmq_url()),
			&format!("-zmqpubsequence={}", self.zmq_url()),
			&format!("-fallbackfee={}", self.config.fallback_fee.to_btc_per_kvb()),
		]);
		if let Some(fr) = self.config.relay_fee {
			cmd.arg(format!("-minrelaytxfee={}", fr.to_btc_per_kvb()));
		}

		if let Some(a) = &self.add_node {
			cmd.arg(format!("-addnode={}", a));
		}

		Ok(cmd)
	}


	async fn wait_for_init(&self) -> anyhow::Result<()> {
		loop {
			if let Ok(client) = self.sync_client() {
				if client.get_blockchain_info().is_ok(){
					return Ok(())
				}
			}
			tokio::time::sleep(Duration::from_millis(100)).await;
		}
	}
}

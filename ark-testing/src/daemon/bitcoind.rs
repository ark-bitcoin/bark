use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

use bitcoin::{Amount, FeeRate, Network, Txid};
use bitcoincore_rpc::{Client as BitcoindClient, Auth, RpcApi};

use crate::{Bark, Aspd};
use crate::daemon::{Daemon, DaemonHelper};
use crate::constants::env::BITCOIND_EXEC;
use crate::util::FeeRateExt;

pub struct BitcoindHelper {
	name : String,
	exec: PathBuf,
	config: BitcoindConfig,
	state: BitcoindState,
}

pub struct BitcoindConfig {
	pub datadir: PathBuf,
	pub txindex: bool,
	pub network: String,
	pub fallback_fee: FeeRate,
	pub relay_fee: Option<FeeRate>,
}

impl Default for BitcoindConfig {
	fn default() -> Self {
		Self {
			datadir: PathBuf::from("~/.bitcoin"),
			txindex: false,
			network: String::from("regtest"),
			fallback_fee: FeeRate::from_sat_per_vb(1).unwrap(),
			relay_fee: None,
		}
	}
}

#[derive(Default)]
pub struct BitcoindState {
	rpc_port: Option<u16>,
	p2p_port: Option<u16>,
}

pub type Bitcoind = Daemon<BitcoindHelper>;

impl Bitcoind {
	fn exec() -> PathBuf {
		if let Ok(e) = std::env::var(&BITCOIND_EXEC) {
			e.into()
		} else if let Ok(e) = which::which("bitcoind") {
			e.into()
		} else {
			panic!("BITCOIND_EXEC env not set")
		}
	}

	pub fn new(name: String, config: BitcoindConfig) -> Self {
		let state = BitcoindState::default();
		let exec = Bitcoind::exec();
		Daemon::wrap(BitcoindHelper { name, exec, config, state})
	}

	pub fn sync_client(&self) -> anyhow::Result<BitcoindClient> {
		self.inner.sync_client()
	}

	pub fn bitcoind_cookie(&self) -> PathBuf {
		self.inner.bitcoind_cookie()
	}

	pub fn bitcoind_url(&self) -> String {
		self.inner.bitcoind_url()
	}

	pub fn bitcoind_rpcport(&self) -> u16 {
		self.inner.bitcoind_rpcport()

	}

	pub fn bitcoind_datadir(&self) -> PathBuf {
		self.inner.config.datadir.clone()
	}

	pub async fn init_wallet(&self) -> anyhow::Result<()> {
		info!("Initialziing a wallet");
		let client = self.sync_client()?;

		match client.get_wallet_info() {
			Ok(_) => Ok(()), // A wallet exists
			Err(_) => {
				let _ = client.create_wallet("", None, None, None, None)?;
				Ok(())
			}
		}
	}

	pub async fn generate(&self, block_num: u64) -> anyhow::Result<()> {
		self.init_wallet().await?;

		let client = self.sync_client()?;
		let address = client.get_new_address(None, None)?.require_network(Network::Regtest)?;
		client.generate_to_address(block_num, &address)?;

		Ok(())
	}

	pub async fn fund_aspd(&self, aspd: &Aspd, amount: Amount) -> anyhow::Result<()> {
		let address = aspd.get_funding_address().await?;
		self.sync_client()?.send_to_address(&address, amount, None, None, None, None, None, None)?;
		Ok(())
	}

	pub async fn fund_bark(&self, bark: &Bark, amount: Amount) -> anyhow::Result<Txid> {
		info!("Fund {} {}", bark.name(), amount);
		let address = bark.get_address().await?;
		let client = self.sync_client()?;
		let txid = client.send_to_address(&address, amount, None, None, None, None, None, None)?;
		Ok(txid)
	}
}

impl BitcoindHelper {
	pub fn auth(&self) -> Auth {
			Auth::CookieFile(self.bitcoind_cookie())
	}

	pub fn bitcoind_cookie(&self) -> PathBuf {
		let cookie = self.config.datadir
			.join(&self.config.network)
			.join(".cookie");

		cookie
	}

	pub fn bitcoind_rpcport(&self) -> u16 {
		self.state.rpc_port.expect("A port has been picked. Is bitcoind running?")
	}

	pub fn bitcoind_url(&self) -> String {
		format!("http://127.0.0.1:{}", self.state.rpc_port.expect("A port has been picked. Is bitcoind running?"))
	}

	pub fn sync_client(&self) -> anyhow::Result<BitcoindClient> {
		let bitcoind_url = self.bitcoind_url();
		let auth = self.auth();
		let client = BitcoindClient::new(&bitcoind_url, auth)?;
		Ok(client)
	}
}

impl DaemonHelper for BitcoindHelper {
	fn name(&self) -> &str {
		&self.name
	}

	async fn make_reservations(&mut self) -> anyhow::Result<()> {
		self.state.rpc_port = Some(portpicker::pick_unused_port().expect("A port is free"));
		self.state.p2p_port = Some(portpicker::pick_unused_port().expect("A port is free"));

		Ok(())
	}
	async fn prepare(&self) -> anyhow::Result<()> {
		debug!("Creating bitcoind datadir in {:?}", self.config.datadir.clone());
		std::fs::create_dir_all(self.config.datadir.clone())?;
		Ok(())
	}

	async fn get_command(&self) -> anyhow::Result<Command> {
		let mut cmd = Command::new(self.exec.clone());
		cmd.args(&[
			&format!("--{}", self.config.network),
			&format!("-datadir={}", self.config.datadir.display().to_string()),
			&format!("-txindex={}", self.config.txindex),
			&format!("-rpcport={}", self.state.rpc_port.expect("A port has been picked")),
			&format!("-port={}", self.state.p2p_port.expect("A port has been picked")),
			&format!("-fallbackfee={}", self.config.fallback_fee.to_btc_per_kvb()),
		]);
		if let Some(fr) = self.config.relay_fee {
			cmd.arg(format!("-minrelaytxfee={}", fr.to_btc_per_kvb()));
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

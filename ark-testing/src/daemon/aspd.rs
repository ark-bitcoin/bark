
use std::env;
use std::time::Duration;
use std::path::PathBuf;
use std::process::Command;

use bitcoin::Network;
use bitcoin::address::{Address, NetworkUnchecked};

use aspd_rpc_client::{AdminServiceClient, ArkServiceClient};
use aspd_rpc_client::Empty;

use crate::{Daemon, DaemonHelper};
use crate::constants::env::ASPD_EXEC;
use crate::util::resolve_path;

pub type Aspd = Daemon<AspdHelper>;

pub type AdminClient = AdminServiceClient<tonic::transport::Channel>;
pub type ArkClient = ArkServiceClient<tonic::transport::Channel>;


pub struct AspdHelper {
	name : String,
	state: AspdState,
	config: AspdConfig,
}

#[derive(Debug, Clone)]
pub struct AspdConfig {
	pub datadir: PathBuf,
	pub bitcoind_url : String,
	pub bitcoind_cookie: PathBuf,
	pub round_interval: Duration,
	pub round_submit_time: Duration,
	pub round_sign_time: Duration,
	pub nb_round_nonces: usize,
}

#[derive(Default)]
struct AspdState {
	public_grpc_address: Option<String>,
	admin_grpc_address: Option<String>,
}

impl Aspd {
	pub fn base_cmd() -> Command {
		let e = env::var(ASPD_EXEC).expect("ASPD_EXEC env not set");
		let exec = resolve_path(e).expect("failed to resolve ASPD_EXEC");
		Command::new(exec)
	}

	pub fn new(name: impl AsRef<str>, config: AspdConfig) -> Self {
		let helper = AspdHelper {
			name: name.as_ref().to_string(),
			config,
			state: AspdState::default(),
		};

		Daemon::wrap(helper)
	}

	pub fn asp_url(&self) -> String {
		self.inner.asp_url()
	}

	pub async fn get_admin_client(&self) -> AdminClient {
		self.inner.connect_admin_client().await.unwrap()
	}

	pub async fn get_public_client(&self) -> ArkClient {
		self.inner.connect_public_client().await.unwrap()
	}

	pub async fn get_funding_address(&self) -> Address {
		let mut admin_client = self.get_admin_client().await;
		let response = admin_client.wallet_status(Empty {}).await.unwrap().into_inner();
		response.address.parse::<Address<NetworkUnchecked>>().unwrap()
			.require_network(Network::Regtest).unwrap()
	}

	pub async fn trigger_round(&self) {
		self.get_admin_client().await.trigger_round(Empty {}).await.unwrap();
	}
}

impl DaemonHelper for AspdHelper {
	fn name(&self) -> &str {
		&self.name
	}

	async fn make_reservations(&mut self) -> anyhow::Result<()> {
		let public_grpc_port = portpicker::pick_unused_port().expect("No ports free");
		let admin_grpc_port = portpicker::pick_unused_port().expect("No ports free");

		let public_grpc_address = format!("0.0.0.0:{}", public_grpc_port);
		let admin_grpc_address = format!("127.0.0.1:{}", admin_grpc_port);

		let mut base_cmd = Aspd::base_cmd();

		let datadir = self.config.datadir.clone();
		let pgrpc = public_grpc_address.clone();
		let agrpc = admin_grpc_address.clone();

		let output = tokio::task::spawn_blocking(move || base_cmd.args([
			"--datadir",
			&datadir.display().to_string(),
			"set-config",
			"--public-rpc-address",
			&pgrpc,
			"--admin-rpc-address",
			&agrpc,
		]).output()).await??;

		if !output.status.success() {
			let stderr = String::from_utf8(output.stderr)?;
			error!("{}", stderr);
			bail!("Failed to configure ports for arkd-1");
		};

		self.state.public_grpc_address = Some(public_grpc_address);
		self.state.admin_grpc_address = Some(admin_grpc_address);

		Ok(())
	}

	async fn prepare(&self) -> anyhow::Result<()> {
		let mut base_cmd = Aspd::base_cmd();
		trace!("base_cmd={:?}", base_cmd);

		let cfg = self.config.clone();
		let output = tokio::task::spawn_blocking(move || base_cmd.args([
			"--datadir",
			&cfg.datadir.display().to_string(),
			"create",
			"--bitcoind-url",
			&cfg.bitcoind_url,
			"--bitcoind-cookie",
			&cfg.bitcoind_cookie.display().to_string(),
			"--network",
			"regtest",
			"--round-interval",
			&cfg.round_interval.as_millis().to_string(),
			"--round-submit-time",
			&cfg.round_submit_time.as_millis().to_string(),
			"--round-sign-time",
			&cfg.round_sign_time.as_millis().to_string(),
			"--nb-round-nonces",
			&cfg.nb_round_nonces.to_string(),
		]).output()).await??;

		if output.status.success() {
			Ok(())
		} else {
			let stderr = String::from_utf8(output.stderr)?;
			error!("{}", stderr);
			bail!("Failed to start arkd-1");
		}
	}

	async fn get_command(&self) -> anyhow::Result<Command> {
		let mut base_cmd = Aspd::base_cmd();
		base_cmd
			.arg("--datadir")
			.arg(&self.config.datadir)
			.arg("start");

		Ok(base_cmd)
	}

	async fn wait_for_init(&self) -> anyhow::Result<()> {
		while !self.is_ready().await {
			tokio::time::sleep(Duration::from_millis(100)).await;
		}
		Ok(())
	}
}

impl AspdHelper {
	async fn is_ready(&self) -> bool {
		return self.admin_grpc_is_ready().await && self.public_grpc_is_ready().await
	}

	async fn public_grpc_is_ready(&self) -> bool {
		if let Ok(mut c) = self.connect_public_client().await {
			c.get_ark_info(Empty {}).await.is_ok()
		} else {
			false
		}
	}

	async fn admin_grpc_is_ready(&self) -> bool {
		if let Ok(mut c) = self.connect_admin_client().await {
			c.wallet_status(Empty {}).await.is_ok()
		} else {
			false
		}
	}

	pub fn asp_url(&self) -> String {
		format!("http://{}", self.state.public_grpc_address.clone().expect("asp not running"))
	}

	pub fn admin_url(&self) -> String {
		format!("http://{}", self.state.admin_grpc_address.clone().expect("asp not running"))
	}

	pub async fn connect_public_client(&self) -> Result<ArkClient, tonic::transport::Error> {
		ArkClient::connect(self.asp_url()).await
	}

	pub async fn connect_admin_client(&self) -> Result<AdminClient, tonic::transport::Error> {
		AdminClient::connect(self.admin_url()).await
	}
}

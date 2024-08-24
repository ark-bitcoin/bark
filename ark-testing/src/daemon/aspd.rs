use std::time::Duration;
use std::env;
use std::path::PathBuf;
use std::process::Command;

use anyhow::Context;
use bitcoin::address::{Address, NetworkUnchecked, NetworkChecked};

use which::which;

use aspd_rpc_client::{AdminServiceClient, ArkServiceClient};
use aspd_rpc_client::Empty;

use crate::{Daemon, DaemonHelper};
use crate::constants::env::ASPD_EXEC;

pub fn get_base_cmd() -> anyhow::Result<Command> {
	match env::var(ASPD_EXEC) {
		Ok(aspd_exec) => {
			let aspd_exe = which(aspd_exec).expect("Failed to find aspd_exec");
			Ok(Command::new(aspd_exe))
		},
		Err(env::VarError::NotPresent) => bail!("ASPD_EXEC not set"),
		Err(_) => bail!("Failed to read ASPD_EXEC"),
	}
}

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
}

#[derive(Default)]
struct AspdState {
	public_grpc_address: Option<String>,
	admin_grpc_address: Option<String>,
}

impl Aspd {
	pub fn new(name: impl AsRef<str>, config: AspdConfig) -> Self {
		let helper = AspdHelper {
			name: name.as_ref().to_string(),
			config,
			state: AspdState::default(),
		};

		Daemon::wrap(helper)
	}

	pub fn asp_url(&self) -> anyhow::Result<String> {
		self.inner.asp_url()
	}

	pub async fn get_admin_client(&self) -> anyhow::Result<AdminClient> {
		self.inner.get_admin_client().await
	}

	pub async fn get_public_client(&self) -> anyhow::Result<ArkClient> {
		self.inner.get_public_client().await
	}

	pub async fn get_funding_address(&self) -> anyhow::Result<Address> {
		let mut admin_client = self.get_admin_client().await?;
		let response = admin_client.wallet_status(Empty {}).await?.into_inner();
		let address: Address<NetworkChecked> = response.address.parse::<Address<NetworkUnchecked>>()?.assume_checked();
		Ok(address)
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

		let mut base_cmd = get_base_cmd()?;

		let datadir = self.config.datadir.clone();
		let pgrpc = public_grpc_address.clone();
		let agrpc = admin_grpc_address.clone();

		let output = tokio::task::spawn_blocking(move || base_cmd
			.arg("--datadir")
			.arg(datadir)
			.arg("set-config")
			.arg("--public-rpc-address")
			.arg(pgrpc)
			.arg("--admin-rpc-address")
			.arg(agrpc)
			.output())
			.await??;

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
		let mut base_cmd = get_base_cmd()?;
		trace!("base_cmd={:?}", base_cmd);

		let cfg = self.config.clone();
		let output = tokio::task::spawn_blocking(move || base_cmd
			.args([
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
			])
			.output()).await??;

		if output.status.success() {
			Ok(())
		} else {
			let stderr = String::from_utf8(output.stderr)?;
			error!("{}", stderr);
			bail!("Failed to start arkd-1");
		}
	}

	async fn get_command(&self) -> anyhow::Result<Command> {

		let mut base_cmd = get_base_cmd()?;
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

	async fn admin_grpc_is_ready(&self) -> bool {
		match self.get_admin_client().await {
				Ok(mut client) => client.wallet_status(Empty {}).await.is_ok(),
				Err(_) => false
			}
	}

	async fn public_grpc_is_ready(&self) -> bool {
		match self.get_admin_client().await {
				Ok(mut client) => client.wallet_status(Empty {}).await.is_ok(),
				Err(_) => false
			}
	}

	pub fn asp_url(&self) -> anyhow::Result<String> {
		Ok(format!("http://{}", self.state.public_grpc_address.clone().context("Is asp running")?))
	}

	pub async fn get_admin_client(&self) -> anyhow::Result<AdminClient> {
		let url = format!("http://{}", self.state.admin_grpc_address.clone().expect("The admin_grpc port is set. Is aspd running?"));
		Ok(AdminClient::connect(url).await?)
	}

	pub async fn get_public_client(&self) -> anyhow::Result<ArkClient> {
		let url = format!("http://{}", self.state.public_grpc_address.clone().expect("The public_grpc_address port is set. Is aspd running?"));
		Ok(ArkClient::connect(url).await?)
	}
}

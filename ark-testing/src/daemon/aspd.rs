use std::time::Duration;
use std::env;
use std::path::PathBuf;
use std::process::{Command, Output};

use anyhow::Context;
use bitcoin::address::{Address, NetworkUnchecked, NetworkChecked};

use which::which;

use aspd_rpc_client::{AdminServiceClient as AspDAdminClient, ArkServiceClient as AspDClient};
use aspd_rpc_client::Empty;

use crate::{Daemon, DaemonHelper};
use crate::constants::env::ASPD_EXE;

pub fn get_base_cmd() -> anyhow::Result<Command> {
	match env::var(ASPD_EXE) {
		Ok(aspd_exec) => {
			let aspd_exe = which(aspd_exec).expect(&format!("Failed to find {}", ASPD_EXE));
			Ok(Command::new(aspd_exe))
		},
		Err(env::VarError::NotPresent) => {
			let mut cmd = Command::new("cargo");
			cmd
				.args(&["run", "--package", "bark-aspd", "--"]);
			Ok(cmd)
		},
		Err(_) => panic!("Failed to read {}", ASPD_EXE),
	}
}
pub type AspD = Daemon<AspDHelper>;

pub struct AspDHelper {
	name : String,
	state: AspDState,
	config: AspDConfig
}

pub struct AspDConfig {
	pub datadir: PathBuf,
	pub bitcoind_url : String,
	pub bitcoind_cookie: PathBuf
}

#[derive(Default)]
struct AspDState {
	public_grpc_address: Option<String>,
	admin_grpc_address: Option<String>,
}

impl AspD {

	pub fn new(name: impl AsRef<str>, config: AspDConfig) -> Self {
		let helper = AspDHelper {
			name: name.as_ref().to_string(),
			config,
			state: AspDState::default()
		};

		Daemon::wrap(helper)
	}

	pub fn asp_url(&self) -> anyhow::Result<String> {
		self.inner.asp_url()
	}

	pub async fn get_admin_client(&self) -> anyhow::Result<AspDAdminClient<tonic::transport::Channel>> {
		self.inner.get_admin_client().await
	}

	pub async fn get_public_client(&self) -> anyhow::Result<AspDClient<tonic::transport::Channel>> {
		self.inner.get_public_client().await
	}

	pub async fn get_funding_address(&self) -> anyhow::Result<Address> {
		let mut admin_client = self.get_admin_client().await?;
		let response = admin_client.wallet_status(Empty {}).await?.into_inner();
		let address: Address<NetworkChecked> = response.address.parse::<Address<NetworkUnchecked>>()?.assume_checked();
		Ok(address)

	}
}

impl DaemonHelper for AspDHelper {

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

		let output : Output = tokio::task::spawn_blocking(move || base_cmd
			.arg("--datadir")
			.arg(datadir)
			.arg("set-config")
			.arg("--public-rpc-address")
			.arg(pgrpc)
			.arg("--admin-rpc-address")
			.arg(agrpc)
			.output())
			.await??;

		if ! output.status.success() {
			let stderr = String::from_utf8(output.stderr)?;
			error!("{}", stderr);
			anyhow::bail!("Failed to configure ports for arkd-1");
		};

		self.state.public_grpc_address = Some(public_grpc_address);
		self.state.admin_grpc_address = Some(admin_grpc_address);

		Ok(())
	}

	async fn prepare(&self) -> anyhow::Result<()> {
		let mut base_cmd = get_base_cmd()?;

		let datadir = self.config.datadir.clone();
		let bd_url = self.config.bitcoind_url.clone();
		let bd_cookie = self.config.bitcoind_cookie.clone();
		let output : Output = tokio::task::spawn_blocking(move || base_cmd
			.arg("--datadir")
			.arg(datadir)
			.arg("create")
			.arg("--bitcoind-url")
			.arg(bd_url)
			.arg("--bitcoind-cookie")
			.arg(bd_cookie)
			.arg("--network")
			.arg("regtest")
			.output()).await??;

		if output.status.success() {
			Ok(())
		} else {
			let stderr = String::from_utf8(output.stderr)?;
			error!("{}", stderr);
			anyhow::bail!("Failed to start arkd-1");
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

impl AspDHelper {

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

	pub async fn get_admin_client(&self) -> anyhow::Result<AspDAdminClient<tonic::transport::Channel>> {
		let url = format!("http://{}", self.state.admin_grpc_address.clone().expect("The admin_grpc port is set. Is aspd running?"));
		Ok(AspDAdminClient::connect(url).await?)
	}

	pub async fn get_public_client(&self) -> anyhow::Result<AspDClient<tonic::transport::Channel>> {
		let url = format!("http://{}", self.state.public_grpc_address.clone().expect("The public_grpc_address port is set. Is aspd running?"));
		Ok(AspDClient::connect(url).await?)
	}
}

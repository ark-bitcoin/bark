use std::env;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;
use std::str::FromStr;
use std::sync::Arc;

use anyhow::Context;
use tokio::sync::Mutex;
use tonic::transport::{Certificate, Channel, channel::ClientTlsConfig, Identity, Uri};

use which::which;

use bark_cln::grpc;
use bark_cln::grpc::node_client::NodeClient;

use crate::constants::env::LIGHTNINGD_EXE;
use crate::daemon::{Daemon, DaemonHelper};

pub fn get_lightningd_base_cmd() -> anyhow::Result<Command> {
	match env::var(LIGHTNINGD_EXE) {
		Ok(lightningd_exe) => {
			let lightningd_exe = which(lightningd_exe).expect("Failed to find `lightingd` in `LIGHTNINGD_EXE`");
			Ok(Command::new(lightningd_exe))
		},
		Err(env::VarError::NotPresent) => {
			let lightningd_exe = which("lightningd").expect("Failed to find `lightnignd`");
			let cmd = Command::new(lightningd_exe);
			Ok(cmd)
		},
		Err(_) => panic!("Failed to read `LIGHTNIGND_EXE`"),
	}
}

#[derive(Default)]
struct LightningDHelperState{
	grpc_port: Option<u16>,
	grpc_client: Option<NodeClient<Channel>>,
	port: Option<u16>,
}

pub struct LightningDConfig {
	pub lightning_dir: PathBuf,
	pub bitcoin_dir: PathBuf,
	pub bitcoin_rpcport: u16,
	pub network: String
}

pub struct LightningDHelper {
	name: String,
	config: LightningDConfig,
	state: Arc<Mutex<LightningDHelperState>>

}

pub type LightningD = Daemon<LightningDHelper>;

impl LightningDHelper {

	async fn write_config_file(&self) -> anyhow::Result<()> {
		trace!("Writing config file");
		let config_filepath = self.config.lightning_dir.join("config");
		if config_filepath.exists() {
			fs::remove_file(&config_filepath).context("Failed to delete config file")?;
		}

		let mut file = fs::OpenOptions::new()
			.create(true)
			.write(true)
			.open(config_filepath)?;

		writeln!(file, "network={}", self.config.network)?;
		writeln!(file, "bitcoin-datadir={}", self.config.bitcoin_dir.to_string_lossy())?;
		writeln!(file, "bitcoin-rpcport={}", self.config.bitcoin_rpcport)?;
		writeln!(file, "alias={}", self.name)?;
		writeln!(file, "")?;

		if let Some(grpc_port) = self.state.lock().await.grpc_port {
			writeln!(file, "grpc-port={}", grpc_port)?;
		}

		if let Some(port) = self.state.lock().await.port {
			writeln!(file, "addr=0.0.0.0:{}", port)?;
		}

		Ok(())
	}

	pub async fn grpc_port(&self) -> Option<u16> {
		self.state.lock().await.grpc_port
	}

	pub async fn grpc_client(&self) -> anyhow::Result<NodeClient<Channel>> {
		let mut unlocked_state = self.state.lock().await;

		match &unlocked_state.grpc_client {
			None => {
				let port = unlocked_state.grpc_port.expect("grpc-port is set");
				unlocked_state.grpc_client = Some(self.new_grpc_client(port).await?);
			},
			Some(_) => {}
		}

		Ok(unlocked_state.grpc_client.clone().unwrap())
	}

	async fn new_grpc_client(&self, grpc_port: u16) -> anyhow::Result<NodeClient<Channel>> {
		// Client doesn't support grpc over http
		// We need to use https using m-TLS authentication
		let ca_pem = fs::read_to_string(self.config.lightning_dir.join("regtest/ca.pem"))?;
		let id_pem = fs::read_to_string(self.config.lightning_dir.join("regtest/client.pem"))?;
		let id_key = fs::read_to_string(self.config.lightning_dir.join("regtest/client-key.pem"))?;

		let grpc_uri : Uri = format!("https://localhost:{}", grpc_port).parse().unwrap();
		let channel = Channel::builder(grpc_uri)
			.tls_config(ClientTlsConfig::new()
				.ca_certificate(Certificate::from_pem(ca_pem))
				.identity(Identity::from_pem(&id_pem, &id_key))
				)?
			.connect()
			.await?;


		let client = NodeClient::new(channel);
		Ok(client)
	}

	/// Returns Ok(()) if ready
	async fn is_ready(&self) -> anyhow::Result<()> {
		let mut client = self.grpc_client().await?;


		let request = grpc::GetinfoRequest{};
		let _response = client.getinfo(request).await?.get_ref();
		Ok(())
	}
}

impl DaemonHelper for LightningDHelper {

	fn name(&self) -> &str {
		&self.name
	}

	async fn make_reservations(&mut self) -> anyhow::Result<()> {
		let grpc_port = portpicker::pick_unused_port().expect("No ports free");
		let port = portpicker::pick_unused_port().expect("No ports free");

		trace!("Reserved grpc_port={} and port={}", grpc_port, port);
		let mut state = self.state.lock().await;
		state.grpc_port = Some(grpc_port);
		state.port = Some(port);

		drop(state);

		self.write_config_file().await?;
		Ok(())
	}

	async fn wait_for_init(&self) -> anyhow::Result<()> {
		loop {
			match self.is_ready().await {
				Ok(()) => return Ok(()),
				Err(_) => {},
			}
			tokio::time::sleep(std::time::Duration::from_millis(100)).await;
		}
	}

	async fn prepare(&self) -> anyhow::Result<()> {
		if !self.config.lightning_dir.exists() {
			fs::create_dir_all(&self.config.lightning_dir)?;
		}

		Ok(())
	}

	async fn get_command(&self) -> anyhow::Result<Command> {
		let mut cmd = get_lightningd_base_cmd()?;
		cmd
			.arg("--lightning-dir")
			.arg(&self.config.lightning_dir)
			.arg("--grpc-port")
			.arg(format!("{}", self.state.lock().await.grpc_port.unwrap()));
			Ok(cmd)
	}

}

impl LightningD {

	pub fn new(name: impl AsRef<str>, config: LightningDConfig) -> Self {
		let inner = LightningDHelper {
			name: name.as_ref().to_owned(),
			config,
			state: Arc::new(Mutex::new(LightningDHelperState::default()))
		};
		Daemon::wrap(inner)
	}

	pub async fn grpc_client(&self) -> anyhow::Result<NodeClient<Channel>> {
		self.inner.grpc_client().await
	}

	pub async fn port(&self) -> Option<u16> {
		self.inner.state.lock().await.port
	}

	pub async fn id(&self) -> anyhow::Result<Vec<u8>> {
		let mut client = self.grpc_client().await?;
		let info = client.getinfo(grpc::GetinfoRequest {}).await?.into_inner();
		Ok(info.id)
	}

	pub async fn connect(&self, other : &LightningD) -> anyhow::Result<()> {
		let mut self_client = self.grpc_client().await?;
		let mut other_client = other.grpc_client().await?;

		// Get the  connection details of the other lightning Node
		let other_id = other_client.getinfo(grpc::GetinfoRequest{}).await?.into_inner().id;
		let other_host = "localhost";
		let other_port : u16 = other.port().await.context(format!("No port configured on `{}`", other.name()))?;

		// Connect both nodes
		self_client.connect_peer(
			grpc::ConnectRequest {
				id: hex::encode(other_id),
				host: Some(other_host.to_owned()),
				port: Some(u32::from(other_port))
			}
		).await?;


		Ok(())
	}

  pub async fn get_onchain_address(&self) -> anyhow::Result<bitcoin::Address> {
      let mut grpc_client = self.grpc_client().await?;
      let response = grpc_client.new_addr(grpc::NewaddrRequest { addresstype: None}).await?.into_inner();
      let bech32 = response.bech32.unwrap();

      Ok(bitcoin::Address::from_str(&bech32)?.assume_checked())
  }
}
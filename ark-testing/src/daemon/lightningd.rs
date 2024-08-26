use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;

use anyhow::Context;
use tokio::sync::Mutex;
use tonic::transport::{Certificate, Channel, channel::ClientTlsConfig, Identity, Uri};

use bark_cln::grpc;
use bark_cln::grpc::node_client::NodeClient;

use crate::constants::env::LIGHTNINGD_EXEC;
use crate::daemon::{Daemon, DaemonHelper};

pub type Lightningd = Daemon<LightningDHelper>;

impl Lightningd {

	pub fn exec() -> PathBuf {
		if let Ok(e) = std::env::var(&LIGHTNINGD_EXEC) {
			e.into()
		} else if let Ok(e) = which::which("lightningd") {
			e.into()
		} else {
			panic!("LIGHTNIGND_EXEC env not set")
		}
	}
}

#[derive(Default)]
struct LightningDHelperState{
	grpc_port: Option<u16>
}

pub struct LightningdConfig {
	pub lightning_dir: PathBuf,
	pub bitcoin_dir: PathBuf,
	pub bitcoin_rpcport: u16,
	pub network: String
}

pub struct LightningDHelper {
	name: String,
	config: LightningdConfig,
	state: Arc<Mutex<LightningDHelperState>>

}


impl LightningDHelper {

	async fn write_config_file(&self) -> anyhow::Result<()> {
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
		writeln!(file, "log-file={}", self.config.lightning_dir.join("stdout.log").to_string_lossy())?;
		writeln!(file, "alias={}", self.name)?;
		writeln!(file, "")?;

		if let Some(grpc_port) = self.state.lock().await.grpc_port {
			writeln!(file, "grpc-port={}", grpc_port)?;
		}

		Ok(())
	}

	pub async fn grpc_port(&self) -> Option<u16> {
		self.state.lock().await.grpc_port
	}

	pub async fn grpc_client(&self) -> anyhow::Result<NodeClient<Channel>> {
		// Client doesn't support grpc over http
		// We need to use https using m-TLS authentication
		let grpc_port = self.grpc_port().await.context("grpc-port is set")?;
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
		self.state.lock().await.grpc_port = Some(grpc_port);
		self.write_config_file().await?;
		Ok(())
	}

	async fn wait_for_init(&self) -> anyhow::Result<()> {
		loop {
			match self.is_ready().await {
				Ok(()) => return Ok(()),
				Err(err) => trace!("Lightningd not ready: {:?}", err)
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
		let mut cmd = Command::new(Lightningd::exec());
		cmd
			.arg("--lightning-dir")
			.arg(&self.config.lightning_dir)
			.arg("--grpc-port")
			.arg(format!("{}", self.state.lock().await.grpc_port.unwrap()));
			Ok(cmd)
	}

}

impl Lightningd {

	pub fn new(name: impl AsRef<str>, config: LightningdConfig) -> Self {
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


}

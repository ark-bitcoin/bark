use std::env;
use std::time::Duration;
use std::path::PathBuf;

use bitcoin::{Amount, Network};
use bitcoin::address::{Address, NetworkUnchecked};
use tokio::sync::{self, mpsc};
use tokio::process::Command;

use aspd_log::{LogMsg, ParsedRecord};
use aspd_rpc_client::{AdminServiceClient, ArkServiceClient};
use aspd_rpc_client::Empty;

use crate::{Daemon, DaemonHelper, Lightningd};
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
	pub vtxo_expiry_delta: u16,
	pub vtxo_exit_delta: u16,
	pub nb_round_nonces: usize,
	pub sweep_threshold: Amount,
	pub cln_grpc_uri: Option<String>,
	pub cln_grpc_server_cert_path: Option<PathBuf>,
	pub cln_grpc_client_cert_path: Option<PathBuf>,
	pub cln_grpc_client_key_path: Option<PathBuf>,
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

	/// Subscribe to all structured logs of the given type.
	pub async fn subscribe_log<L: LogMsg>(&mut self) -> mpsc::UnboundedReceiver<L> {
		let (tx, rx) = sync::mpsc::unbounded_channel();
		self.add_stdout_handler(move |l: &str| {
			if l.starts_with("{") {
				let rec = serde_json::from_str::<ParsedRecord>(l)
					.expect("invalid slog struct");
				if rec.is::<L>() {
					return tx.send(rec.try_as().expect("invalid slog data")).is_err();
				}
			}
			false
		}).await;
		rx
	}

	/// Wait for the first occurrence of the given log message type and return it.
	pub async fn wait_for_log<L: LogMsg>(&mut self) -> L {
		let (tx, mut rx) = sync::mpsc::channel(0);
		self.add_stdout_handler(move |l: &str| {
			if l.starts_with("{") {
				let rec = serde_json::from_str::<ParsedRecord>(l)
					.expect("invalid slog struct");
				if rec.is::<L>() {
					tx.try_send(rec.try_as().expect("invalid slog data"))
						.expect("channel closed");
					return true;
				}
			}
			false
		}).await;
		rx.recv().await.expect("log wait channel closed")
	}
}

impl DaemonHelper for AspdHelper {
	fn name(&self) -> &str {
		&self.name
	}

	fn datadir(&self) -> PathBuf {
		self.config.datadir.clone()
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

		let output = base_cmd.args([
			"--datadir",
			&datadir.display().to_string(),
			"set-config",
			"--public-rpc-address",
			&pgrpc,
			"--admin-rpc-address",
			&agrpc,
		]).output().await?;

		if !output.status.success() {
			let stderr = String::from_utf8(output.stderr)?;
			error!("{}", stderr);
			bail!("Failed to configure ports for aspd '{}'", self.name());
		};

		self.state.public_grpc_address = Some(public_grpc_address);
		self.state.admin_grpc_address = Some(admin_grpc_address);

		Ok(())
	}

	async fn prepare(&self) -> anyhow::Result<()> {
		if !self.datadir().exists() {
			self.create().await?;
		}
		Ok(())
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

	async fn create(&self) -> anyhow::Result<()> {
		let cfg = self.config.clone();
		let output = {
			let mut cmd = Aspd::base_cmd();
			let datadir = cfg.datadir.display().to_string();
			let bitcoind_cookie = cfg.bitcoind_cookie.display().to_string();
			let round_interval = cfg.round_interval.as_millis().to_string();
			let round_submit_time = cfg.round_submit_time.as_millis().to_string();
			let round_sign_time = cfg.round_sign_time.as_millis().to_string();
			let nb_round_nonces = cfg.nb_round_nonces.to_string();
			let vtxo_expiry_delta = cfg.vtxo_expiry_delta.to_string();
			let vtxo_exit_delta = cfg.vtxo_exit_delta.to_string();
			let sweep_threshold = cfg.sweep_threshold.to_string();

			let mut args = vec![
				"create",
				"--datadir", &datadir,
				"--bitcoind-url", &cfg.bitcoind_url,
				"--bitcoind-cookie", &bitcoind_cookie,
				"--network", "regtest",
				"--round-interval", &round_interval,
				"--round-submit-time", &round_submit_time,
				"--round-sign-time",  &round_sign_time,
				"--nb-round-nonces", &nb_round_nonces,
				"--vtxo-expiry-delta", &vtxo_expiry_delta,
				"--vtxo-exit-delta", &vtxo_exit_delta,
				"--sweep-threshold", &sweep_threshold,
			];


			if cfg.cln_grpc_uri.is_some() {
				args.extend(["--cln-grpc-uri", cfg.cln_grpc_uri.as_ref().unwrap()]);
			}
			if cfg.cln_grpc_server_cert_path.is_some() {
				args.extend(["--cln-grpc-server-cert-path", cfg.cln_grpc_server_cert_path.as_ref().unwrap().to_str().unwrap()]);
			}
			if cfg.cln_grpc_client_cert_path.is_some() {
				args.extend(["--cln-grpc-client-cert-path", cfg.cln_grpc_client_cert_path.as_ref().unwrap().to_str().unwrap()]);
			}
			if cfg.cln_grpc_client_key_path.is_some() {
				args.extend(["--cln-grpc-client-key-path", cfg.cln_grpc_client_key_path.as_ref().unwrap().to_str().unwrap()]);
			}

			trace!("base_cmd={:?}; args={:?}", cmd, args);
			cmd.args(args).output()
		}.await?;

		if output.status.success() {
			Ok(())
		} else {
			let stderr = String::from_utf8(output.stderr)?;
			error!("stderr: {}", stderr);
			bail!("Failed to create aspd '{}'", self.name());
		}
	}
}

impl AspdConfig {
	pub async fn configure_lighting(&mut self, lightningd: &Lightningd) {
		let grpc_details = lightningd.grpc_details().await;

		self.cln_grpc_uri = Some(grpc_details.uri);
		self.cln_grpc_server_cert_path = Some(grpc_details.server_cert_path);
		self.cln_grpc_client_cert_path = Some(grpc_details.client_cert_path);
		self.cln_grpc_client_key_path = Some(grpc_details.client_key_path);
	}
}

use std::{env, fs};
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;
use std::str::FromStr;
use std::sync::Arc;

use anyhow::Context;
use bitcoin::hashes::Hash;
use tokio::sync::Mutex;
use tonic::transport::{Certificate, Channel, channel::ClientTlsConfig, Identity, Uri};

use bitcoin::{Amount, Txid};

use bark_cln::grpc;
use bark_cln::grpc::node_client::NodeClient;

use crate::Bitcoind;
use crate::constants::env::{LIGHTNINGD_EXEC, LIGHTNINGD_PLUGINS};
use crate::daemon::{Daemon, DaemonHelper};
use crate::util::resolve_path;

pub type Lightningd = Daemon<LightningDHelper>;

impl Lightningd {
	pub fn exec() -> PathBuf {
		if let Ok(e) = std::env::var(&LIGHTNINGD_EXEC) {
			resolve_path(e).expect("failed to resolve LIGHTNINGD_EXEC")
		} else if let Ok(e) = which::which("lightningd") {
			e.into()
		} else {
			panic!("LIGHTNIGND_EXEC env not set")
		}
	}
}

#[derive(Default)]
struct LightningDHelperState{
	grpc_port: Option<u16>,
	grpc_client: Option<NodeClient<Channel>>,
	port: Option<u16>,
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
	async fn write_config_file(&self) {
		trace!("Writing config file");
		let config_filepath = self.config.lightning_dir.join("config");
		if config_filepath.exists() {
			fs::remove_file(&config_filepath).context("Failed to delete config file").unwrap();
		}

		let mut file = fs::OpenOptions::new()
			.create(true)
			.write(true)
			.open(config_filepath)
			.expect("failed to open cln config file");

		writeln!(file, "network={}", self.config.network).unwrap();
		writeln!(file, "bitcoin-datadir={}", self.config.bitcoin_dir.to_string_lossy()).unwrap();
		writeln!(file, "bitcoin-rpcport={}", self.config.bitcoin_rpcport).unwrap();
		if let Ok(dir) = env::var(LIGHTNINGD_PLUGINS) {
			writeln!(file, "plugin-dir={}", dir).unwrap();
		}
		writeln!(file, "alias={}", self.name).unwrap();
		writeln!(file, "").unwrap();
		writeln!(file, "# Make tests run faster and get better error messages").unwrap();
		writeln!(file, "developer").unwrap();
		writeln!(file, "dev-fast-gossip").unwrap();
		writeln!(file, "dev-bitcoind-poll=1").unwrap();
		writeln!(file, "allow-deprecated-apis=false").unwrap();

		if let Some(grpc_port) = self.state.lock().await.grpc_port {
			writeln!(file, "grpc-port={}", grpc_port).unwrap();
		}

		if let Some(port) = self.state.lock().await.port {
			writeln!(file, "addr=0.0.0.0:{}", port).unwrap();
		}
	}

	pub async fn grpc_port(&self) -> Option<u16> {
		self.state.lock().await.grpc_port
	}

	async fn new_grpc_client(&self, grpc_port: u16) -> anyhow::Result<NodeClient<Channel>> {
		// Client doesn't support grpc over http
		// We need to use https using m-TLS authentication
		let dir = &self.config.lightning_dir;
		let ca_pem = fs::read_to_string(dir.join("regtest/ca.pem"))?;
		let id_pem = fs::read_to_string(dir.join("regtest/client.pem"))?;
		let id_key = fs::read_to_string(dir.join("regtest/client-key.pem"))?;

		let grpc_uri : Uri = format!("https://localhost:{}", grpc_port).parse().unwrap();
		let channel = Channel::builder(grpc_uri).tls_config(ClientTlsConfig::new()
			.ca_certificate(Certificate::from_pem(ca_pem))
			.identity(Identity::from_pem(&id_pem, &id_key))
		)?.connect().await?;


		let client = NodeClient::new(channel);
		Ok(client)
	}

	pub async fn try_grpc_client(&self) -> anyhow::Result<NodeClient<Channel>> {
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

	pub async fn grpc_client(&self) -> NodeClient<Channel> {
		self.try_grpc_client().await.expect("failed to create rpc client")
	}

	async fn is_ready(&self) -> bool {
		if let Ok(mut client) = self.try_grpc_client().await {
			let req = grpc::GetinfoRequest{};
			client.getinfo(req).await.is_ok()
		} else {
			false
		}
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

		self.write_config_file().await;
		Ok(())
	}

	async fn wait_for_init(&self) -> anyhow::Result<()> {
		loop {
			if self.is_ready().await {
				return Ok(());
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

	pub async fn grpc_client(&self) -> NodeClient<Channel> {
		self.inner.grpc_client().await
	}

	pub async fn port(&self) -> Option<u16> {
		self.inner.state.lock().await.port
	}

	pub async fn id(&self) -> Vec<u8> {
		let mut client = self.grpc_client().await;
		client.getinfo(grpc::GetinfoRequest {}).await.unwrap().into_inner().id
	}

	pub async fn connect(&self, other : &Lightningd) {
		// Get the  connection details of the other lightning Node
		let other_id = other.grpc_client().await
			.getinfo(grpc::GetinfoRequest{}).await.unwrap()
			.into_inner().id;
		let other_host = "localhost";
		let other_port = other.port().await
			.expect(&format!("No port configured on `{}`", other.name()));

		// Connect both nodes
		let mut client = self.grpc_client().await;
		client.connect_peer(
			grpc::ConnectRequest {
				id: hex::encode(other_id),
				host: Some(other_host.to_owned()),
				port: Some(u32::from(other_port))
			}
		).await.unwrap();
	}

	/// Wait for block
	pub async fn wait_for_block(&self, blockheight: u64) {
		trace!("{} - Wait for block {}", self.name(), blockheight);
		let mut client = self.grpc_client().await;
		client.wait_block_height(grpc::WaitblockheightRequest {
			blockheight: u32::try_from(blockheight).unwrap(),
			timeout: None,
		}).await.unwrap();
	}

	/// Wait until lightnignd is synced with bitcoind
	pub async fn wait_for_block_sync(&self, bitcoind: &Bitcoind) {
		let height = bitcoind.get_block_count().await;
		self.wait_for_block(height)	.await;
	}

	pub async fn get_onchain_address(&self) -> bitcoin::Address {
		let mut client = self.grpc_client().await;
		let response = client.new_addr(grpc::NewaddrRequest {
			addresstype: None,
		}).await.unwrap().into_inner();
		let bech32 = response.bech32.unwrap();

		bitcoin::Address::from_str(&bech32).unwrap().assume_checked()
	}

	pub async fn fund_channel(&self, other: &Lightningd, amount: Amount) -> bitcoin::Txid {
		let mut client = self.grpc_client().await;
		let request = grpc::FundchannelRequest {
			id: other.id().await,
			amount: Some(grpc::AmountOrAll{value : Some(grpc::amount_or_all::Value::Amount(grpc::Amount {msat : amount.to_sat()*1000}))}),
			feerate: None, announce: None, push_msat: None, close_to: None, request_amt: None, compact_lease: None, minconf: None,
			utxos: vec![], mindepth: None, reserve: None, channel_type: vec![]};

		let response : grpc::FundchannelResponse = client.fund_channel(request).await.unwrap().into_inner();
		Txid::from_slice(&response.txid).unwrap()
	}

	pub async fn invoice(
		&self,
		amount: Amount,
		label: impl AsRef<str>,
		description: impl AsRef<str>,
	) -> String {
		let mut client = self.grpc_client().await;
		client.invoice(grpc::InvoiceRequest {
			description: description.as_ref().to_owned(),
			label: label.as_ref().to_owned(),
			amount_msat: Some(grpc::AmountOrAny{ value: Some(grpc::amount_or_any::Value::Amount(grpc::Amount { msat: amount.to_sat()*1_000} ))}),
			cltv: None, fallbacks: vec![], preimage: None, expiry: None, exposeprivatechannels: vec![], deschashonly: None
		}).await.unwrap().into_inner().bolt11
	}

	pub async fn pay_bolt11(&self, bolt11: impl AsRef<str>) {
		let mut client = self.grpc_client().await;
		let response = client.pay(grpc::PayRequest {
			bolt11: bolt11.as_ref().to_string(),
			amount_msat: None, label: None, maxfeepercent: None, maxfee: None, retry_for: None, maxdelay: None,
			exemptfee: None, riskfactor: None, exclude: vec![], description: None,
			localinvreqid: None, partial_msat: None
		}).await.unwrap().into_inner();

		if response.status != grpc::pay_response::PayStatus::Complete as i32 {
			panic!("Payment failed with status {}", response.status);
		}
	}

	pub async fn wait_invoice_paid(&self, label: impl AsRef<str>) {
		let mut client = self.grpc_client().await;
		let invoice_status = client.wait_invoice(grpc::WaitinvoiceRequest {
			label: label.as_ref().to_string(),
		}).await.unwrap().into_inner();

		if invoice_status.status != grpc::waitinvoice_response::WaitinvoiceStatus::Paid as i32 {
			panic!("Invoice expired before payment");
		}
	}
}

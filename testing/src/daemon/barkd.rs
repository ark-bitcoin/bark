
use std::env;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::Context;
use bitcoin::{Amount, Network};
use bitcoin::secp256k1::rand::{self, RngCore};
use log::info;
use tokio::process::Command;

use bark_json::cli::{
	ArkInfo, Balance, ExitProgressResponse, ExitTransactionStatus,
	InvoiceInfo, LightningReceiveInfo, NextRoundStart, PendingBoardInfo,
};
use bark_json::cli::onchain::{Address, OnchainBalance};
use bark_json::notifications::WalletNotification;
use bark_json::primitives::{TransactionInfo, UtxoInfo, WalletVtxoInfo};
use bark_json::web::{
	BarkNetwork, ConnectedResponse, CreateWalletRequest, EncodedVtxoResponse,
	ExitStartResponse, FeeEstimateResponse, MailboxSyncResponse, OnchainFeeRatesResponse,
	PendingRoundInfo, TipResponse,
};
use bark_rest::auth::AuthToken;
use bark_rest_client::apis::configuration::Configuration;
use bark_rest_client::apis::{
	bitcoin_api, boards_api, default_api, exits_api, fees_api, lightning_api,
	onchain_api, wallet_api,
};
use bark_rest_client::models::{
	BoardRequest, ExitClaimAllRequest, ExitClaimVtxosRequest, ExitProgressRequest,
	ExitStartRequest, LightningInvoiceRequest, RefreshRequest,
};
use futures::{Stream, StreamExt};
use tokio_tungstenite::tungstenite::Message;

use crate::{Bitcoind, Daemon, DaemonHelper};
use crate::constants::env::{BARKD_EXEC, BARK_TOKIO_WORKER_THREADS};
use crate::util::resolve_path;

pub type Barkd = Daemon<BarkdHelper>;

const AUTH_TOKEN_FILE: &str = "auth_token";

/// Chain source configuration for barkd.
pub enum BarkdChainSource {
	Esplora(String),
	Bitcoind { url: String, cookie: PathBuf },
}

pub struct BarkdHelper {
	name: String,
	datadir: PathBuf,
	#[allow(dead_code)]
	ark_server_url: String,
	#[allow(dead_code)]
	chain_source: BarkdChainSource,
	/// Optional dedicated bitcoind kept alive for the duration of the test.
	_bitcoind: Option<Bitcoind>,
	port: u16,
	auth_token: AuthToken,
}

impl Barkd {
	pub fn base_cmd() -> Command {
		let e = env::var(BARKD_EXEC).expect("BARKD_EXEC env not set");
		let exec = resolve_path(e).expect("failed to resolve BARKD_EXEC");
		Command::new(exec)
	}

	pub fn new(
		name: impl AsRef<str>,
		datadir: PathBuf,
		ark_server_url: String,
		chain_source: BarkdChainSource,
		bitcoind: Option<Bitcoind>,
	) -> Self {
		let mut secret = [0u8; 32];
		rand::thread_rng().fill_bytes(&mut secret);

		let helper = BarkdHelper {
			name: name.as_ref().to_string(),
			datadir,
			ark_server_url,
			chain_source,
			_bitcoind: bitcoind,
			port: 0,
			auth_token: AuthToken::new(secret),
		};
		Daemon::wrap(helper)
	}

	pub fn base_url(&self) -> String {
		format!("http://127.0.0.1:{}", self.inner.port)
	}

	pub fn client_config(&self) -> Configuration {
		let mut headers = reqwest::header::HeaderMap::new();
		headers.insert(
			reqwest::header::AUTHORIZATION,
			reqwest::header::HeaderValue::from_str(&format!("Bearer {}", self.inner.auth_token.encode()))
				.expect("invalid auth token header value"),
		);

		let client = reqwest::Client::builder()
			.default_headers(headers)
			.build()
			.expect("failed to build reqwest client");

		Configuration {
			base_path: self.base_url(),
			client,
			..Configuration::default()
		}
	}

	/// Create the barkd wallet via REST. Call this once after the daemon has started.
	///
	/// Expects a config.toml to already exist in the datadir (written by
	/// [`BarkdBuilder::create`](crate::context::builders::BarkdBuilder::create)).
	/// The request omits `ark_server` and `chain_source` so that
	/// `create_wallet` loads them from the file, mirroring the
	/// `bark create` CLI pattern.
	pub async fn create_wallet(&self) -> anyhow::Result<()> {
		let req = CreateWalletRequest {
			ark_server: None,
			ark_server_access_token: None,
			chain_source: None,
			mnemonic: None,
			network: BarkNetwork::Regtest,
			birthday_height: None,
		};

		let config = self.client_config();
		wallet_api::create_wallet(&config, req).await
			.context("failed to create barkd wallet")?;
		Ok(())
	}

	/// Get a new on-chain receiving address from barkd.
	pub async fn onchain_address(&self) -> bitcoin::Address {
		let config = self.client_config();
		let addr: Address = onchain_api::onchain_address(&config).await
			.expect("failed to get barkd onchain address");
		addr.address.require_network(Network::Regtest).unwrap()
	}

	/// Generate a new Ark receiving address.
	pub async fn ark_address(&self) -> String {
		let config = self.client_config();
		let resp = wallet_api::address(&config).await
			.expect("failed to get barkd ark address");
		resp.address
	}

	/// Request a short-lived websocket authentication ticket.
	async fn create_ws_ticket(&self) -> String {
		// The ticket endpoint is exercised directly via reqwest rather than the
		// generated bark-rest-client because its ticket + websocket flow can't
		// be represented in OpenAPI and we need a raw websocket handshake
		// afterwards anyway.
		let url = format!("{}/api/v1/notifications/ws/ticket", self.base_url());
		let resp = reqwest::Client::new()
			.get(&url)
			.bearer_auth(self.inner.auth_token.encode())
			.send()
			.await
			.expect("barkd ws ticket request failed")
			.error_for_status()
			.expect("barkd ws ticket non-success status");
		resp.json::<String>().await.expect("barkd ws ticket decode failed")
	}

	/// Open a websocket connection to `/notifications/ws` and return a stream
	/// of [`WalletNotification`]s pushed by the daemon.
	///
	/// Subscribe *before* triggering the event you want to observe — the
	/// underlying broadcast channel does not buffer messages for late
	/// subscribers.
	pub async fn notification_websocket(&self)
		-> impl Stream<Item = WalletNotification> + Unpin + Send
	{
		let ticket = self.create_ws_ticket().await;
		let url = format!(
			"ws://127.0.0.1:{}/api/v1/notifications/ws?ticket={}",
			self.inner.port, ticket,
		);
		let (ws, _resp) = tokio_tungstenite::connect_async(&url).await
			.expect("failed to open barkd websocket");
		let (_sink, stream) = ws.split();
		Box::pin(stream.filter_map(|msg| async move {
			match msg.ok()? {
				Message::Text(txt) => Some(
					serde_json::from_str::<WalletNotification>(&txt)
						.expect("invalid WalletNotification json"),
				),
				_ => None,
			}
		}))
	}

	/// Ping the barkd REST server.
	pub async fn ping(&self) {
		let config = self.client_config();
		default_api::ping(&config).await
			.expect("barkd ping failed");
	}

	/// Query the chain source for the current best block height.
	pub async fn tip(&self) -> TipResponse {
		let config = self.client_config();
		bitcoin_api::tip(&config).await
			.expect("failed to get barkd tip")
	}

	/// Return whether the wallet is connected to the Ark server.
	pub async fn connected(&self) -> ConnectedResponse {
		let config = self.client_config();
		wallet_api::connected(&config).await
			.expect("failed to check barkd connection")
	}

	/// Return Ark server configuration parameters.
	pub async fn ark_info(&self) -> ArkInfo {
		let config = self.client_config();
		wallet_api::ark_info(&config).await
			.expect("failed to get barkd ark info")
	}

	/// Return the next scheduled Ark round start time.
	pub async fn next_round(&self) -> NextRoundStart {
		let config = self.client_config();
		wallet_api::next_round(&config).await
			.expect("failed to get barkd next round")
	}

	/// List UTXOs in the on-chain wallet without syncing first.
	pub async fn onchain_utxos(&self) -> Vec<UtxoInfo> {
		let config = self.client_config();
		onchain_api::onchain_utxos(&config).await
			.expect("failed to list barkd onchain utxos")
	}

	/// List transactions in the on-chain wallet without syncing first.
	pub async fn onchain_transactions(&self) -> Vec<TransactionInfo> {
		let config = self.client_config();
		onchain_api::onchain_transactions(&config).await
			.expect("failed to list barkd onchain transactions")
	}

	/// Return the on-chain balance without syncing first.
	pub async fn onchain_balance(&self) -> Amount {
		let config = self.client_config();
		let balance: OnchainBalance = onchain_api::onchain_balance(&config).await
			.expect("failed to get barkd onchain balance");
		balance.total
	}

	/// Return the bark (off-chain) balance without syncing first.
	pub async fn bark_balance(&self) -> Balance {
		let config = self.client_config();
		wallet_api::balance(&config).await
			.expect("failed to get barkd bark balance")
	}

	/// List VTXOs in the wallet.
	pub async fn vtxos(&self, all: Option<bool>) -> Vec<WalletVtxoInfo> {
		let config = self.client_config();
		wallet_api::vtxos(&config, all).await
			.expect("failed to list barkd vtxos")
	}

	/// Get a single VTXO by id.
	pub async fn get_vtxo(&self, id: &str) -> WalletVtxoInfo {
		let config = self.client_config();
		wallet_api::get_vtxo(&config, id).await
			.expect("failed to get barkd vtxo")
	}

	/// Get the hex-encoded serialization of a VTXO.
	pub async fn get_vtxo_encoded(&self, id: &str) -> EncodedVtxoResponse {
		let config = self.client_config();
		wallet_api::get_vtxo_encoded(&config, id).await
			.expect("failed to get encoded barkd vtxo")
	}

	/// Import VTXOs from hex-encoded strings.
	pub async fn import_vtxo(&self, vtxo_hexes: Vec<String>) -> Vec<WalletVtxoInfo> {
		let config = self.client_config();
		let req = bark_json::web::ImportVtxoRequest { vtxos: vtxo_hexes };
		wallet_api::import_vtxo(&config, req).await
			.expect("failed to import barkd vtxos")
	}

	/// Board all on-chain funds into Ark.
	pub async fn board_all(&self) -> PendingBoardInfo {
		info!("{}: Boarding all on-chain funds via REST", self.name);
		let config = self.client_config();
		boards_api::board_all(&config).await
			.expect("barkd board_all failed")
	}

	/// Board the specified amount into Ark.
	pub async fn board_amount(&self, amount: Amount) -> PendingBoardInfo {
		info!("{}: Boarding {} via REST", self.name, amount);
		let config = self.client_config();
		boards_api::board_amount(&config, BoardRequest { amount_sat: amount.to_sat() }).await
			.expect("barkd board_amount failed")
	}

	/// Return all pending boards (funding transactions not yet confirmed).
	pub async fn get_pending_boards(&self) -> Vec<PendingBoardInfo> {
		let config = self.client_config();
		boards_api::get_pending_boards(&config).await
			.expect("failed to get barkd pending boards")
	}

	/// Estimate the board fee for the given amount.
	pub async fn board_fee(&self, amount: Amount) -> FeeEstimateResponse {
		let config = self.client_config();
		fees_api::board_fee(&config, amount.to_sat() as i64).await
			.expect("failed to get barkd board fee estimate")
	}

	/// Get on-chain fee rates.
	pub async fn onchain_fee_rates(&self) -> OnchainFeeRatesResponse {
		let config = self.client_config();
		fees_api::onchain_fee_rates(&config).await
			.expect("failed to get barkd onchain fee rates")
	}

	/// Refresh all VTXOs in the next round.
	pub async fn refresh_all(&self) -> PendingRoundInfo {
		let config = self.client_config();
		wallet_api::refresh_all(&config).await
			.expect("barkd refresh_all failed")
	}

	/// Refresh specific VTXOs by ID.
	pub async fn refresh_vtxos(&self, vtxo_ids: Vec<String>) -> PendingRoundInfo {
		let config = self.client_config();
		wallet_api::refresh_vtxos(&config, RefreshRequest {
			vtxos: vtxo_ids,
		}).await.expect("barkd refresh_vtxos failed")
	}

	/// List pending rounds.
	pub async fn pending_rounds(&self) -> Vec<PendingRoundInfo> {
		let config = self.client_config();
		wallet_api::pending_rounds(&config).await
			.expect("failed to get barkd pending rounds")
	}

	/// Start emergency exit for all VTXOs.
	pub async fn exit_start_all(&self) -> ExitStartResponse {
		let config = self.client_config();
		exits_api::exit_start_all(&config).await
			.expect("barkd exit_start_all failed")
	}

	/// Start emergency exit for specific VTXOs.
	pub async fn exit_start_vtxos(&self, vtxo_ids: Vec<String>) -> ExitStartResponse {
		let config = self.client_config();
		exits_api::exit_start_vtxos(&config, ExitStartRequest {
			vtxos: vtxo_ids,
		}).await.expect("barkd exit_start_vtxos failed")
	}

	/// Progress all in-flight exits by one step.
	pub async fn exit_progress(&self) -> ExitProgressResponse {
		let config = self.client_config();
		exits_api::exit_progress(&config, ExitProgressRequest {
			wait: None,
			fee_rate: None,
		}).await.expect("barkd exit_progress failed")
	}

	/// Return the status of all emergency exits.
	pub async fn get_all_exit_status(&self, history: Option<bool>, transactions: Option<bool>) -> Vec<ExitTransactionStatus> {
		let config = self.client_config();
		exits_api::get_all_exit_status(&config, history, transactions).await
			.expect("failed to get barkd exit status")
	}

	/// Claim all claimable exit outputs to an on-chain address.
	pub async fn exit_claim_all(&self, destination: &str) -> bark_json::web::ExitClaimResponse {
		let config = self.client_config();
		exits_api::exit_claim_all(&config, ExitClaimAllRequest {
			destination: destination.to_string(),
			fee_rate: None,
		}).await.expect("barkd exit_claim_all failed")
	}

	/// Claim specific exit outputs to an on-chain address.
	pub async fn exit_claim_vtxos(&self, destination: &str, vtxo_ids: Vec<String>) -> bark_json::web::ExitClaimResponse {
		let config = self.client_config();
		exits_api::exit_claim_vtxos(&config, ExitClaimVtxosRequest {
			destination: destination.to_string(),
			vtxos: vtxo_ids,
			fee_rate: None,
		}).await.expect("barkd exit_claim_vtxos failed")
	}

	/// Force a full off-chain sync via `POST /sync`. Updates fee rates,
	/// pulls the mailbox, and progresses rounds / lightning / boards /
	/// offboards. Does not sync the on-chain BDK wallet — use
	/// [`Barkd::onchain_sync`] for that.
	pub async fn sync(&self) {
		let config = self.client_config();
		wallet_api::sync(&config).await.expect("barkd /sync failed");
	}

	/// Sync the on-chain BDK wallet via `POST /onchain/sync` so barkd
	/// picks up new UTXOs and confirmations.
	pub async fn onchain_sync(&self) {
		let config = self.client_config();
		onchain_api::onchain_sync(&config).await.expect("barkd /onchain/sync failed");
	}

	/// Trigger a mailbox-only sync via `POST /sync/mailbox` and return the
	/// new mailbox tip.
	pub async fn sync_mailbox(&self) -> MailboxSyncResponse {
		let config = self.client_config();
		wallet_api::sync_mailbox(&config).await
			.expect("barkd /sync/mailbox failed")
	}

	/// Create a BOLT11 invoice for the given amount.
	pub async fn lightning_invoice(&self, amount: Amount) -> InvoiceInfo {
		info!("{}: Create lightning invoice for {}", self.name, amount);
		let config = self.client_config();
		let req = LightningInvoiceRequest { amount_sat: amount.to_sat() };
		lightning_api::generate_invoice(&config, req).await
			.expect("failed to generate lightning invoice via barkd")
	}

	/// Return all pending (not-yet-finished) lightning receives.
	pub async fn pending_lightning_receives(&self) -> Vec<LightningReceiveInfo> {
		let config = self.client_config();
		lightning_api::list_receive_statuses(&config).await
			.expect("failed to list pending lightning receives via barkd")
	}
}

#[async_trait]
impl DaemonHelper for BarkdHelper {
	fn name(&self) -> &str {
		&self.name
	}

	fn datadir(&self) -> PathBuf {
		self.datadir.clone()
	}

	async fn get_command(&self) -> anyhow::Result<Command> {
		let mut cmd = Barkd::base_cmd();

		if let Ok(nb) = env::var(BARK_TOKIO_WORKER_THREADS) {
			cmd.env("TOKIO_WORKER_THREADS", nb);
		}

		cmd.args([
			"--datadir", self.datadir.to_str().expect("non-UTF-8 datadir"),
			"--port", &self.port.to_string(),
			"--verbose",
		]);
		Ok(cmd)
	}

	async fn make_reservations(&mut self) -> anyhow::Result<()> {
		self.port = portpicker::pick_unused_port().expect("No ports free");
		Ok(())
	}

	async fn prepare(&self) -> anyhow::Result<()> {
		std::fs::create_dir_all(&self.datadir)?;
		std::fs::write(
			self.datadir.join(AUTH_TOKEN_FILE),
			self.auth_token.encode(),
		)?;
		Ok(())
	}

	async fn wait_for_init(&self) -> anyhow::Result<()> {
		// `wait_for_init` is on `BarkdHelper`, not the `Barkd` type alias, so
		// `client_config()` is not available here. Construct the config inline.
		let config = Configuration {
			base_path: format!("http://127.0.0.1:{}", self.port),
			..Configuration::default()
		};
		loop {
			if default_api::ping(&config).await.is_ok() {
				return Ok(());
			}
			tokio::time::sleep(Duration::from_millis(100)).await;
		}
	}
}

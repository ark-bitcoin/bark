//! Dispatch of NWC commands onto a bark wallet.

use std::sync::{Arc, Weak};

use bitcoin_ext::AmountExt;
use nostr::key::PublicKey;
use nostr::nips::nip47::{
	GetBalanceResponse, GetInfoResponse, Method, NIP47Error, Request, RequestParams,
	ResponseResult,
};
use parking_lot::RwLock;

use crate::{Wallet, WalletInner};

use bark_nwc::connection::ConnectionStore;
use bark_nwc::error::{ContextExt, NIP47ErrorExt};
use bark_nwc::handler::{HandlerFuture, RequestHandler};


/// Serves NWC requests from a bark wallet, limited to the methods each
/// connection was granted.
pub struct WalletHandler {
	/// Weak because the wallet owns the manager that owns this handler, so a
	/// strong reference would keep the wallet alive after its last handle is
	/// dropped.
	wallet: Weak<WalletInner>,
	connections: Arc<RwLock<ConnectionStore>>,
}

impl WalletHandler {
	pub fn new(wallet: Wallet, connections: Arc<RwLock<ConnectionStore>>) -> Self {
		WalletHandler { wallet: Arc::downgrade(&wallet.inner), connections }
	}

	fn wallet(&self) -> Result<Wallet, NIP47Error> {
		let inner = self.wallet.upgrade().internal("wallet is closed")?;
		Ok(Wallet { inner })
	}

	async fn get_balance(&self) -> Result<ResponseResult, NIP47Error> {
		let balance = self.wallet()?.balance().await
			.internal("balance lookup")?;
		Ok(ResponseResult::GetBalance(GetBalanceResponse {
			balance: balance.spendable.to_msat(),
		}))
	}

	async fn get_info(&self, methods: Vec<Method>) -> Result<ResponseResult, NIP47Error> {
		let wallet = self.wallet()?;
		let network = wallet.network().await
			.internal("network lookup")?;
		let block_height = wallet.chain().tip().await
			.internal("chain tip lookup")?;

		Ok(ResponseResult::GetInfo(GetInfoResponse {
			alias: Some("bark".to_string()),
			color: None,
			pubkey: None,
			network: Some(network.to_string()),
			block_height: Some(block_height.into()),
			block_hash: None,
			methods: methods,
			notifications: Vec::new(),
		}))
	}
}

impl RequestHandler for WalletHandler {
	fn handle(
		&self,
		client: PublicKey,
		request: Request,
	) -> HandlerFuture<'_> {
		Box::pin(async move {
			self.connections.read().authorise(&client.to_hex(), &request.method)?;

			match request.params {
				RequestParams::GetBalance => self.get_balance().await,
				RequestParams::GetInfo => self.get_info(self.supported_methods()).await,
				_ => Err(NIP47Error::not_implemented(
					format!("{} is not supported by bark", request.method),
				)),
			}
		})
	}

	fn supported_methods(&self) -> Vec<Method> {
		vec![
			Method::GetInfo,
			Method::GetBalance,
		]
	}
}

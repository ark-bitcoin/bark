//! Dispatch of NWC commands onto a bark wallet.

use std::sync::{Arc, Weak};
use std::time::Duration;

use bitcoin_ext::AmountExt;
use log::warn;
use nostr::key::PublicKey;
use nostr::nips::nip47::{
	ErrorCode, GetBalanceResponse, GetInfoResponse, MakeInvoiceRequest, MakeInvoiceResponse,
	Method, NIP47Error, PayInvoiceRequest, PayInvoiceResponse, Request, RequestParams,
	ResponseResult,
};
use parking_lot::RwLock;

use crate::{Wallet, WalletInner};
use crate::actions::lightning::pay::LightningSendState;

use bark_nwc::amount::{pay_amount, receive_amount};
use bark_nwc::connection::ConnectionStore;
use bark_nwc::error::{ContextExt, NIP47ErrorExt};
use bark_nwc::handler::{HandlerFuture, RequestHandler};


/// How long to wait for a lightning payment before answering the client.
///
/// An Ark lightning send is not instant, but NIP-47 clients time out and a
/// request may carry an expiration. Waiting forever would hold the request loop
/// and still lose the race, so we bound it and report a timeout as a failure
/// the client can retry safely: `pay_invoice` is idempotent on payment hash.
const PAY_TIMEOUT: Duration = Duration::from_secs(60);


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

	async fn make_invoice(&self, p: MakeInvoiceRequest) -> Result<ResponseResult, NIP47Error> {
		// bark cannot bind a description hash into the invoice it mints. An
		// invoice that silently drops one fails verification at the payer, so
		// refusing is the honest answer.
		if p.description_hash.is_some() {
			return Err(NIP47Error::not_implemented(
				"bark cannot create invoices with a description hash",
			));
		}
		if p.expiry == Some(0) {
			return Err(NIP47Error::other("expiry must be at least one second"));
		}

		let amount = receive_amount(p.amount)?;
		let invoice = self.wallet()?.bolt11_invoice_builder()
			.amount(amount)
			.description(p.description.clone())
			.expiry(p.expiry.map(Duration::from_secs))
			.build().await
			.internal("invoice creation")?;

		Ok(ResponseResult::MakeInvoice(MakeInvoiceResponse {
			invoice: invoice.to_string(),
			payment_hash: Some(invoice.payment_hash().to_string()),
			description: p.description,
			description_hash: None,
			preimage: None,
			// What the invoice actually asks for, which is the requested amount
			// rounded down to whole sats. Echoing the request instead would name
			// an amount no payer can settle.
			amount: Some(amount.to_msat()),
			created_at: Some(nostr::types::Timestamp::now()),
			expires_at: invoice.expires_at()
				.map(|t| nostr::types::Timestamp::from_secs(t.as_secs())),
		}))
	}

	async fn pay_invoice(&self, p: PayInvoiceRequest) -> Result<ResponseResult, NIP47Error> {
		let user_amount = p.amount.map(pay_amount);

		let wallet = self.wallet()?;
		let paid = bark_runtime::timeout(
			PAY_TIMEOUT,
			wallet.pay_lightning_invoice(p.invoice.as_str(), user_amount, true),
		).await;

		let invoice = match paid {
			Err(_) => {
				// The payment may still land. Reporting failure is the least
				// bad answer, and retrying the same invoice is safe.
				return Err(NIP47Error {
					code: ErrorCode::PaymentFailed,
					message: format!(
						"payment did not settle within {}s and is still in progress",
						PAY_TIMEOUT.as_secs(),
					),
				});
			},
			Ok(Err(e)) => {
				warn!("NWC pay_invoice failed: {e:#}");
				return Err(NIP47Error {
					code: ErrorCode::PaymentFailed,
					message: "the payment failed".into(),
				});
			},
			Ok(Ok(invoice)) => invoice,
		};

		let hash = invoice.payment_hash();
		let state = wallet.lightning_send_state(hash).await
			.internal("send state lookup")?;

		let LightningSendState::Paid(paid) = state else {
			return Err(NIP47Error {
				code: ErrorCode::PaymentFailed,
				message: "the payment did not settle".into(),
			});
		};

		Ok(ResponseResult::PayInvoice(PayInvoiceResponse {
			preimage: paid.preimage.to_string(),
			fees_paid: None,
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
				RequestParams::MakeInvoice(p) => self.make_invoice(p).await,
				RequestParams::PayInvoice(p) => self.pay_invoice(p).await,
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
			Method::MakeInvoice,
			Method::PayInvoice,
		]
	}
}

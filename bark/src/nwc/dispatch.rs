//! Dispatch of NWC commands onto a bark wallet.

use std::sync::{Arc, Weak};
use std::time::Duration;

use bitcoin_ext::AmountExt;
use log::{debug, warn};
use nostr::key::PublicKey;
use nostr::nips::nip47::{
	ErrorCode, GetBalanceResponse, GetInfoResponse, LookupInvoiceResponse, ListTransactionsRequest,
	MakeInvoiceRequest, MakeInvoiceResponse, Method, NIP47Error, PayInvoiceRequest,
	PayInvoiceResponse, Request, RequestParams, ResponseResult, TransactionState,
	TransactionType,
};
use parking_lot::RwLock;

use crate::{Wallet, WalletInner};
use crate::actions::lightning::pay::LightningSendState;
use crate::actions::lightning::receive::LightningReceiveState;
use crate::movement::{MovementStatus, PaymentMethod};

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


/// The NWC methods a bark wallet answers.
///
/// A free function rather than only [RequestHandler::supported_methods], so
/// that hosts can validate and document connections without a wallet.
pub fn supported_methods() -> Vec<Method> {
	vec![
		Method::GetInfo,
		Method::GetBalance,
		Method::MakeInvoice,
		Method::LookupInvoice,
		Method::PayInvoice,
		Method::ListTransactions,
	]
}


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

	async fn lookup_invoice(
		&self,
		payment_hash: Option<String>,
		invoice: Option<String>,
	) -> Result<ResponseResult, NIP47Error> {
		// The invoice is kept, not just the hash it yields: it is the fallback
		// source of the amount once a settled payment's checkpoint is gone.
		let parsed = parse_invoice(invoice.as_deref());
		let hash = match (&payment_hash, &parsed) {
			(Some(hash), _) => hash.parse()
				.other("payment_hash is not valid hex")?,
			(None, Some(invoice)) => (*invoice.payment_hash()).into(),
			(None, None) => {
				return Err(NIP47Error::other(
					"either payment_hash or a parseable invoice is required",
				));
			},
		};

		// A hash can name either direction, so both are checked. An outgoing
		// payment is looked at first because it is the one a client is most
		// likely to be polling.
		let wallet = self.wallet()?;
		let send = wallet.lightning_send_state(hash).await
			.internal("send state lookup")?;
		if let LightningSendState::Paid(paid) = send {
			// PaidInvoice records neither amount nor fee, so they come from the
			// checkpoint while it exists and from the invoice otherwise.
			// Reporting a settled payment as zero would read as a free payment.
			let checkpoint = wallet.lightning_send_checkpoint(hash).await
			.internal("send checkpoint lookup")?;
			let (amount, fees_paid) = match checkpoint {
				Some(cp) => (cp.payment_amount.to_msat(), cp.fee.to_msat()),
				None => {
					let amount = parsed.as_ref()
						.and_then(|i| i.amount_milli_satoshis())
						.unwrap_or(0);
					if amount == 0 {
						debug!("No amount available for settled payment {hash}");
					}
					(amount, 0)
				},
			};

			return Ok(ResponseResult::LookupInvoice(LookupInvoiceResponse {
				transaction_type: Some(TransactionType::Outgoing),
				state: Some(TransactionState::Settled),
				invoice: invoice.clone(),
				description: None,
				description_hash: None,
				preimage: Some(paid.preimage.to_string()),
				payment_hash: paid.payment_hash.to_string(),
				amount: amount,
				fees_paid: fees_paid,
				created_at: to_timestamp(paid.paid_at),
				expires_at: None,
				settled_at: Some(to_timestamp(paid.paid_at)),
				metadata: None,
			}));
		}

		if let LightningSendState::InProgress(pending) = send {
			return Ok(ResponseResult::LookupInvoice(LookupInvoiceResponse {
				transaction_type: Some(TransactionType::Outgoing),
				state: Some(TransactionState::Pending),
				invoice: Some(pending.invoice.to_string()),
				description: None,
				description_hash: None,
				preimage: None,
				payment_hash: hash.to_string(),
				amount: pending.payment_amount.to_msat(),
				fees_paid: pending.fee.to_msat(),
				created_at: nostr::types::Timestamp::now(),
				expires_at: None,
				settled_at: None,
				metadata: None,
			}));
		}

		// lightning_receive_state fails rather than answering for a hash it
		// does not know, so an unknown hash is caught here as NOT_FOUND.
		let known = wallet.lightning_receive_preimage(hash).await
			.internal("receive lookup")?;
		if known.is_none() {
			return Err(NIP47Error {
				code: ErrorCode::NotFound,
				message: "no payment with this payment hash".into(),
			});
		}

		let receive = wallet.lightning_receive_state(hash).await
			.internal("receive state lookup")?;
		match receive {
			LightningReceiveState::Settled(settled) => {
				Ok(ResponseResult::LookupInvoice(LookupInvoiceResponse {
					transaction_type: Some(TransactionType::Incoming),
					state: Some(TransactionState::Settled),
					invoice: Some(settled.invoice.to_string()),
					description: None,
					description_hash: None,
					preimage: Some(settled.preimage.to_string()),
					payment_hash: settled.payment_hash.to_string(),
					amount: settled.amount.to_msat(),
					fees_paid: 0,
					created_at: to_timestamp(settled.settled_at),
					expires_at: None,
					settled_at: Some(to_timestamp(settled.settled_at)),
					metadata: None,
				}))
			},
			LightningReceiveState::InProgress(pending) => {
				Ok(ResponseResult::LookupInvoice(LookupInvoiceResponse {
					transaction_type: Some(TransactionType::Incoming),
					state: Some(TransactionState::Pending),
					invoice: Some(pending.invoice.to_string()),
					description: None,
					description_hash: None,
					preimage: None,
					payment_hash: pending.payment_hash.to_string(),
					amount: pending.invoice.amount_milli_satoshis().unwrap_or(0),
					fees_paid: 0,
					created_at: nostr::types::Timestamp::now(),
					expires_at: None,
					settled_at: None,
					metadata: None,
				}))
			},
		}
	}

	async fn list_transactions(
		&self,
		p: ListTransactionsRequest,
	) -> Result<ResponseResult, NIP47Error> {
		let movements = self.wallet()?.history().await
			.internal("history lookup")?;

		let mut transactions = Vec::new();
		for movement in movements {
			// Only lightning movements have a NWC representation; boards,
			// exits and refreshes have no invoice or payment hash to report.
			let Some(transaction) = movement_to_transaction(&movement)? else { continue };

			if let Some(kind) = p.transaction_type {
				if transaction.transaction_type != Some(kind) {
					continue;
				}
			}
			if let Some(from) = p.from {
				if transaction.created_at < from {
					continue;
				}
			}
			if let Some(until) = p.until {
				if transaction.created_at > until {
					continue;
				}
			}
			transactions.push(transaction);
		}

		let offset = p.offset.unwrap_or(0) as usize;
		let limit = p.limit.map(|l| l as usize).unwrap_or(usize::MAX);
		let transactions = transactions.into_iter().skip(offset).take(limit).collect();

		Ok(ResponseResult::ListTransactions(transactions))
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
				RequestParams::LookupInvoice(p) => {
					self.lookup_invoice(p.payment_hash, p.invoice).await
				},
				RequestParams::ListTransactions(p) => self.list_transactions(p).await,
				_ => Err(NIP47Error::not_implemented(
					format!("{} is not supported by bark", request.method),
				)),
			}
		})
	}

	fn supported_methods(&self) -> Vec<Method> {
		supported_methods()
	}
}


fn to_timestamp(dt: chrono::DateTime<chrono::Local>) -> nostr::types::Timestamp {
	nostr::types::Timestamp::from_secs(dt.timestamp().max(0) as u64)
}

/// Parse a bolt11 invoice the client supplied, if it supplied one.
///
/// Kept rather than reduced to its payment hash, because it is the fallback
/// source of a settled payment's amount once its checkpoint is gone.
fn parse_invoice(invoice: Option<&str>) -> Option<lightning_invoice::Bolt11Invoice> {
	invoice?.parse().ok()
}

/// Represent a lightning movement as a NWC transaction, if it is one.
///
/// Movements that carry no invoice, such as boards, exits and refreshes, have
/// no payment hash to report and so have no NWC representation at all.
fn movement_to_transaction(
	movement: &crate::movement::Movement,
) -> Result<Option<LookupInvoiceResponse>, NIP47Error> {
	let outgoing = movement.sent_to.iter()
		.find_map(|d| match &d.destination {
			PaymentMethod::Invoice(invoice) => Some((invoice, d.amount, TransactionType::Outgoing)),
			_ => None,
		});
	let incoming = movement.received_on.iter()
		.find_map(|d| match &d.destination {
			PaymentMethod::Invoice(invoice) => Some((invoice, d.amount, TransactionType::Incoming)),
			_ => None,
		});

	let Some((invoice, amount, kind)) = outgoing.or(incoming) else {
		debug!("Skipping non-lightning movement {:?}", movement.id);
		return Ok(None);
	};

	// Only a completed movement has settled. A pending one is still in flight
	// and a failed one never will be, and reporting either as settled would
	// tell a client a payment arrived when it did not.
	let (state, settled_at) = match movement.status {
		MovementStatus::Successful => {
			(TransactionState::Settled, movement.time.completed_at.map(to_timestamp))
		},
		MovementStatus::Pending => (TransactionState::Pending, None),
		MovementStatus::Failed | MovementStatus::Canceled => (TransactionState::Failed, None),
	};

	Ok(Some(LookupInvoiceResponse {
		transaction_type: Some(kind),
		state: Some(state),
		invoice: Some(invoice.to_string()),
		description: None,
		description_hash: None,
		preimage: None,
		payment_hash: invoice.payment_hash().to_string(),
		amount: amount.to_msat(),
		fees_paid: movement.offchain_fee.to_msat(),
		created_at: to_timestamp(movement.time.created_at),
		expires_at: None,
		settled_at: settled_at,
		metadata: None,
	}))
}

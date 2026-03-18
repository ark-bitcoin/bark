
use anyhow::Context;
use bitcoin::Amount;
use bitcoin::hex::DisplayHex;
use bitcoin_ext::{AmountExt, BlockDelta};
use tokio::sync::broadcast;
use tracing::{error, trace};
use ark::lightning::{Invoice, PaymentHash, Preimage};

use crate::database;
use crate::database::ln::LightningPaymentStatus;
use super::ClnGrpcClient;

/// Handles calling the pay cln endpoint and processing the response.
pub(super) async fn handle_pay_invoice(
	db: database::Db,
	payment_update_tx: broadcast::Sender<PaymentHash>,
	mut rpc: ClnGrpcClient,
	invoice: Box<Invoice>,
	amount: Option<Amount>,
	max_cltv_expiry_delta: BlockDelta,
) {
	let payment_hash = invoice.payment_hash();
	match call_xpay(&mut rpc, &invoice, amount, max_cltv_expiry_delta).await {
		Ok(preimage) => {
			// NB we don't do db stuff when it's succesful, because
			// it will happen in the sendpay stream of the monitor process
			trace!("Payment successful, preimage: {} for payment hash {}",
				preimage.as_hex(), payment_hash.as_hex(),
			);
		},
		// Fetch and store the attempt as failed.
		Err(pay_err) => {
			error!("Error calling pay-command: {}", pay_err);
			match db.get_open_lightning_payment_attempt_by_payment_hash(payment_hash).await {
				Ok(Some(attempt)) => match db.verify_and_update_invoice(
					payment_hash,
					&attempt,
					LightningPaymentStatus::Submitted,
					Some(&format!("pay rpc call error: {}", pay_err)),
					None,
					None,
				).await {
					Ok(_) => {},
					Err(e) => error!("Error updating invoice after pay error: {e:#}"),
				}
				Ok(None) => error!("Failed to find attempt for invoice just started \
					payment_hash={payment_hash}"),
				Err(e) => error!("Error querying attempt for invoice just started \
					payment_hash={payment_hash}: {e:#}"),
			}
			let _ = payment_update_tx.send(payment_hash);
		},
	}
}

/// Calls the xpay-command over gRPC.
/// If the payment completes successfully it will return the pre-image
/// Otherwise, an error will be returned
pub(super) async fn call_xpay(
	rpc: &mut ClnGrpcClient,
	invoice: &Invoice,
	user_amount: Option<Amount>,
	max_cltv_expiry_delta: BlockDelta,
) -> anyhow::Result<Preimage> {
	match (user_amount, invoice.amount_msat()) {
		(Some(user), Some(inv)) => {
			let inv = Amount::from_msat_ceil(inv);
			if user != inv {
				bail!("invoice amount {inv} and given amount {user} don't match");
			}
		},
		(None, None) => {
			bail!("Amount not encoded in invoice nor provided by user. Please provide amount");
		},
		_ => {},
	}

	// Call the xpay command
	let pay_response = rpc.xpay(cln_rpc::XpayRequest {
		invstring: invoice.to_string(),
		amount_msat: {
			if invoice.amount_msat().is_none() {
				Some(user_amount.unwrap().into())
			} else {
				None
			}
		},
		maxdelay: Some(max_cltv_expiry_delta as u32),
		maxfee: None,
		retry_for: None,
		partial_msat: None,
		layers: vec![],
	}).await?.into_inner();

	if pay_response.payment_preimage.len() > 0 {
		Ok(pay_response.payment_preimage.try_into().ok().context("invalid preimage not 32 bytes")?)
	} else {
		bail!("xpay returned invalid preimage: {}", pay_response.payment_preimage.as_hex());
	}
}

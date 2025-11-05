use anyhow::Context;
use bitcoin::Amount;
use bitcoin::hex::DisplayHex;
use lightning_invoice::Bolt11Invoice;
use lnurllib::lightning_address::LightningAddress;
use log::info;

use ark::lightning::{Invoice, Offer, Preimage};

use crate::Wallet;

pub async fn pay_invoice(
	invoice: Bolt11Invoice,
	amount: Option<Amount>,
	comment: Option<String>,
	no_sync: bool,
	wallet: &Wallet,
) -> anyhow::Result<Preimage> {
	let inv_amount = invoice.amount_milli_satoshis()
		.map(|v| Amount::from_sat(v.div_ceil(1000)));
	if let (Some(_), Some(inv)) = (amount, inv_amount) {
		bail!("Invoice has amount of {} encoded. Please omit amount argument", inv);
	}
	let final_amount = amount.or(inv_amount)
		.context("amount required on invoice without amount")?;
	if comment.is_some() {
		bail!("comment not supported for bolt11 invoice");
	}

	if !no_sync {
		info!("Syncing wallet...");
		wallet.sync().await;
	}
	info!("Sending bolt11 payment of {} to invoice {}", final_amount, invoice);
	let preimage = wallet.send_lightning_payment(Invoice::Bolt11(invoice), amount).await?;
	info!("Payment preimage received: {}", preimage.as_hex());

	Ok(preimage)
}

pub async fn pay_offer(
	offer: Offer,
	amount: Option<Amount>,
	comment: Option<String>,
	no_sync: bool,
	wallet: &Wallet,
) -> anyhow::Result<Preimage> {
	if comment.is_some() {
		bail!("comment not supported for bolt12 offer");
	}

	if !no_sync {
		info!("Syncing wallet...");
		wallet.sync().await;
	}

	info!("Sending bolt12 payment of {:?} to offer {}", amount, offer);
	let (invoice, preimage) = wallet.pay_offer(offer, amount).await?;
	info!("Paid invoice: {:?}", invoice);
	info!("Payment preimage received: {}", preimage.as_hex());

	Ok(preimage)
}

pub async fn pay_lnaddr(
	lnaddr: LightningAddress,
	amount: Option<Amount>,
	comment: Option<String>,
	no_sync: bool,
	wallet: &Wallet,
) -> anyhow::Result<Preimage> {
	let amount = amount.context("amount missing")?;

	if !no_sync {
		info!("Syncing wallet...");
		wallet.sync().await;
	}
	info!("Sending {} to lightning address {}", amount, lnaddr);
	let comment = comment.as_ref().map(|c| c.as_str());
	let (inv, preimage) = wallet.send_lnaddr(&lnaddr, amount, comment).await?;
	info!("Paid invoice {}", inv);
	info!("Payment preimage received: {}", preimage.as_hex());

	Ok(preimage)
}


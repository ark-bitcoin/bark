pub mod pay;
pub mod receive;

use anyhow::Context;
use bitcoin::Amount;
use bitcoin::hex::DisplayHex;
use lightning_invoice::Bolt11Invoice;
use lnurllib::LnUrlResponse;
use lnurllib::lightning_address::LightningAddress;
use log::info;

use ark::lightning::{Bolt11InvoiceExt, Offer, Preimage};
use bitcoin_ext::AmountExt;

use crate::Wallet;

pub async fn pay_invoice(
	invoice: Bolt11Invoice,
	amount: Option<Amount>,
	comment: Option<String>,
	no_sync: bool,
	wallet: &Wallet,
) -> anyhow::Result<Preimage> {
	let amount = invoice.get_final_amount(amount)?;
	if comment.is_some() {
		bail!("comment not supported for bolt11 invoice");
	}

	if !no_sync {
		info!("Syncing wallet...");
		wallet.sync().await;
	}
	info!("Sending bolt11 payment of {} to invoice {}", amount, invoice);
	let preimage = wallet.pay_lightning_invoice(invoice, Some(amount)).await?;
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
	let (invoice, preimage) = wallet.pay_lightning_offer(offer, amount).await?;
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
	let (inv, preimage) = wallet.pay_lightning_address(&lnaddr, amount, comment).await?;
	info!("Paid invoice {}", inv);
	info!("Payment preimage received: {}", preimage.as_hex());

	Ok(preimage)
}

async fn lnurlp_invoice(
	lnurlp: &str,
	amount: Amount,
	comment: Option<&str>,
) -> anyhow::Result<Bolt11Invoice> {
	let client = lnurllib::Builder::default().build_async().context("lnurl client error")?;
	let resp = match client.make_request(lnurlp).await.context("failed to make lnurl request")? {
		LnUrlResponse::LnUrlPayResponse(v) => v,
		LnUrlResponse::LnUrlWithdrawResponse(_) => bail!("received lnurl withdraw"),
		LnUrlResponse::LnUrlChannelResponse(_) => bail!("received lnurl channel"),
	};

	let invoice = client.get_invoice(&resp, amount.to_msat(), None, comment).await
		.context("failed to fetch invoice from lnurlpay")?.pr;

	Ok(invoice.parse().with_context(|| format!("received invalid invoice: {}", invoice))?)
}

async fn lnaddr_invoice(
	addr: &LightningAddress,
	amount: Amount,
	comment: Option<&str>,
) -> anyhow::Result<Bolt11Invoice> {
	let lnurl = addr.lnurlp_url();
	Ok(lnurlp_invoice(&lnurl, amount, comment).await?)
}


#[cfg(test)]
mod test {
	use std::str::FromStr;
	use std::sync::Arc;

	use bitcoin::Network;
	use ark::lightning::{Bolt12Invoice, Bolt12InvoiceExt, Invoice};
	use lightning_invoice::Bolt11Invoice;

	use crate::{Config, SqliteClient, Wallet};

	#[allow(unused)] // just exists for compile check
	async fn pay_lightning_invoice_argument() {
		//! Check the different possible argument for pay_lightning_invoice

		let db = Arc::new(SqliteClient::open("").unwrap());
		let w = Wallet::open(
			&"".parse().unwrap(), db, Config::network_default(Network::Regtest),
		).await.unwrap();

		let bolt11 = Bolt11Invoice::from_str("").unwrap();
		w.pay_lightning_invoice(bolt11, None).await.unwrap();

		let bolt12 = Bolt12Invoice::from_str("").unwrap();
		w.pay_lightning_invoice(bolt12, None).await.unwrap();

		let string = format!("lnbc1..");
		w.pay_lightning_invoice(string, None).await.unwrap();

		let strr = "lnbc1..";
		w.pay_lightning_invoice(strr, None).await.unwrap();

		let invoice = Invoice::Bolt11("".parse().unwrap());
		w.pay_lightning_invoice(invoice, None).await.unwrap();
	}
}

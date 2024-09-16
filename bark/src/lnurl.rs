
use anyhow::Context;
use bitcoin::Amount;
use lightning_invoice::Bolt11Invoice;
use lnurllib::api::LnUrlResponse;
use lnurllib::lightning_address::LightningAddress;


pub async fn lnurlp_invoice(
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

	let invoice = client.get_invoice(&resp, amount.to_sat() * 1000, None, comment).await
		.context("failed to fetch invoice from lnurlpay")?.pr;

	Ok(invoice.parse().with_context(|| format!("received invalid invoice: {}", invoice))?)
}

pub async fn lnaddr_invoice(
	addr: &LightningAddress,
	amount: Amount,
	comment: Option<&str>,
) -> anyhow::Result<Bolt11Invoice> {
	let lnurl = addr.lnurlp_url();
	Ok(lnurlp_invoice(&lnurl, amount, comment).await?)
}

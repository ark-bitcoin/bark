
mod pay;
mod receive;

use anyhow::Context;
use bitcoin::Amount;
use bitcoin::hashes::Hash;
use lightning_invoice::{Bolt11Invoice, Bolt11InvoiceDescriptionRef};
use lnurllib::LnUrlResponse;
use lnurllib::lightning_address::LightningAddress;
use lnurllib::pay::PayResponse;
use log::warn;

use bitcoin_ext::AmountExt;

/// Verifies that a BOLT11 invoice returned by an LNURL-pay endpoint
/// matches the request we made, since the endpoint is untrusted.
fn verify_lnurlp_invoice(
	invoice: &Bolt11Invoice,
	amount: Amount,
	resp: &PayResponse,
) -> anyhow::Result<()> {
	match invoice.amount_milli_satoshis() {
		Some(msat) if msat == amount.to_msat() => {},
		Some(msat) => bail!(
			"lnurl-pay endpoint returned an invoice for {} msat, \
			but we requested {} ({} msat)",
			msat, amount, amount.to_msat(),
		),
		None => bail!(
			"lnurl-pay endpoint returned an amountless invoice, \
			but we requested {}", amount,
		),
	}

	// nb this is no longer a hard requirement in LUD-06 spec
	let metadata_bound = match invoice.description() {
		Bolt11InvoiceDescriptionRef::Hash(h) => h.0.to_byte_array() == resp.metadata_hash(),
		Bolt11InvoiceDescriptionRef::Direct(_) => false,
	};
	if !metadata_bound {
		warn!("lnurl-pay invoice description hash does not commit to the endpoint metadata");
	}

	Ok(())
}

/// Performs an LNURL-Pay request against `lnurlp` and returns the BOLT11
/// invoice the endpoint issues for the requested amount.
///
/// `comment` is forwarded as the LNURL-Pay `comment` field when present; the
/// endpoint may reject or truncate it according to its own `commentAllowed`
/// limit.
///
/// Returns an error if the endpoint resolves to a non-pay LNURL response
/// (withdraw, channel), if the HTTP request fails, if the returned bolt11
/// string is not a valid invoice, or if the invoice's amount doesn't match
/// the requested amount.
pub(crate) async fn lnurlp_invoice(
	lnurlp: &str,
	amount: Amount,
	comment: Option<impl AsRef<str>>,
) -> anyhow::Result<Bolt11Invoice> {
	let client = lnurllib::Builder::default().build_async().context("lnurl client error")?;
	let resp = match client.make_request(lnurlp).await.context("failed to make lnurl request")? {
		LnUrlResponse::LnUrlPayResponse(v) => v,
		LnUrlResponse::LnUrlWithdrawResponse(_) => bail!("received lnurl withdraw"),
		LnUrlResponse::LnUrlChannelResponse(_) => bail!("received lnurl channel"),
	};

	let comment = comment.as_ref().map(|s| s.as_ref());
	let invoice = client.get_invoice(&resp, amount.to_msat(), None, comment).await
		.context("failed to fetch invoice from lnurlpay")?.pr;

	let invoice: Bolt11Invoice = invoice.parse()
		.with_context(|| format!("received invalid invoice: {}", invoice))?;
	verify_lnurlp_invoice(&invoice, amount, &resp)?;

	Ok(invoice)
}

/// Resolves a Lightning Address (`user@domain`) to its LNURL-Pay endpoint and
/// returns a BOLT11 invoice issued by that endpoint for the requested amount.
///
/// Thin wrapper over [`lnurlp_invoice`]; see it for the meaning of `comment`
/// and for the set of conditions under which this call can fail.
pub(crate) async fn lnaddr_invoice(
	addr: &LightningAddress,
	amount: Amount,
	comment: Option<impl AsRef<str>>,
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
	use lnurllib::Tag;

	use crate::{Config, OpenWalletArgs, Wallet, WalletSeed};
	use crate::lock_manager::memory::MemoryLockManager;
	use crate::persist::adaptor::StorageAdaptorWrapper;

	use super::*;

	/// A known-valid BOLT11 invoice on signet for 100u (10,000 sat).
	const TEST_INVOICE_STR: &str = "lntbs100u1p5j0x82sp5d0rwfh7tgrrlwsegy9rx3tzpt36cqwjqza5x4wvcjxjzscfaf6jspp5d8q7354dg3p8h0kywhqq5dq984r8f5en98hf9ln85ug0w8fx6hhsdqqcqzpc9qyysgqyk54v7tpzprxll7e0jyvtxcpgwttzk84wqsfjsqvcdtq47zt2wssxsmtjhz8dka62mdnf9jafhu3l4cpyfnsx449v4wstrwzzql2w5qqs8uh7p";

	fn dummy_pay_response() -> PayResponse {
		PayResponse {
			callback: "https://example.com/callback".into(),
			max_sendable: 100_000_000_000,
			min_sendable: 1_000,
			tag: Tag::PayRequest,
			metadata: "[[\"text/plain\",\"test\"]]".into(),
			comment_allowed: None,
			allows_nostr: None,
			nostr_pubkey: None,
		}
	}

	#[test]
	fn lnurlp_invoice_amount_verification() {
		let invoice = Bolt11Invoice::from_str(TEST_INVOICE_STR).unwrap();
		let resp = dummy_pay_response();

		// the invoice is for exactly 10,000 sat
		verify_lnurlp_invoice(&invoice, Amount::from_sat(10_000), &resp).unwrap();

		// an invoice for any other amount must be rejected
		let err = verify_lnurlp_invoice(&invoice, Amount::from_sat(9_000), &resp).unwrap_err();
		assert!(err.to_string().contains("10000000 msat"), "err: {}", err);
		verify_lnurlp_invoice(&invoice, Amount::from_sat(11_000), &resp).unwrap_err();
	}

	#[allow(unused)] // just exists for compile check
	async fn pay_lightning_invoice_argument() {
		//! Check the different possible argument for pay_lightning_invoice

		let db = Arc::new(StorageAdaptorWrapper::new_memory());
		let w = Wallet::open(
			Network::Regtest,
			WalletSeed::new_from_seed(Network::Regtest, &[1; 64]),
			Config::network_default(Network::Regtest),
			OpenWalletArgs {
				lock_manager: Some(Box::new(MemoryLockManager::new())),
				persister: Some(db),
				..Default::default()
			},
		).await.unwrap();

		let bolt11 = Bolt11Invoice::from_str("").unwrap();
		w.pay_lightning_invoice(bolt11, None, false).await.unwrap();

		let bolt12 = Bolt12Invoice::from_str("").unwrap();
		w.pay_lightning_invoice(bolt12, None, false).await.unwrap();

		let string = format!("lnbc1..");
		w.pay_lightning_invoice(string, None, false).await.unwrap();

		let strr = "lnbc1..";
		w.pay_lightning_invoice(strr, None, false).await.unwrap();

		let invoice = Invoice::Bolt11("".parse().unwrap());
		w.pay_lightning_invoice(invoice, None, false).await.unwrap();
	}
}

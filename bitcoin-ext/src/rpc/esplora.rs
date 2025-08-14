use std::collections::{HashMap, HashSet};

use bdk_esplora::esplora_client::Amount;
use bitcoin::{FeeRate, Transaction, Txid, Wtxid};
use bitcoin::consensus::encode::serialize_hex;
use reqwest::{Body, Response};
use serde::Deserialize;

#[derive(Deserialize, Debug)]
pub struct SubmitPackageResult {
	/// The transaction package result message. "success" indicates all transactions were accepted
	/// into or are already in the mempool.
	pub package_msg: String,
	/// Transaction results keyed by [`Wtxid`].
	#[serde(rename = "tx-results")]
	pub tx_results: HashMap<Wtxid, TxResult>,
	/// List of txids of replaced transactions.
	#[serde(rename = "replaced-transactions")]
	pub replaced_transactions: Option<Vec<Txid>>,
}

#[derive(Deserialize, Debug)]
pub struct TxResult {
	/// The transaction id.
	pub txid: Txid,
	/// The [`Wtxid`] of a different transaction with the same [`Txid`] but different witness found
	/// in the mempool.
	///
	/// If set, this means the submitted transaction was ignored.
	#[serde(rename = "other-wtxid")]
	pub other_wtxid: Option<Wtxid>,
	/// Sigops-adjusted virtual transaction size.
	pub vsize: Option<u32>,
	/// Transaction fees.
	pub fees: Option<MempoolFeesSubmitPackage>,
	/// The transaction error string, if it was rejected by the mempool
	pub error: Option<String>,
}

#[derive(Deserialize, Debug)]
pub struct MempoolFeesSubmitPackage {
	/// Transaction fee.
	#[serde(with = "bitcoin::amount::serde::as_btc")]
	pub base: Amount,
	/// The effective feerate.
	///
	/// Will be `None` if the transaction was already in the mempool. For example, the package
	/// feerate and/or feerate with modified fees from the `prioritisetransaction` JSON-RPC method.
	#[serde(rename = "effective-feerate", default, deserialize_with = "deserialize_feerate")]
	pub effective_feerate: Option<FeeRate>,
	/// If [Self::effective_feerate] is provided, this holds the [`Wtxid`]s of the transactions
	/// whose fees and vsizes are included in effective-feerate.
	#[serde(rename = "effective-includes")]
	pub effective_includes: Option<Vec<Wtxid>>,
}

#[async_trait::async_trait]
pub trait EsploraClientExt {
	fn _client(&self) -> &reqwest::Client;
	fn _base_url(&self) -> &str;

	/// Make an HTTP POST request to given URL, converting any `T` that
	/// implement [`Into<Body>`] and setting query parameters, if any.
	///
	/// # Errors
	///
	/// This function will return an error either from the HTTP client, or the
	/// response's [`serde_json`] deserialization.
	// implementation borrowed from esplora-client crate
	async fn post_request_bytes<T: Into<Body> + Send>(
		&self,
		path: &str,
		body: T,
		query_params: Option<HashSet<(&str, String)>>,
	) -> Result<Response, bdk_esplora::esplora_client::Error> {
		let url: String = format!("{}{}", self._base_url(), path);
		let mut request = self._client().post(url).body(body);

		for param in query_params.unwrap_or_default() {
			request = request.query(&param);
		}

		let response = request.send().await?;

		if !response.status().is_success() {
			return Err(bdk_esplora::esplora_client::Error::HttpResponse {
				status: response.status().as_u16(),
				message: response.text().await?,
			});
		}

		Ok(response)
	}

	/// Broadcast a package of [`Transaction`] to Esplora
	///
	/// if `maxfeerate` is provided, any transaction whose
	/// fee is higher will be rejected
	///
	/// if  `maxburnamount` is provided, any transaction
	/// with higher provably unspendable outputs amount
	/// will be rejected
	async fn submit_package(
		&self,
		transactions: &[Transaction],
		maxfeerate: Option<f64>,
		maxburnamount: Option<f64>,
	) -> Result<SubmitPackageResult, bdk_esplora::esplora_client::Error> {
		let mut queryparams = HashSet::<(&str, String)>::new();
		if let Some(maxfeerate) = maxfeerate {
			queryparams.insert(("maxfeerate", maxfeerate.to_string()));
		}
		if let Some(maxburnamount) = maxburnamount {
			queryparams.insert(("maxburnamount", maxburnamount.to_string()));
		}

		let serialized_txs = transactions
			.iter()
			.map(|tx| serialize_hex(&tx))
			.collect::<Vec<_>>();

		let response = self
			.post_request_bytes(
				"/txs/package",
				serde_json::to_string(&serialized_txs).unwrap(),
				Some(queryparams),
			)
			.await?;

		Ok(response.json::<SubmitPackageResult>().await?)
	}
}

impl EsploraClientExt for bdk_esplora::esplora_client::AsyncClient {
	fn _client(&self) -> &reqwest::Client { self.client() }
	fn _base_url(&self) -> &str { self.url() }
}

fn deserialize_feerate<'de, D>(d: D) -> Result<Option<FeeRate>, D::Error>
where
	D: serde::de::Deserializer<'de>,
{
	use serde::de::Error;

	let btc_per_kvb = match Option::<f64>::deserialize(d)? {
		Some(v) => v,
		None => return Ok(None),
	};
	let sat_per_kwu = btc_per_kvb * 25_000_000.0;
	if sat_per_kwu.is_infinite() {
		return Err(D::Error::custom("feerate overflow"));
	}
	Ok(Some(FeeRate::from_sat_per_kwu(sat_per_kwu as u64)))
}

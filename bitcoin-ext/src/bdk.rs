
use std::collections::{HashMap, HashSet};
use std::borrow::BorrowMut;

use bdk_wallet::coin_selection::InsufficientFunds;
use bdk_wallet::{SignOptions, TxBuilder, TxOrdering, Wallet};
use bdk_wallet::chain::BlockId;
use bdk_wallet::error::CreateTxError;
use bitcoin::consensus::encode::serialize_hex;
use bitcoin::{psbt, Amount, FeeRate, OutPoint, Transaction, TxOut, Txid, Weight, Wtxid};
use cbitcoin::{BlockHash, Psbt, Witness};
use reqwest::{Body, Response};
use serde::Deserialize;

use crate::{fee, BlockHeight, P2TR_DUST};
use crate::bitcoin::TransactionExt;


/// An extension trait for [TxBuilder].
pub trait TxBuilderExt<'a, A>: BorrowMut<TxBuilder<'a, A>> {
	/// Add an input to the tx that spends a fee anchor.
	fn add_fee_anchor_spend(&mut self, anchor: OutPoint, output: &TxOut)
	where
		A: bdk_wallet::coin_selection::CoinSelectionAlgorithm,
	{
		let psbt_in = psbt::Input {
			witness_utxo: Some(output.clone()),
			final_script_witness: Some(Witness::new()),
			..Default::default()
		};
		self.borrow_mut().add_foreign_utxo(anchor, psbt_in, fee::FEE_ANCHOR_SPEND_WEIGHT)
			.expect("adding foreign utxo");
	}
}
impl<'a, A> TxBuilderExt<'a, A> for TxBuilder<'a, A> {}


/// Error resulting from the [WalletExt::make_cpfp] function.
#[derive(Debug, thiserror::Error)]
pub enum CpfpError {
	#[error("tx has no fee anchor: {0}")]
	NoFeeAnchor(Txid),
	#[error("you need more confirmations on your on-chain funds: {0}")]
	InsufficientConfirmedFunds(InsufficientFunds),
}


/// An extension trait for [Wallet].
pub trait WalletExt: BorrowMut<Wallet> {
	/// Returns an iterator for each unconfirmed transaction in the wallet. Useful for syncing the
	/// wallet with bitcoind.
	fn unconfirmed_txids(&self) -> impl Iterator<Item = Txid> {
		self.borrow().transactions().filter_map(|tx| {
			if tx.chain_position.is_unconfirmed() {
				Some(tx.tx_node.txid)
			} else {
				None
			}
		})
	}

	/// Return all vtxos that are untrusted: unconfirmed and not change.
	fn untrusted_utxos(&self, confirmed_height: Option<BlockHeight>) -> Vec<OutPoint> {
		let w = self.borrow();
		let mut ret = Vec::new();
		for utxo in w.list_unspent() {
			// We trust confirmed utxos if they are confirmed enough.
			if let Some(h) = utxo.chain_position.confirmation_height_upper_bound() {
				if let Some(min) = confirmed_height {
					if h <= min {
						continue;
					}
				} else {
					continue;
				}
			}

			// For unconfirmed, we only trust txs from which all inputs are ours.
			// NB this is still not 100% safe, because this can mark a tx that spends
			// an untrusted tx as trusted. We don't create such txs in our codebase,
			// but we should be careful not to start doing this.
			let txid = utxo.outpoint.txid;
			if let Some(tx) = w.get_tx(txid) {
				if tx.tx_node.tx.input.iter().all(|i| w.get_tx(i.previous_output.txid).is_some()) {
					continue;
				}
			}

			ret.push(utxo.outpoint);
		}
		ret
	}

	/// Create a cpfp spend that spends the fee anchors in the given txs.
	///
	/// This method doesn't broadcast any txs.
	fn make_cpfp(
		&mut self,
		txs: &[&Transaction],
		fee_rate: FeeRate,
	) -> Result<Psbt, CpfpError> {
		let wallet = self.borrow_mut();

		assert!(!txs.is_empty());
		let anchors = txs.iter().map(|tx| {
			tx.fee_anchor().ok_or_else(|| CpfpError::NoFeeAnchor(tx.compute_txid()))
		}).collect::<Result<Vec<_>, _>>()?;

		// Since BDK doesn't support adding extra weight for fees, we have to
		// first build the tx regularly, and then build it again.
		// Since we have to guarantee that we have enough money in the inputs,
		// we will "fake" create an output on the first attempt. This might
		// overshoot the fee, but we prefer that over undershooting it.

		let package_weight = txs.iter().map(|t| t.weight()).sum::<Weight>();
		let extra_fee_needed = fee_rate * package_weight;

		// Since BDK doesn't allow tx without recipients, we add a drain output.
		let change_addr = wallet.reveal_next_address(bdk_wallet::KeychainKind::Internal);

		let balance = wallet.balance().total();

		let untrusted_utxos = wallet.untrusted_utxos(None);
		let template_weight = {
			let mut b = wallet.build_tx();
			b.ordering(TxOrdering::Untouched);
			b.only_witness_utxo();
			b.unspendable(untrusted_utxos.clone());
			for (point, txout) in &anchors {
				b.add_fee_anchor_spend(*point, txout);
			}
			b.add_recipient(change_addr.address.script_pubkey(), extra_fee_needed + P2TR_DUST);
			b.fee_rate(fee_rate);
			let mut psbt = match b.finish() {
				Ok(psbt) => psbt,
				Err(CreateTxError::CoinSelection(e)) if e.needed <= balance => {
					return Err(CpfpError::InsufficientConfirmedFunds(e));
				},
				Err(e) => panic!("error creating tx: {}", e),
			};
			let opts = SignOptions {
				trust_witness_utxo: true,
				..Default::default()
			};
			let finalized = wallet.sign(&mut psbt, opts)
				.expect("failed to sign anchor spend template");
			assert!(finalized);
			let tx = psbt.extract_tx()
				.expect("anchor spend template not fully signed");
			assert_eq!(
				tx.input[0].witness.size() as u64,
				fee::FEE_ANCHOR_SPEND_WEIGHT.to_wu(),
			);
			tx.weight()
		};

		let total_weight = template_weight + package_weight;
		let total_fee = fee_rate * total_weight;
		let extra_fee_needed = total_fee;

		// Then build actual tx.
		let mut b = wallet.build_tx();
		b.only_witness_utxo();
		b.unspendable(untrusted_utxos);
		b.version(3); // for 1p1c package relay
		for (point, txout) in &anchors {
			b.add_fee_anchor_spend(*point, txout);
		}
		b.drain_to(change_addr.address.script_pubkey());
		b.fee_absolute(extra_fee_needed);
		Ok(b.finish().expect("failed to craft anchor spend tx"))
	}

	/// Insert a checkpoint into the wallet.
	///
	/// It's advised to use this only when recovering a wallet with a birthday.
	fn set_checkpoint(&mut self, height: u32, hash: BlockHash) {
		let checkpoint = BlockId { height, hash };
		let wallet = self.borrow_mut();
		wallet.apply_update(bdk_wallet::Update {
			chain: Some(wallet.latest_checkpoint().insert(checkpoint)),
			..Default::default()
		}).expect("should work, might fail if tip is genesis");
	}
}
impl WalletExt for Wallet {}


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

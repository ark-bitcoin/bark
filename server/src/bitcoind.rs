//! Server-side helpers around bitcoind RPC.
//!
//! The async paths use the upstream [`bitcoind_async_client::Client`]
//! directly, calling [`Client::call_raw`] (raw_rpc feature) and
//! deserialising into the existing `bitcoincore_rpc::json::*` and
//! bitcoin-ext result types. Most one-shot RPCs are inlined at their
//! call site; this module keeps only the helpers that have non-trivial
//! logic or many call sites.
//!
//! `bdk_bitcoind_rpc::Emitter` is sync-only upstream; the wallet keeps a
//! sync [`bitcoin_ext::rpc::BitcoinRpcClient`] companion and runs the
//! Emitter loop inside `tokio::task::spawn_blocking`.

use std::borrow::Borrow;

use anyhow::{bail, Context};
use bitcoin::consensus::encode;
use bitcoin::{Amount, BlockHash, FeeRate, Network, OutPoint, Transaction, TxOut, Txid, Weight};
use bitcoind_async_client::Client;
use bitcoind_async_client::error::ClientError;
use bitcoind_async_client::traits::{Broadcaster, Reader};
use bitcoin_ext::rpc::{
	self, Auth, GetRawTransactionResult, RPC_INVALID_ADDRESS_OR_KEY,
	RPC_VERIFY_ALREADY_IN_UTXO_SET, SubmitPackageResult,
};
use bitcoin_ext::{BlockHeight, BlockRef, DEEPLY_CONFIRMED, TxStatus};
use serde::Deserialize;
use serde_json::Value;

/// v31 added the chunk fields of `getmempoolentry`.
const MIN_BITCOIND_VERSION: usize = 31_00_00;

/// Build a [`bitcoind_async_client::Client`] from our config-supplied auth.
///
/// The upstream `Auth` enum has no `None` variant; anonymous auth is
/// rejected explicitly. The server config always supplies a cookie file
/// or user/pass.
pub fn build_client(url: &str, auth: Auth) -> anyhow::Result<Client> {
	let async_auth = match auth {
		Auth::None => bail!(
			"bitcoind RPC auth is required (cookie file or user/pass)",
		),
		Auth::UserPass(u, p) => bitcoind_async_client::Auth::UserPass(u, p),
		Auth::CookieFile(p) => bitcoind_async_client::Auth::CookieFile(p),
	};
	// Cap the per-request timeout (upstream default is 30s) so that a
	// hanging request to a down bitcoind can't stall shutdown for long.
	const TIMEOUT_SECONDS: u64 = 10;
	Client::new(url.to_owned(), async_auth, None, None, Some(TIMEOUT_SECONDS))
		.context("failed to create bitcoind rpc client")
}

/// Inspect bitcoind RPC errors. Mirrors the sync-side `BitcoinRpcErrorExt`
/// from `bitcoin_ext::rpc`.
pub trait BitcoindErrorExt: Borrow<ClientError> {
	fn is_not_found(&self) -> bool {
		matches!(self.borrow(), ClientError::Server(c, _) if *c == RPC_INVALID_ADDRESS_OR_KEY)
	}

	fn is_in_utxo_set(&self) -> bool {
		matches!(self.borrow(), ClientError::Server(c, _) if *c == RPC_VERIFY_ALREADY_IN_UTXO_SET)
	}

	fn is_already_in_mempool(&self) -> bool {
		matches!(self.borrow(), ClientError::Server(_, m) if m.contains("txn-already-in-mempool"))
	}
}
impl BitcoindErrorExt for ClientError {}

/// Serialize a value as a JSON arg, mapping serde errors into [`ClientError`].
pub fn json_arg<T: serde::Serialize>(v: T) -> Result<Value, ClientError> {
	serde_json::to_value(v).map_err(|e| ClientError::Param(e.to_string()))
}

// --- Derived helpers -----------------------------------------------------

pub async fn tip(client: &Client) -> Result<BlockRef, ClientError> {
	let height = client.get_block_count().await?;
	let hash = client.get_block_hash(height).await?;
	Ok(BlockRef { height: height as BlockHeight, hash })
}

pub async fn deep_tip(client: &Client) -> Result<BlockRef, ClientError> {
	let count = client.get_block_count().await?;
	let height = count.saturating_sub(DEEPLY_CONFIRMED as u64);
	let hash = client.get_block_hash(height).await?;
	Ok(BlockRef { height: height as BlockHeight, hash })
}

pub async fn get_block_by_height(
	client: &Client, height: BlockHeight,
) -> Result<BlockRef, ClientError> {
	let hash = client.get_block_hash(height as u64).await?;
	Ok(BlockRef { height, hash })
}

/// Get a raw txout using getrawtransaction rpc
pub async fn get_raw_txout(client: &Client, point: OutPoint) -> Result<TxOut, ClientError> {
	let tx = client.get_raw_transaction_verbosity_zero(&point.txid).await?.0;
	tx.output.get(point.vout as usize).cloned()
		.ok_or_else(|| ClientError::Other(format!("vout out of range")))
}

pub async fn tx_status(client: &Client, txid: Txid) -> Result<TxStatus, ClientError> {
	match custom_get_raw_transaction_info(client, txid, None).await? {
		Some(tx) => match tx.blockhash {
			Some(hash) => {
				let block: rpc::json::GetBlockHeaderResult = client.call_raw(
					"getblockheader", &[json_arg(hash)?, true.into()],
				).await?;
				if block.confirmations > 0 {
					Ok(TxStatus::Confirmed(BlockRef {
						height: block.height as BlockHeight,
						hash: block.hash,
					}))
				} else {
					Ok(TxStatus::Mempool)
				}
			}
			None => Ok(TxStatus::Mempool),
		},
		None => Ok(TxStatus::NotFound),
	}
}

/// Broadcast a transaction. Swallows the
/// [`RPC_VERIFY_ALREADY_IN_UTXO_SET`] error so a re-broadcast of an
/// already-mined tx is not surfaced as an error.
pub async fn broadcast_tx(client: &Client, tx: &Transaction) -> Result<(), ClientError> {
	match client.send_raw_transaction(tx, None).await {
		Ok(_) => Ok(()),
		Err(e) if e.is_in_utxo_set() => Ok(()),
		Err(e) => Err(e),
	}
}

/// `getrawtransaction txid true [block_hash]` with `is_not_found` mapped
/// to `Ok(None)`.
pub async fn custom_get_raw_transaction_info(
	client: &Client, txid: Txid, block_hash: Option<&BlockHash>,
) -> Result<Option<GetRawTransactionResult>, ClientError> {
	let mut params = vec![json_arg(txid)?, true.into()];
	if let Some(bh) = block_hash {
		params.push(json_arg(bh)?);
	}
	match client.call_raw("getrawtransaction", &params).await {
		Ok(v) => Ok(Some(v)),
		Err(e) if e.is_not_found() => Ok(None),
		Err(e) => Err(e),
	}
}

/// Walk the mempool to find a tx spending the given outpoint.
pub async fn get_mempool_spending_tx(
	client: &Client, outpoint: OutPoint,
) -> Result<Option<Txid>, ClientError> {
	let mempool_txids = client.get_raw_mempool().await?.0;
	for txid in mempool_txids {
		let tx = client.get_raw_transaction_verbosity_zero(&txid).await?.0;
		for input in &tx.input {
			if input.previous_output == outpoint {
				return Ok(Some(txid));
			}
		}
	}
	Ok(None)
}

/// The `getmempoolentry` fields the server reads. The bitcoincore_rpc
/// type predates the chunk fields.
#[derive(Debug, Clone, Deserialize)]
pub struct MempoolEntry {
	/// Sigops-adjusted weight of the tx's chunk.
	#[serde(rename = "chunkweight")]
	pub chunk_weight: u64,
	pub fees: MempoolEntryFees,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MempoolEntryFees {
	/// Fees of the tx's chunk, `prioritisetransaction` deltas included.
	#[serde(with = "bitcoin::amount::serde::as_btc")]
	pub chunk: Amount,
}

/// The chunk feerate of a mempool tx: its fees plus those of the txs
/// bitcoind mines it with, over their weight, rounded down so the tx is
/// never reported to pay more than it does. `Ok(None)` if the tx is not
/// in the mempool.
pub async fn chunk_fee_rate(
	client: &Client, txid: Txid,
) -> Result<Option<FeeRate>, ClientError> {
	let entry: MempoolEntry = match client.call_raw(
		"getmempoolentry", &[json_arg(txid)?],
	).await {
		Ok(e) => e,
		Err(e) if e.is_not_found() => return Ok(None),
		Err(e) => return Err(e),
	};
	let weight = Weight::from_wu(entry.chunk_weight);
	let feerate = entry.fees.chunk.div_by_weight_floor(weight).ok_or_else(|| {
		ClientError::Parse("invalid chunk fee/weight from getmempoolentry".to_owned())
	})?;
	Ok(Some(feerate))
}

pub async fn submit_package<T: Borrow<Transaction>>(
	client: &Client, txs: &[T],
) -> Result<SubmitPackageResult, ClientError> {
	let hexes: Vec<String> = txs.iter()
		.map(|t| encode::serialize_hex(t.borrow()))
		.collect();
	client.call_raw("submitpackage", &[hexes.into()]).await
}

pub async fn test_mempool_accept(
	client: &Client, txs: &[&Transaction],
) -> Result<Vec<rpc::json::TestMempoolAcceptResult>, ClientError> {
	let hexes: Vec<String> = txs.iter().map(|t| encode::serialize_hex(*t)).collect();
	client.call_raw("testmempoolaccept", &[hexes.into()]).await
}

// --- Startup checks ------------------------------------------------------

pub async fn require_network(client: &Client, expected: Network) -> anyhow::Result<()> {
	let network = client.network().await
		.context("failed to query network from bitcoind")?;
	if network != expected {
		bail!("Network mismatch: server is configured to use {:?} but bitcoind uses {:?}",
			expected, network,
		);
	}
	Ok(())
}

pub async fn require_version(client: &Client) -> anyhow::Result<()> {
	#[derive(Debug, serde::Deserialize)]
	struct Response { version: usize }
	let res: Response = client.call_raw("getnetworkinfo", &[]).await
		.context("failed to get version from bitcoind")?;
	if res.version < MIN_BITCOIND_VERSION {
		bail!("Old bitcoind version detected. Please upgrade to v31 or later");
	}
	Ok(())
}

#[cfg(test)]
mod test {
	use super::*;

	#[test]
	fn mempool_entry_parses_chunk_fields() {
		let entry: MempoolEntry = serde_json::from_str(r#"{
			"vsize": 141, "ancestorsize": 141, "chunkweight": 998,
			"fees": {"base": 0.00000141, "ancestor": 0.00000141, "chunk": 0.00025100},
			"spentby": []
		}"#).unwrap();
		assert_eq!(entry.chunk_weight, 998);
		assert_eq!(entry.fees.chunk, Amount::from_sat(25_100));
	}
}

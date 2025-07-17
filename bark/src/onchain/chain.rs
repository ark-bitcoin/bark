

use std::time::UNIX_EPOCH;
use std::{borrow::Borrow, time::SystemTime};
use std::collections::{HashMap, HashSet};

use anyhow::Context;
use bdk_bitcoind_rpc::{BitcoindRpcErrorExt, NO_EXPECTED_MEMPOOL_TXIDS};
use bdk_bitcoind_rpc::bitcoincore_rpc::{self, RpcApi};
use bdk_bitcoind_rpc::bitcoincore_rpc::json::EstimateMode;
use bdk_esplora::{esplora_client, EsploraAsyncExt};
use bdk_wallet::chain::{BlockId, ChainPosition, CheckPoint};
use bitcoin::constants::genesis_block;
use bitcoin::{Amount, Block, BlockHash, FeeRate, Network, OutPoint, Transaction, Txid, Wtxid};
use log::{debug, error, info, warn};
use tokio::sync::RwLock;

use bitcoin_ext::{BlockHeight, BlockRef, FeeRateExt};
use bitcoin_ext::bdk::{EsploraClientExt, WalletExt};
pub(crate) use bitcoin_ext::rpc::{BitcoinRpcExt, TxStatus};

use crate::onchain;

const FEE_RATE_TARGET_CONF_FAST: u16 = 1;
const FEE_RATE_TARGET_CONF_REGULAR: u16 = 3;
const FEE_RATE_TARGET_CONF_SLOW: u16 = 6;

const TX_ALREADY_IN_CHAIN_ERROR: i32 = -27;
const MIN_BITCOIND_VERSION: usize = 290000;

#[derive(Clone, Debug)]
pub enum ChainSource {
	Bitcoind {
		url: String,
		auth: bitcoincore_rpc::Auth,
	},
	Esplora {
		url: String,
	},
}

pub (crate) enum InnerChainSourceClient {
	Bitcoind(bitcoincore_rpc::Client),
	Esplora(esplora_client::AsyncClient),
}

impl InnerChainSourceClient {
	async fn check_network(&self, expected: Network) -> anyhow::Result<()> {
		match self {
			InnerChainSourceClient::Bitcoind(ref bitcoind) => {
				let network = bitcoind.get_blockchain_info()?;
				if expected != network.chain {
					bail!("Network mismatch: expected {:?}, got {:?}", expected, network.chain);
				}
			},
			InnerChainSourceClient::Esplora(ref client) => {
				let genesis_hash = client.get_block_hash(0).await?;
				if genesis_hash != genesis_block(expected).block_hash() {
					bail!("Network mismatch: expected {:?}, got {:?}", expected, genesis_hash);
				}
			},
		};

		Ok(())
	}
}

pub struct ChainSourceClient {
	inner: InnerChainSourceClient,
	network: Network,
	fee_rates: RwLock<FeeRates>,
}

impl ChainSourceClient {
	/// Checks that the version of the chain source is compatible with Bark.
	///
	/// For bitcoind, it checks if the version is at least 29.0
	/// This is the first version for which 0 fee-anchors are considered standard
	pub fn require_version(&self) -> anyhow::Result<()> {
		if let InnerChainSourceClient::Bitcoind(ref bitcoind) = self.inner {
			if bitcoind.version()? < MIN_BITCOIND_VERSION {
				bail!("Bitcoin Core version is too old, you can participate in rounds but won't be able to unilaterally exit. Please upgrade to 29.0 or higher.");
			}
		}

		Ok(())
	}

	pub async fn fee_rates(&self) -> FeeRates {
		self.fee_rates.read().await.clone()
	}

	pub fn network(&self) -> Network {
		self.network
	}

	pub async fn new(chain_source: ChainSource, network: Network, fallback_fee: Option<FeeRate>) -> anyhow::Result<Self> {
		let inner = match chain_source {
			ChainSource::Bitcoind { url, auth } => InnerChainSourceClient::Bitcoind(
				bitcoincore_rpc::Client::new(&url, auth)
					.context("failed to create bitcoind rpc client")?
			),
			ChainSource::Esplora { url } => InnerChainSourceClient::Esplora({
				// the esplora client doesn't deal well with trailing slash in url
				let url = url.strip_suffix("/").unwrap_or(&url);
				esplora_client::Builder::new(url).build_async()
					.with_context(|| format!("failed to create esplora client for url {}", url))?
			}),
		};

		inner.check_network(network).await?;

		let fee = fallback_fee.unwrap_or(FeeRate::BROADCAST_MIN);
		let fee_rates = RwLock::new(FeeRates { fast: fee, regular: fee, slow: fee });

		Ok(Self { inner, network, fee_rates })
	}

	async fn fetch_fee_rates(&self) -> anyhow::Result<FeeRates> {
		match self.inner {
			InnerChainSourceClient::Bitcoind(ref bitcoind) => {
				let get_fee_rate = |target| {
					let fee = bitcoind.estimate_smart_fee(target, Some(EstimateMode::Economical))?;
					if let Some(fee_rate) = fee.fee_rate {
						Ok(FeeRate::from_amount_per_kvb_ceil(fee_rate))
					} else {
						Err(anyhow!("No rate returned from estimate_smart_fee for a {} confirmation target", target))
					}
				};
				Ok(FeeRates {
					fast: get_fee_rate(FEE_RATE_TARGET_CONF_FAST)?,
					regular: get_fee_rate(FEE_RATE_TARGET_CONF_REGULAR).expect("should exist"),
					slow: get_fee_rate(FEE_RATE_TARGET_CONF_SLOW).expect("should exist"),
				})
			},
			InnerChainSourceClient::Esplora(ref client) => {
				// The API should return rates for targets 1-25, 144 and 1008
				let estimates = client.get_fee_estimates().await?;
				let get_fee_rate = |target| {
					let fee = estimates.get(&target).with_context(||
						format!("No rate returned from get_fee_estimates for a {} confirmation target", target)
					)?;
					FeeRate::from_sat_per_vb_decimal_checked_ceil(*fee).with_context(||
						format!("Invalid rate returned from get_fee_estimates {} for a {} confirmation target", fee, target)
					)
				};
				Ok(FeeRates {
					fast: get_fee_rate(FEE_RATE_TARGET_CONF_FAST)?,
					regular: get_fee_rate(FEE_RATE_TARGET_CONF_REGULAR)?,
					slow: get_fee_rate(FEE_RATE_TARGET_CONF_SLOW)?,
				})
			}
		}
	}

	pub async fn tip(&self) -> anyhow::Result<BlockHeight> {
		match self.inner {
			InnerChainSourceClient::Bitcoind(ref bitcoind) => {
				Ok(bitcoind.get_block_count()? as BlockHeight)
			},
			InnerChainSourceClient::Esplora(ref client) => {
				Ok(client.get_height().await?)
			},
		}
	}

	pub async fn block_id(&self, height: BlockHeight) -> anyhow::Result<BlockId> {
		match self.inner {
			InnerChainSourceClient::Bitcoind(ref bitcoind) => {
				let hash = bitcoind.get_block_hash(height as u64)?;
				Ok(BlockId::from((height, hash)))
			},
			InnerChainSourceClient::Esplora(ref client) => {
				let hash = client.get_block_hash(height).await?;
				Ok(BlockId::from((height, hash)))
			},
		}
	}

	pub async fn block(&self, hash: &BlockHash) -> anyhow::Result<Option<Block>> {
		match self.inner {
			InnerChainSourceClient::Bitcoind(ref bitcoind) => {
				match bitcoind.get_block(hash) {
					Ok(b) => Ok(Some(b)),
					Err(e) if e.is_not_found_error() => Ok(None),
					Err(e) => Err(e.into()),
				}
			},
			InnerChainSourceClient::Esplora(ref client) => {
				Ok(client.get_block_by_hash(hash).await?)
			},
		}
	}

	pub async fn sync_wallet(
		&self,
		onchain: &mut onchain::Wallet,
	) -> anyhow::Result<Amount> {
		debug!("Starting wallet sync...");
		let now = SystemTime::now().duration_since(UNIX_EPOCH).expect("now").as_secs();

		let prev_tip = onchain.wallet.latest_checkpoint();
		match self.inner {
			InnerChainSourceClient::Bitcoind(ref bitcoind) => {
				debug!("Syncing with bitcoind, starting at block height {}...", prev_tip.height());
				let unconfirmed = onchain.wallet.unconfirmed_txids();
				let mut emitter = bdk_bitcoind_rpc::Emitter::new(
					bitcoind, prev_tip.clone(), prev_tip.height(), unconfirmed,
				);
				let mut count = 0;
				while let Some(em) = emitter.next_block()? {
					onchain.wallet.apply_block_connected_to(
						&em.block, em.block_height(), em.connected_to(),
					)?;
					count += 1;

					if count % 10_000 == 0 {
						onchain.persist()?;
						info!("Synced until block height {}", em.block_height());
					}
				}

				let mempool = emitter.mempool()?;
				onchain.wallet.apply_evicted_txs(mempool.evicted_ats());
				onchain.wallet.apply_unconfirmed_txs(mempool.new_txs);
				onchain.persist()?;
				debug!("Finished syncing with bitcoind, {}", onchain.wallet.balance());
			},
			InnerChainSourceClient::Esplora(ref client) => {
				debug!("Syncing with esplora...");
				const STOP_GAP: usize = 50;
				const PARALLEL_REQS: usize = 4;

				let request = onchain.wallet.start_full_scan();
				let update = client.full_scan(request, STOP_GAP, PARALLEL_REQS).await?;
				onchain.wallet.apply_update(update)?;
				onchain.persist()?;
				debug!("Finished syncing with esplora, {}", onchain.wallet.balance());
			},
		}

		let balance = onchain.wallet.balance();

		// Ultimately, let's try to rebroadcast all our unconfirmed txs.
		let transactions = onchain.wallet.transactions().filter(|tx| {
			if let ChainPosition::Unconfirmed { last_seen, .. } = tx.chain_position {
				match last_seen {
					Some(last_seen) => last_seen < now,
					None => true,
				}
			} else {
				false
			}
		}).collect::<Vec<_>>();
		for tx in transactions {
			if let Err(e) = self.broadcast_tx(&tx.tx_node.tx).await {
				warn!("Error broadcasting tx {}: {}", tx.tx_node.txid, e);
			}
		}

		Ok(balance.total())
	}

	/// For each provided outpoint, fetches the ID of any confirmed or unconfirmed in which the
	/// outpoint is spent.
	pub async fn txs_spending_inputs<T: IntoIterator<Item = OutPoint>>(
		&self,
		outpoints: T,
		block_scan_start: BlockHeight,
	) -> anyhow::Result<TxsSpendingInputsResult> {
		let mut res = TxsSpendingInputsResult::new();
		match self.inner {
			InnerChainSourceClient::Bitcoind(ref bitcoind) => {
				// We must offset the height to account for the fact we iterate using next_block()
				let start = if block_scan_start == 0 { 0 } else { block_scan_start - 1 };
				let block = self.block_id(start).await?;
				let cp = CheckPoint::new(block);

				let mut emitter = bdk_bitcoind_rpc::Emitter::new(
					bitcoind, cp.clone(), cp.height(), NO_EXPECTED_MEMPOOL_TXIDS,
				);

				debug!("Scanning blocks for spent outpoints with bitcoind, starting at block height {}...", block_scan_start);
				let outpoint_set = outpoints.into_iter().collect::<HashSet<_>>();
				while let Some(em) = emitter.next_block()? {
					// Provide updates as the scan can take a long time
					if em.block_height() % 1000 == 0 {
						info!("Scanned for spent outpoints until block height {}", em.block_height());
					}
					for tx in &em.block.txdata {
						for txin in tx.input.iter() {
							if outpoint_set.contains(&txin.previous_output) {
								res.add(
									txin.previous_output.clone(),
									tx.compute_txid(),
									TxStatus::Confirmed(BlockRef {
										height: em.block_height(), hash: em.block.block_hash().clone()
									})
								);
							}
						}
					}
				}

				debug!("Finished scanning blocks for spent outpoints, now checking the mempool...");
				let mempool = emitter.mempool()?;
				for (tx, _last_seen) in &mempool.new_txs {
					for txin in tx.input.iter() {
						if outpoint_set.contains(&txin.previous_output) {
							res.add(txin.previous_output.clone(), tx.compute_txid(), TxStatus::Mempool);
						}
					}
				}
				debug!("Finished checking the mempool for spent outpoints");
			},
			InnerChainSourceClient::Esplora(ref client) => {
				for outpoint in outpoints {
					let output_status = client.get_output_status(&outpoint.txid, outpoint.vout.into()).await?;

					if let Some(output_status) = output_status {
						if output_status.spent {
							let tx_status = {
								let status = output_status.status.expect("Status should be valid if an outpoint is spent");
								if status.confirmed {
									TxStatus::Confirmed(BlockRef {
										height: status.block_height.expect("Confirmed transaction missing block_height"),
										hash: status.block_hash.expect("Confirmed transaction missing block_hash"),
									})
								} else {
									TxStatus::Mempool
								}
							};
							let txid = output_status.txid.expect("Txid should be valid if an outpoint is spent");
							res.add(outpoint, txid, tx_status);
						}
					}
				}
			},
		}

		Ok(res)
	}

	pub async fn broadcast_tx(&self, tx: &Transaction) -> anyhow::Result<()> {
		match self.inner {
			InnerChainSourceClient::Bitcoind(ref bitcoind) => {
				match bitcoind.send_raw_transaction(tx) {
					Ok(_) => Ok(()),
					Err(bitcoincore_rpc::Error::JsonRpc(
						bitcoincore_rpc::jsonrpc::Error::Rpc(e))
					) if e.code == TX_ALREADY_IN_CHAIN_ERROR => Ok(()),
					Err(e) => Err(e.into()),
				}
			},
			InnerChainSourceClient::Esplora(ref client) => {
				client.broadcast(tx).await?;
				Ok(())
			},
		}
	}

	pub async fn broadcast_package(&self, txs: &[impl Borrow<Transaction>]) -> anyhow::Result<()> {
		#[derive(Debug, Deserialize)]
		struct PackageTxInfo {
			txid: Txid,
			error: Option<String>,
		}
		#[derive(Debug, Deserialize)]
		struct SubmitPackageResponse {
			#[serde(rename = "tx-results")]
			tx_results: HashMap<Wtxid, PackageTxInfo>,
			package_msg: String,
		}

		match self.inner {
			InnerChainSourceClient::Bitcoind(ref bitcoind) => {
				let hexes = txs.iter()
					.map(|t| bitcoin::consensus::encode::serialize_hex(t.borrow()))
					.collect::<Vec<_>>();
				let res = bitcoind.call::<SubmitPackageResponse>("submitpackage", &[hexes.into()])?;
				if res.package_msg != "success" {
					let errors = res.tx_results.values()
						.map(|t| format!("tx {}: {}",
							t.txid, t.error.as_ref().map(|s| s.as_str()).unwrap_or("(no error)"),
						))
						.collect::<Vec<_>>();
					bail!("msg: '{}', errors: {:?}", res.package_msg, errors);
				}
				Ok(())
			},
			InnerChainSourceClient::Esplora(ref client) => {
				let txs = txs.iter().map(|t| t.borrow().clone()).collect::<Vec<_>>();
				let res = client.submit_package(&txs, None, None).await?;
				if res.package_msg != "success" {
					let errors = res.tx_results.values()
						.map(|t| format!("tx {}: {}",
							t.txid, t.error.as_ref().map(|s| s.as_str()).unwrap_or("(no error)"),
						))
						.collect::<Vec<_>>();
					bail!("msg: '{}', errors: {:?}", res.package_msg, errors);
				}

				Ok(())
			},
		}
	}

	pub async fn get_tx(&self, txid: &Txid) -> anyhow::Result<Option<Transaction>> {
		match self.inner {
			InnerChainSourceClient::Bitcoind(ref bitcoind) => {
				match bitcoind.get_raw_transaction(txid, None) {
					Ok(tx) => Ok(Some(tx)),
					Err(e) if e.is_not_found_error() => Ok(None),
					Err(e) => Err(e.into()),
				}
			},
			InnerChainSourceClient::Esplora(ref client) => {
				Ok(client.get_tx(txid).await?)
			},
		}
	}

	/// Returns the block height the tx is confirmed in, if any.
	pub async fn tx_confirmed(&self, txid: &Txid) -> anyhow::Result<Option<BlockHeight>> {
		Ok(self.tx_status(txid).await?.confirmed_height())
	}

	/// Returns the status of the given transaction, including the block height if it is confirmed
	pub async fn tx_status(&self, txid: &Txid) -> anyhow::Result<TxStatus> {
		match self.inner {
			InnerChainSourceClient::Bitcoind(ref bitcoind) => {
				bitcoind.tx_status(&txid)
					.map_err(|e| format_err!(e))
			},
			InnerChainSourceClient::Esplora(ref esplora) => {
				match esplora.get_tx_info(&txid).await? {
					Some(info) => match (info.status.block_height, info.status.block_hash) {
						(Some(block_height), Some(block_hash)) => Ok(TxStatus::Confirmed(BlockRef {
							height: block_height,
							hash: block_hash,
						} )),
						_ => Ok(TxStatus::Mempool),
					},
					None => Ok(TxStatus::NotFound),
				}
			},
		}
	}

	#[allow(unused)]
	pub async fn txout_value(&self, outpoint: &OutPoint) -> anyhow::Result<Amount> {
		let tx = match self.inner {
			InnerChainSourceClient::Bitcoind(ref bitcoind) => {
				bitcoind.get_raw_transaction(&outpoint.txid, None)
					.with_context(|| format!("tx {} unknown", outpoint.txid))?
			},
			InnerChainSourceClient::Esplora(ref client) => {
				client.get_tx(&outpoint.txid).await?
					.with_context(|| format!("tx {} unknown", outpoint.txid))?
			},
		};
		Ok(tx.output.get(outpoint.vout as usize).context("outpoint vout out of range")?.value)
	}

	/// Gets the current fee rates from the chain source, falling back to user-specified values if
	/// necessary
	pub async fn update_fee_rates(&self, fallback_fee: Option<FeeRate>) -> anyhow::Result<()> {
		let fee_rates = match (self.fetch_fee_rates().await, fallback_fee) {
			(Ok(fee_rates), _) => Ok(fee_rates),
			(Err(e), None) => Err(e),
			(Err(e), Some(fallback)) => {
				error!("Error getting fee rates, falling back to {} sat/kvB: {}",
					fallback.to_btc_per_kvb(), e,
				);
				Ok(FeeRates { fast: fallback, regular: fallback, slow: fallback })
			}
		}?;

		*self.fee_rates.write().await = fee_rates;
		Ok(())
	}
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FeeRates {
	pub fast: FeeRate,
	pub regular: FeeRate,
	pub slow: FeeRate,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TxsSpendingInputsResult {
	pub map: HashMap<OutPoint, (Txid, TxStatus)>,
}

impl TxsSpendingInputsResult {
	pub fn new() -> Self {
		Self { map: HashMap::new() }
	}

	pub fn add(&mut self, outpoint: OutPoint, txid: Txid, status: TxStatus) {
		self.map.insert(outpoint, (txid, status));
	}

	pub fn get(&self, outpoint: &OutPoint) -> Option<&(Txid, TxStatus)> {
		self.map.get(outpoint)
	}

	pub fn confirmed_txids(&self) -> impl Iterator<Item = (Txid, BlockRef)> + '_ {
		self.map
			.iter()
			.filter_map(|(_, (txid, status))| {
				match status {
					TxStatus::Confirmed(block) => Some((*txid, *block)),
					_ => None,
				}
			})
	}

	pub fn mempool_txids(&self) -> impl Iterator<Item = Txid> + '_ {
		self.map
			.iter()
			.filter(|(_, (_, status))| matches!(status, TxStatus::Mempool))
			.map(|(_, (txid, _))| *txid)
	}
}

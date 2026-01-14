

use std::borrow::Borrow;
use std::collections::{HashMap, HashSet};
use std::str::FromStr as _;

use anyhow::Context;
use bdk_core::{BlockId, CheckPoint};
use bdk_esplora::esplora_client;
use bitcoin::constants::genesis_block;
use bitcoin::{
	Amount, Block, BlockHash, FeeRate, Network, OutPoint, Transaction, Txid, Weight,
};
use log::{debug, info, warn};
use tokio::sync::RwLock;

use bitcoin_ext::{BlockHeight, BlockRef, FeeRateExt, TxStatus};
use bitcoin_ext::rpc::{self, BitcoinRpcExt, BitcoinRpcErrorExt, RpcApi};
use bitcoin_ext::esplora::EsploraClientExt;

const FEE_RATE_TARGET_CONF_FAST: u16 = 1;
const FEE_RATE_TARGET_CONF_REGULAR: u16 = 3;
const FEE_RATE_TARGET_CONF_SLOW: u16 = 6;

const TX_ALREADY_IN_CHAIN_ERROR: i32 = -27;
const MIN_BITCOIND_VERSION: usize = 290000;

/// Configuration for the onchain data source.
///
/// [ChainSource] selects which backend to use for blockchain data and transaction broadcasting:
/// - Bitcoind: uses a Bitcoin Core node via JSON-RPC
/// - Esplora: uses the HTTP API endpoint of [esplora-electrs](https://github.com/Blockstream/electrs)
///
/// Typical usage is to construct a ChainSource from configuration and pass it to
/// [ChainSource::new] along with the expected [Network].
///
/// Notes:
/// - For [ChainSourceSpec::Bitcoind], authentication must be provided (cookie file or user/pass).
#[derive(Clone, Debug)]
pub enum ChainSourceSpec {
	Bitcoind {
		/// RPC URL of the Bitcoin Core node (e.g. <http://127.0.0.1:8332>).
		url: String,
		/// Authentication method for JSON-RPC (cookie file or user/pass).
		auth: rpc::Auth,
	},
	Esplora {
		/// Base URL of the esplora-electrs instance (e.g. <https://esplora.signet.2nd.dev>).
		url: String,
	},
}

pub enum ChainSourceClient {
	Bitcoind(rpc::Client),
	Esplora(esplora_client::AsyncClient),
}

impl ChainSourceClient {
	async fn check_network(&self, expected: Network) -> anyhow::Result<()> {
		match self {
			ChainSourceClient::Bitcoind(bitcoind) => {
				let network = bitcoind.get_blockchain_info()?;
				if expected != network.chain {
					bail!("Network mismatch: expected {:?}, got {:?}", expected, network.chain);
				}
			},
			ChainSourceClient::Esplora(client) => {
				let res = client.client().get(format!("{}/block-height/0", client.url()))
					.send().await?.text().await?;
				let genesis_hash = BlockHash::from_str(&res)
					.context("bad response from server (not a blockhash). Esplora client possibly misconfigured")?;
				if genesis_hash != genesis_block(expected).block_hash() {
					bail!("Network mismatch: expected {:?}, got {:?}", expected, genesis_hash);
				}
			},
		};

		Ok(())
	}
}

/// Client for interacting with the configured on-chain backend.
///
/// [ChainSource] abstracts over multiple backends using [ChainSourceSpec] to provide:
/// - Chain queries (tip, block headers/blocks, transaction status and fetching)
/// - Mempool-related utilities (ancestor fee/weight, spending lookups)
/// - Broadcasting single transactions or packages (RBF/CPFP workflows)
/// - Fee estimation and caching with optional fallback values
///
/// Behavior notes:
/// - [ChainSource::update_fee_rates] refreshes internal fee estimates; if backend estimates
///   fail and a fallback fee is provided, it will be used for all tiers.
/// - [ChainSource::fee_rates] returns the last cached [FeeRates].
///
/// Examples:
///
/// ```rust
/// # async fn func() {
/// use bark::chain::{ChainSource, ChainSourceSpec};
/// use bdk_bitcoind_rpc::bitcoincore_rpc::Auth;
/// use bitcoin::{FeeRate, Network};
///
/// let spec = ChainSourceSpec::Bitcoind {
///     url: "http://localhost:8332".into(),
///     auth: Auth::UserPass("user".into(), "password".into()),
/// };
/// let network = Network::Bitcoin;
/// let fallback_fee = FeeRate::from_sat_per_vb(5);
///
/// let instance = ChainSource::new(spec, network, fallback_fee).await.unwrap();
/// # }
/// ```
pub struct ChainSource {
	inner: ChainSourceClient,
	network: Network,
	fee_rates: RwLock<FeeRates>,
}

impl ChainSource {
	/// Checks that the version of the chain source is compatible with Bark.
	///
	/// For bitcoind, it checks if the version is at least 29.0
	/// This is the first version for which 0 fee-anchors are considered standard
	pub fn require_version(&self) -> anyhow::Result<()> {
		if let ChainSourceClient::Bitcoind(bitcoind) = self.inner() {
			if bitcoind.version()? < MIN_BITCOIND_VERSION {
				bail!("Bitcoin Core version is too old, you can participate in rounds but won't be able to unilaterally exit. Please upgrade to 29.0 or higher.");
			}
		}

		Ok(())
	}

	pub(crate) fn inner(&self) -> &ChainSourceClient {
		&self.inner
	}

	/// Gets a cached copy of the calculated network [FeeRates]
	pub async fn fee_rates(&self) -> FeeRates {
		self.fee_rates.read().await.clone()
	}

	/// Gets the network that the [ChainSource] was validated against.
	pub fn network(&self) -> Network {
		self.network
	}

	/// Creates a new instance of the object with the specified chain source, network, and optional
	/// fallback fee rate.
	///
	/// This function initializes the internal chain source client based on the provided `chain_source`:
	/// - If `chain_source` is of type [ChainSourceSpec::Bitcoind], it creates a Bitcoin Core RPC client
	///   using the provided URL and authentication parameters.
	/// - If `chain_source` is of type [ChainSourceSpec::Esplora], it creates an Esplora client with the
	///   given URL.
	///
	/// Both clients are initialized asynchronously, and any errors encountered during their
	/// creation will be returned as part of the [anyhow::Result].
	///
	/// Additionally, the function performs a network consistency check to ensure the specified
	/// network (e.g., `mainnet` or `signet`) matches the network configuration of the initialized
	/// chain source client.
	///
	/// The `fallback_fee` parameter is optional. If provided, it is used as the default fee rate
	/// for transactions. If not specified, the `FeeRate::BROADCAST_MIN` is used as the default fee
	/// rate.
	///
	/// # Arguments
	///
	/// * `chain_source` - Specifies the backend to use for blockchain data.
	/// * `network` - The Bitcoin network to operate on (e.g., `mainnet`, `testnet`, `regtest`).
	/// * `fallback_fee` - An optional fallback fee rate to use for transaction fee estimation. If
	///   not provided, a default fee rate of [FeeRate::BROADCAST_MIN] will be used.
	///
	/// # Returns
	///
	/// * `Ok(Self)` - If the object is successfully created with all necessary configurations.
	/// * `Err(anyhow::Error)` - If there is an error in initializing the chain source client or
	///   verifying the network.
	pub async fn new(spec: ChainSourceSpec, network: Network, fallback_fee: Option<FeeRate>) -> anyhow::Result<Self> {
		let inner = match spec {
			ChainSourceSpec::Bitcoind { url, auth } => ChainSourceClient::Bitcoind(
				rpc::Client::new(&url, auth)
					.context("failed to create bitcoind rpc client")?
			),
			ChainSourceSpec::Esplora { url } => ChainSourceClient::Esplora({
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
		match self.inner() {
			ChainSourceClient::Bitcoind(bitcoind) => {
				let get_fee_rate = |target| {
					let fee = bitcoind.estimate_smart_fee(
						target, Some(rpc::json::EstimateMode::Economical),
					)?;
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
			ChainSourceClient::Esplora(client) => {
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
		match self.inner() {
			ChainSourceClient::Bitcoind(bitcoind) => {
				Ok(bitcoind.get_block_count()? as BlockHeight)
			},
			ChainSourceClient::Esplora(client) => {
				Ok(client.get_height().await?)
			},
		}
	}

	pub async fn tip_ref(&self) -> anyhow::Result<BlockRef> {
		self.block_ref(self.tip().await?).await
	}

	pub async fn block_ref(&self, height: BlockHeight) -> anyhow::Result<BlockRef> {
		match self.inner() {
			ChainSourceClient::Bitcoind(bitcoind) => {
				let hash = bitcoind.get_block_hash(height as u64)?;
				Ok(BlockRef { height, hash })
			},
			ChainSourceClient::Esplora(client) => {
				let hash = client.get_block_hash(height).await?;
				Ok(BlockRef { height, hash })
			},
		}
	}

	pub async fn block(&self, hash: BlockHash) -> anyhow::Result<Option<Block>> {
		match self.inner() {
			ChainSourceClient::Bitcoind(bitcoind) => {
				match bitcoind.get_block(&hash) {
					Ok(b) => Ok(Some(b)),
					Err(e) if e.is_not_found() => Ok(None),
					Err(e) => Err(e.into()),
				}
			},
			ChainSourceClient::Esplora(client) => {
				Ok(client.get_block_by_hash(&hash).await?)
			},
		}
	}

	/// Retrieves basic CPFP ancestry information of the given transaction. Confirmed transactions
	/// are ignored as they are not relevant to CPFP.
	pub async fn mempool_ancestor_info(&self, txid: Txid) -> anyhow::Result<MempoolAncestorInfo> {
		let mut result = MempoolAncestorInfo::new(txid);

		// TODO: Determine if any line of descendant transactions increase the effective fee rate
		//		 of the target txid.
		match self.inner() {
			ChainSourceClient::Bitcoind(bitcoind) => {
				let entry = bitcoind.get_mempool_entry(&txid)?;
				let err = || anyhow!("missing weight parameter from getmempoolentry");

				result.total_fee = entry.fees.ancestor;
				result.total_weight = Weight::from_wu(entry.weight.ok_or_else(err)?) +
					Weight::from_vb(entry.ancestor_size).ok_or_else(err)?;
			},
			ChainSourceClient::Esplora(client) => {
				// We should first verify the transaction is in the mempool to maintain the same
				// behavior as Bitcoin Core
				let status = self.tx_status(txid).await?;
				if !matches!(status, TxStatus::Mempool) {
					return Err(anyhow!("{} is not in the mempool, status is {:?}", txid, status));
				}

				let mut info_map: HashMap<Txid, esplora_client::Tx> = HashMap::new();
				let mut set = HashSet::from([txid]);
				while !set.is_empty() {
					// Start requests asynchronously
					let requests = set.iter().filter_map(|txid| if info_map.contains_key(txid) {
						None
					} else {
						Some((txid, client.get_tx_info(&txid)))
					}).collect::<Vec<_>>();

					// Collect txids to be added to the set
					let mut next_set = HashSet::new();

					// Process each request, ignoring parents of confirmed transactions
					for (txid, request) in requests {
						let info = request.await?
							.ok_or_else(|| anyhow!("unable to retrieve tx info for {}", txid))?;
						if !info.status.confirmed {
							for vin in info.vin.iter() {
								next_set.insert(vin.txid);
							}
						}
						info_map.insert(*txid, info);
					}
					set = next_set;
				}
				// Calculate the total weight and fee of the unconfirmed ancestry
				for info in info_map.into_values().filter(|info| !info.status.confirmed) {
					result.total_fee += info.fee();
					result.total_weight += info.weight();
				}
			},
		}
		// Now calculate the effective fee rate of the package
		Ok(result)
	}

	/// For each provided outpoint, fetches the ID of any confirmed or unconfirmed in which the
	/// outpoint is spent.
	pub async fn txs_spending_inputs<T: IntoIterator<Item = OutPoint>>(
		&self,
		outpoints: T,
		block_scan_start: BlockHeight,
	) -> anyhow::Result<TxsSpendingInputsResult> {
		let mut res = TxsSpendingInputsResult::new();
		match self.inner() {
			ChainSourceClient::Bitcoind(bitcoind) => {
				// We must offset the height to account for the fact we iterate using next_block()
				let start = block_scan_start.saturating_sub(1);
				let block_ref = self.block_ref(start).await?;
				let cp = CheckPoint::new(BlockId {
					height: block_ref.height,
					hash: block_ref.hash,
				});

				let mut emitter = bdk_bitcoind_rpc::Emitter::new(
					bitcoind, cp.clone(), cp.height(), bdk_bitcoind_rpc::NO_EXPECTED_MEMPOOL_TXS,
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
								// We can stop early if we've found a spending tx for each outpoint
								if res.map.len() == outpoint_set.len() {
									return Ok(res);
								}
							}
						}
					}
				}

				debug!("Finished scanning blocks for spent outpoints, now checking the mempool...");
				let mempool = emitter.mempool()?;
				for (tx, _last_seen) in &mempool.update {
					for txin in tx.input.iter() {
						if outpoint_set.contains(&txin.previous_output) {
							res.add(
								txin.previous_output.clone(),
								tx.compute_txid(),
								TxStatus::Mempool,
							);

							// We can stop early if we've found a spending tx for each outpoint
							if res.map.len() == outpoint_set.len() {
								return Ok(res);
							}
						}
					}
				}
				debug!("Finished checking the mempool for spent outpoints");
			},
			ChainSourceClient::Esplora(client) => {
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
		match self.inner() {
			ChainSourceClient::Bitcoind(bitcoind) => {
				match bitcoind.send_raw_transaction(tx) {
					Ok(_) => Ok(()),
					Err(rpc::Error::JsonRpc(
						rpc::jsonrpc::Error::Rpc(e))
					) if e.code == TX_ALREADY_IN_CHAIN_ERROR => Ok(()),
					Err(e) => Err(e.into()),
				}
			},
			ChainSourceClient::Esplora(client) => {
				client.broadcast(tx).await?;
				Ok(())
			},
		}
	}

	pub async fn broadcast_package(&self, txs: &[impl Borrow<Transaction>]) -> anyhow::Result<()> {
		match self.inner() {
			ChainSourceClient::Bitcoind(bitcoind) => {
				let res = bitcoind.submit_package(txs)?;
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
			ChainSourceClient::Esplora(client) => {
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
		match self.inner() {
			ChainSourceClient::Bitcoind(bitcoind) => {
				match bitcoind.get_raw_transaction(txid, None) {
					Ok(tx) => Ok(Some(tx)),
					Err(e) if e.is_not_found() => Ok(None),
					Err(e) => Err(e.into()),
				}
			},
			ChainSourceClient::Esplora(client) => {
				Ok(client.get_tx(txid).await?)
			},
		}
	}

	/// Returns the block height the tx is confirmed in, if any.
	pub async fn tx_confirmed(&self, txid: Txid) -> anyhow::Result<Option<BlockHeight>> {
		Ok(self.tx_status(txid).await?.confirmed_height())
	}

	/// Returns the status of the given transaction, including the block height if it is confirmed
	pub async fn tx_status(&self, txid: Txid) -> anyhow::Result<TxStatus> {
		match self.inner() {
			ChainSourceClient::Bitcoind(bitcoind) => Ok(bitcoind.tx_status(&txid)?),
			ChainSourceClient::Esplora(esplora) => {
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
		let tx = match self.inner() {
			ChainSourceClient::Bitcoind(bitcoind) => {
				bitcoind.get_raw_transaction(&outpoint.txid, None)
					.with_context(|| format!("tx {} unknown", outpoint.txid))?
			},
			ChainSourceClient::Esplora(client) => {
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
				warn!("Error getting fee rates, falling back to {} sat/kvB: {}",
					fallback.to_btc_per_kvb(), e,
				);
				Ok(FeeRates { fast: fallback, regular: fallback, slow: fallback })
			}
		}?;

		*self.fee_rates.write().await = fee_rates;
		Ok(())
	}
}

/// The [FeeRates] struct represents the fee rates for transactions categorized by speed or urgency.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FeeRates {
	/// The fee for fast transactions (higher cost, lower time delay).
	pub fast: FeeRate,
	/// The fee for standard-priority transactions.
	pub regular: FeeRate,
	/// The fee for slower transactions (lower cost, higher time delay).
	pub slow: FeeRate,
}

/// Contains the fee information for an unconfirmed transaction found in the mempool.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MempoolAncestorInfo {
	/// The ID of the transaction that was queried.
	pub txid: Txid,
	/// The total fee of this transaction and all of its unconfirmed ancestors. If the transaction
	/// is to be replaced, the total fees of the published package MUST exceed this.
	pub total_fee: Amount,
	/// The total weight of this transaction and all of its unconfirmed ancestors.
	pub total_weight: Weight,
}

impl MempoolAncestorInfo {
	pub fn new(txid: Txid) -> Self {
		Self {
			txid,
			total_fee: Amount::ZERO,
			total_weight: Weight::ZERO,
		}
	}

	pub fn effective_fee_rate(&self) -> Option<FeeRate> {
		FeeRate::from_amount_and_weight_ceil(self.total_fee, self.total_weight)
	}
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

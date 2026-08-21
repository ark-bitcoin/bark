

use std::borrow::Borrow;
use std::collections::{HashMap, HashSet};
use std::str::FromStr as _;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use bark_runtime::Instant;
use bdk_core::{BlockId, CheckPoint};
use bdk_esplora::esplora_client;
use bitcoin::constants::genesis_block;
use bitcoin::{
	Amount, Block, BlockHash, FeeRate, Network, OutPoint, Transaction, Txid, Weight,
};
use log::{debug, info, warn};
use tokio::sync::RwLock;

use bitcoin_ext::{BlockHeight, BlockRef, FeeRateExt, TxStatus};
use bitcoin_ext::rpc;
#[cfg(feature = "bitcoind-rpc")]
use bitcoin_ext::rpc::{
	BitcoinAsyncRpcExt, BitcoinRpcClient, RPC_INVALID_ADDRESS_OR_KEY,
	RPC_VERIFY_ALREADY_IN_UTXO_SET,
};
#[cfg(feature = "bitcoind-rpc")]
use bitcoind_async_client::Client as BitcoindClient;
#[cfg(feature = "bitcoind-rpc")]
use bitcoind_async_client::error::ClientError as BitcoindClientError;
#[cfg(feature = "bitcoind-rpc")]
use bitcoind_async_client::traits::{Broadcaster, Reader};

use crate::daemon::tip_watcher::{TipSource, TipWatcher};

const FEE_RATE_TARGET_CONF_FAST: u16 = 1;
const FEE_RATE_TARGET_CONF_REGULAR: u16 = 3;
const FEE_RATE_TARGET_CONF_SLOW: u16 = 6;

/// Coalesce bursts of `tip()` calls within the same `Wallet::sync()` cycle
/// (parallel sub-syncs each fetch tip, and the exit progress state machine
/// fetches it twice per iteration). Short enough to be invisible to tests
/// and UI; long enough to dedupe within a single sync burst.
const TIP_CACHE_TTL: Duration = Duration::from_secs(1);

/// Fee estimates change on the scale of minutes, so refreshing more often
/// than this buys nothing while costing one HTTP round trip per sync tick.
const FEE_RATES_CACHE_TTL: Duration = Duration::from_secs(30);

#[cfg(feature = "bitcoind-rpc")]
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
/// - For [ChainSourceSpec::Bitcoind], authentication must be provided (cookie file or user/pass)
///   and the node must run with `txindex=1`.
#[derive(Clone, Debug)]
pub enum ChainSourceSpec {
	Bitcoind {
		/// RPC URL of the Bitcoin Core node (e.g. <http://127.0.0.1:8332>).
		url: String,
		/// Authentication method for JSON-RPC (cookie file or user/pass).
		auth: rpc::Auth,
		/// ZMQ endpoint of the node (e.g. `tcp://127.0.0.1:28332`), used to get
		/// notified of new blocks. When unset, the chain tip is polled instead.
		zmq: Option<String>,
	},
	Esplora {
		/// Base URL of the esplora-electrs instance (e.g. <https://esplora.signet.2nd.dev>).
		url: String,
	},
}

impl ChainSourceSpec {
	pub(crate) fn url(&self) -> &String {
		match self {
			ChainSourceSpec::Bitcoind { url, .. } => url,
			ChainSourceSpec::Esplora { url } => url,
		}
	}
}

pub enum ChainSourceClient {
	/// Native bitcoind backend.
	///
	/// Carries an async client for everything the wallet does asynchronously
	/// and a sync companion for `bdk_bitcoind_rpc::Emitter`, which is sync-only
	/// upstream and runs inside `tokio::task::spawn_blocking`.
	#[cfg(feature = "bitcoind-rpc")]
	Bitcoind {
		rpc: BitcoindClient,
		sync: BitcoinRpcClient,
	},
	Esplora(esplora_client::AsyncClient),
}

impl ChainSourceClient {
	async fn check_network(&self, expected: Network) -> anyhow::Result<()> {
		match self {
			#[cfg(feature = "bitcoind-rpc")]
			ChainSourceClient::Bitcoind { rpc, .. } => {
				let network = rpc.network().await?;
				if expected != network {
					bail!("Network mismatch: expected {:?}, got {:?}", expected, network);
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
///     zmq: None,
/// };
/// let network = Network::Bitcoin;
/// let fallback_fee = FeeRate::from_sat_per_vb(5);
/// #[cfg(feature = "socks5-proxy")]
/// let socks5 = Some("socks5h://127.0.0.1:9050");
///
/// let instance = ChainSource::new(spec, network, fallback_fee, socks5).await.unwrap();
/// # }
/// ```
pub struct ChainSource {
	inner: ChainSourceClient,
	network: Network,
	/// The ZMQ endpoint of the bitcoind backend, if one was configured.
	zmq_endpoint: Option<String>,
	fee_rates: RwLock<FeeRates>,
	/// `None` until the first successful (or fallback) `update_fee_rates`.
	/// `Some(t)` makes subsequent calls within `FEE_RATES_CACHE_TTL` a no-op.
	fee_rates_fetched_at: RwLock<Option<Instant>>,
	/// Last observed tip height with the time it was fetched, used to
	/// short-circuit repeat `tip()` calls within `TIP_CACHE_TTL`.
	tip_cache: RwLock<Option<(BlockHeight, Instant)>>,
}

impl ChainSource {
	/// Checks that the version of the chain source is compatible with Bark.
	///
	/// For bitcoind, it checks if the version is at least 29.0
	/// This is the first version for which 0 fee-anchors are considered standard
	pub async fn require_version(&self) -> anyhow::Result<()> {
		#[cfg(feature = "bitcoind-rpc")]
		if let ChainSourceClient::Bitcoind { rpc, .. } = self.inner() {
			#[derive(Debug, serde::Deserialize)]
			struct NetworkInfo { version: usize }
			let info: NetworkInfo = rpc.call_raw("getnetworkinfo", &[]).await?;
			if info.version < MIN_BITCOIND_VERSION {
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
	pub async fn new(
		spec: ChainSourceSpec,
		network: Network,
		fallback_fee: Option<FeeRate>,
		#[cfg(feature = "socks5-proxy")] proxy: Option<&str>,
	) -> anyhow::Result<Self> {
		let (inner, zmq_endpoint) = match spec {
			#[cfg(feature = "bitcoind-rpc")]
			ChainSourceSpec::Bitcoind { url, auth, zmq } => {
				// `bdk_bitcoind_rpc::Emitter` is sync-only upstream, so we keep
				// a sync companion to drive it inside `spawn_blocking`. The async
				// client is used everywhere else. `BitcoinRpcClient` (rather
				// than the bare `bitcoincore_rpc::Client`) is required so the
				// `spawn_blocking` closure can take an owned, `Clone` value.
				//
				// The sync companion currently does not honour `socks5-proxy`;
				// SOCKS5 is supported on the Esplora backend, where it is the
				// realistic Tor-via-bitcoind use case.
				let sync = BitcoinRpcClient::new(&url, auth.clone())
					.context("failed to create sync bitcoind rpc client")?;
				let async_auth = match auth {
					rpc::Auth::None => bail!(
						"bitcoind RPC auth is required (cookie file or user/pass)",
					),
					rpc::Auth::UserPass(u, p) => bitcoind_async_client::Auth::UserPass(u, p),
					rpc::Auth::CookieFile(p) => bitcoind_async_client::Auth::CookieFile(p),
				};
				let rpc = BitcoindClient::new(url, async_auth, None, None, None)
					.context("failed to create async bitcoind rpc client")?;
				rpc.require_txindex().await?;
				(ChainSourceClient::Bitcoind { rpc, sync }, zmq)
			},
			#[cfg(not(feature = "bitcoind-rpc"))]
			ChainSourceSpec::Bitcoind { .. } => bail!(
				"bitcoind RPC backend is not available: this build was compiled without \
				 the `bitcoind-rpc` feature (notably the wasm-web build)",
			),
			ChainSourceSpec::Esplora { url } => (ChainSourceClient::Esplora({
				let url = crate::utils::url_with_default_https_scheme(&url);
				// the esplora client doesn't deal well with trailing slash in url
				let url = url.strip_suffix("/").unwrap_or(&url);
				let mut builder = esplora_client::Builder::new(url);
				#[cfg(feature = "socks5-proxy")]
				if let Some(proxy) = proxy {
					builder = builder.proxy(proxy);
				}
				builder.build_async()
					.with_context(|| format!("failed to create esplora client for url {}", url))?
			}), None),
		};

		inner.check_network(network).await?;

		let fee = fallback_fee.unwrap_or(FeeRate::BROADCAST_MIN);
		let fee_rates = RwLock::new(FeeRates { fast: fee, regular: fee, slow: fee });

		Ok(Self {
			inner,
			network,
			zmq_endpoint,
			fee_rates,
			fee_rates_fetched_at: RwLock::new(None),
			tip_cache: RwLock::new(None),
		})
	}

	async fn fetch_fee_rates(&self) -> anyhow::Result<FeeRates> {
		match self.inner() {
			#[cfg(feature = "bitcoind-rpc")]
			ChainSourceClient::Bitcoind { rpc, .. } => {
				let get_fee_rate = async |target: u16| -> anyhow::Result<FeeRate> {
					let fee: rpc::json::EstimateSmartFeeResult = rpc.call_raw(
						"estimatesmartfee",
						&[
							target.into(),
							serde_json::to_value(rpc::json::EstimateMode::Economical)
								.expect("serializable"),
						],
					).await?;
					if let Some(fee_rate) = fee.fee_rate {
						Ok(FeeRate::from_amount_per_kvb_ceil(fee_rate))
					} else {
						Err(anyhow!("No rate returned from estimate_smart_fee for a {} confirmation target", target))
					}
				};
				Ok(FeeRates {
					fast: get_fee_rate(FEE_RATE_TARGET_CONF_FAST).await?,
					regular: get_fee_rate(FEE_RATE_TARGET_CONF_REGULAR).await.expect("should exist"),
					slow: get_fee_rate(FEE_RATE_TARGET_CONF_SLOW).await.expect("should exist"),
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

	/// The ZMQ endpoint of the bitcoind backend, if one was configured.
	///
	/// Always `None` for the Esplora backend.
	pub fn zmq_endpoint(&self) -> Option<&str> {
		self.zmq_endpoint.as_deref()
	}

	async fn fetch_tip(&self) -> anyhow::Result<BlockHeight> {
		match self.inner() {
			#[cfg(feature = "bitcoind-rpc")]
			ChainSourceClient::Bitcoind { rpc, .. } => {
				Ok(rpc.get_block_count().await? as BlockHeight)
			},
			ChainSourceClient::Esplora(client) => {
				Ok(client.get_height().await?)
			},
		}
	}

	pub async fn tip(&self) -> anyhow::Result<BlockHeight> {
		if let Some((height, fetched_at)) = *self.tip_cache.read().await {
			if fetched_at.elapsed() < TIP_CACHE_TTL {
				return Ok(height);
			}
		}
		let height = self.fetch_tip().await?;
		*self.tip_cache.write().await = Some((height, Instant::now()));
		Ok(height)
	}

	/// Drop the cached tip and fee-rate values, forcing the next call to
	/// `tip()` or `update_fee_rates()` to round-trip the backend. Useful
	/// in tests that fabricate chain changes faster than the TTL so the
	/// next observation is deterministic without sleeping.
	pub async fn invalidate_caches(&self) {
		*self.tip_cache.write().await = None;
		*self.fee_rates_fetched_at.write().await = None;
	}

	pub async fn tip_ref(&self) -> anyhow::Result<BlockRef> {
		self.block_ref(self.tip().await?).await
	}

	/// The current tip, always round-tripping the backend instead of serving
	/// the `TIP_CACHE_TTL` cache. Used by the tip watcher, which only fetches
	/// when there is reason to believe the tip changed.
	pub(crate) async fn tip_ref_uncached(&self) -> anyhow::Result<BlockRef> {
		self.block_ref(self.fetch_tip().await?).await
	}

	/// Starts a [TipWatcher] tracking the chain tip of this source.
	///
	/// When this source has a ZMQ endpoint configured, block notifications
	/// wake the watcher and `poll_interval` becomes the reconcile interval;
	/// otherwise the tip is polled at `poll_interval`.
	pub async fn tip_watcher(
		self: &Arc<Self>,
		poll_interval: Duration,
	) -> anyhow::Result<TipWatcher> {
		#[cfg(all(feature = "bitcoind-rpc", not(target_arch = "wasm32")))]
		if let Some(zmq) = self.zmq_endpoint() {
			return TipWatcher::start_zmq(self.clone(), zmq, poll_interval).await;
		}
		TipWatcher::start_poll(self.clone(), poll_interval).await
	}

	pub async fn block_ref(&self, height: BlockHeight) -> anyhow::Result<BlockRef> {
		match self.inner() {
			#[cfg(feature = "bitcoind-rpc")]
			ChainSourceClient::Bitcoind { rpc, .. } => {
				let hash = rpc.get_block_hash(height as u64).await?;
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
			#[cfg(feature = "bitcoind-rpc")]
			ChainSourceClient::Bitcoind { rpc, .. } => {
				match rpc.get_block(&hash).await {
					Ok(block) => Ok(Some(block)),
					Err(e) if is_not_found(&e) => Ok(None),
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
			#[cfg(feature = "bitcoind-rpc")]
			ChainSourceClient::Bitcoind { rpc, .. } => {
				let entry: rpc::json::GetMempoolEntryResult = rpc.call_raw(
					"getmempoolentry", &[serde_json::to_value(txid).expect("serializable")],
				).await?;
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
		#[cfg_attr(not(feature = "bitcoind-rpc"), allow(unused_variables))]
		block_scan_start: BlockHeight,
	) -> anyhow::Result<TxsSpendingInputsResult> {
		let mut res = TxsSpendingInputsResult::new();
		match self.inner() {
			#[cfg(feature = "bitcoind-rpc")]
			ChainSourceClient::Bitcoind { sync, .. } => {
				// We must offset the height to account for the fact we iterate using next_block()
				let start = block_scan_start.saturating_sub(1);
				let block_ref = self.block_ref(start).await?;
				let cp = CheckPoint::new(BlockId {
					height: block_ref.height,
					hash: block_ref.hash,
				});

				debug!("Scanning blocks for spent outpoints with bitcoind, starting at block height {}...", block_scan_start);
				let outpoint_set = outpoints.into_iter().collect::<HashSet<_>>();

				// `bdk_bitcoind_rpc::Emitter` is sync-only upstream, so the
				// scan loop runs inside `spawn_blocking` with the sync companion.
				let sync_client = sync.clone();
				let cp_for_blocking = cp.clone();
				res = tokio::task::spawn_blocking(move || -> anyhow::Result<TxsSpendingInputsResult> {
					let mut res = res;
					let mut emitter = bdk_bitcoind_rpc::Emitter::new(
						&sync_client,
						cp_for_blocking.clone(),
						cp_for_blocking.height(),
						bdk_bitcoind_rpc::NO_EXPECTED_MEMPOOL_TXS,
					);
					while let Some(em) = emitter.next_block()? {
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
											height: em.block_height(),
											hash: em.block.block_hash().clone(),
										}),
									);
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
								if res.map.len() == outpoint_set.len() {
									return Ok(res);
								}
							}
						}
					}
					debug!("Finished checking the mempool for spent outpoints");
					Ok(res)
				}).await.context("Emitter scan task panicked")??;
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
			#[cfg(feature = "bitcoind-rpc")]
			ChainSourceClient::Bitcoind { rpc, .. } => {
				match rpc.send_raw_transaction(tx, None).await {
					Ok(_) => Ok(()),
					Err(e) if is_in_utxo_set(&e) => Ok(()),
					Err(e) => Err(e.into()),
				}
			},
			ChainSourceClient::Esplora(client) => {
				client.broadcast(tx).await?;
				Ok(())
			},
		}
	}

	pub async fn broadcast_package(&self, txs: &[impl Borrow<Transaction>]) -> Result<(), BroadcastError> {
		let package_order = txs.iter()
			.map(|t| t.borrow().compute_txid())
			.collect::<Vec<_>>();
		match self.inner() {
			#[cfg(feature = "bitcoind-rpc")]
			ChainSourceClient::Bitcoind { rpc, .. } => {
				let hexes: Vec<String> = txs.iter()
					.map(|t| bitcoin::consensus::encode::serialize_hex(t.borrow()))
					.collect();
				let res: rpc::SubmitPackageResult = rpc.call_raw("submitpackage", &[hexes.into()])
					.await
					.map_err(|e| BroadcastError::Other(e.to_string()))?;
				if res.package_msg != "success" {
					return Err(classify_submit_package_errors(
						&res.package_msg,
						res.tx_results.values().map(|t| (t.txid, t.error.as_deref())),
						&package_order,
					));
				}
				Ok(())
			},
			ChainSourceClient::Esplora(client) => {
				let txs = txs.iter().map(|t| t.borrow().clone()).collect::<Vec<_>>();
				let res = client.submit_package(&txs, None, None)
					.await
					.map_err(|e| BroadcastError::Other(e.to_string()))?;
				if res.package_msg != "success" {
					return Err(classify_submit_package_errors(
						&res.package_msg,
						res.tx_results.values().map(|t| (t.txid, t.error.as_deref())),
						&package_order,
					));
				}

				Ok(())
			},
		}
	}

	pub async fn get_tx(&self, txid: &Txid) -> anyhow::Result<Option<Transaction>> {
		match self.inner() {
			#[cfg(feature = "bitcoind-rpc")]
			ChainSourceClient::Bitcoind { rpc, .. } => {
				match rpc.get_raw_transaction_verbosity_zero(txid).await {
					Ok(tx) => Ok(Some(tx.0)),
					Err(e) if is_not_found(&e) => Ok(None),
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
			#[cfg(feature = "bitcoind-rpc")]
			ChainSourceClient::Bitcoind { rpc, .. } => Ok(bitcoind_tx_status(rpc, txid).await?),
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
			#[cfg(feature = "bitcoind-rpc")]
			ChainSourceClient::Bitcoind { rpc, .. } => {
				rpc.get_raw_transaction_verbosity_zero(&outpoint.txid).await
					.with_context(|| format!("tx {} unknown", outpoint.txid))?
					.0
			},
			ChainSourceClient::Esplora(client) => {
				client.get_tx(&outpoint.txid).await?
					.with_context(|| format!("tx {} unknown", outpoint.txid))?
			},
		};
		Ok(tx.output.get(outpoint.vout as usize).context("outpoint vout out of range")?.value)
	}

	/// Whether `outpoint` has been spent by a transaction that is confirmed, i.e.
	/// whether any transaction spending it can still be mined.
	///
	/// A spend sitting only in the mempool reports `false`: it can still be
	/// replaced, so it decides nothing.
	///
	/// The caller must know `outpoint`'s own transaction is confirmed. `gettxout`
	/// reads the confirmed utxo set, so it cannot tell an output spent on-chain
	/// apart from one whose transaction has yet to be mined.
	pub async fn outpoint_spent_confirmed(&self, outpoint: OutPoint) -> anyhow::Result<bool> {
		match self.inner() {
			#[cfg(feature = "bitcoind-rpc")]
			ChainSourceClient::Bitcoind { rpc, .. } => {
				// `include_mempool: false` keeps a mempool-only spend out of the
				// answer: the output stays in the confirmed set until its spender is
				// mined.
				let utxo = rpc.try_get_tx_out(outpoint, false).await
					.with_context(|| format!("gettxout {} failed", outpoint))?;
				Ok(utxo.is_none())
			},
			ChainSourceClient::Esplora(client) => {
				let status = client.get_output_status(&outpoint.txid, outpoint.vout as u64).await
					.with_context(|| format!("outspend lookup for {} failed", outpoint))?;
				Ok(status.is_some_and(|s| {
					s.spent && s.status.is_some_and(|s| s.confirmed)
				}))
			},
		}
	}

	/// Gets the current fee rates from the chain source, falling back to user-specified values if
	/// necessary.
	///
	/// No-ops if a previous successful call ran within `FEE_RATES_CACHE_TTL`.
	/// The fallback path overwrites the cached rates but deliberately does
	/// not advance the cache timestamp, so the next call retries the backend
	/// instead of serving the fallback for another full TTL.
	pub async fn update_fee_rates(&self, fallback_fee: Option<FeeRate>) -> anyhow::Result<()> {
		if let Some(fetched_at) = *self.fee_rates_fetched_at.read().await {
			if fetched_at.elapsed() < FEE_RATES_CACHE_TTL {
				return Ok(());
			}
		}
		let (fee_rates, used_fallback) = match (self.fetch_fee_rates().await, fallback_fee) {
			(Ok(fee_rates), _) => (fee_rates, false),
			(Err(e), None) => return Err(e),
			(Err(e), Some(fallback)) => {
				warn!("Error getting fee rates, falling back to {} sat/kvB: {}",
					fallback.to_btc_per_kvb(), e,
				);
				(FeeRates { fast: fallback, regular: fallback, slow: fallback }, true)
			}
		};

		*self.fee_rates.write().await = fee_rates;
		if !used_fallback {
			*self.fee_rates_fetched_at.write().await = Some(Instant::now());
		}
		Ok(())
	}
}

impl TipSource for ChainSource {
	async fn tip_ref(&self) -> anyhow::Result<BlockRef> {
		ChainSource::tip_ref_uncached(self).await
	}
}

// ----- bitcoind-rpc feature-gated helpers ---------------------------------

/// Inspect upstream `bitcoind-async-client` JSON-RPC errors for the
/// "transaction not found" code. Mirrors the sync-side `BitcoinRpcErrorExt`
/// in `bitcoin_ext::rpc`.
#[cfg(feature = "bitcoind-rpc")]
fn is_not_found(e: &BitcoindClientError) -> bool {
	matches!(e, BitcoindClientError::Server(c, _) if *c == RPC_INVALID_ADDRESS_OR_KEY)
}

/// Inspect upstream errors for the "already in utxo set" code.
#[cfg(feature = "bitcoind-rpc")]
fn is_in_utxo_set(e: &BitcoindClientError) -> bool {
	matches!(e, BitcoindClientError::Server(c, _) if *c == RPC_VERIFY_ALREADY_IN_UTXO_SET)
}

/// Two-step `getrawtransaction` + `getblockheader` to determine whether a
/// txid is confirmed, in the mempool, or unknown.
#[cfg(feature = "bitcoind-rpc")]
async fn bitcoind_tx_status(
	rpc: &BitcoindClient, txid: Txid,
) -> Result<TxStatus, BitcoindClientError> {
	let res: Result<rpc::GetRawTransactionResult, _> = rpc.call_raw(
		"getrawtransaction",
		&[serde_json::to_value(txid).expect("serializable"), true.into()],
	).await;
	let info = match res {
		Ok(info) => info,
		Err(e) if is_not_found(&e) => return Ok(TxStatus::NotFound),
		Err(e) => return Err(e),
	};
	let Some(hash) = info.blockhash else {
		return Ok(TxStatus::Mempool);
	};
	let header: rpc::json::GetBlockHeaderResult = rpc.call_raw(
		"getblockheader",
		&[serde_json::to_value(hash).expect("serializable"), true.into()],
	).await?;
	if header.confirmations > 0 {
		Ok(TxStatus::Confirmed(BlockRef {
			height: header.height as BlockHeight,
			hash: header.hash,
		}))
	} else {
		Ok(TxStatus::Mempool)
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

/// Classified failure modes when broadcasting a transaction package.
///
/// The reject reasons covered by the typed variants are stable Bitcoin Core mempool policy
/// constants (`txn-already-known`, `bad-txns-inputs-missingorspent`, `insufficient fee, rejecting
/// replacement`). Esplora forwards bitcoind's reject reasons verbatim, so the same matching works
/// for both backends.
#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum BroadcastError {
	/// The transaction is already in the mempool. Treated as success for retry-safety.
	#[error("transaction already known to the mempool")]
	AlreadyKnown,
	/// Inputs are missing or already spent — typically a conflicting replacement is in the mempool.
	#[error("transaction inputs are missing or already spent")]
	MissingOrSpentInputs,
	/// The replacement fee is insufficient under RBF policy.
	#[error("insufficient fee, rejecting replacement")]
	InsufficientReplacementFee,
	/// Any other failure (unrecognized reject reason, RPC/transport error, etc.).
	#[error("{0}")]
	Other(String),
}

impl BroadcastError {
	/// True if the error means the transaction (or an equivalent one) is already known to the
	/// network — i.e., not a sign that our transaction is invalid.
	pub fn is_mempool_conflict(&self) -> bool {
		matches!(
			self,
			BroadcastError::AlreadyKnown
				| BroadcastError::MissingOrSpentInputs
				| BroadcastError::InsufficientReplacementFee,
		)
	}
}

fn classify_submit_package_errors<'a>(
	package_msg: &str,
	tx_results: impl Iterator<Item = (Txid, Option<&'a str>)>,
	package_order: &[Txid],
) -> BroadcastError {
	// `submitpackage` returns tx_results keyed (and thus iterated) by wtxid, not in
	// package order. Within a package, rejections only cascade downstream: when an
	// ancestor is rejected, every descendant necessarily fails with
	// bad-txns-inputs-missingorspent because the output it spends never came into
	// existence.
	let mut results: Vec<(Txid, Option<&'a str>)> = tx_results.collect();
	results.sort_by_key(|(txid, _)| {
		package_order.iter().position(|t| t == txid).unwrap_or(usize::MAX)
	});

	let mut saw_already_known = false;
	let mut root_cause = None;
	for (_, err) in &results {
		if let Some(err) = err {
			if err.contains("txn-already-known") {
				// Effectively success for this tx; keep looking for a real failure.
				saw_already_known = true;
				continue;
			}
			root_cause = Some(*err);
			break;
		} else {
			continue;
		}
	}

	match root_cause {
		Some(e) if e.contains("bad-txns-inputs-missingorspent") => {
			BroadcastError::MissingOrSpentInputs
		},
		Some(e) if e.contains("insufficient fee, rejecting replacement") => {
			BroadcastError::InsufficientReplacementFee
		},
		Some(_) => {
			let combined = results.iter()
				.map(|(txid, e)| format!("tx {}: {}", txid, e.unwrap_or("(no error)")))
				.collect::<Vec<_>>()
				.join(", ");
			BroadcastError::Other(format!("msg: '{}', errors: [{}]", package_msg, combined))
		},
		None if saw_already_known => BroadcastError::AlreadyKnown,
		None => BroadcastError::Other(format!("msg: '{}', no tx errors", package_msg)),
	}
}

#[cfg(test)]
mod test {
	use super::*;
	use std::str::FromStr;

	#[test]
	fn classify_package_errors_attributes_root_cause_in_package_order() {
		let parent = Txid::from_str(
			"1111111111111111111111111111111111111111111111111111111111111111").unwrap();
		let child = Txid::from_str(
			"2222222222222222222222222222222222222222222222222222222222222222").unwrap();
		let order = [parent, child];

		// Only the child fails: its own (non-package) input is spent. This is the
		// genuine dead-CPFP case and must classify as MissingOrSpentInputs.
		let res = classify_submit_package_errors("transaction failed", [
			(parent, None),
			(child, Some("bad-txns-inputs-missingorspent")),
		].into_iter(), &order);
		assert_eq!(res, BroadcastError::MissingOrSpentInputs);

		// The parent fails for an unrelated reason; the child's missingorspent is only
		// the cascade of the parent never existing. The parent's error is the root
		// cause, so this must NOT classify as MissingOrSpentInputs. Results are fed in
		// wtxid order (child first) to mimic submitpackage's map ordering.
		let res = classify_submit_package_errors("transaction failed", [
			(child, Some("bad-txns-inputs-missingorspent")),
			(parent, Some("version")),
		].into_iter(), &order);
		assert!(matches!(res, BroadcastError::Other(_)), "got {:?}", res);

		// The parent being already known is success for the parent, not the root
		// cause: the child's failure must win over it.
		let res = classify_submit_package_errors("transaction failed", [
			(parent, Some("txn-already-known")),
			(child, Some("bad-txns-inputs-missingorspent")),
		].into_iter(), &order);
		assert_eq!(res, BroadcastError::MissingOrSpentInputs);

		// Everything already known: the package is effectively in the mempool.
		let res = classify_submit_package_errors("transaction failed", [
			(parent, Some("txn-already-known")),
			(child, Some("txn-already-known")),
		].into_iter(), &order);
		assert_eq!(res, BroadcastError::AlreadyKnown);

		// RBF rejection on the child with a clean parent.
		let res = classify_submit_package_errors("transaction failed", [
			(parent, None),
			(child, Some("insufficient fee, rejecting replacement")),
		].into_iter(), &order);
		assert_eq!(res, BroadcastError::InsufficientReplacementFee);

		// No per-tx errors at all: fall back to the package message.
		let res = classify_submit_package_errors("package-mempool-limits", [
			(parent, None),
			(child, None),
		].into_iter(), &order);
		assert!(matches!(res, BroadcastError::Other(ref s) if s.contains("package-mempool-limits")));
	}
}

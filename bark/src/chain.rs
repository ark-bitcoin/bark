

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
use bitcoin_ext::rpc;
#[cfg(feature = "bitcoind-rpc")]
use bitcoin_ext::rpc::{
	BitcoinRpcClient, RPC_INVALID_ADDRESS_OR_KEY, RPC_VERIFY_ALREADY_IN_UTXO_SET,
};
#[cfg(feature = "bitcoind-rpc")]
use bitcoind_async_client::Client as BitcoindClient;
#[cfg(feature = "bitcoind-rpc")]
use bitcoind_async_client::error::ClientError as BitcoindClientError;
#[cfg(feature = "bitcoind-rpc")]
use bitcoind_async_client::traits::{Broadcaster, Reader};

const FEE_RATE_TARGET_CONF_FAST: u16 = 1;
const FEE_RATE_TARGET_CONF_REGULAR: u16 = 3;
const FEE_RATE_TARGET_CONF_SLOW: u16 = 6;

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
	fee_rates: RwLock<FeeRates>,
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
		let inner = match spec {
			#[cfg(feature = "bitcoind-rpc")]
			ChainSourceSpec::Bitcoind { url, auth } => {
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
				ChainSourceClient::Bitcoind { rpc, sync }
			},
			#[cfg(not(feature = "bitcoind-rpc"))]
			ChainSourceSpec::Bitcoind { .. } => bail!(
				"bitcoind RPC backend is not available: this build was compiled without \
				 the `bitcoind-rpc` feature (notably the wasm-web build)",
			),
			ChainSourceSpec::Esplora { url } => ChainSourceClient::Esplora({
				// the esplora client doesn't deal well with trailing slash in url
				let url = url.strip_suffix("/").unwrap_or(&url);
				let mut builder = esplora_client::Builder::new(url);
				#[cfg(feature = "socks5-proxy")]
				if let Some(proxy) = proxy {
					builder = builder.proxy(proxy);
				}
				builder.build_async()
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

	pub async fn tip(&self) -> anyhow::Result<BlockHeight> {
		match self.inner() {
			#[cfg(feature = "bitcoind-rpc")]
			ChainSourceClient::Bitcoind { rpc, .. } => {
				let count = rpc.get_block_count().await?;
				Ok(count as BlockHeight)
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
				match rpc.send_raw_transaction(tx).await {
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
) -> BroadcastError {
	let errors: Vec<String> = tx_results
		.map(|(txid, err)| format!("tx {}: {}", txid, err.unwrap_or("(no error)")))
		.collect();
	let combined = errors.join(", ");
	if combined.contains("txn-already-known") {
		BroadcastError::AlreadyKnown
	} else if combined.contains("bad-txns-inputs-missingorspent") {
		BroadcastError::MissingOrSpentInputs
	} else if combined.contains("insufficient fee, rejecting replacement") {
		BroadcastError::InsufficientReplacementFee
	} else {
		BroadcastError::Other(format!("msg: '{}', errors: [{}]", package_msg, combined))
	}
}

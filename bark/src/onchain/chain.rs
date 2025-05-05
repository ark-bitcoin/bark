

use std::time::UNIX_EPOCH;
use std::{borrow::Borrow, time::SystemTime};
use std::collections::{HashMap, HashSet};

use anyhow::Context;
use bdk_bitcoind_rpc::bitcoincore_rpc::{self, RpcApi};
use bdk_bitcoind_rpc::BitcoindRpcErrorExt;
use bdk_esplora::{esplora_client, EsploraAsyncExt};
use bdk_wallet::chain::{ChainPosition, CheckPoint};
use bdk_wallet::{chain::BlockId, PersistedWallet, WalletPersister};
use bitcoin::{Amount, Block, BlockHash, FeeRate, OutPoint, Transaction, Txid, Wtxid};
use bitcoin_ext::bdk::EsploraClientExt;
use bitcoin_ext::rpc::BitcoinRpcExt;
use bitcoin_ext::BlockHeight;
use log::{debug, info, warn};

use crate::persist::{BarkPersister, WalletPersisterError};

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

pub enum ChainSourceClient {
	Bitcoind(bitcoincore_rpc::Client),
	Esplora(esplora_client::AsyncClient),
}

impl ChainSourceClient {
	/// Checks that the version of the chain source is compatible with Bark.
	///
	/// For bitcoind, it checks if the version is at least 29.0
	/// This is the first version for which 0 fee-anchors are considered standard
	pub fn require_version(&self) -> anyhow::Result<()> {
		if let ChainSourceClient::Bitcoind(ref bitcoind) = self {
			if bitcoind.version()? < MIN_BITCOIND_VERSION {
				bail!("Bitcoin Core version is too old, you can participate in rounds but won't be able to unilaterally exit. Please upgrade to 29.0 or higher.");
			}
		}

		Ok(())
	}

	pub fn new(chain_source: ChainSource) -> anyhow::Result<Self> {
		Ok(match chain_source {
			ChainSource::Bitcoind { url, auth } => ChainSourceClient::Bitcoind(
				bitcoincore_rpc::Client::new(&url, auth)
					.context("failed to create bitcoind rpc client")?
			),
			ChainSource::Esplora { url } => ChainSourceClient::Esplora({
				// the esplora client doesn't deal well with trailing slash in url
				let url = url.strip_suffix("/").unwrap_or(&url);
				esplora_client::Builder::new(url).build_async()
					.with_context(|| format!("failed to create esplora client for url {}", url))?
			}),
		})
	}

	pub async fn tip(&self) -> anyhow::Result<BlockHeight> {
		match self {
			ChainSourceClient::Bitcoind(ref bitcoind) => {
				Ok(bitcoind.get_block_count()? as BlockHeight)
			},
			ChainSourceClient::Esplora(ref client) => {
				Ok(client.get_height().await?)
			},
		}
	}

	pub async fn block_id(&self, height: BlockHeight) -> anyhow::Result<BlockId> {
		match self {
			ChainSourceClient::Bitcoind(ref bitcoind) => {
				let hash = bitcoind.get_block_hash(height as u64)?;
				Ok(BlockId::from((height, hash)))
			},
			ChainSourceClient::Esplora(ref client) => {
				let hash = client.get_block_hash(height).await?;
				Ok(BlockId::from((height, hash)))
			},
		}
	}

	pub async fn block(&self, hash: &BlockHash) -> anyhow::Result<Option<Block>> {
		match self {
			ChainSourceClient::Bitcoind(ref bitcoind) => {
				match bitcoind.get_block(hash) {
					Ok(b) => Ok(Some(b)),
					Err(e) if e.is_not_found_error() => Ok(None),
					Err(e) => Err(e.into()),
				}
			},
			ChainSourceClient::Esplora(ref client) => {
				Ok(client.get_block_by_hash(hash).await?)
			},
		}
	}

	pub async fn sync_wallet<P>(&self, wallet: &mut PersistedWallet<P>, db: &mut P) -> anyhow::Result<Amount>
		where
			P: BarkPersister,
			<P as WalletPersister>::Error: WalletPersisterError,
	{
		debug!("Starting wallet sync...");
		let now = SystemTime::now().duration_since(UNIX_EPOCH).expect("now").as_secs();

		let prev_tip = wallet.latest_checkpoint();
		match self {
			ChainSourceClient::Bitcoind(ref bitcoind) => {
				debug!("Syncing with bitcoind, starting at block height {}...", prev_tip.height());
				let mut emitter = bdk_bitcoind_rpc::Emitter::new(
					bitcoind, prev_tip.clone(), prev_tip.height(),
				);
				let mut count = 0;
				while let Some(em) = emitter.next_block()? {
					wallet.apply_block_connected_to(
						&em.block, em.block_height(), em.connected_to(),
					)?;
					count += 1;

					if count % 10_000 == 0 {
						wallet.persist(db)?;
						info!("Synced until block height {}", em.block_height());
					}
				}

				let mempool = emitter.mempool()?;
				wallet.apply_unconfirmed_txs(mempool);
				wallet.persist(db)?;
				debug!("Finished syncing with bitcoind, {}", wallet.balance());
			},
			ChainSourceClient::Esplora(ref client) => {
				debug!("Syncing with esplora...");
				const STOP_GAP: usize = 50;
				const PARALLEL_REQS: usize = 4;

				let request = wallet.start_full_scan();
				let now = std::time::UNIX_EPOCH.elapsed().unwrap().as_secs();
				let update = client.full_scan(request, STOP_GAP, PARALLEL_REQS).await?;
				wallet.apply_update_at(update, now)?;
				wallet.persist(db)?;
				debug!("Finished syncing with esplora, {}", wallet.balance());
			},
		}

		let balance = wallet.balance();

		// Ultimately, let's try to rebroadcast all our unconfirmed txs.
		let transactions = wallet
			.transactions()
			.filter(|tx| {
				if let ChainPosition::Unconfirmed { last_seen } = tx.chain_position {
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

	/// For each provided outpoint, fetches any confirmed or unconfirmed
	/// transaction in which it is spent, then returns a tupple containing
	/// _outpoint>confirmed tx_ map and _outpoint>unconfirmed tx_ map
	pub async fn txs_spending_inputs(&self, outpoints: Vec<OutPoint>, start: BlockHeight)
		-> anyhow::Result<(HashMap<OutPoint, (BlockHeight, Txid)>, HashMap<OutPoint, Txid>)>
	{
		let mut txs_by_outpoint = HashMap::<OutPoint, (BlockHeight, Txid)>::new();
		let mut unconfirmed_txs_by_outpoint = HashMap::<OutPoint, Txid>::new();

		match self {
			ChainSourceClient::Bitcoind(ref bitcoind) => {
				let block = self.block_id(start).await?;
				let cp = CheckPoint::new(block);

				let mut emitter = bdk_bitcoind_rpc::Emitter::new(
					bitcoind, cp.clone(), cp.height(),
				);

				let outpoint_set: HashSet<bitcoin::OutPoint> = HashSet::from_iter(outpoints.clone().into_iter());

				while let Some(em) = emitter.next_block()? {
					for tx in &em.block.txdata {
						for txin in tx.input.iter() {
							if outpoint_set.contains(&txin.previous_output) {
								txs_by_outpoint.insert(txin.previous_output.clone(), (
									em.block.bip34_block_height().unwrap() as BlockHeight, tx.compute_txid()
								));
							}
						}
					}
				}

				let mempool = emitter.mempool()?;
				for (tx, _last_seen) in &mempool {
					for txin in tx.input.iter() {
						if outpoint_set.contains(&txin.previous_output) {
							unconfirmed_txs_by_outpoint.insert(txin.previous_output.clone(), tx.compute_txid());
						}
					}
				}
			},
			ChainSourceClient::Esplora(ref client) => {
				for outpoint in outpoints {
					let output_status = client.get_output_status(&outpoint.txid, outpoint.vout.into()).await?;

					if let Some(output_status) = output_status {
						if let Some(block_height) = output_status.status.and_then(|s| s.block_height) {
							txs_by_outpoint.insert(outpoint, (block_height.into(), output_status.txid.expect("tx is confirmed")));
							continue;
						}

						if output_status.spent {
							unconfirmed_txs_by_outpoint.insert(outpoint, output_status.txid.expect("output is spent"));
						}
					}
				}
			},
		}

		Ok((txs_by_outpoint, unconfirmed_txs_by_outpoint))
	}

	pub async fn broadcast_tx(&self, tx: &Transaction) -> anyhow::Result<()> {
		match self {
			ChainSourceClient::Bitcoind(ref bitcoind) => {
				match bitcoind.send_raw_transaction(tx) {
					Ok(_) => Ok(()),
					Err(bitcoincore_rpc::Error::JsonRpc(
						bitcoincore_rpc::jsonrpc::Error::Rpc(e))
					) if e.code == TX_ALREADY_IN_CHAIN_ERROR => Ok(()),
					Err(e) => Err(e.into()),
				}
			},
			ChainSourceClient::Esplora(ref client) => {
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

		match self {
			ChainSourceClient::Bitcoind(ref bitcoind) => {
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
			ChainSourceClient::Esplora(ref client) => {
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

	pub async fn get_tx(&self, txid: Txid) -> anyhow::Result<Option<Transaction>> {
		match self {
			ChainSourceClient::Bitcoind(ref bitcoind) => {
				Ok(bitcoind.get_raw_transaction(&txid, None).ok())
			},
			ChainSourceClient::Esplora(ref client) => {
				Ok(client.get_tx(&txid).await?)
			},
		}
	}

	/// Returns the block height the tx is confirmed in, if any.
	pub async fn tx_confirmed(&self, txid: Txid) -> anyhow::Result<Option<BlockHeight>> {
		let ret = match self {
			ChainSourceClient::Bitcoind(ref bitcoind) => {
				//TODO(stevenroose) would be nice if we cna distinguish network Error
				//or tx unknown error here (my refactor branch does that, liquid also)
				let tx = bitcoind.custom_get_raw_transaction_info(&txid, None)?;
				if let Some(hash) = tx.blockhash {
					let block = bitcoind.get_block_header_info(&hash)?;
					if block.confirmations > 0 {
						Some(block.height as BlockHeight)
					} else {
						None
					}
				} else {
					None
				}
			},
			ChainSourceClient::Esplora(ref client) => {
				client.get_tx_status(&txid).await?.block_height
			},
		};
		Ok(ret)
	}

	#[allow(unused)]
	pub async fn txout_value(&self, outpoint: OutPoint) -> anyhow::Result<Amount> {
		let tx = match self {
			ChainSourceClient::Bitcoind(ref bitcoind) => {
				bitcoind.get_raw_transaction(&outpoint.txid, None)
					.with_context(|| format!("tx {} unknown", outpoint.txid))?
			},
			ChainSourceClient::Esplora(ref client) => {
				client.get_tx(&outpoint.txid).await?
					.with_context(|| format!("tx {} unknown", outpoint.txid))?
			},
		};
		Ok(tx.output.get(outpoint.vout as usize).context("outpoint vout out of range")?.value)
	}

	/// Fee rate to use for regular txs like boards.
	pub (crate) fn regular_feerate(&self) -> FeeRate {
		FeeRate::from_sat_per_vb(5).unwrap()
	}

	/// Fee rate to use for urgent txs like exits.
	pub (crate) fn urgent_feerate(&self) -> FeeRate {
		FeeRate::from_sat_per_vb(7).unwrap()
	}
}

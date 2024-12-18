

use std::time::UNIX_EPOCH;
use std::{borrow::Borrow, time::SystemTime};
use std::collections::HashMap;

use anyhow::Context;
use ark::BlockHeight;
use bdk_bitcoind_rpc::bitcoincore_rpc::{self, RpcApi};
use bdk_esplora::{esplora_client, EsploraAsyncExt};
use bdk_wallet::chain::{ChainPosition, CheckPoint};
use bdk_wallet::{chain::BlockId, PersistedWallet, WalletPersister};
use bitcoin::{Amount, FeeRate, OutPoint, Transaction, Txid, Wtxid};
use serde::ser::StdError;

use crate::persist::BarkPersister;

const TX_ALREADY_IN_CHAIN_ERROR: i32 = -27;

#[derive(Clone)]
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
	/// For bitcoind, it checks if the version is at least 28.0, because unilateral exits rely on `package relay`, which was added in this version.
	/// For esplora, it always returns `Ok(())` because there is no version to check.
	pub fn require_version(&self) -> anyhow::Result<()> {
		if let ChainSourceClient::Bitcoind(ref bitcoind) = self {
			if bitcoind.version()? < 280000 {
				bail!("Bitcoin Core version is too old, you can participate in rounds but won't be able to unilaterally exit. Please upgrade to 28.0 or higher.");
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
			ChainSource::Esplora { url } => ChainSourceClient::Esplora(
				esplora_client::Builder::new(&url).build_async()
					.with_context(|| format!("failed to create esplora client for url {}", url))?
			),
		})
	}

	pub async fn tip(&self) -> anyhow::Result<u32> {
		match self {
			ChainSourceClient::Bitcoind(ref bitcoind) => {
				Ok(bitcoind.get_block_count()? as u32)
			},
			ChainSourceClient::Esplora(ref client) => {
				Ok(client.get_height().await?)
			},
		}
	}

	pub async fn block_id(&self, height: u32) -> anyhow::Result<BlockId> {
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

	pub async fn sync_wallet<P>(&self, wallet: &mut PersistedWallet<P>, db: &mut P) -> anyhow::Result<Amount>
		where
			P: BarkPersister,
			<P as WalletPersister>::Error: 'static + std::fmt::Debug + std::fmt::Display + Send + Sync + StdError
	{
		debug!("Starting wallet sync...");
		let now = SystemTime::now().duration_since(UNIX_EPOCH).expect("now").as_secs();

		let prev_tip = wallet.latest_checkpoint();
		match self {
			ChainSourceClient::Bitcoind(ref bitcoind) => {
				let mut emitter = bdk_bitcoind_rpc::Emitter::new(
					bitcoind, prev_tip.clone(), prev_tip.height(),
				);
				while let Some(em) = emitter.next_block()? {
					wallet.apply_block_connected_to(
						&em.block, em.block_height(), em.connected_to(),
					)?;
				}

				let mempool = emitter.mempool()?;
				wallet.apply_unconfirmed_txs(mempool);
				wallet.persist(db)?;
			},
			ChainSourceClient::Esplora(ref client) => {
				const STOP_GAP: usize = 50;
				const PARALLEL_REQS: usize = 4;

				let request = wallet.start_full_scan();
				let now = std::time::UNIX_EPOCH.elapsed().unwrap().as_secs();
				let update = client.full_scan(request, STOP_GAP, PARALLEL_REQS).await?;
				wallet.apply_update_at(update, now)?;
				wallet.persist(db)?;
			},
		}

		let balance = wallet.balance();

		// Ultimately, let's try to rebroadcast all our unconfirmed txs.
		for tx in wallet.transactions() {
			if let ChainPosition::Unconfirmed { last_seen: Some(last_seen) } = tx.chain_position {
				if last_seen < now {
					if let Err(e) = self.broadcast_tx(&tx.tx_node.tx).await {
						warn!("Error broadcasting tx {}: {}", tx.tx_node.txid, e);
					}
				}
			}
		}

		Ok(balance.total())
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
		struct SubmitPacakgeResponse {
			#[serde(rename = "tx-results")]
			tx_results: HashMap<Wtxid, PackageTxInfo>,
			package_msg: String,
		}

		match self {
			ChainSourceClient::Bitcoind(ref bitcoind) => {
				let hexes = txs.iter()
					.map(|t| bitcoin::consensus::encode::serialize_hex(t.borrow()))
					.collect::<Vec<_>>();
				let res = bitcoind.call::<SubmitPacakgeResponse>("submitpackage", &[hexes.into()])?;
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
			ChainSourceClient::Esplora(ref _client) => unimplemented!(),
		}
	}

	/// Returns the block height the tx is confirmed in, if any.
	pub async fn tx_confirmed(&self, txid: Txid) -> anyhow::Result<Option<u32>> {
		let ret = match self {
			ChainSourceClient::Bitcoind(ref bitcoind) => {
				//TODO(stevenroose) would be nice if we cna distinguish network Error
				//or tx unknown error here (my refactor branch does that, liquid also)
				let tx = bitcoind.get_raw_transaction_info(&txid, None)?;
				if let Some(hash) = tx.blockhash {
					let block = bitcoind.get_block_header_info(&hash)?;
					if block.confirmations > 0 {
						Some(block.height as u32)
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

	/// Fee rate to use for regular txs like onboards.
	pub (crate) fn regular_feerate(&self) -> FeeRate {
		FeeRate::from_sat_per_vb(10).unwrap()
	}

	/// Fee rate to use for urgent txs like exits.
	pub (crate) fn urgent_feerate(&self) -> FeeRate {
		FeeRate::from_sat_per_vb(15).unwrap()
	}
}

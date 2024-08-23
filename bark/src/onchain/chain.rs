

use anyhow::Context;
use bdk_bitcoind_rpc::bitcoincore_rpc::{self, RpcApi};
use bdk_esplora::esplora_client;
use bitcoin::{Amount, OutPoint, Transaction, Txid};

const TX_ALREADY_IN_CHAIN_ERROR: i32 = -27;

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
}

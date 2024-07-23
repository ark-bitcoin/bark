

use anyhow::Context;
use bdk_bitcoind_rpc::bitcoincore_rpc::{self, RpcApi};
use bdk_esplora::esplora_client;
use bitcoin::{OutPoint, Transaction};

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

	pub async fn txout_confirmations(&self, outpoint: OutPoint) -> anyhow::Result<Option<u32>> {
		match self {
			ChainSourceClient::Bitcoind(ref bitcoind) => {
				Ok(bitcoind.get_tx_out(
					&outpoint.txid, outpoint.vout, Some(true), // include mempool
				)?.map(|txout| txout.confirmations))
			},
			ChainSourceClient::Esplora(ref client) => {
				let height = client.get_tx_status(&outpoint.txid).await?.block_height;
				if let Some(height) = height {
					let tip = client.get_height().await?;
					Ok(Some(tip.saturating_sub(height) + 1))
				} else {
					Ok(None)
				}
			},
		}
	}
}

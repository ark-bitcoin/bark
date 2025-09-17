use anyhow::{bail, Context};
use bitcoin::Network;
use bitcoin_ext::rpc::RpcApi;

const MIN_BITCOIND_VERSION: usize = 29_00_00;


pub trait BitcoinRpcClientExt: RpcApi {
	fn require_txindex(&self) -> anyhow::Result<()> {
		let indices = self.get_index_info()
			.context("failed to getindexinfo from bitcoind")?;

		if indices.txindex.is_none() {
			bail!("txindex is not enabled. Run bitcoind with txindex = 1")
		}

		Ok(())
	}

	fn require_network(&self, expected: Network) -> anyhow::Result<()> {
		let chain = self.get_blockchain_info()
			.context("failed to getblockchaininfo from bitcoind")?;

		if chain.chain != expected {
			bail!("Network mismatch: server is configured to use {:?} but bitcoind uses {:?}",
				expected, chain.chain,
			);
		}

		Ok(())
	}

	fn require_version(&self) -> anyhow::Result<()> {
		let version = self.version().context("failed to get version from bitcoind")?;

		if version < MIN_BITCOIND_VERSION {
			bail!("Old bitcoind version detected. Please upgrade to v29 or later");
		}

		Ok(())
	}
}

impl<T: RpcApi> BitcoinRpcClientExt for T {}

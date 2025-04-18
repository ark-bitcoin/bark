

pub use bdk_bitcoind_rpc::bitcoincore_rpc::RpcApi;


use std::borrow::Borrow;

use bdk_bitcoind_rpc::bitcoincore_rpc::{jsonrpc, Auth, Client, Error};
use bitcoin::Transaction;
use bitcoin_ext::BlockRef;

use crate::DEEPLY_CONFIRMED;


/// Error code for RPC_VERIFY_ALREADY_IN_UTXO_SET.
const RPC_VERIFY_ALREADY_IN_UTXO_SET: i32 = -27;

/// Error code for RPC_INVALID_ADDRESS_OR_KEY, used when a tx is not found.
const RPC_INVALID_ADDRESS_OR_KEY: i32 = -5;


/// Clonable bitcoind rpc client.
#[derive(Debug)]
pub struct BitcoinRpcClient {
	client: Client,
	url: String,
	auth: Auth,
}

impl BitcoinRpcClient {
	pub fn new(url: &str, auth: Auth) -> anyhow::Result<Self> {
		Ok(BitcoinRpcClient {
			client: Client::new(url, auth.clone())?,
			url: url.to_owned(),
			auth: auth,
		})
	}
}

impl RpcApi for BitcoinRpcClient {
	fn call<T: for<'a> serde::de::Deserialize<'a>>(
		&self, cmd: &str, args: &[serde_json::Value],
	) -> Result<T, Error> {
		self.client.call(cmd, args)
	}
}

impl Clone for BitcoinRpcClient {
	fn clone(&self) -> Self {
		BitcoinRpcClient {
			client: Client::new(&self.url, self.auth.clone()).expect("we did it before"),
			url: self.url.clone(),
			auth: self.auth.clone(),
		}
	}
}

pub trait BitcoinRpcErrorExt: Borrow<Error> {
	/// Whether this error indicates that the tx was not found.
	fn is_not_found(&self) -> bool {
		if let Error::JsonRpc(jsonrpc::Error::Rpc(e)) = self.borrow() {
			e.code == RPC_INVALID_ADDRESS_OR_KEY
		} else {
			false
		}
	}

	/// Whether this error indicates that the tx is already in the utxo set.
	fn is_in_utxo_set(&self) -> bool {
		if let Error::JsonRpc(jsonrpc::Error::Rpc(e)) = self.borrow() {
			e.code == RPC_VERIFY_ALREADY_IN_UTXO_SET
		} else {
			false
		}
	}

	fn is_already_in_mempool(&self) -> bool {
		if let Error::JsonRpc(jsonrpc::Error::Rpc(e)) = self.borrow() {
			e.message.contains("txn-already-in-mempool")
		} else {
			false
		}
	}
}
impl BitcoinRpcErrorExt for Error {}


pub trait BitcoinRpcExt: RpcApi {
	fn broadcast_tx(&self, tx: &Transaction) -> Result<(), Error> {
		match self.send_raw_transaction(tx) {
			Ok(_) => Ok(()),
			Err(e) if e.is_in_utxo_set() => Ok(()),
			Err(e) => Err(e),
		}
	}

	fn tip(&self) -> Result<BlockRef, Error> {
		let height = self.get_block_count()?;
		let hash = self.get_block_hash(height)?;
		Ok(BlockRef { height, hash })
	}

	fn deep_tip(&self) -> Result<BlockRef, Error> {
		let tip = self.get_block_count()?;
		let height = tip.saturating_sub(DEEPLY_CONFIRMED);
		let hash = self.get_block_hash(height)?;
		Ok(BlockRef { height, hash })
	}
}
impl <T: RpcApi> BitcoinRpcExt for T {}

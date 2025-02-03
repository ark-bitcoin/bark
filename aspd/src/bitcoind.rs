

use std::borrow::Borrow;

use bdk_bitcoind_rpc::bitcoincore_rpc::{jsonrpc, Error, RpcApi};
use bitcoin::Transaction;

use ark::BlockRef;


/// Error code for RPC_VERIFY_ALREADY_IN_UTXO_SET.
const RPC_VERIFY_ALREADY_IN_UTXO_SET: i32 = -27;

/// Error code for RPC_INVALID_ADDRESS_OR_KEY, used when a tx is not found.
const RPC_INVALID_ADDRESS_OR_KEY: i32 = -5;


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
}
impl <T: RpcApi> BitcoinRpcExt for T {}

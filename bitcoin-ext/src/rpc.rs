use std::borrow::Borrow;

use cbitcoin::address::NetworkUnchecked;
use cbitcoin::hex::FromHex;
use cbitcoin::{Address, Amount, Transaction};
use serde::{self, Deserialize, Serialize};
use serde::de::Error as SerdeError;

use bdk_bitcoind_rpc::bitcoincore_rpc::{jsonrpc, Auth, Client, Error, Result as RpcResult, RpcApi};

use crate::{BlockHeight, BlockRef, DEEPLY_CONFIRMED};

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
	pub fn new(url: &str, auth: Auth) -> Result<Self, Error> {
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
		Self::new(&self.url, self.auth.clone()).unwrap()
	}
}

/// A module used for serde serialization of bytes in hexadecimal format.
///
/// The module is compatible with the serde attribute.
mod serde_hex {
	use bitcoin::hex::{DisplayHex, FromHex};
	use serde::de::Error;
	use serde::{Deserializer, Serializer};

	pub fn serialize<S: Serializer>(b: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
		s.serialize_str(&b.to_lower_hex_string())
	}

	pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
		let hex_str: String = ::serde::Deserialize::deserialize(d)?;
		Ok(FromHex::from_hex(&hex_str).map_err(D::Error::custom)?)
	}

	pub mod opt {
		use bitcoin::hex::{DisplayHex, FromHex};
		use serde::de::Error;
		use serde::{Deserializer, Serializer};

		pub fn serialize<S: Serializer>(b: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
			match *b {
				None => s.serialize_none(),
				Some(ref b) => s.serialize_str(&b.to_lower_hex_string()),
			}
		}

		pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Vec<u8>>, D::Error> {
			let hex_str: String = ::serde::Deserialize::deserialize(d)?;
			Ok(Some(FromHex::from_hex(&hex_str).map_err(D::Error::custom)?))
		}
	}
}

/// deserialize_hex_array_opt deserializes a vector of hex-encoded byte arrays.
fn deserialize_hex_array_opt<'de, D>(deserializer: D) -> Result<Option<Vec<Vec<u8>>>, D::Error>
where
	D: serde::Deserializer<'de>,
{
	//TODO(stevenroose) Revisit when issue is fixed:
	// https://github.com/serde-rs/serde/issues/723

	let v: Vec<String> = Vec::deserialize(deserializer)?;
	let mut res = Vec::new();
	for h in v.into_iter() {
		res.push(FromHex::from_hex(&h).map_err(D::Error::custom)?);
	}
	Ok(Some(res))
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetRawTransactionResultVinScriptSig {
	pub asm: String,
	#[serde(with = "serde_hex")]
	pub hex: Vec<u8>,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetRawTransactionResultVin {
	pub sequence: u32,
	/// The raw scriptSig in case of a coinbase tx.
	#[serde(default, with = "serde_hex::opt")]
	pub coinbase: Option<Vec<u8>>,
	/// Not provided for coinbase txs.
	pub txid: Option<bitcoin::Txid>,
	/// Not provided for coinbase txs.
	pub vout: Option<u32>,
	/// The scriptSig in case of a non-coinbase tx.
	pub script_sig: Option<GetRawTransactionResultVinScriptSig>,
	/// Not provided for coinbase txs.
	#[serde(default, deserialize_with = "deserialize_hex_array_opt")]
	pub txinwitness: Option<Vec<Vec<u8>>>,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetRawTransactionResultVout {
	#[serde(with = "bitcoin::amount::serde::as_btc")]
	pub value: Amount,
	pub n: u32,
	pub script_pub_key: GetRawTransactionResultVoutScriptPubKey,
}

#[allow(non_camel_case_types)]
#[derive(Copy, Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ScriptPubkeyType {
	Nonstandard,
	Anchor,
	Pubkey,
	PubkeyHash,
	ScriptHash,
	MultiSig,
	NullData,
	Witness_v0_KeyHash,
	Witness_v0_ScriptHash,
	Witness_v1_Taproot,
	Witness_Unknown,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetRawTransactionResultVoutScriptPubKey {
	pub asm: String,
	#[serde(with = "serde_hex")]
	pub hex: Vec<u8>,
	pub req_sigs: Option<usize>,
	#[serde(rename = "type")]
	pub type_: Option<ScriptPubkeyType>,
	// Deprecated in Bitcoin Core 22
	#[serde(default)]
	pub addresses: Vec<Address<NetworkUnchecked>>,
	// Added in Bitcoin Core 22
	#[serde(default)]
	pub address: Option<Address<NetworkUnchecked>>,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetRawTransactionResult {
	#[serde(rename = "in_active_chain")]
	pub in_active_chain: Option<bool>,
	#[serde(with = "serde_hex")]
	pub hex: Vec<u8>,
	pub txid: bitcoin::Txid,
	pub hash: bitcoin::Wtxid,
	pub size: usize,
	pub vsize: usize,
	pub version: u32,
	pub locktime: u32,
	pub vin: Vec<GetRawTransactionResultVin>,
	pub vout: Vec<GetRawTransactionResultVout>,
	pub blockhash: Option<bitcoin::BlockHash>,
	pub confirmations: Option<u32>,
	pub time: Option<usize>,
	pub blocktime: Option<usize>,
}

/// Shorthand for converting a variable into a serde_json::Value.
fn into_json<T>(val: T) -> RpcResult<serde_json::Value>
where
	T: serde::ser::Serialize,
{
	Ok(serde_json::to_value(val)?)
}

/// Shorthand for converting an Option into an Option<serde_json::Value>.
fn opt_into_json<T>(opt: Option<T>) -> RpcResult<serde_json::Value>
where
	T: serde::ser::Serialize,
{
	match opt {
		Some(val) => Ok(into_json(val)?),
		None => Ok(serde_json::Value::Null),
	}
}

/// Handle default values in the argument list
///
/// Substitute `Value::Null`s with corresponding values from `defaults` table,
/// except when they are trailing, in which case just skip them altogether
/// in returned list.
///
/// Note, that `defaults` corresponds to the last elements of `args`.
///
/// ```norust
/// arg1 arg2 arg3 arg4
///           def1 def2
/// ```
///
/// Elements of `args` without corresponding `defaults` value, won't
/// be substituted, because they are required.
fn handle_defaults<'a, 'b>(
	args: &'a mut [serde_json::Value],
	defaults: &'b [serde_json::Value],
) -> &'a [serde_json::Value] {
	assert!(args.len() >= defaults.len());

	// Pass over the optional arguments in backwards order, filling in defaults after the first
	// non-null optional argument has been observed.
	let mut first_non_null_optional_idx = None;
	for i in 0..defaults.len() {
		let args_i = args.len() - 1 - i;
		let defaults_i = defaults.len() - 1 - i;
		if args[args_i] == serde_json::Value::Null {
			if first_non_null_optional_idx.is_some() {
				if defaults[defaults_i] == serde_json::Value::Null {
					panic!("Missing `default` for argument idx {}", args_i);
				}
				args[args_i] = defaults[defaults_i].clone();
			}
		} else if first_non_null_optional_idx.is_none() {
			first_non_null_optional_idx = Some(args_i);
		}
	}

	let required_num = args.len() - defaults.len();

	if let Some(i) = first_non_null_optional_idx {
		&args[..i + 1]
	} else {
		&args[..required_num]
	}
}

/// Shorthand for `serde_json::Value::Null`.
fn null() -> serde_json::Value {
	serde_json::Value::Null
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
	fn custom_get_raw_transaction_info(
		&self,
		txid: &bitcoin::Txid,
		block_hash: Option<&bitcoin::BlockHash>,
	) -> RpcResult<Option<GetRawTransactionResult>> {
		let mut args = [into_json(txid)?, into_json(true)?, opt_into_json(block_hash)?];
		match self.call("getrawtransaction", handle_defaults(&mut args, &[null()])) {
			Ok(ret) => Ok(Some(ret)),
			Err(e) if e.is_not_found() => Ok(None),
			Err(e) => Err(e),
		}
	}

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
		Ok(BlockRef { height: height as BlockHeight, hash })
	}

	fn deep_tip(&self) -> Result<BlockRef, Error> {
		let tip = self.get_block_count()?;
		let height = tip.saturating_sub(DEEPLY_CONFIRMED as u64);
		let hash = self.get_block_hash(height)?;
		Ok(BlockRef { height: height as BlockHeight, hash })
	}

	fn tx_status(&self, txid: &bitcoin::Txid) -> Result<TxStatus, Error> {
		match self.custom_get_raw_transaction_info(txid, None)? {
			Some(tx) => match tx.blockhash {
				Some(hash) => {
					let block = self.get_block_header_info(&hash)?;
					if block.confirmations > 0 {
						Ok(TxStatus::Confirmed(BlockRef { height: block.height as BlockHeight, hash: block.hash }))
					} else {
						Ok(TxStatus::Mempool)
					}
				},
				None => Ok(TxStatus::Mempool),
			},
			None => Ok(TxStatus::NotFound)
		}
	}
}

impl <T: RpcApi> BitcoinRpcExt for T {}


#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum TxStatus {
	Confirmed(BlockRef),
	Mempool,
	NotFound,
}

impl TxStatus {
	pub fn confirmed_height(&self) -> Option<BlockHeight> {
		match self {
			TxStatus::Confirmed(block_ref) => Some(block_ref.height),
			_ => None,
		}
	}

	pub fn confirmed_in(&self) -> Option<BlockRef> {
		match self {
			TxStatus::Confirmed(block_ref) => Some(*block_ref),
			_ => None,
		}
	}
}

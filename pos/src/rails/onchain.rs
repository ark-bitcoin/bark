//! The on-chain rail: one address per sale, derived from the owner's
//! public descriptor.
//!
//! posd watches the addresses in a watch-only wallet of its own on bitcoind.
//! Each sale address is imported when the sale is created. A fresh address
//! has no history, so the import needs no rescan.

use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

use anyhow::{Context, bail};
use bdk_wallet::miniscript::ForEachKey;
use bdk_wallet::miniscript::descriptor::{Descriptor, DescriptorPublicKey, Wildcard};
use bitcoin::{Address, Amount, Network};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};


/// A public, single-path, ranged descriptor such as
/// `tr([fp/86'/0'/1']xpub…/0/*)`.
#[derive(Debug, Clone)]
pub struct StoreDescriptor(Descriptor<DescriptorPublicKey>);

impl StoreDescriptor {
	pub fn parse(s: &str) -> anyhow::Result<StoreDescriptor> {
		let desc = Descriptor::<DescriptorPublicKey>::from_str(s)
			.context("not a valid public descriptor")?;
		if !desc.has_wildcard() {
			bail!("the descriptor must be ranged (end in /*)");
		}
		if desc.is_multipath() {
			bail!("the descriptor must have a single derivation path");
		}
		// A hardened wildcard needs a private key to derive.
		let hardened = desc.for_any_key(|k| match k {
			DescriptorPublicKey::XPub(x) => x.wildcard == Wildcard::Hardened,
			DescriptorPublicKey::MultiXPub(x) => x.wildcard == Wildcard::Hardened,
			DescriptorPublicKey::Single(_) => false,
		});
		if hardened {
			bail!("the descriptor must derive without private keys (no hardened wildcard)");
		}
		Ok(StoreDescriptor(desc))
	}

	pub fn address(&self, index: u32, network: Network) -> anyhow::Result<Address> {
		let derived = self.0.at_derivation_index(index)
			.context("index out of range for the descriptor")?;
		derived.address(network).context("the descriptor has no address form")
	}
}

/// What the chain shows for an address.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AddressFunds {
	/// Paid to the address with at least 1 confirmation.
	pub confirmed: Amount,
	/// Paid to the address in mempool transactions.
	pub pending: Amount,
	pub txids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitcoindConfig {
	/// The RPC URL, for example `http://127.0.0.1:8332`.
	pub url: String,
	/// The RPC cookie file. Used when `rpc_user` is not set.
	pub cookie: Option<PathBuf>,
	pub rpc_user: Option<String>,
	#[serde(skip_serializing)]
	pub rpc_password: Option<String>,
	/// The watch-only wallet posd creates and uses.
	#[serde(default = "default_wallet")]
	pub wallet: String,
}

fn default_wallet() -> String { "posd".into() }

pub struct Chain {
	cfg: BitcoindConfig,
	http: reqwest::Client,
}

impl Chain {
	/// Connects, and creates or loads the watch-only wallet.
	pub async fn connect(cfg: BitcoindConfig) -> anyhow::Result<Chain> {
		let http = reqwest::Client::builder().timeout(Duration::from_secs(30)).build()?;
		let chain = Chain { cfg, http };
		chain.open_wallet().await?;
		Ok(chain)
	}

	async fn open_wallet(&self) -> anyhow::Result<()> {
		let name = self.cfg.wallet.clone();
		let loaded = self.call(None, "listwallets", json!([])).await?;
		if loaded.as_array().is_some_and(|w| w.iter().any(|n| n.as_str() == Some(&name))) {
			return Ok(());
		}
		if self.call(None, "loadwallet", json!([name])).await.is_ok() {
			return Ok(());
		}
		// A blank descriptor wallet without private keys.
		self.call(None, "createwallet", json!([name, true, true, "", false, true, true]))
			.await.context("failed to create the watch-only wallet")?;
		Ok(())
	}

	/// Starts watching an address. Its history starts now.
	pub async fn watch(&self, address: &Address) -> anyhow::Result<()> {
		let desc = format!("addr({})", address);
		let info = self.call(None, "getdescriptorinfo", json!([desc])).await?;
		let desc = info.get("descriptor").and_then(|d| d.as_str())
			.context("getdescriptorinfo returned no descriptor")?;
		let res = self.call(Some(&self.cfg.wallet), "importdescriptors", json!([[{
			"desc": desc,
			"timestamp": "now",
			"label": "",
		}]])).await?;
		let ok = res.get(0).and_then(|r| r.get("success")).and_then(|s| s.as_bool());
		if ok != Some(true) {
			bail!("bitcoind refused to watch {}: {}", address, res);
		}
		Ok(())
	}

	/// The payments to an address. Spends from it do not count: the owner
	/// spending a payment does not undo the sale.
	pub async fn funds(&self, address: &Address) -> anyhow::Result<AddressFunds> {
		let wallet = Some(self.cfg.wallet.as_str());
		let addr = address.to_string();
		let all = self.call(wallet, "getreceivedbyaddress", json!([addr, 0])).await?;
		let confirmed = self.call(wallet, "getreceivedbyaddress", json!([addr, 1])).await?;
		let all = btc_value(&all)?;
		let confirmed = btc_value(&confirmed)?;
		let list = self.call(wallet, "listreceivedbyaddress", json!([0, false, true, addr])).await?;
		let txids = list.get(0).and_then(|e| e.get("txids")).and_then(|t| t.as_array())
			.map(|t| t.iter().filter_map(|x| x.as_str().map(String::from)).collect())
			.unwrap_or_default();
		Ok(AddressFunds {
			confirmed,
			pending: all.checked_sub(confirmed).unwrap_or(Amount::ZERO),
			txids,
		})
	}

	async fn call(&self, wallet: Option<&str>, method: &str, params: Value) -> anyhow::Result<Value> {
		let url = match wallet {
			Some(w) => format!("{}/wallet/{}", self.cfg.url.trim_end_matches('/'), w),
			None => self.cfg.url.clone(),
		};
		let (user, pass) = self.credentials()?;
		let body = json!({ "jsonrpc": "1.0", "id": "posd", "method": method, "params": params });
		let resp = self.http.post(url).basic_auth(user, Some(pass)).json(&body).send().await
			.with_context(|| format!("bitcoind {} request failed", method))?;
		let status = resp.status();
		let resp: Value = resp.json().await
			.with_context(|| format!("bitcoind {} returned {} without JSON", method, status))?;
		if let Some(err) = resp.get("error").filter(|e| !e.is_null()) {
			bail!("bitcoind {} failed: {}", method, err);
		}
		Ok(resp.get("result").cloned().unwrap_or(Value::Null))
	}

	fn credentials(&self) -> anyhow::Result<(String, String)> {
		if let Some(user) = &self.cfg.rpc_user {
			return Ok((user.clone(), self.cfg.rpc_password.clone().unwrap_or_default()));
		}
		let path = self.cfg.cookie.as_ref().context("bitcoind needs rpc_user or a cookie file")?;
		// Read on every call: bitcoind writes a new cookie when it restarts.
		let cookie = std::fs::read_to_string(path)
			.with_context(|| format!("failed to read the bitcoind cookie {}", path.display()))?;
		let (user, pass) = cookie.trim().split_once(':').context("the bitcoind cookie is malformed")?;
		Ok((user.to_string(), pass.to_string()))
	}
}

fn btc_value(v: &Value) -> anyhow::Result<Amount> {
	// bitcoind prints amounts with exactly 8 decimals, so the text form is
	// exact.
	let s = v.to_string();
	Amount::from_str_in(&s, bitcoin::Denomination::Bitcoin)
		.with_context(|| format!("bitcoind returned an invalid amount: {}", s))
}

#[cfg(test)]
mod test {
	use super::*;

	use bitcoin::bip32::{Xpriv, Xpub};
	use bitcoin::secp256k1::Secp256k1;

	#[test]
	fn parses_descriptors() {
		let xpriv = Xpriv::new_master(Network::Regtest, &[7u8; 32]).unwrap();
		let xpub = Xpub::from_priv(&Secp256k1::new(), &xpriv).to_string();
		let desc = StoreDescriptor::parse(&format!("tr({}/0/*)", xpub)).unwrap();
		let a0 = desc.address(0, Network::Regtest).unwrap();
		let a1 = desc.address(1, Network::Regtest).unwrap();
		assert_ne!(a0, a1);
		assert_eq!(a0, desc.address(0, Network::Regtest).unwrap());

		assert!(StoreDescriptor::parse(&format!("tr({}/0/0)", xpub)).is_err(), "not ranged");
		assert!(StoreDescriptor::parse(&format!("tr({}/<0;1>/*)", xpub)).is_err(), "multipath");
		assert!(StoreDescriptor::parse(&format!("tr({}/0/*')", xpub)).is_err(), "hardened");
		assert!(StoreDescriptor::parse("tr(nonsense)").is_err());
	}

	#[test]
	fn reads_btc_values() {
		assert_eq!(btc_value(&json!(0.00035)).unwrap(), Amount::from_sat(35_000));
		assert_eq!(btc_value(&json!(0)).unwrap(), Amount::ZERO);
		assert_eq!(btc_value(&json!(21.12345678)).unwrap(), Amount::from_sat(2_112_345_678));
	}
}

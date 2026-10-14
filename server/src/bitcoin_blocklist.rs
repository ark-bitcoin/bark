

use std::collections::HashSet;
use std::sync::Arc;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

use anyhow::Context;
use bitcoin::{Address, Network, OutPoint, Script, ScriptBuf, Transaction};
use bitcoind_async_client::Client as BitcoindClient;
use futures::StreamExt;
use tokio::io::AsyncBufReadExt;
use tokio_stream::wrappers::LinesStream;
use tracing::{debug, error, info, warn};

use crate::bitcoind as bcd;
use crate::error::ContextExt;
use crate::system::RuntimeManager;


/// the default refresh interval for loading the file from disk is 1 hour
pub const DEFAULT_REFRESH_INTERVAL: Duration = Duration::from_secs(60 * 60);


/// Return type of [BitcoinAddressBlocklist::check_tx]
pub enum AddressBlocklistCheckResult {
	Ok,
	BadInput {
		idx: usize,
		addr: Option<bitcoin::Address>,
	},
	BadOutput {
		idx: usize,
		addr: Option<bitcoin::Address>,
	},
	UnknownInput {
		idx: usize,
		point: OutPoint,
		err: anyhow::Error,
	},
	ChainError(anyhow::Error),
}

impl AddressBlocklistCheckResult {
	/// Whether this is ok
	pub fn is_ok(&self) -> bool {
		matches!(self, Self::Ok)
	}

	/// Convert into an [anyhow::Result] to return to user
	///
	/// Returns badarg error if the tx violates or for unknown inputs
	/// and upstreams regular errors on bitcoind failure.
	pub fn into_user_result(self) -> anyhow::Result<()> {
		match self {
			Self::Ok => Ok(()),
			Self::BadInput { idx, addr } => {
				badarg!("address in input #{} is blocked: {:?}", idx, addr)
			},
			Self::BadOutput { idx, addr } => {
				badarg!("address in output #{} is blocked: {:?}", idx, addr)
			},
			Self::UnknownInput { idx, point, err } => Err(err).with_badarg(|| {
				format!("unknown utxo {} at input #{}", point, idx)
			}),
			Self::ChainError(e) => Err(e)
				.context("bitcoind error while checking address blocklist"),
		}
	}

	/// Returns the violating address, if any violation
	pub fn violating_address(&self) -> Option<&bitcoin::Address> {
		match self {
			Self::Ok => None,
			Self::BadInput { addr, .. } => addr.as_ref(),
			Self::BadOutput { addr, .. } => addr.as_ref(),
			Self::UnknownInput { .. } => None,
			Self::ChainError(_) => None,
		}
	}

	/// Convert into an [anyhow::Result<bool>] that errors only for chainsync and then returns
	/// true if the tx is blocked.
	pub fn is_blocked(self) -> anyhow::Result<bool> {
		match self {
			Self::Ok => Ok(false),
			Self::BadInput { .. } => Ok(true),
			Self::BadOutput { .. } => Ok(true),
			Self::UnknownInput { err, .. } => Err(err).context("unknown input"),
			Self::ChainError(e) => Err(e).context("bitcoind error while checking address blocklist"),
		}
	}
}

/// Result of [BitcoinAddressBlocklist::reload]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlocklistReload {
	pub total: usize,
	pub added: usize,
	pub removed: usize,
}

/// A bitcoin address blocklist with auto-refresh
///
/// Auto-refresh assumes only new addresses will be added, never any removed.
#[derive(Clone)]
pub struct BitcoinAddressBlocklist {
	path: PathBuf,
	network: Network,
	bitcoind: BitcoindClient,
	list: Arc<tokio::sync::RwLock<HashSet<ScriptBuf>>>,
}

impl BitcoinAddressBlocklist {
	/// Create and start auto-refresh of address blocklist
	pub async fn new(
		network: Network,
		bitcoind: BitcoindClient,
		path: impl AsRef<Path>,
	) -> anyhow::Result<Self> {
		let path = path.as_ref().to_path_buf();
		// Load the file a first time to get going
		let list = parse_bitcoin_address_blocklist::<HashSet<_>>(network, &path).await
			.context("error reading list")?;

		Ok(BitcoinAddressBlocklist {
			path, network, bitcoind,
			list: Arc::new(tokio::sync::RwLock::new(list)),
		})
	}

	async fn try_reload(&self) -> anyhow::Result<()> {
		let mut new_list = parse_bitcoin_address_blocklist::<Vec<_>>(self.network, &self.path).await
			.context("error reading list")?;

		// We try to minimize the times and time we need to take the write lock.
		// We will first take the read lock to see if we need to add any items.
		let read_guard = self.list.read().await;
		new_list.retain(|i| !read_guard.contains(i));
		drop(read_guard);

		if new_list.is_empty() {
			return Ok(());
		}

		let mut write_guard = self.list.write().await;
		write_guard.extend(new_list);
		drop(write_guard);
		Ok(())
	}

	/// Re-read the file and replace the list, so removals apply too
	///
	/// Refuses to replace a non-empty list with an empty one.
	pub async fn reload(&self) -> anyhow::Result<BlocklistReload> {
		let new_list = parse_bitcoin_address_blocklist::<HashSet<_>>(self.network, &self.path).await
			.context("error reading list")?;

		let mut list = self.list.write().await;
		if new_list.is_empty() && !list.is_empty() {
			bail!("{} has no valid addresses, keeping the current {}", self.path.display(), list.len());
		}
		let ret = BlocklistReload {
			total: new_list.len(),
			added: new_list.difference(&list).count(),
			removed: list.difference(&new_list).count(),
		};
		*list = new_list;
		drop(list);

		info!("Reloaded bitcoin address blocklist: {} addresses, {} added, {} removed",
			ret.total, ret.added, ret.removed,
		);
		Ok(ret)
	}

	pub fn start_auto_update_thread(
		&self,
		rtmgr: RuntimeManager,
		update_interval: Duration,
	) {
		let list = self.clone();
		tokio::spawn(async move {
			let _guard = rtmgr.spawn("BitcoinAddressBlocklist");

			let mut interval = tokio::time::interval(update_interval);
			interval.reset();
			loop {
				tokio::select! {
					_ = interval.tick() => {},
					_ = rtmgr.shutdown_signal() => {
						info!("Shutdown signal received. Exiting blocklist refresh...");
						return;
					},
				}

				if Arc::strong_count(&list.list) == 1 {
					// we're the only ones left looking at this list
					warn!("Shutting down bitcoin address updating \
						because no one is looking at list");
					return;
				}

				if let Err(e) = list.try_reload().await {
					warn!("Failed to update address blocklist: {:#}", e);
				}
			}
		});
	}

	/// Check if a particular address is in the list (by scriptPubkey)
	pub async fn check_spk(&self, spk: &Script) -> bool {
		self.list.read().await.contains(spk)
	}

	/// Check the bitcoin tx against the blocklist
	///
	/// Both output addresses and input addresses are checked.
	pub async fn check_tx(
		&self,
		tx: &Transaction,
	) -> AddressBlocklistCheckResult {
		let list = self.list.read().await;

		for (idx, outp) in tx.output.iter().enumerate() {
			if list.contains(&outp.script_pubkey) {
				// NB we don't want to pass network until here, address format will be wrong
				// for testnets but I doubt any testnet will care about blocklists
				let addr = Address::from_script(&outp.script_pubkey, self.network).ok();
				return AddressBlocklistCheckResult::BadOutput { idx, addr };
			}
		}

		for (idx, inp) in tx.input.iter().enumerate() {
			let point = inp.previous_output;

			if point.is_null() {
				// coinbase inputs don't exist
				continue;
			}

			let utxo = match bcd::get_raw_txout(&self.bitcoind, point).await {
				Ok(u) => u,
				Err(e) if e.is_retriable() => {
					return AddressBlocklistCheckResult::ChainError(e.into());
				},
				Err(e) => {
					return AddressBlocklistCheckResult::UnknownInput { idx, point, err: e.into() };
				},
			};
			if list.contains(&utxo.script_pubkey) {
				let addr = Address::from_script(&utxo.script_pubkey, self.network).ok();
				return AddressBlocklistCheckResult::BadInput { idx, addr };
			}
		}

		AddressBlocklistCheckResult::Ok
	}
}

/// Parse a bitcoin address blocklist file
///
/// One address per line, returned as a vector of scriptPubkeys.
async fn parse_bitcoin_address_blocklist<T>(
	network: Network,
	path: &Path,
) -> anyhow::Result<T>
where
	T: Default + Extend<ScriptBuf>,
{
	info!("Reading bitcoin address blocklist file at {}...", path.display());
	let file = tokio::fs::File::open(path).await.with_context(|| format!(
		"failed to open bitcoin address blocklist at {}", path.display(),
	))?;

	let reader = tokio::io::BufReader::new(file);
	let mut lines = LinesStream::new(reader.lines()).enumerate();
	let mut ret = T::default();
	let mut nb_lines = 0;
	let mut nb_success = 0;
	while let Some((idx, res)) = lines.next().await {
		let line = res?;
		match bitcoin::Address::from_str(&line)
			.with_context(|| format!("error parsing blocklist address on line {}", idx))
			.and_then(|addr| addr.require_network(network)
				.with_context(|| format!("blocklist address on line {} not valid network", idx))
			)
		{
			Ok(addr) => {
				ret.extend([addr.script_pubkey()]);
				nb_success += 1;
			},
			Err(e) => debug!("Error parsing blocklist address '{}': {:#}", line, e),
		}
		nb_lines += 1;
	}

	if nb_lines > 5 && nb_success == 0 {
		error!("blocklist: non-empty blocklist without any valid address");
	}

	Ok(ret)
}

#[cfg(test)]
mod test {
	use super::*;

	const A: &str = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq";
	const B: &str = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2";
	const C: &str = "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy";

	fn spk(addr: &str) -> ScriptBuf {
		Address::from_str(addr).unwrap().assume_checked().script_pubkey()
	}

	#[tokio::test]
	async fn reload_replaces_list() {
		let path = std::env::temp_dir().join(format!("blocklist-reload-{}.txt", std::process::id()));
		std::fs::write(&path, format!("{A}\n{B}\n")).unwrap();
		let bitcoind = BitcoindClient::new(
			"http://127.0.0.1:1".into(),
			bitcoind_async_client::Auth::UserPass("u".into(), "p".into()),
			None, None, None,
		).unwrap();
		let list = BitcoinAddressBlocklist::new(Network::Bitcoin, bitcoind, &path).await.unwrap();

		std::fs::write(&path, format!("{B}\n{C}\n")).unwrap();
		let r = list.reload().await.unwrap();
		assert_eq!(r, BlocklistReload { total: 2, added: 1, removed: 1 });
		assert!(!list.check_spk(&spk(A)).await);
		assert!(list.check_spk(&spk(B)).await);
		assert!(list.check_spk(&spk(C)).await);

		std::fs::write(&path, "not an address\n").unwrap();
		assert!(list.reload().await.is_err());
		assert!(list.check_spk(&spk(C)).await);

		std::fs::remove_file(&path).unwrap();
	}
}

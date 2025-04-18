
use std::{fmt, ops};
use std::path::PathBuf;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH, Instant};

use anyhow::Context;
use bdk_bitcoind_rpc::bitcoincore_rpc::RpcApi;
use bdk_wallet::{SignOptions, Wallet, Balance, KeychainKind};
use bip39::Mnemonic;
use bitcoin::{bip32, Address, Network};
use bitcoin::{hex::DisplayHex, Psbt, Transaction};
use bitcoin_ext::BlockRef;
use bitcoin_ext::bdk::WalletExt;
use bitcoin_ext::rpc::BitcoinRpcExt;
use log::error;

use crate::database;


/// The location of the mnemonic file in aspd's datadir.
pub const MNEMONIC_FILE: &str = "mnemonic";

/// The BIP32 child index of the rounds wallet.
///
/// Number picked as hash of "rounds" string, see unit test.
pub const BIP32_IDX_ROUNDS: bip32::ChildNumber = bip32::ChildNumber::Hardened { index: 1856555996 };


/// Type to indicate which internal wallet to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalletKind {
	Rounds,
}

impl WalletKind {
	pub fn name(&self) -> &'static str {
		match self {
			Self::Rounds => "rounds",
		}
	}

	pub fn child_number(&self) -> bip32::ChildNumber {
		match self {
			Self::Rounds => BIP32_IDX_ROUNDS,
		}
	}
}

impl fmt::Display for WalletKind {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str(self.name())
	}
}

/// aspd-specific extension trait for the BDK [Wallet] struct.
#[async_trait]
pub trait BdkWalletExt: WalletExt {
	/// Finish the PSBT by signing it and committing it to the wallet.
	///
	/// This method does not persist changes to the databse.
	fn finish_tx(&mut self, mut psbt: Psbt) -> anyhow::Result<Transaction> {
		let opts = SignOptions {
			trust_witness_utxo: true,
			..Default::default()
		};
		let wallet = self.borrow_mut();
		let finalized = wallet.sign(&mut psbt, opts).context("error signing psbt")?;
		ensure!(finalized, "tx not finalized after signing, psbt: {}", psbt.serialize().as_hex());
		Ok(psbt.extract_tx().context("error extracting finalized tx from psbt")?)
	}

	/// Commit the tx into our BDK wallet.
	fn commit_tx(&mut self, tx: &Transaction) {
		let now = SystemTime::now().duration_since(UNIX_EPOCH)
			.expect("Unix epoch is in the past").as_secs();
		self.borrow_mut().apply_unconfirmed_txs([(tx.clone(), now)]);
	}
}
impl BdkWalletExt for Wallet {}

pub struct PersistedWallet {
	wallet: Wallet,
	kind: WalletKind,
	db: database::Db,
}

impl PersistedWallet {
	/// Load a wallet from the database, or create if it doesn't exist yet.
	pub async fn load_from_xpriv(
		db: database::Db,
		network: Network,
		xpriv: &bip32::Xpriv,
		kind: WalletKind,
		deep_tip: BlockRef,
		legacy_wallet: bool,
	) -> anyhow::Result<Self> {
		let init = db.read_aggregate_changeset(kind).await?;
		let fresh = init.is_none();

		let mut wallet = if let Some(changeset) = init {
			if legacy_wallet {
				let desc = format!("tr({}/84'/0'/0'/0/*)", xpriv);
				bdk_wallet::Wallet::load()
					.descriptor(bdk_wallet::KeychainKind::External, Some(desc))
					.check_network(network)
					.extract_keys()
					.load_wallet_no_persist(changeset)
					.context("error loading bdk wallet")?
					.expect("changeset is not empty")
			} else {
				let ext = format!("tr({}/0/*)", xpriv);
				let int = format!("tr({}/1/*)", xpriv);
				bdk_wallet::Wallet::load()
					.descriptor(bdk_wallet::KeychainKind::External, Some(ext))
					.descriptor(bdk_wallet::KeychainKind::Internal, Some(int))
					.check_network(network)
					.extract_keys()
					.load_wallet_no_persist(changeset)
					.context("error loading bdk wallet")?
					.expect("changeset is not empty")
			}
		} else {
			let ext = format!("tr({}/0/*)", xpriv);
			let int = format!("tr({}/1/*)", xpriv);
			bdk_wallet::Wallet::create(ext, int)
				.network(network)
				.create_wallet_no_persist()
				.context("error creating bdk wallet")?
		};

		if fresh {
			wallet.set_checkpoint(deep_tip.height, deep_tip.hash);
			let cs = wallet.take_staged().expect("should have stored tip");
			db.store_changeset(kind, &cs).await.context("error storing initial wallet state")?;
		}

		Ok(Self { wallet, kind, db })
	}

	/// Persist the committed wallet changes to the database.
	pub async fn persist(&mut self) -> anyhow::Result<()> {
		// NB we make sure that we don't erase the changeset if an error happened
		// in the db.
		if let Some(change) = self.wallet.staged() {
			self.db.store_changeset(self.kind, &change).await
				.context("error persisting wallet changes to db")?;
			self.wallet.take_staged();
		}
		Ok(())
	}

	pub async fn sync(&mut self, bitcoind: &impl RpcApi) -> anyhow::Result<Balance> {
		let start_time = Instant::now();

		let prev_tip = self.latest_checkpoint();
		let prev_balance = self.balance();

		slog!(WalletSyncStarting, wallet: self.kind.name().into(), block_height: prev_tip.height());
		let mut emitter = bdk_bitcoind_rpc::Emitter::new(
			bitcoind, prev_tip.clone(), prev_tip.height(),
		);
		while let Some(em) = emitter.next_block()? {
			self.apply_block_connected_to(&em.block, em.block_height(), em.connected_to())?;

			// this is to make sure that during initial sync we don't lose all
			// progress if we halt the process mid-way
			if em.block_height() % 10_000 == 0 {
				slog!(WalletSyncCommittingProgress, wallet: self.kind.name().into(),
					block_height: em.block_height(),
				);
				self.persist().await?;
			}
		}
		self.persist().await?;

		// rebroadcast unconfirmed txs
		// NB during some round failures we commit a tx but fail to broadcast it,
		// so this ensures we still broadcast them afterwards
		for tx in self.transactions() {
			if !tx.chain_position.is_confirmed() {
				if let Err(e) = bitcoind.broadcast_tx(&*tx.tx_node.tx) {
					slog!(WalletTransactionBroadcastFailure, wallet: self.kind.name().into(),
						error: e.to_string(), txid: tx.tx_node.txid,
					);
				}
			}
		}

		let checkpoint = self.latest_checkpoint();
		slog!(WalletSyncComplete, wallet: self.kind.name().into(), sync_time: start_time.elapsed(),
			new_block_height: checkpoint.height(), previous_block_height: prev_tip.height(),
		);

		let balance = self.balance();
		if balance != prev_balance {
			slog!(WalletBalanceUpdated, wallet: self.kind.name().into(), balance: balance.clone(),
				block_height: checkpoint.height(),
			);
		} else {
			slog!(WalletBalanceUnchanged, wallet: self.kind.name().into(), balance: balance.clone(),
				block_height: checkpoint.height(),
			);
		}
		Ok(balance)
	}

	pub async fn status(&mut self) -> aspd_rpc::WalletStatus {
		// NB we decide not to persist the address reveal to make this call
		// infallible even without database.
		let address = self.reveal_next_address(KeychainKind::External).address;
		let (confirmed, unconfirmed) = self.list_unspent()
			.partition::<Vec<_>, _>(|u| u.chain_position.is_confirmed());
		let balance = self.balance();
		aspd_rpc::WalletStatus {
			total_balance: balance.total(),
			trusted_pending_balance: balance.trusted_pending,
			untrusted_pending_balance: balance.untrusted_pending,
			confirmed_balance: balance.confirmed,
			address: address.into_unchecked(),
			confirmed_utxos: confirmed.into_iter().map(|u| u.outpoint).collect(),
			unconfirmed_utxos: unconfirmed.into_iter().map(|u| u.outpoint).collect(),
		}
	}

	/// This function is primarily intended for dev, not prod usage.
	pub async fn drain(
		&mut self,
		address: Address<bitcoin::address::NetworkUnchecked>,
		bitcoind: &impl RpcApi,
	) -> anyhow::Result<Transaction> {
		//TODO(stevenroose) also claim all expired round vtxos here!

		let addr = address.require_network(self.wallet.network())?;

		let mut b = self.build_tx();
		b.drain_to(addr.script_pubkey());
		b.drain_wallet();
		let psbt = b.finish().context("error building tx")?;

		let tx = self.finish_tx(psbt)?;
		self.commit_tx(&tx);
		self.persist().await?;

		if let Err(e) = bitcoind.broadcast_tx(&tx) {
			error!("Error broadcasting tx: {}", e);
			error!("Try yourself: {}", bitcoin::consensus::encode::serialize_hex(&tx));
		}

		Ok(tx)
	}
}

impl ops::Deref for PersistedWallet {
	type Target = Wallet;
	fn deref(&self) -> &Self::Target {
		&self.wallet
	}
}

impl ops::DerefMut for PersistedWallet {
	fn deref_mut(&mut self) -> &mut Self::Target {
		&mut self.wallet
	}
}


pub fn read_mnemonic_from_datadir(data_dir: &PathBuf) -> anyhow::Result<Mnemonic> {
	let mnemonic = std::fs::read_to_string(data_dir.join(MNEMONIC_FILE))
		.context("failed to read mnemonic")?;
	Ok(Mnemonic::from_str(&mnemonic)?)
}

#[cfg(test)]
mod test {
	use super::*;
	use bitcoin::bip32;
	use bitcoin::hashes::{sha256, siphash24, Hash};

	#[test]
	fn bip32_indices() {
		const MASK_U31: u64 = 0x7FFF_FFFF;

		let rounds = {
			let sha = sha256::Hash::hash("rounds".as_bytes());
			let sip = siphash24::Hash::hash(&sha[..]);
			let idx = (sip.as_u64() & MASK_U31) as u32;
			bip32::ChildNumber::from_hardened_idx(idx).expect("31 bit mask")
		};
		assert_eq!(rounds, BIP32_IDX_ROUNDS);
	}
}

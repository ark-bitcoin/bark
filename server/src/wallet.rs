
use std::collections::HashSet;
use std::sync::Arc;
use std::{fmt, ops};
use std::path::Path;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH, Instant};

use anyhow::Context;
use bdk_wallet::{Balance, Wallet};
use bip39::Mnemonic;
use bitcoin::{bip32, Address, Amount, FeeRate, Network, OutPoint, ScriptBuf};
use bitcoin::{hex::DisplayHex, Psbt, Transaction};
use tracing::{error, trace};

use bitcoin_ext::{BlockHeight, BlockRef};
use bitcoin_ext::bdk::{WalletExt, KEYCHAIN};
use bitcoin_ext::rpc::{BitcoinRpcExt, RpcApi};

use crate::{database, telemetry, SECP};


/// The location of the mnemonic file in server's datadir.
pub const MNEMONIC_FILE: &str = "mnemonic";

/// The BIP32 child index of the rounds wallet.
///
/// Number picked as hash of "rounds" string, see unit test.
pub const BIP32_IDX_ROUNDS: bip32::ChildNumber =
	bip32::ChildNumber::Hardened { index: 1856555996 };

/// The BIP32 child index of the Watchman wallet.
///
/// Number picked as hash of "watchman" string, see unit test.
pub const BIP32_IDX_WATCHMAN: bip32::ChildNumber =
	bip32::ChildNumber::Hardened { index: 38644432 };


/// Type to indicate which internal wallet to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalletKind {
	/// For the round scheduler
	Rounds,
	/// For the watchman
	Watchman,
}

impl WalletKind {
	pub fn name(&self) -> &'static str {
		match self {
			Self::Rounds => "rounds",
			Self::Watchman => "watchman",
		}
	}

	pub fn child_number(&self) -> bip32::ChildNumber {
		match self {
			Self::Rounds => BIP32_IDX_ROUNDS,
			Self::Watchman => BIP32_IDX_WATCHMAN,
		}
	}
}

impl fmt::Display for WalletKind {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str(self.name())
	}
}

/// server-specific extension trait for the BDK [Wallet] struct.
#[async_trait]
pub trait BdkWalletExt: WalletExt {
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
	locked_outputs: LockedWalletUtxosIndex,
}

impl PersistedWallet {
	/// Load a wallet from the database, or create if it doesn't exist yet.
	pub async fn load_from_xpriv(
		db: database::Db,
		network: Network,
		xpriv: &bip32::Xpriv,
		kind: WalletKind,
		deep_tip: BlockRef,
	) -> anyhow::Result<Self> {
		let init = db.read_aggregate_changeset(kind).await?;
		let fresh = init.is_none();

		let desc = format!("tr({}/0/*)", xpriv);
		let mut wallet = if let Some(changeset) = init {
			bdk_wallet::Wallet::load()
				.descriptor(KEYCHAIN, Some(desc))
				.check_network(network)
				.extract_keys()
				.load_wallet_no_persist(changeset)
				.context("error loading bdk wallet")?
				.expect("changeset is not empty")
		} else {
			bdk_wallet::Wallet::create_single(desc)
				.network(network)
				.create_wallet_no_persist()
				.context("error creating bdk wallet")?
		};

		if fresh {
			wallet.set_checkpoint(deep_tip.height, deep_tip.hash);
			let cs = wallet.take_staged().expect("should have stored tip");
			db.store_changeset(kind, &cs).await.context("error storing initial wallet state")?;
		}

		Ok(Self { wallet, kind, db, locked_outputs: LockedWalletUtxosIndex::new() })
	}

	/// Load a wallet from the database, deriving the wallet's xpriv using the master xpriv
	/// and the wallet kind
	pub async fn load_derive_from_master_xpriv(
		db: database::Db,
		network: Network,
		master_xpriv: &bip32::Xpriv,
		kind: WalletKind,
		deep_tip: BlockRef,
	) -> anyhow::Result<Self> {
		let wallet_xpriv = master_xpriv.derive_priv(&*SECP, &[kind.child_number()])
			.expect("can't error");
		Self::load_from_xpriv(db, network, &wallet_xpriv, kind, deep_tip).await
	}

	/// Persist the committed wallet changes to the database.
	#[tracing::instrument(skip(self))]
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

	#[tracing::instrument(skip(self, bitcoind), fields(wallet = self.kind.name().to_string()))]
	pub async fn sync(
		&mut self,
		bitcoind: &impl RpcApi,
		mempool: bool,
	) -> anyhow::Result<Balance> {
		let start_time = Instant::now();

		let prev_tip = self.latest_checkpoint();
		let prev_balance = self.balance();

		slog!(WalletSyncStarting, wallet: self.kind.name().into(), block_height: prev_tip.height());
		let mut emitter = bdk_bitcoind_rpc::Emitter::new(
			bitcoind, prev_tip.clone(), prev_tip.height(), self.wallet.unconfirmed_txs(),
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

		if mempool {
			let mempool = emitter.mempool()?;
			trace!("Syncing {} new mempool txs and {} evicted mempool txs...",
				mempool.update.len(), mempool.evicted.len(),
			);
			self.apply_evicted_txs(mempool.evicted);
			self.apply_unconfirmed_txs(mempool.update);
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
			next_address: self.peek_next_address().address.into_unchecked(),
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

		telemetry::set_wallet_balance(self.kind, balance.clone());

		Ok(balance)
	}

	pub fn status(&mut self) -> server_rpc::WalletStatus {
		// NB we decide not to persist the address reveal to make this call
		// infallible even without database.
		let address = self.reveal_next_address(KEYCHAIN).address;
		let (confirmed, unconfirmed) = self.list_unspent()
			.partition::<Vec<_>, _>(|u| u.chain_position.is_confirmed());
		let balance = self.balance();
		server_rpc::WalletStatus {
			total_balance: balance.total(),
			trusted_pending_balance: balance.trusted_pending,
			untrusted_pending_balance: balance.untrusted_pending,
			confirmed_balance: balance.confirmed,
			address: address.into_unchecked(),
			confirmed_utxos: confirmed.into_iter().map(|u| u.outpoint).collect(),
			unconfirmed_utxos: unconfirmed.into_iter().map(|u| u.outpoint).collect(),
		}
	}

	/// Finish the PSBT by signing it and committing it to the wallet.
	///
	/// This method does not persist changes to the database.
	pub fn finish_tx(&mut self, mut psbt: Psbt) -> anyhow::Result<Transaction> {
		#[allow(deprecated)]
		let opts = bdk_wallet::SignOptions {
			trust_witness_utxo: true,
			..Default::default()
		};
		let fee = psbt.fee().context("error calculating fee")?;
		let finalized = self.sign(&mut psbt, opts).context("error signing psbt")?;
		ensure!(finalized, "tx not finalized after signing, psbt: {}", psbt.serialize().as_hex());
		let ret = psbt.extract_tx().context("error extracting finalized tx from psbt")?;
		let txid = ret.compute_txid();
		let raw_tx = bitcoin::consensus::serialize(&ret);
		slog!(WalletSignedTx, wallet: self.kind.name().into(), txid, fee, raw_tx,
			inputs: ret.input.iter().map(|i| i.previous_output).collect(),
		);
		Ok(ret)
	}


	/// Send money to an address.
	#[tracing::instrument(skip(self, script_pubkey))]
	pub async fn send(
		&mut self,
		script_pubkey: impl Into<ScriptBuf>,
		amount: Amount,
		fee_rate: FeeRate,
	) -> anyhow::Result<Transaction> {
		let unavailable = self.unavailable_outputs(None);
		let mut b = self.build_tx();
		b.unspendable(unavailable);
		b.add_recipient(script_pubkey, amount);
		b.fee_rate(fee_rate);
		let psbt = b.finish()?;
		let tx = self.finish_tx(psbt)?;
		self.commit_tx(&tx);
		self.persist().await?;
		Ok(tx)
	}

	/// This function is primarily intended for dev, not prod usage.
	#[tracing::instrument(skip(self, address, bitcoind))]
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

	pub fn unavailable_outputs(&self, confirmed_height: Option<BlockHeight>) -> Vec<OutPoint> {
		self.untrusted_utxos(confirmed_height).into_iter()
			.chain(self.locked_outputs.utxos())
			.collect::<Vec<_>>()
	}

	pub fn lock_wallet_utxo(
		&self,
		utxo: OutPoint,
	) -> Result<WalletUtxoGuard, UtxoAlreadyLockedError> {
		WalletUtxoGuard::new(self.locked_outputs.clone(), utxo)
	}

	pub fn lock_wallet_utxos(
		&self,
		utxos: impl IntoIterator<Item = OutPoint>,
	) -> Result<WalletUtxosGuard, UtxoAlreadyLockedError> {
		WalletUtxosGuard::new(self.locked_outputs.clone(), utxos)
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


pub fn read_mnemonic_from_datadir(data_dir: &Path) -> anyhow::Result<Mnemonic> {
	let mnemonic = std::fs::read_to_string(data_dir.join(MNEMONIC_FILE))
		.context("failed to read mnemonic")?;
	Ok(Mnemonic::from_str(&mnemonic)?)
}

/// An index of all locked utxos in the wallet, with a mutex over it.
#[derive(Debug, Clone)]
pub struct LockedWalletUtxosIndex(Arc<parking_lot::Mutex<HashSet<OutPoint>>>);

impl LockedWalletUtxosIndex {
	pub fn new() -> Self {
		Self(Arc::new(parking_lot::Mutex::new(HashSet::new())))
	}

	pub fn utxos(&self) -> HashSet<OutPoint> {
		self.0.lock().clone()
	}
}

#[derive(Debug, Clone, thiserror::Error)]
#[error("utxo already locked: {0}")]
pub struct UtxoAlreadyLockedError(pub OutPoint);

/// A guard over a utxo in the wallet to keep it locked during guard
/// lifetime.
///
/// Creating a guard will add the utxo to the locked index, and dropping
/// the guard will remove it from the index.
#[derive(Debug, Clone)]
pub struct WalletUtxoGuard {
	index: LockedWalletUtxosIndex,
	utxo: OutPoint,
}

impl WalletUtxoGuard {
	fn new(index: LockedWalletUtxosIndex, utxo: OutPoint) -> Result<Self, UtxoAlreadyLockedError> {
		let mut index_lock = index.0.lock();
		let inserted = index_lock.insert(utxo);
		drop(index_lock);
		if inserted {
			Ok(Self { index, utxo })
		} else {
			Err(UtxoAlreadyLockedError(utxo))
		}
	}

	pub fn utxo(&self) -> OutPoint {
		self.utxo.clone()
	}
}

impl ops::Drop for WalletUtxoGuard {
	fn drop(&mut self) {
		let mut index_lock = self.index.0.lock();
		index_lock.remove(&self.utxo);
	}
}

/// A guard over a set of utxos in the wallet to keep them locked during guard
/// lifetime.
///
/// Creating a guard will add the utxos to the locked index, and dropping
/// the guard will remove them from the index.
#[derive(Debug, Clone)]
pub struct WalletUtxosGuard {
	index: LockedWalletUtxosIndex,
	utxos: Vec<OutPoint>,
}

impl WalletUtxosGuard {
	fn new(
		index: LockedWalletUtxosIndex,
		utxos: impl IntoIterator<Item = OutPoint>,
	) -> Result<Self, UtxoAlreadyLockedError> {
		let utxos = utxos.into_iter().collect::<Vec<_>>();
		let mut index_lock = index.0.lock();
		for (idx, utxo) in utxos.iter().copied().enumerate() {
			if !index_lock.insert(utxo) {
				// also remove the ones we just added
				for remove_utxo in utxos.iter().take(idx) {
					assert!(index_lock.remove(remove_utxo), "just added");
				}
				return Err(UtxoAlreadyLockedError(utxo))
			}
		}
		drop(index_lock);
		Ok(Self { index, utxos })
	}

	pub fn utxos(&self) -> &[OutPoint] {
		&self.utxos
	}
}

impl ops::Drop for WalletUtxosGuard {
	fn drop(&mut self) {
		let mut index_lock = self.index.0.lock();
		for utxo in &self.utxos {
			index_lock.remove(utxo);
		}
	}
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
		assert_eq!(rounds, WalletKind::Rounds.child_number());

		let watchman = {
			let sha = sha256::Hash::hash("watchman".as_bytes());
			let sip = siphash24::Hash::hash(&sha[..]);
			let idx = (sip.as_u64() & MASK_U31) as u32;
			bip32::ChildNumber::from_hardened_idx(idx).expect("31 bit mask")
		};
		assert_eq!(watchman, BIP32_IDX_WATCHMAN);
		assert_eq!(watchman, WalletKind::Watchman.child_number());
	}

	#[test]
	fn wallet_utxo_guard_double_lock() {
		let index = LockedWalletUtxosIndex::new();
		let utxo = OutPoint::new(
			bitcoin::Txid::from_byte_array([0u8; 32]),
			0,
		);

		// First lock should succeed
		let guard1 = WalletUtxoGuard::new(index.clone(), utxo);
		assert!(guard1.is_ok());

		// Second lock of same UTXO should fail
		let guard2 = WalletUtxoGuard::new(index.clone(), utxo);
		assert!(guard2.is_err());

		// After dropping first guard, locking should succeed again
		drop(guard1);
		let guard3 = WalletUtxoGuard::new(index.clone(), utxo);
		assert!(guard3.is_ok());
	}
}

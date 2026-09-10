pub mod sync;

use std::collections::HashSet;
use std::sync::Arc;
use std::{fmt, ops};
use std::path::Path;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context};
use bdk_wallet::{TxBuilder, Wallet};
use bdk_wallet::coin_selection::CoinSelectionAlgorithm;
use bip39::Mnemonic;
use bitcoin::{
	bip32, Address, Amount, FeeRate, Network, OutPoint, Psbt, Transaction, Weight,
};
use bitcoin::hex::DisplayHex;
use bitcoind_async_client::Client as BitcoindClient;
use tracing::{error, warn};

use bitcoin_ext::BlockRef;
use bitcoin_ext::bdk::{TrustedBalance, TrustedCanonicalization, WalletExt, KEYCHAIN};

use crate::bitcoin_blocklist::BitcoinAddressBlocklist;
use crate::bitcoind as bcd;
use crate::utils::{InstrumentedLock, InstrumentedOwnedLockGuard};
use crate::{database, fs_perms, SECP};


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

/// Maximum number of build attempts
/// [PersistedWallet::build_tx_at_chunk_feerate] makes before it fails.
const MAX_FEE_BUMP_ATTEMPTS: usize = 10;


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
	bitcoind: BitcoindClient,
	locked_outputs: LockedWalletUtxosIndex,
	min_trusted_confs: u32,
	address_blocklist: Option<BitcoinAddressBlocklist>,
}

impl PersistedWallet {
	/// Load a wallet from the database, or create if it doesn't exist yet.
	pub async fn load_from_xpriv(
		db: database::Db,
		bitcoind: BitcoindClient,
		network: Network,
		xpriv: &bip32::Xpriv,
		kind: WalletKind,
		deep_tip: BlockRef,
		min_trusted_confs: u32,
	) -> anyhow::Result<Self> {
		let init = db.read(async |tx| { tx.read_aggregate_changeset(kind).await }).await?;
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
			db.write(async |tx| { tx.store_changeset(kind, &cs).await }).await.context("error storing initial wallet state")?;
		}

		Ok(Self {
			wallet, kind, db, bitcoind, min_trusted_confs,
			locked_outputs: LockedWalletUtxosIndex::new(),
			address_blocklist: None,
		})
	}

	/// Load a wallet from the database, deriving the wallet's xpriv using the master xpriv
	/// and the wallet kind
	pub async fn load_derive_from_master_xpriv(
		db: database::Db,
		bitcoind: BitcoindClient,
		network: Network,
		master_xpriv: &bip32::Xpriv,
		kind: WalletKind,
		deep_tip: BlockRef,
		min_trusted_confs: u32,
	) -> anyhow::Result<Self> {
		let wallet_xpriv = master_xpriv.derive_priv(&*SECP, &[kind.child_number()])
			.expect("can't error");
		Self::load_from_xpriv(db, bitcoind, network, &wallet_xpriv, kind, deep_tip, min_trusted_confs).await
	}

	/// Set the address blocklist for this wallet
	pub fn set_address_blocklist(&mut self, blocklist: BitcoinAddressBlocklist) {
		self.address_blocklist = Some(blocklist);
	}

	/// Persist the committed wallet changes to the database.
	#[tracing::instrument(skip(self))]
	pub async fn persist(&mut self) -> anyhow::Result<()> {
		// NB we make sure that we don't erase the changeset if an error happened
		// in the db.
		if let Some(change) = self.wallet.staged() {
			self.db.write(async |t| t.store_changeset(self.kind, &change).await).await
				.context("error persisting wallet changes to db")?;
			self.wallet.take_staged();
		}
		Ok(())
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
			trusted_balance: balance.trusted,
			untrusted_balance: balance.untrusted,
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


	/// This function is primarily intended for dev, not prod usage.
	#[tracing::instrument(skip(self, address))]
	pub async fn drain(
		&mut self,
		address: Address<bitcoin::address::NetworkUnchecked>,
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

		if let Err(e) = bcd::broadcast_tx(&self.bitcoind, &tx).await {
			error!("Error broadcasting tx: {}", e);
			error!("Try yourself: {}", bitcoin::consensus::encode::serialize_hex(&tx));
		}

		Ok(tx)
	}

	/// The outputs a new tx must not spend: untrusted or locked.
	fn unspendable_outputs(&self, canon: &TrustedCanonicalization) -> Vec<OutPoint> {
		canon.list_unspent()
			.filter(|utxo| !utxo.is_trusted)
			.map(|utxo| utxo.outpoint)
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

	/// Get the wallet kind.
	pub fn kind(&self) -> WalletKind {
		self.kind
	}

	/// Compute the wallet balance using our recursive trust model.
	pub fn balance(&self) -> TrustedBalance {
		self.wallet.trusted_balance(self.min_trusted_confs)
	}

	/// Check if the wallet has at least the given amount of trusted funds.
	pub fn has_trusted_balance(&self, amount: Amount) -> bool {
		self.balance().trusted >= amount
	}

	/// Build a tx that pays `target` for itself and adds what its
	/// unconfirmed ancestors lack to pay `target`, so the mempool chunk
	/// it is mined in pays `target` too.
	///
	/// Coin selection skips untrusted and locked outputs. `configure`
	/// sets everything on the builder except the fee.
	pub fn build_tx_at_chunk_feerate<Cs: CoinSelectionAlgorithm + Clone>(
		&mut self,
		coin_selection: Cs,
		target: FeeRate,
		configure: impl Fn(&mut TxBuilder<'_, Cs>) -> anyhow::Result<()>,
	) -> anyhow::Result<Psbt> {
		let canon = TrustedCanonicalization::from_wallet(&self.wallet, self.min_trusted_confs);
		let unspendable = self.unspendable_outputs(&canon);
		let (psbt, ancestors) = build_at_chunk_feerate(
			&mut self.wallet, &canon, coin_selection, target, &unspendable, configure,
		)?;
		if ancestors.shortfall > Amount::ZERO {
			slog!(WalletBumpedAncestors, wallet: self.kind.name().into(),
				txid: psbt.unsigned_tx.compute_txid(),
				fee: psbt.fee().context("fee of freshly built psbt")?,
				ancestors: ancestors.count, shortfall: ancestors.shortfall,
			);
		}
		Ok(psbt)
	}
}

impl InstrumentedLock<PersistedWallet> {
	/// Take the wallet lock and run `build` on the blocking pool, then
	/// hand both the lock and the result back. bdk's coin selection
	/// blocks the thread it runs on, so a tx must never be built on an
	/// async worker.
	///
	/// The lock is held for the whole build. Drop the returned guard as
	/// soon as the caller is done with the wallet.
	pub async fn build_blocking<T: Send + 'static>(
		&self,
		build: impl FnOnce(&mut PersistedWallet) -> anyhow::Result<T> + Send + 'static,
	) -> anyhow::Result<(InstrumentedOwnedLockGuard<PersistedWallet>, T)> {
		let mut wallet = self.lock_owned().await;
		// The guard is returned with the result, so a failed build still
		// hands the lock back to the caller.
		let (wallet, built) = tokio::task::spawn_blocking(move || {
			let built = build(&mut wallet);
			(wallet, built)
		}).await.context("wallet build task panicked")?;
		Ok((wallet, built?))
	}
}

/// What the unconfirmed ancestors of a tx add to its fee at a target
/// feerate. See [build_at_chunk_feerate].
#[derive(Debug)]
struct AncestorSet {
	/// Total amount the ancestors lack to pay the target feerate.
	shortfall: Amount,
	/// Number of unconfirmed ancestors.
	count: usize,
}

/// The unconfirmed ancestors of `tx` in `canon`, with the total amount
/// they lack to pay `target`.
fn unconfirmed_ancestor_set(
	wallet: &Wallet,
	canon: &TrustedCanonicalization,
	tx: &Transaction,
	target: FeeRate,
) -> AncestorSet {
	// The walk stops at a confirmed ancestor and at one the canonical
	// view does not hold. Every input we spend is canonical and a
	// canonical tx has only canonical ancestors, so the second case is
	// defensive. bdk visits an ancestor of two inputs once.
	let unconfirmed = wallet.tx_graph().walk_ancestors(tx.clone(), |_depth, ancestor| {
		let txid = ancestor.compute_txid();
		match canon.get(txid) {
			Some(entry) if !entry.chain_position.is_confirmed() => Some((txid, ancestor)),
			_ => None,
		}
	});

	let mut ancestors = AncestorSet { shortfall: Amount::ZERO, count: 0 };
	for (txid, ancestor) in unconfirmed {
		ancestors.count += 1;
		// The wallet cannot compute the fee of a tx whose inputs it does
		// not know. Only a pinned input reaches such a tx.
		let fee = wallet.calculate_fee(&ancestor).unwrap_or_else(|e| {
			warn!("Unconfirmed ancestor {} spends outputs this wallet does not know ({}); \
				paying its whole fee at the target", txid, e,
			);
			Amount::ZERO
		});
		let owed = ancestor.weight() * target;
		ancestors.shortfall += owed.checked_sub(fee).unwrap_or(Amount::ZERO);
	}
	ancestors
}

/// Build a tx that pays `target` for itself and adds what each of its
/// unconfirmed ancestors lacks to pay `target`. An ancestor that pays
/// more than `target` adds nothing, because bitcoind mines it in a
/// chunk of its own. Every set of txs that contains the new tx then
/// pays at least `target`, and so does the chunk it is mined in.
///
/// `canon` must come from [TrustedCanonicalization::from_wallet] on
/// `wallet`. Every attempt runs `configure` again and keeps the inputs
/// of the attempt before it, so the ancestor set only grows. The build
/// fails when the wallet cannot pay the fee, or after
/// [MAX_FEE_BUMP_ATTEMPTS] attempts.
fn build_at_chunk_feerate<Cs: CoinSelectionAlgorithm + Clone>(
	wallet: &mut Wallet,
	canon: &TrustedCanonicalization,
	coin_selection: Cs,
	target: FeeRate,
	unspendable: &[OutPoint],
	configure: impl Fn(&mut TxBuilder<'_, Cs>) -> anyhow::Result<()>,
) -> anyhow::Result<(Psbt, AncestorSet)> {
	// The signed weight is the unsigned weight, plus the satisfaction
	// weight of each input, plus the segwit marker and flag. All inputs
	// are ours. This is exact for `tr(key)`: miniscript assumes a
	// 65-byte signature and omits the witness count byte, and the two
	// errors cancel for a 64-byte signature.
	let satisfaction_weight = wallet.public_descriptor(KEYCHAIN)
		.max_weight_to_satisfy()
		.context("failed to compute the descriptor satisfaction weight")?;
	let est_signed_weight = |psbt: &Psbt| {
		psbt.unsigned_tx.weight()
			+ satisfaction_weight * psbt.unsigned_tx.input.len() as u64
			+ Weight::from_wu(2)
	};

	// The first attempt pays the target rate for the tx alone; every
	// later one pays the absolute fee the previous attempt fell
	// short of, spending at least the same inputs.
	let mut fee_needed: Option<Amount> = None;
	let mut carried_inputs = Vec::<OutPoint>::new();
	let mut last_attempt = None;
	for attempt in 1..=MAX_FEE_BUMP_ATTEMPTS {
		let psbt = {
			let mut b = wallet.build_tx().coin_selection(coin_selection.clone());
			b.unspendable(unspendable.to_vec());
			configure(&mut b)?;
			// `add_utxos` bypasses `unspendable`, but every carried input
			// either passed it on the previous attempt or `configure`
			// added it by hand.
			if !carried_inputs.is_empty() {
				b.add_utxos(&carried_inputs)
					.context("previous attempt's inputs are no longer in the wallet")?;
			}
			match fee_needed {
				None => b.fee_rate(target),
				Some(fee) => b.fee_absolute(fee),
			};
			b.finish().with_context(|| match fee_needed {
				None => format!("attempt {} at {:#}", attempt, target),
				Some(fee) => format!("attempt {} at an absolute fee of {}", attempt, fee),
			})?
		};
		let tx_weight = est_signed_weight(&psbt);
		let ancestors = unconfirmed_ancestor_set(wallet, canon, &psbt.unsigned_tx, target);
		let needed = tx_weight * target + ancestors.shortfall;
		let fee = psbt.fee();
		if fee.as_ref().map_or(false, |fee| *fee >= needed) {
			return Ok((psbt, ancestors));
		}

		// Give back the change index bdk revealed for the discarded psbt.
		// Otherwise every attempt wastes an address.
		wallet.mark_output_keys_unused(&psbt.unsigned_tx);

		let fee = fee.context("fee of freshly built psbt")?;
		// Inputs only accumulate, so the tx's weight and its ancestor set
		// both grow and `needed` never falls. The `max` guards against
		// that reasoning being wrong; no build needs it today.
		fee_needed = Some(fee_needed.map_or(needed, |f| f.max(needed)));
		carried_inputs = psbt.unsigned_tx.input.iter()
			.map(|i| i.previous_output)
			.collect();
		last_attempt = Some((fee, needed, ancestors));
	}
	let (fee, needed, ancestors) = last_attempt.expect("at least one attempt ran");
	bail!("fee did not converge at {:#} after {} attempts: the last paid {} \
		where it and its {} unconfirmed ancestors needed {}",
		target, MAX_FEE_BUMP_ATTEMPTS, fee, ancestors.count, needed,
	);
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
	let path = data_dir.join(MNEMONIC_FILE);
	fs_perms::warn_if_loose(data_dir, 0o700);
	fs_perms::warn_if_loose(&path, 0o600);
	let mnemonic = std::fs::read_to_string(&path)
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
#[derive(Debug)]
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
		assert!(index_lock.remove(&self.utxo),
			"WalletUtxoGuard already unlocked; utxo={}", self.utxo,
		);
	}
}

/// A guard over a set of utxos in the wallet to keep them locked during guard
/// lifetime.
///
/// Creating a guard will add the utxos to the locked index, and dropping
/// the guard will remove them from the index.
#[derive(Debug)]
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
			assert!(index_lock.remove(utxo), "WalletUtxosGuard already unlocked; utxo={}", utxo);
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

#[cfg(test)]
mod builder_test {
	use super::*;

	use ark::rounds::ROUND_TX_VTXO_TREE_VOUT;
	use bdk_wallet::chain::BlockId;
	use bdk_wallet::coin_selection::{DefaultCoinSelectionAlgorithm, SingleRandomDraw};
	use bdk_wallet::test_utils::{
		get_test_tr_single_sig_xprv, insert_checkpoint, insert_tx, receive_output_in_latest_block,
	};
	use bitcoin::{BlockHash, ScriptBuf, Txid};
	use bitcoin::hashes::Hash;

	use bitcoin_ext::bdk::{PreferConfirmedCoinSelection, WithGuaranteedChange};

	/// An in-memory taproot wallet holding the specified confirmed coins.
	fn wallet_with_coins(coins: &[Amount]) -> (Wallet, Vec<OutPoint>) {
		let mut wallet = Wallet::create_single(get_test_tr_single_sig_xprv())
			.network(Network::Regtest)
			.create_wallet_no_persist()
			.unwrap();
		insert_checkpoint(&mut wallet, BlockId { height: 1_000, hash: BlockHash::all_zeros() });
		let coins = coins.iter()
			.map(|value| receive_output_in_latest_block(&mut wallet, *value))
			.collect();
		(wallet, coins)
	}

	fn sign(wallet: &mut Wallet, mut psbt: Psbt) -> Transaction {
		#[allow(deprecated)]
		let opts = bdk_wallet::SignOptions { trust_witness_utxo: true, ..Default::default() };
		assert!(wallet.sign(&mut psbt, opts).unwrap());
		psbt.extract_tx().unwrap()
	}

	/// Spend exactly `inputs` into `outputs` fresh wallet addresses of
	/// `value` each plus change, at `fee_rate`, and record the signed tx
	/// as unconfirmed. Returns the tx.
	fn spend_to_self(
		wallet: &mut Wallet,
		inputs: &[OutPoint],
		outputs: usize,
		value: Amount,
		fee_rate: FeeRate,
	) -> Transaction {
		let scripts = (0..outputs)
			.map(|_| wallet.reveal_next_address(KEYCHAIN).address.script_pubkey())
			.collect::<Vec<_>>();
		let mut b = wallet.build_tx().coin_selection(WithGuaranteedChange(SingleRandomDraw));
		b.add_utxos(inputs).unwrap();
		b.manually_selected_only();
		for spk in scripts {
			b.add_recipient(spk, value);
		}
		b.fee_rate(fee_rate);
		let psbt = b.finish().unwrap();
		let tx = sign(wallet, psbt);
		insert_tx(wallet, tx.clone());
		tx
	}

	/// Drain `input` into one fresh wallet address at `fee_rate` and
	/// record the signed tx as unconfirmed. Returns the tx.
	fn drain_to_self(wallet: &mut Wallet, input: OutPoint, fee_rate: FeeRate) -> Transaction {
		let spk = wallet.reveal_next_address(KEYCHAIN).address.script_pubkey();
		let mut b = wallet.build_tx();
		b.add_utxo(input).unwrap();
		b.manually_selected_only();
		b.drain_to(spk);
		b.fee_rate(fee_rate);
		let psbt = b.finish().unwrap();
		let tx = sign(wallet, psbt);
		insert_tx(wallet, tx.clone());
		tx
	}

	/// A script that is not ours, so a recipient output is never confused
	/// with the change output.
	fn foreign_spk(seed: u8) -> ScriptBuf {
		ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::from_byte_array([seed; 20]))
	}

	fn sat_per_vb(rate: u64) -> FeeRate {
		FeeRate::from_sat_per_vb(rate).unwrap()
	}

	#[test]
	fn build_bumps_a_low_fee_parent_to_the_target_rate() {
		let (mut wallet, coins) = wallet_with_coins(&[Amount::from_btc(1.0).unwrap()]);
		// The parent pays 2 sat/vB and is the only thing left to spend.
		let parent = spend_to_self(&mut wallet, &coins, 1, Amount::from_sat(50_000_000), sat_per_vb(2));
		let target = sat_per_vb(20);

		// Foreign, so the change output is the only one that is ours.
		let recipient = foreign_spk(1);
		let canon = TrustedCanonicalization::from_wallet(&wallet, 1);
		// The change address the first attempt reveals. A discarded attempt
		// must give it back. Otherwise every retry wastes one.
		let change_spk = wallet.next_unused_address(KEYCHAIN).address.script_pubkey();
		let input = OutPoint::new(parent.compute_txid(), 0);
		let (psbt, _) = build_at_chunk_feerate(
			&mut wallet, &canon, WithGuaranteedChange(SingleRandomDraw), target, &[], |b| {
				b.add_utxo(input).unwrap();
				b.manually_selected_only();
				b.add_recipient(recipient.clone(), Amount::from_sat(10_000_000));
				Ok(())
			},
		).unwrap();
		assert!(psbt.unsigned_tx.output.iter().any(|o| o.script_pubkey == change_spk),
			"the retry must reuse the change address the discarded attempt revealed",
		);
		let child_fee = psbt.fee().unwrap();
		let child = sign(&mut wallet, psbt);

		let chunk_weight = child.weight() + parent.weight();
		let chunk_fee = child_fee + wallet.calculate_fee(&parent).unwrap();
		assert!(chunk_fee >= chunk_weight * target,
			"chunk pays {} for {} at a {:#} target", chunk_fee, chunk_weight, target,
		);
		// Only the parent's shortfall was added: a few sats of rounding at most.
		assert!(chunk_fee <= chunk_weight * target + Amount::from_sat(100),
			"chunk overpays: {} for {}", chunk_fee, chunk_weight,
		);
		// The child alone paid over the target rate, so a retry raised it.
		assert!(child_fee > child.weight() * target);
	}

	/// A tx that spends two children of the same parent pays for that
	/// parent once. The dedup is bdk's: TxAncestors keeps a visited set
	/// that its docs do not promise, so this test pins the behaviour we
	/// rely on. Without it, a bdk bump that walks a shared ancestor
	/// twice would double count the shortfall and silently overpay.
	#[test]
	fn ancestor_set_counts_a_shared_ancestor_once() {
		let (mut wallet, coins) = wallet_with_coins(&[Amount::from_btc(1.0).unwrap()]);
		let rate = sat_per_vb(2);
		// A diamond: b and c both spend a, the new tx spends both.
		let a = spend_to_self(&mut wallet, &coins, 2, Amount::from_sat(10_000_000), rate);
		let a_id = a.compute_txid();
		let b = spend_to_self(&mut wallet, &[OutPoint::new(a_id, 0)], 1, Amount::from_sat(1_000_000), rate);
		let c = spend_to_self(&mut wallet, &[OutPoint::new(a_id, 1)], 1, Amount::from_sat(1_000_000), rate);
		let inputs = [OutPoint::new(b.compute_txid(), 0), OutPoint::new(c.compute_txid(), 0)];

		let mut builder = wallet.build_tx();
		builder.add_utxos(&inputs).unwrap();
		builder.manually_selected_only();
		builder.drain_to(ScriptBuf::new());
		let psbt = builder.finish().unwrap();

		let target = sat_per_vb(20);
		let canon = TrustedCanonicalization::from_wallet(&wallet, 1);
		let ancestors = unconfirmed_ancestor_set(&wallet, &canon, &psbt.unsigned_tx, target);
		assert_eq!(ancestors.count, 3);
		let shortfall = [&a, &b, &c].iter()
			.map(|tx| tx.weight() * target - wallet.calculate_fee(tx).unwrap())
			.sum::<Amount>();
		assert_eq!(ancestors.shortfall, shortfall);
	}

	/// An ancestor that pays above target is mined in its own chunk, so
	/// it must not pay for an ancestor that is below target. A tx that
	/// spends both still raises the one below target to the full amount.
	#[test]
	fn build_bumps_only_the_parent_below_target() {
		let btc = Amount::from_btc(1.0).unwrap();
		let (mut wallet, coins) = wallet_with_coins(&[btc, btc]);
		let half = Amount::from_sat(50_000_000);
		let above = spend_to_self(&mut wallet, &[coins[0]], 1, half, sat_per_vb(200));
		let below = spend_to_self(&mut wallet, &[coins[1]], 1, half, sat_per_vb(1));
		let inputs = [OutPoint::new(above.compute_txid(), 0), OutPoint::new(below.compute_txid(), 0)];
		let target = sat_per_vb(20);

		let recipient = wallet.reveal_next_address(KEYCHAIN).address.script_pubkey();
		let canon = TrustedCanonicalization::from_wallet(&wallet, 1);
		let (psbt, _) = build_at_chunk_feerate(
			&mut wallet, &canon, WithGuaranteedChange(SingleRandomDraw), target, &[], |b| {
				b.add_utxos(&inputs).unwrap();
				b.manually_selected_only();
				b.add_recipient(recipient.clone(), Amount::from_sat(60_000_000));
				Ok(())
			},
		).unwrap();
		let child_fee = psbt.fee().unwrap();
		let child = sign(&mut wallet, psbt);

		// The chunk bitcoind forms from the parent below target and the
		// child pays the target on its own, without the other parent.
		let chunk_weight = child.weight() + below.weight();
		let chunk_fee = child_fee + wallet.calculate_fee(&below).unwrap();
		assert!(chunk_fee >= chunk_weight * target,
			"chunk pays {} for {} at a {:#} target", chunk_fee, chunk_weight, target,
		);
		assert!(chunk_fee <= chunk_weight * target + Amount::from_sat(100),
			"chunk overpays: {} for {}", chunk_fee, chunk_weight,
		);
	}

	/// A deposit from a third party spends outputs the wallet never saw,
	/// so the wallet cannot compute its fee. Only a pinned input reaches
	/// such a tx. The build counts it as paying nothing and pays its
	/// whole fee, instead of failing.
	#[test]
	fn build_pays_an_ancestor_with_unknown_fee_in_full() {
		let (mut wallet, _) = wallet_with_coins(&[Amount::from_btc(1.0).unwrap()]);
		let spk = wallet.reveal_next_address(KEYCHAIN).address.script_pubkey();
		let foreign = Transaction {
			version: bitcoin::transaction::Version::TWO,
			lock_time: bitcoin::absolute::LockTime::ZERO,
			input: vec![bitcoin::TxIn {
				previous_output: OutPoint::new(Txid::from_byte_array([9u8; 32]), 0),
				script_sig: ScriptBuf::new(),
				sequence: bitcoin::Sequence::MAX,
				witness: bitcoin::Witness::new(),
			}],
			output: vec![bitcoin::TxOut { value: Amount::from_btc(0.5).unwrap(), script_pubkey: spk }],
		};
		insert_tx(&mut wallet, foreign.clone());
		let deposit = OutPoint::new(foreign.compute_txid(), 0);
		let target = sat_per_vb(20);
		let canon = TrustedCanonicalization::from_wallet(&wallet, 1);

		let recipient = wallet.reveal_next_address(KEYCHAIN).address.script_pubkey();
		let (psbt, ancestors) = build_at_chunk_feerate(
			&mut wallet, &canon, WithGuaranteedChange(SingleRandomDraw), target, &[], |b| {
				b.add_utxo(deposit).unwrap();
				b.manually_selected_only();
				b.add_recipient(recipient.clone(), Amount::from_sat(10_000_000));
				Ok(())
			},
		).unwrap();
		assert_eq!(ancestors.count, 1);
		assert_eq!(ancestors.shortfall, foreign.weight() * target);
		let child = sign(&mut wallet, psbt.clone());
		assert!(psbt.fee().unwrap() >= (child.weight() + foreign.weight()) * target);
	}


	/// A retry keeps the inputs of the first attempt and adds more, so the
	/// ancestor set grows and the fee is computed again over the whole set.
	#[test]
	fn build_recomputes_the_fee_when_a_retry_adds_an_input() {
		let coin = Amount::from_sat(20_000);
		let (mut wallet, coins) = wallet_with_coins(&[coin, coin]);
		// Two parents at 1 sat/vB. One covers the recipient at the target
		// rate but not the raised fee, so the retry must add the other.
		let p1 = drain_to_self(&mut wallet, coins[0], sat_per_vb(1));
		let p2 = drain_to_self(&mut wallet, coins[1], sat_per_vb(1));
		let target = sat_per_vb(20);
		let canon = TrustedCanonicalization::from_wallet(&wallet, 1);

		let recipient = wallet.reveal_next_address(KEYCHAIN).address.script_pubkey();
		let (psbt, ancestors) = build_at_chunk_feerate(
			&mut wallet, &canon, WithGuaranteedChange(SingleRandomDraw), target,
			&[], |b| {
				b.add_recipient(recipient.clone(), Amount::from_sat(16_000));
				Ok(())
			},
		).unwrap();
		// The tx spends both parents, so it paid for both. A run that
		// dropped the carried inputs, or kept the smaller fee of the
		// first attempt, would underpay the chunk.
		assert_eq!(psbt.unsigned_tx.input.len(), 2);
		assert_eq!(ancestors.count, 2);
		let child_fee = psbt.fee().unwrap();
		let child = sign(&mut wallet, psbt);
		let chunk_weight = child.weight() + p1.weight() + p2.weight();
		let chunk_fee = child_fee
			+ wallet.calculate_fee(&p1).unwrap()
			+ wallet.calculate_fee(&p2).unwrap();
		assert!(chunk_fee >= chunk_weight * target,
			"chunk pays {} for {} at a {:#} target", chunk_fee, chunk_weight, target,
		);
	}

	/// A wallet that cannot pay the fee of its ancestors fails the build.
	/// It must never produce a chunk below target instead.
	#[test]
	fn build_fails_when_the_ancestor_fee_is_unaffordable() {
		let (mut wallet, coins) = wallet_with_coins(&[Amount::from_sat(20_000)]);
		// The only coin left covers the recipient at the target rate, but
		// not once the parent's shortfall is added on top.
		drain_to_self(&mut wallet, coins[0], sat_per_vb(1));
		let canon = TrustedCanonicalization::from_wallet(&wallet, 1);

		let recipient = wallet.reveal_next_address(KEYCHAIN).address.script_pubkey();
		let err = build_at_chunk_feerate(
			&mut wallet, &canon, WithGuaranteedChange(SingleRandomDraw), sat_per_vb(20),
			&[], |b| {
				b.add_recipient(recipient.clone(), Amount::from_sat(15_500));
				Ok(())
			},
		).unwrap_err();
		let err = format!("{:#}", err);
		assert!(err.contains("attempt 2 at an absolute fee of"), "{}", err);
		assert!(err.contains("Insufficient funds"), "{}", err);
	}

	/// With no unconfirmed ancestors there is nothing to pay for, so the
	/// build finishes on the first attempt at bdk's own fee. A weight
	/// estimate that does not match bdk's own would send every such build
	/// into the retry path instead.
	#[test]
	fn build_without_ancestors_pays_the_plain_target_fee() {
		let btc = Amount::from_btc(1.0).unwrap();
		let (mut wallet, coins) = wallet_with_coins(&[btc, btc, btc]);
		let target = sat_per_vb(20);
		let canon = TrustedCanonicalization::from_wallet(&wallet, 1);
		let recipient = wallet.reveal_next_address(KEYCHAIN).address.script_pubkey();

		for n in 1..=coins.len() {
			let inputs = &coins[..n];
			let (psbt, ancestors) = build_at_chunk_feerate(
				&mut wallet, &canon, WithGuaranteedChange(SingleRandomDraw), target,
				&[], |b| {
					b.add_utxos(inputs).unwrap();
					b.manually_selected_only();
					b.add_recipient(recipient.clone(), Amount::from_sat(10_000_000));
					Ok(())
				},
			).unwrap();
			assert_eq!(ancestors.count, 0);
			assert_eq!(ancestors.shortfall, Amount::ZERO);

			let mut b = wallet.build_tx().coin_selection(WithGuaranteedChange(SingleRandomDraw));
			b.add_utxos(inputs).unwrap();
			b.manually_selected_only();
			b.add_recipient(recipient.clone(), Amount::from_sat(10_000_000));
			b.fee_rate(target);
			let plain = b.finish().unwrap();
			assert_eq!(psbt.fee().unwrap(), plain.fee().unwrap(),
				"{} input(s) took a retry instead of returning bdk's own fee", n,
			);
		}
	}

	/// The round's own selection with a pinned unconfirmed input: the
	/// extra fee must not disturb the output order the round tx needs.
	#[test]
	fn round_selection_keeps_the_tree_output_first_through_a_bump() {
		let btc = Amount::from_btc(1.0).unwrap();
		let (mut wallet, coins) = wallet_with_coins(&[btc, btc]);
		// The pinned input is the previous round's low-fee change.
		let parent = spend_to_self(&mut wallet, &coins[..1], 1, Amount::from_sat(50_000_000), sat_per_vb(2));
		let pinned = OutPoint::new(parent.compute_txid(), 0);
		let target = sat_per_vb(20);
		let canon = TrustedCanonicalization::from_wallet(&wallet, 1);

		let tree_spk = wallet.reveal_next_address(KEYCHAIN).address.script_pubkey();
		let selection = WithGuaranteedChange(
			PreferConfirmedCoinSelection(DefaultCoinSelectionAlgorithm::default()),
		);
		let (psbt, ancestors) = build_at_chunk_feerate(
			&mut wallet, &canon, selection, target, &[], |b| {
				b.ordering(bdk_wallet::TxOrdering::Untouched);
				// NB: manual selection overrides the unspendable outputs
				b.add_utxo(pinned).unwrap();
				b.add_recipient(tree_spk.clone(), Amount::from_sat(60_000_000));
				Ok(())
			},
		).unwrap();

		// The pinned input drags its parent in, so a bump happened.
		assert_eq!(ancestors.count, 1);
		assert!(ancestors.shortfall > Amount::ZERO);
		assert!(psbt.unsigned_tx.input.iter().any(|i| i.previous_output == pinned));
		assert_eq!(psbt.unsigned_tx.output[ROUND_TX_VTXO_TREE_VOUT as usize].script_pubkey,
			tree_spk, "the tree output must stay at vout {}", ROUND_TX_VTXO_TREE_VOUT,
		);
	}

}

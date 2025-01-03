
mod wallet;

use std::{io, iter};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use anyhow::{bail, Context};
use bitcoin::consensus::encode::{deserialize, serialize};
use bitcoin::{Transaction, Txid};
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{schnorr, PublicKey};
use rocksdb::{
	BoundColumnFamily, Direction, FlushOptions, IteratorMode, OptimisticTransactionOptions,
	WriteBatchWithTransaction, WriteOptions,
};

use ark::{BlockHeight, VtxoId, Vtxo};
use ark::tree::signed::SignedVtxoTree;

use self::wallet::{CF_BDK_CHANGESETS, ChangeSetDbState};


// COLUMN FAMILIES

/// mapping VtxoId -> ForfeitVtxo
const CF_FORFEIT_VTXO: &str = "forfeited_vtxos";
/// mapping Txid -> serialized StoredRound
const CF_ROUND: &str = "rounds";
/// set [expiry][txid]
const CF_ROUND_EXPIRY: &str = "rounds_by_expiry";
/// set [outpoint]
const CF_OOR_COSIGNED: &str = "oor_cosign";
/// set [pubkey][vtxo]
const CF_OOR_MAILBOX: &str = "oor_mailbox";
/// map Txid -> Transaction
const CF_PENDING_SWEEPS: &str = "pending_sweeps";

// ROOT ENTRY KEYS

const MASTER_SEED: &str = "master_seed";
const MASTER_MNEMONIC: &str = "master_mnemonic";


/// A vtxo that has been forfeited and is now ours.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ForfeitVtxo {
	pub vtxo: Vtxo,
	pub forfeit_sigs: Vec<schnorr::Signature>,
}

impl ForfeitVtxo {
	pub fn id(&self) -> VtxoId {
		self.vtxo.id()
	}

	fn encode(&self) -> Vec<u8> {
		let mut buf = Vec::new();
		ciborium::into_writer(self, &mut buf).unwrap();
		buf
	}
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RoundExpiryKey {
	// NB keep this type explicit as u32 instead of BlockHeight to ensure encoding is stable
	expiry: u32,
	id: Txid,
}

impl RoundExpiryKey {
	fn new(expiry: u32, id: Txid) -> Self {
		Self { expiry, id }
	}

	fn encode(&self) -> [u8; 36] {
		let mut ret = [0u8; 36];
		ret[0..4].copy_from_slice(&self.expiry.to_le_bytes());
		ret[4..].copy_from_slice(&self.id[..]);
		ret
	}

	fn decode(b: &[u8]) -> Self {
		assert_eq!(b.len(), 36, "corrupt round expiry key");
		Self {
			expiry: {
				let mut buf = [0u8; 4];
				buf[..].copy_from_slice(&b[0..4]);
				u32::from_le_bytes(buf)
			},
			id: Txid::from_slice(&b[4..]).unwrap(),
		}
	}
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct StoredRound {
	pub tx: Transaction,
	pub signed_tree: SignedVtxoTree,
	pub nb_input_vtxos: u64,
}

impl StoredRound {
	pub fn id(&self) -> Txid {
		self.tx.compute_txid()
	}

	fn encode(&self) -> Vec<u8> {
		let mut buf = Vec::new();
		ciborium::into_writer(self, &mut buf).unwrap();
		buf
	}

	fn decode(bytes: &[u8]) -> Result<Self, ciborium::de::Error<io::Error>> {
		ciborium::from_reader(bytes)
	}
}

/// Type alias for the underlying RocksDB type.
type RocksDb = rocksdb::OptimisticTransactionDB<rocksdb::MultiThreaded>;

pub struct Db {
	db: RocksDb,
	wallet: ChangeSetDbState,
}

impl Db {
	pub fn open(path: &Path) -> anyhow::Result<Db> {
		let mut opts = rocksdb::Options::default();
		opts.create_if_missing(true);
		opts.create_missing_column_families(true);

		let cfs = [
			CF_FORFEIT_VTXO,
			CF_ROUND,
			CF_ROUND_EXPIRY,
			CF_OOR_COSIGNED,
			CF_OOR_MAILBOX,
			CF_BDK_CHANGESETS,
			CF_PENDING_SWEEPS,
		];
		let db = rocksdb::OptimisticTransactionDB::open_cf(&opts, path, cfs)
			.context("failed to open db")?;
		let wallet = ChangeSetDbState::new();
		Ok(Db { db, wallet })
	}

	fn cf_forfeit_vtxo<'a>(&'a self) -> Arc<BoundColumnFamily<'a>> {
		self.db.cf_handle(CF_FORFEIT_VTXO).expect("db missing forfeit vtxo cf")
	}

	fn cf_round<'a>(&'a self) -> Arc<BoundColumnFamily<'a>> {
		self.db.cf_handle(CF_ROUND).expect("db missing round cf")
	}

	fn cf_round_expiry<'a>(&'a self) -> Arc<BoundColumnFamily<'a>> {
		self.db.cf_handle(CF_ROUND_EXPIRY).expect("db missing round expiry cf")
	}

	fn cf_oor_cosigned<'a>(&'a self) -> Arc<BoundColumnFamily<'a>> {
		self.db.cf_handle(CF_OOR_COSIGNED).expect("db missing oor cosigned cf")
	}

	fn cf_oor_mailbox<'a>(&'a self) -> Arc<BoundColumnFamily<'a>> {
		self.db.cf_handle(CF_OOR_MAILBOX).expect("db missing oor mailbox cf")
	}

	fn cf_pending_sweeps<'a>(&'a self) -> Arc<BoundColumnFamily<'a>> {
		self.db.cf_handle(CF_PENDING_SWEEPS).expect("db missing pending sweeps cf")
	}


	pub fn store_master_mnemonic_and_seed(&self, mnemonic: &bip39::Mnemonic) -> anyhow::Result<()> {
		let mut b = WriteBatchWithTransaction::<true>::default();
		b.put(MASTER_MNEMONIC, mnemonic.to_string().as_bytes());
		b.put(MASTER_SEED, mnemonic.to_seed("").to_vec());
		let mut opts = WriteOptions::default();
		opts.set_sync(true);
		self.db.write_opt(b, &opts)?;
		Ok(())
	}

	pub fn get_master_seed(&self) -> anyhow::Result<Option<Vec<u8>>> {
		Ok(self.db.get(MASTER_SEED)?)
	}

	pub fn get_master_mnemonic(&self) -> anyhow::Result<Option<String>> {
		Ok(self.db.get(MASTER_MNEMONIC)?.map(|b| String::from_utf8(b)).transpose()?)
	}

	pub fn store_round(
		&self,
		round_tx: Transaction,
		vtxos: SignedVtxoTree,
		nb_input_vtxos: usize,
	) -> anyhow::Result<()> {
		let round = StoredRound {
			tx: round_tx,
			signed_tree: vtxos,
			nb_input_vtxos: nb_input_vtxos as u64,
		};
		let id = round.id();
		let encoded_round = round.encode();
		let expiry_key = RoundExpiryKey::new(round.signed_tree.spec.expiry_height, id);

		let mut opts = WriteOptions::default();
		opts.set_sync(true);
		let mut oopts = OptimisticTransactionOptions::new();
		oopts.set_snapshot(false);

		//TODO(stevenroose) consider writing a macro for this sort of block
		loop {
			let tx = self.db.transaction_opt(&opts, &oopts);
			tx.put_cf(&self.cf_round(), id, &encoded_round)?;
			tx.put_cf(&self.cf_round_expiry(), expiry_key.encode(), [])?;

			match tx.commit() {
				Ok(()) => break,
				Err(e) if e.kind() == rocksdb::ErrorKind::TryAgain => continue,
				Err(e) if e.kind() == rocksdb::ErrorKind::Busy => continue,
				Err(e) => bail!("failed to commit db tx: {}", e),
			}
		}

		let mut opts = FlushOptions::default();
		opts.set_wait(true); //TODO(stevenroose) is this needed?
		self.db.flush_cfs_opt(
			&[&self.cf_round(), &self.cf_forfeit_vtxo(), &self.cf_round_expiry()], &opts,
		).context("error flushing db")?;

		Ok(())
	}

	pub fn remove_round(&self, id: Txid) -> anyhow::Result<()> {
		let round = match self.get_round(id)? {
			Some(r) => r,
			None => return Ok(()),
		};
		let expiry_key = RoundExpiryKey::new(round.signed_tree.spec.expiry_height, id);

		let opts = WriteOptions::default();
		let oopts = OptimisticTransactionOptions::new();

		//TODO(stevenroose) consider writing a macro for this sort of block
		loop {
			let tx = self.db.transaction_opt(&opts, &oopts);
			tx.delete_cf(&self.cf_round(), id)?;
			tx.delete_cf(&self.cf_round_expiry(), expiry_key.encode())?;

			match tx.commit() {
				Ok(()) => break,
				Err(e) if e.kind() == rocksdb::ErrorKind::TryAgain => continue,
				Err(e) if e.kind() == rocksdb::ErrorKind::Busy => continue,
				Err(e) => bail!("failed to commit db tx: {}", e),
			}
		}
		Ok(())
	}

	pub fn get_round(&self, id: Txid) -> anyhow::Result<Option<StoredRound>> {
		Ok(self.db.get_pinned_cf(&self.cf_round(), id)?.map(|b| {
			StoredRound::decode(&b).expect("corrupt db")
		}))
	}

	/// Get all round IDs of rounds that expired before or on `height`.
	pub fn get_expired_rounds(&self, height: BlockHeight) -> anyhow::Result<Vec<Txid>> {
		let mut ret = Vec::new();

		let mut iter = self.db.iterator_cf(&self.cf_round_expiry(), IteratorMode::Start);
		while let Some(res) = iter.next() {
			let (key, _) = res.context("db round expiry iter error")?;
			let expkey = RoundExpiryKey::decode(&key);
			if expkey.expiry as BlockHeight > height {
				break;
			}
			ret.push(expkey.id);
		}

		Ok(ret)
	}

	pub fn get_fresh_round_ids(&self, start_height: u32) -> anyhow::Result<Vec<Txid>> {
		let mut ret = Vec::new();

		let mut iter = self.db.iterator_cf(&self.cf_round_expiry(),
			IteratorMode::From(&start_height.to_le_bytes(), Direction::Forward),
		);
		while let Some(res) = iter.next() {
			let (key, _) = res.context("db round expiry iter error")?;
			ret.push(RoundExpiryKey::decode(&key).id);
		}

		Ok(ret)
	}

	/// Get an iterator that yields each round in the database.
	///
	/// No particular order is guaranteed.
	pub fn fetch_all_rounds(&self) -> impl Iterator<Item = anyhow::Result<StoredRound>> + '_ {
		let mut iter = self.db.iterator_cf(&self.cf_round(), IteratorMode::Start);
		iter::from_fn(move || {
			if let Some(res) = iter.next() {
				match res.context("dn round iter error") {
					Ok((_k, v)) => {
						let round = StoredRound::decode(&v).expect("corrupt db");
						Some(Ok(round))
					},
					Err(e) => Some(Err(e)),
				}
			} else {
				None
			}
		})
	}

	pub fn store_forfeit_vtxo(&self, vtxo: ForfeitVtxo) -> anyhow::Result<()> {
		self.db.put_cf(&self.cf_forfeit_vtxo(), vtxo.id(), vtxo.encode())?;
		Ok(())
	}

	/// Returns [None] if all the ids were not previously marked as signed
	/// and are now correctly marked as such.
	/// Returns [Some] for the first vtxo that was already signed.
	///
	/// This is atomic so that a user can't try to make us double sign by firing
	/// multiple cosign requests at the same time.
	pub fn atomic_check_mark_oors_cosigned(
		&self,
		ids: impl Iterator<Item = VtxoId> + Clone,
	) -> anyhow::Result<Option<VtxoId>> {
		let opts = WriteOptions::default();
		let oopts = OptimisticTransactionOptions::new();

		//TODO(stevenroose) consider writing a macro for this sort of block
		loop {
			let tx = self.db.transaction_opt(&opts, &oopts);

			for id in ids.clone() {
				if tx.get_cf(&self.cf_oor_cosigned(), id)?.is_some() {
					tx.rollback()?;
					return Ok(Some(id));
				}
			}

			match tx.commit() {
				Ok(()) => break,
				Err(e) if e.kind() == rocksdb::ErrorKind::TryAgain => continue,
				Err(e) if e.kind() == rocksdb::ErrorKind::Busy => continue,
				Err(e) => bail!("failed to commit db tx: {}", e),
			}
		}
		Ok(None)
	}

	pub fn clear_oor_cosigned(&self) -> anyhow::Result<()> {
		self.db.drop_cf(CF_OOR_COSIGNED)?;

		let mut opts = rocksdb::Options::default();
		opts.create_if_missing(true);
		opts.create_missing_column_families(true);
		self.db.create_cf(CF_OOR_COSIGNED, &opts)?;
		Ok(())
	}

	pub fn store_oor(&self, pubkey: PublicKey, vtxo: Vtxo) -> anyhow::Result<()> {
		let mut buf = Vec::new();
		buf.extend(pubkey.serialize());
		vtxo.encode_into(&mut buf);
		self.db.put_cf(&self.cf_oor_mailbox(), buf, [])?;
		Ok(())
	}

	pub fn pull_oors(&self, pubkey: PublicKey) -> anyhow::Result<Vec<Vtxo>> {
		let pk = pubkey.serialize();
		assert_eq!(33, pk.len());

		let mut ret = Vec::new();
		let mut iter = self.db.iterator_cf(&self.cf_oor_mailbox(),
			IteratorMode::From(&pk, Direction::Forward),
		);
		while let Some(res) = iter.next() {
			let (item, _) = res.context("db oor iter error")?;
			if item[0..33] == pk {
				ret.push(Vtxo::decode(&item[33..]).expect("corrupt db: invalid vtxo"));
				self.db.delete_cf(&self.cf_oor_mailbox(), &item)?;
			} else {
				break;
			}
		}

		Ok(ret)
	}

	/// Add the pending sweep tx.
	pub fn store_pending_sweep(&self, txid: &Txid, tx: &Transaction) -> anyhow::Result<()> {
		let raw = serialize(tx);
		self.db.put_cf(&self.cf_pending_sweeps(), txid, raw)?;
		Ok(())
	}

	/// Drop the pending sweep tx by txid.
	pub fn drop_pending_sweep(&self, txid: &Txid) -> anyhow::Result<()> {
		self.db.delete_cf(&self.cf_pending_sweeps(), txid)?;
		Ok(())
	}

	/// Fetch all pending sweep txs.
	pub fn fetch_pending_sweeps(&self) -> anyhow::Result<HashMap<Txid, Transaction>> {
		let mut iter = self.db.iterator_cf(&self.cf_pending_sweeps(), IteratorMode::Start);

		let mut ret = HashMap::new();
		while let Some(res) = iter.next() {
			let (key, value) = res.context("db pending sweeps iter error")?;
			let txid = Txid::from_slice(&key).context("corrupt db: invalid pending sweep txid")?;
			let tx = deserialize(&value).context("corrupt db: invalid pending sweep txid")?;
			ret.insert(txid, tx);
		}

		Ok(ret)
	}
}

//TODO(stevenroose) write test to make sure the iterator in get_fresh_round_ids doesn't skip
//any rounds on the same height.

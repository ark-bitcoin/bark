use std::borrow::Cow;
use std::str::FromStr;

use anyhow::{Context, bail};

use ark::vtxo::{Bare, Full, Policy};
use bitcoin::{Amount, OutPoint, Transaction, Txid};
use bitcoin::secp256k1::PublicKey;
use bitcoin::consensus::deserialize;
use bitcoin_ext::BlockHeight;
use chrono::{DateTime, Local};
use tokio_postgres::Row;

use ark::{ProtocolEncoding, ServerVtxoPolicy, Vtxo, VtxoId, VtxoPolicy};

// Used by mailbox as an always increasing number for data sorting.
pub type Checkpoint = u64;

#[derive(Debug)]
pub struct VtxoState<G = Full, P: Policy = VtxoPolicy> {
	pub id: i64,
	/// The id of the VTXO
	pub vtxo_id: VtxoId,

	/// The vtxo.
	pub vtxo: Vtxo<G, P>,
	// NB keep this type explicit as u32 instead of BlockHeight to ensure encoding is stable
	pub expiry: u32,

	/// If this vtxo was spent in an OOR tx, the txid of the OOR tx.
	pub oor_spent_txid: Option<Txid>,

	/// The round id this vtxo was forfeited in.
	pub spent_in_round: Option<i64>,

	/// If this VTXO was offboarded, the offboard tx's txid
	pub offboarded_in: Option<Txid>,

	/// If this vtxo is banned, the block height until which it is banned
	// NB keep this type explicit as u32 instead of BlockHeight to ensure encoding is stable
	pub banned_until_height: Option<u32>,

	/// If this is a board vtxo, the time at which it was swept.
	pub created_at: DateTime<Local>,
	pub updated_at: DateTime<Local>,
}

impl VtxoState<Full, ServerVtxoPolicy> {
	pub fn try_into_user_vtxo_state(self) -> Result<VtxoState<Full, VtxoPolicy>, Self> {
		match self.vtxo.try_into_user_vtxo() {
			Ok(v) => {
				Ok(VtxoState {
					id: self.id,
					vtxo_id: self.vtxo_id,
					vtxo: v,
					expiry: self.expiry,
					oor_spent_txid: self.oor_spent_txid,
					spent_in_round: self.spent_in_round,
					offboarded_in: self.offboarded_in,
					banned_until_height: self.banned_until_height,
					created_at: self.created_at,
					updated_at: self.updated_at,
				})
			},
			Err(v) => {
				Err(VtxoState {
					id: self.id,
					vtxo_id: self.vtxo_id,
					vtxo: v,
					expiry: self.expiry,
					oor_spent_txid: self.oor_spent_txid,
					spent_in_round: self.spent_in_round,
					offboarded_in: self.offboarded_in,
					banned_until_height: self.banned_until_height,
					created_at: self.created_at,
					updated_at: self.updated_at,
				})
			},
		}
	}
}

impl<G, P: Policy> VtxoState<G, P> {
	/// A vtxo is spendable if it is unspent and not banned at the given tip
	pub fn is_spendable(&self, chain_tip: BlockHeight) -> bool {
		self.is_unspent() && !self.is_banned_at(chain_tip)
	}

	/// Check that the vtxo is spendable, returning a descriptive error if not.
	pub fn check_spendable(&self, chain_tip: BlockHeight) -> anyhow::Result<()> {
		if self.is_spent() {
			bail!("vtxo {} is already spent", self.vtxo_id);
		}
		self.check_not_banned(chain_tip)
	}

	/// Like [check_spendable] but tolerates a vtxo that was already
	/// OOR-spent by the same `oor_txid` (idempotent cosign retry).
	/// Rejects vtxos spent via rounds, offboards, or a *different* OOR tx.
	pub fn check_spendable_for_oor(&self, chain_tip: BlockHeight, oor_txid: Txid) -> anyhow::Result<()> {
		if self.spent_in_round.is_some() {
			bail!("vtxo {} is already spent in a round", self.vtxo_id);
		}
		if self.offboarded_in.is_some() {
			bail!("vtxo {} is already offboarded", self.vtxo_id);
		}
		if let Some(existing) = self.oor_spent_txid {
			if existing != oor_txid {
				bail!("vtxo {} is already spent in a different OOR tx", self.vtxo_id);
			}
		}
		self.check_not_banned(chain_tip)
	}

	/// Check that the vtxo is not banned at the given chain tip.
	fn check_not_banned(&self, chain_tip: BlockHeight) -> anyhow::Result<()> {
		if let Some(until) = self.banned_until_height {
			if chain_tip < until {
				let remaining = until - chain_tip;
				bail!(
					"vtxo {} is temporarily banned until block {} ({} blocks remaining)",
					self.vtxo_id, until, remaining,
				);
			}
		}
		Ok(())
	}

	/// Returns true if the vtxo is banned at the given block height.
	///
	/// A vtxo is banned if `banned_until_height` is set and strictly
	/// greater than `tip`.
	pub fn is_banned_at(&self, tip: BlockHeight) -> bool {
		match self.banned_until_height {
			Some(until) => tip < until,
			None => false,
		}
	}

	/// Returns true if the vtxo has not been spent in any way
	pub fn is_unspent(&self) -> bool {
		self.oor_spent_txid.is_none()
			&& self.spent_in_round.is_none()
			&& self.offboarded_in.is_none()
	}

	/// Returns true if the vtxo has been spent (via oor, round, or offboard)
	pub fn is_spent(&self) -> bool {
		!self.is_unspent()
	}
}

impl<P: Policy> AsRef<Vtxo<Full, P>> for VtxoState<Full, P> {
	fn as_ref(&self) -> &Vtxo<Full, P> {
	    &self.vtxo
	}
}

impl<P: Policy + ProtocolEncoding> TryFrom<Row> for VtxoState<Full, P> {
	type Error = anyhow::Error;

	fn try_from(row: Row) -> Result<Self, Self::Error> {
		let vtxo_id = VtxoId::from_str(row.get::<_, &str>("vtxo_id"))?;
		let vtxo = Vtxo::deserialize(row.get("vtxo"))?;
		debug_assert_eq!(vtxo_id, vtxo.id());

		Ok(Self {
			id: row.get("id"),
			vtxo_id,
			vtxo,
			expiry: u32::try_from(row.get::<_, i32>("expiry"))?,
			oor_spent_txid: row
				.get::<_, Option<&str>>("oor_spent_txid")
				.map(|txid| Txid::from_str(txid))
				.transpose()?,
			spent_in_round: row.get("spent_in_round"),
			offboarded_in: row
				.get::<_, Option<&str>>("offboarded_in")
				.map(|txid| Txid::from_str(txid))
				.transpose()?,
			banned_until_height: row.get::<_, Option<i32>>("banned_until_height")
				.map(|h| u32::try_from(h))
				.transpose()?,
			created_at: row.get("created_at"),
			updated_at: row.get("updated_at"),
		})
	}
}

impl<P: Policy + ProtocolEncoding> TryFrom<Row> for VtxoState<Bare, P> {
	type Error = anyhow::Error;

	fn try_from(row: Row) -> Result<Self, Self::Error> {
		let vtxo_id = VtxoId::from_str(row.get::<_, &str>("vtxo_id"))?;
		let point = vtxo_id.utxo();

		let exit_delta = row.get::<_, i32>("exit_delta") as u16;
		let policy = P::deserialize(row.get::<_, &[u8]>("policy"))?;
		let server_pubkey = PublicKey::from_str(row.get::<_, &str>("server_pubkey"))?;
		let amount = Amount::from_sat(row.get::<_, i64>("amount") as u64);
		let anchor_point = OutPoint::from_str(row.get::<_, &str>("anchor_point"))
			.context("invalid anchor_point")?;
		let expiry = u32::try_from(row.get::<_, i32>("expiry"))?;

		let vtxo = Vtxo::new(
			point, policy, amount, expiry, server_pubkey, exit_delta, anchor_point,
		);

		Ok(Self {
			id: row.get("id"),
			vtxo_id,
			vtxo,
			expiry,
			oor_spent_txid: row
				.get::<_, Option<&str>>("oor_spent_txid")
				.map(|txid| Txid::from_str(txid))
				.transpose()?,
			spent_in_round: row.get("spent_in_round"),
			offboarded_in: row
				.get::<_, Option<&str>>("offboarded_in")
				.map(|txid| Txid::from_str(txid))
				.transpose()?,
			banned_until_height: row
				.get::<_, Option<i32>>("banned_until_height")
				.map(|h| u32::try_from(h))
				.transpose()?,
			created_at: row.get("created_at"),
			updated_at: row.get("updated_at"),
		})
	}
}

#[derive(Debug, Clone)]
pub struct Sweep {
	pub txid: Txid,
	pub tx: Transaction
}

impl TryFrom<Row> for Sweep {
	type Error = anyhow::Error;

	fn try_from(value: Row) -> Result<Self, Self::Error> {
		let txid = Txid::from_str(&value.get::<_, String>("txid"))?;
		let tx = deserialize::<Transaction>(value.get("tx"))?;
		debug_assert_eq!(tx.compute_txid(), txid);

		Ok(Self { txid, tx })
	}
}

/// A persisted virtual transaction
#[derive(Debug, Clone)]
pub struct VirtualTransaction<'a> {
	/// The [bitcoin::Txid] of the transaction
	pub txid: Txid,
	/// If we know the signatures this contains the signed transaction
	/// This is empty if the signature isn't known (yet)
	pub signed_tx: Option<Cow<'a, Transaction>>,
	/// True if this is a funding transaction
	pub is_funding: bool,
	/// The datetime when an descendant became server-owned, or `None` if all
	/// descendants are client-owned. When set, the server MUST ensure `signed_tx`
	/// is populated.
	pub server_may_own_descendant_since: Option<DateTime<Local>>,
}

impl<'a> VirtualTransaction<'a> {
	pub fn signed_tx(&self) -> Option<&Transaction> {
		self.signed_tx.as_deref()
	}

	/// Returns true if an descendant of this transaction is owned by the server.
	pub fn server_may_own_descendant(&self) -> bool {
		self.server_may_own_descendant_since.is_some()
	}

	pub fn new_unsigned(txid: Txid) -> Self {
		Self { txid, signed_tx: None, is_funding: false, server_may_own_descendant_since: None }
	}

	pub fn new_signed_ref(tx: &'a Transaction) -> Self {
		Self {
			txid: tx.compute_txid(),
			signed_tx: Some(Cow::Borrowed(tx)),
			is_funding: false,
			server_may_own_descendant_since: None,
		}
	}

	pub fn new_signed_owned(tx: Transaction) -> VirtualTransaction<'static> {
		VirtualTransaction {
			txid: tx.compute_txid(),
			signed_tx: Some(Cow::Owned(tx)),
			is_funding: false,
			server_may_own_descendant_since: None,
		}
	}

	pub fn as_funding(mut self) -> Self {
		self.is_funding = true;
		self
	}

	pub fn as_server_owned_since(mut self, since: DateTime<Local>) -> Self {
		self.server_may_own_descendant_since = Some(since);
		self
	}
}


impl TryFrom<Row> for VirtualTransaction<'static> {
	type Error = anyhow::Error;

	fn try_from(row: Row) -> Result<Self, Self::Error> {
		// Parse the txid first. We use it for error messages
		let txid: &str = row.get("txid");
		let txid: Txid = Txid::from_str(txid)
				.with_context(|| format!("Invalid txid {}", txid))?;

		let signed_tx: Option<Cow<'static, Transaction>> = row.get::<_, Option<&[u8]>>("signed_tx")
			.map(|tx| deserialize(tx)).transpose()
			.with_context(|| format!("Failed to parse signed_tx for txid {}", txid))?
			.map(|tx| Cow::Owned(tx));
		let is_funding: bool = row.get("is_funding");
		let server_may_own_descendant_since: Option<DateTime<Local>> =
			row.get("server_may_own_descendant_since");

		Ok(Self { txid, signed_tx, is_funding, server_may_own_descendant_since })
	}
}

#[cfg(test)]
mod test {
	use super::*;

	use bitcoin::hashes::Hash;

	/// An unspent, unbanned vtxo state for testing.
	///
	/// SAFETY: The vtxo field is uninitialized and must not be accessed.
	/// The test methods only look at the spent/banned fields.
	#[allow(invalid_value)]
	fn unspent() -> VtxoState {
		let vtxo = unsafe {
			std::mem::MaybeUninit::<Vtxo<Full, VtxoPolicy>>::uninit().assume_init()
		};
		VtxoState {
			id: 0,
			vtxo_id: VtxoId::from_slice(&[0; 36]).unwrap(),
			vtxo,
			expiry: 0,
			oor_spent_txid: None,
			spent_in_round: None,
			offboarded_in: None,
			banned_until_height: None,
			created_at: Local::now(),
			updated_at: Local::now(),
		}
	}

	#[test]
	fn unspent_unbanned_is_spendable() {
		let v = unspent();
		assert!(v.is_unspent());
		assert!(!v.is_spent());
		assert!(!v.is_banned_at(100));
		assert!(v.is_spendable(100));
		assert!(v.check_spendable(100).is_ok());
	}

	#[test]
	fn spent_oor_is_not_spendable() {
		let mut v = unspent();
		v.oor_spent_txid = Some(Txid::all_zeros());
		assert!(!v.is_unspent());
		assert!(v.is_spent());
		assert!(!v.is_spendable(100));
		assert!(v.check_spendable(100).is_err());
	}

	#[test]
	fn spent_in_round_is_not_spendable() {
		let mut v = unspent();
		v.spent_in_round = Some(1);
		assert!(!v.is_unspent());
		assert!(!v.is_spendable(100));
	}

	#[test]
	fn offboarded_is_not_spendable() {
		let mut v = unspent();
		v.offboarded_in = Some(Txid::all_zeros());
		assert!(!v.is_unspent());
		assert!(!v.is_spendable(100));
	}

	#[test]
	fn banned_in_future_is_not_spendable() {
		let mut v = unspent();
		v.banned_until_height = Some(200);
		assert!(v.is_unspent());
		assert!(v.is_banned_at(100));
		assert!(!v.is_spendable(100));

		let err = v.check_spendable(100).unwrap_err();
		let msg = format!("{}", err);
		assert!(msg.contains("temporarily banned"), "got: {}", msg);
		assert!(msg.contains("100 blocks remaining"), "got: {}", msg);
	}

	#[test]
	fn ban_expired_is_spendable() {
		let mut v = unspent();
		v.banned_until_height = Some(100);
		// At tip == 100, the ban has expired (not strictly greater)
		assert!(!v.is_banned_at(100));
		assert!(v.is_spendable(100));

		// At tip == 200, well past the ban
		assert!(!v.is_banned_at(200));
		assert!(v.is_spendable(200));
	}

	#[test]
	fn banned_at_exact_boundary() {
		let mut v = unspent();
		v.banned_until_height = Some(100);
		// At tip == 99, still banned
		assert!(v.is_banned_at(99));
		assert!(!v.is_spendable(99));
		// At tip == 100, ban expired
		assert!(!v.is_banned_at(100));
		assert!(v.is_spendable(100));
	}

	#[test]
	fn spent_and_banned() {
		let mut v = unspent();
		v.oor_spent_txid = Some(Txid::all_zeros());
		v.banned_until_height = Some(200);
		assert!(!v.is_spendable(100));
		let err = v.check_spendable(100).unwrap_err();
		let msg = format!("{}", err);
		assert!(msg.contains("already spent"), "got: {}", msg);
	}

	#[test]
	fn oor_spent_same_tx_is_spendable_for_oor() {
		let mut v = unspent();
		let txid = Txid::all_zeros();
		v.oor_spent_txid = Some(txid);
		// check_spendable rejects it
		assert!(v.check_spendable(100).is_err());
		// but check_spendable_for_oor allows it when the txid matches
		assert!(v.check_spendable_for_oor(100, txid).is_ok());
	}

	#[test]
	fn oor_spent_different_tx_is_not_spendable_for_oor() {
		let mut v = unspent();
		v.oor_spent_txid = Some(Txid::all_zeros());
		let other_txid = "0000000000000000000000000000000000000000000000000000000000000001"
			.parse().unwrap();
		let err = v.check_spendable_for_oor(100, other_txid).unwrap_err();
		let msg = format!("{}", err);
		assert!(msg.contains("different OOR tx"), "got: {}", msg);
	}

	#[test]
	fn round_spent_is_not_spendable_for_oor() {
		let mut v = unspent();
		v.spent_in_round = Some(1);
		assert!(v.check_spendable_for_oor(100, Txid::all_zeros()).is_err());
	}

	#[test]
	fn offboarded_is_not_spendable_for_oor() {
		let mut v = unspent();
		v.offboarded_in = Some(Txid::all_zeros());
		assert!(v.check_spendable_for_oor(100, Txid::all_zeros()).is_err());
	}

	#[test]
	fn banned_is_not_spendable_for_oor() {
		let mut v = unspent();
		v.banned_until_height = Some(200);
		assert!(v.check_spendable_for_oor(100, Txid::all_zeros()).is_err());
	}
}

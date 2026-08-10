use std::borrow::Cow;
use std::fmt;
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
use ark::vtxo::policy::{check_block_delta, check_block_height, VtxoPolicyKind};

// Used by mailbox as an always increasing number for data sorting.
pub type Checkpoint = u64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpendState {
	/// The vtxo is available for spending.
	Spendable,
	/// The vtxo originates from a round but forfeits haven't been signed yet.
	/// The server didn't release the unlock preimage yet.
	Unclaimed,
	/// The vtxo has been fully spent (via round, OOR, or offboard).
	Spent,
	/// The VTXO is part of the VTXO pool
	Pool,
	/// The VTXO is an htlc-recv that hasn't been claimed yet
	HtlcRecvUnclaimed,
	/// The vtxo is an htlc-send HTLC to the server
	LnSpent,
	/// The vtxo is a forfeit for a round input
	RoundForfeit,
	/// The vtxo is a forfeit for an offboard input
	OffboardForfeit,
	/// The vtxo is a connector output for an offboard
	OffboardConnector,
	/// The vtxo's signed transaction chain hasn't been uploaded yet via
	/// `register_vtxo_transactions`. Spend attempts fail until the client
	/// registers the chain, at which point the vtxo transitions to
	/// `Spendable`.
	Unregistered,
}

impl SpendState {
	pub fn as_str(&self) -> &'static str {
		match self {
			SpendState::Spendable => "spendable",
			SpendState::Unclaimed => "unclaimed",
			SpendState::Spent => "spent",
			SpendState::Pool => "pool",
			SpendState::HtlcRecvUnclaimed => "htlc-recv-unclaimed",
			SpendState::LnSpent => "ln-spent",
			SpendState::RoundForfeit => "round-forfeit",
			SpendState::OffboardForfeit => "offboard-forfeit",
			SpendState::OffboardConnector => "offboard-connector",
			SpendState::Unregistered => "unregistered",
		}
	}
}

impl fmt::Display for SpendState {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str(self.as_str())
	}
}

impl FromStr for SpendState {
	type Err = anyhow::Error;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		match s {
			"spendable" => Ok(SpendState::Spendable),
			"unclaimed" => Ok(SpendState::Unclaimed),
			"spent" => Ok(SpendState::Spent),
			"pool" => Ok(SpendState::Pool),
			"htlc-recv-unclaimed" => Ok(SpendState::HtlcRecvUnclaimed),
			"ln-spent" => Ok(SpendState::LnSpent),
			"round-forfeit" => Ok(SpendState::RoundForfeit),
			"offboard-forfeit" => Ok(SpendState::OffboardForfeit),
			"offboard-connector" => Ok(SpendState::OffboardConnector),
			"unregistered" => Ok(SpendState::Unregistered),
			other => bail!("invalid spend_state: {}", other),
		}
	}
}

#[derive(Debug)]
pub struct VtxoState<G = Full, P: Policy = VtxoPolicy> {
	pub id: i64,
	/// The id of the VTXO
	pub vtxo_id: VtxoId,

	/// The vtxo.
	pub vtxo: Vtxo<G, P>,

	/// If this vtxo was spent in an OOR tx, the txid of the OOR tx.
	pub oor_spent_txid: Option<Txid>,

	/// The round id this vtxo was forfeited in.
	pub spent_in_round: Option<i64>,

	/// If this VTXO was offboarded, the offboard tx's txid
	pub offboarded_in: Option<Txid>,

	/// If this vtxo is banned, the block height until which it is banned
	// NB keep this type explicit as u32 instead of BlockHeight to ensure encoding is stable
	pub banned_until_height: Option<u32>,

	/// The spend lifecycle state of the vtxo. `check_spendable` consults
	/// this so unregistered vtxos can't be used as inputs.
	pub spend_state: SpendState,

	/// If this vtxo exited onchain, the height at which its onchain
	/// transaction confirmed.
	///
	/// We never serve an exited vtxo and will not sign any forfeit,
	/// arkoor or other transaction anymore.
	pub confirmed_height: Option<BlockHeight>,

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
					oor_spent_txid: self.oor_spent_txid,
					spent_in_round: self.spent_in_round,
					offboarded_in: self.offboarded_in,
					banned_until_height: self.banned_until_height,
					confirmed_height: self.confirmed_height,
					spend_state: self.spend_state,
					created_at: self.created_at,
					updated_at: self.updated_at,
				})
			},
			Err(v) => {
				Err(VtxoState {
					id: self.id,
					vtxo_id: self.vtxo_id,
					vtxo: v,
					oor_spent_txid: self.oor_spent_txid,
					spent_in_round: self.spent_in_round,
					offboarded_in: self.offboarded_in,
					banned_until_height: self.banned_until_height,
					confirmed_height: self.confirmed_height,
					spend_state: self.spend_state,
					created_at: self.created_at,
					updated_at: self.updated_at,
				})
			},
		}
	}
}

impl<G, P: Policy> VtxoState<G, P> {
	/// Whether this vtxo exited: its onchain transaction is confirmed.
	pub fn is_exited(&self) -> bool {
		self.confirmed_height.is_some()
	}

	/// Whether this vtxo may be spent as a freely chosen input: a round, an
	/// offboard or an arkoor. HTLC VTXOs are refused.
	///
	/// The lightning circuits that legitimately spend them don't come through
	/// here: sending uses [Self::check_htlc_send_spendable], revoking and
	/// claiming are gated on the payment instead.
	pub fn check_spendable(&self, chain_tip: BlockHeight) -> anyhow::Result<()> {
		let policy = self.vtxo.policy().policy_type();
		if policy != VtxoPolicyKind::Pubkey {
			return badarg!("vtxo {} is not spendable as a round, offboard or arkoor input \
				(policy: {})", self.vtxo_id, policy,
			);
		}
		self.check_state_spendable(chain_tip)
	}

	/// Whether this htlc-send vtxo may fund the lightning payment
	///
	/// Deliberately not reachable through [Self::check_spendable]: this is the
	/// one gate where an HTLC vtxo is the expected input.
	pub fn check_htlc_send_spendable(&self, chain_tip: BlockHeight) -> anyhow::Result<()> {
		let policy = self.vtxo.policy().policy_type();
		if policy != VtxoPolicyKind::ServerHtlcSend {
			return badarg!("vtxo {} is not an htlc-send vtxo (policy: {})", self.vtxo_id, policy);
		}
		self.check_state_spendable(chain_tip)
	}

	/// The spend-lifecycle half of the checks above, shared by both.
	fn check_state_spendable(&self, chain_tip: BlockHeight) -> anyhow::Result<()> {
		if self.is_exited() {
			return badarg!("vtxo {} has exited onchain", self.vtxo_id);
		}
		if self.spend_state != SpendState::Spendable {
			return badarg!("vtxo {} is not spendable (state: {})", self.vtxo_id, self.spend_state);
		}
		self.check_not_banned(chain_tip)
	}

	/// Checks whether this vtxo is acceptable as a lightning-receive anti-DoS
	/// ownership proof.
	///
	/// Unlike [Self::check_spendable] this also accepts `Unregistered` vtxos.
	/// The proof only demonstrates that the user controls a genuine stake in
	/// the Ark (one the server itself cosigned); it never spends the vtxo, so
	/// requiring the signed transaction chain to be uploaded first is
	/// unnecessary. Banned and exited vtxos are still rejected: an exited
	/// vtxo no longer represents a stake in the Ark.
	pub fn check_valid_anti_dos_proof(&self, chain_tip: BlockHeight) -> anyhow::Result<()> {
		if self.is_exited() {
			return badarg!("vtxo {} has exited onchain", self.vtxo_id);
		}
		if !matches!(self.spend_state, SpendState::Spendable | SpendState::Unregistered) {
			return badarg!(
				"vtxo {} is not a valid anti-dos proof (state: {})", self.vtxo_id, self.spend_state,
			);
		}
		self.check_not_banned(chain_tip)
	}

	fn check_not_banned(&self, chain_tip: BlockHeight) -> anyhow::Result<()> {
		if let Some(until) = self.banned_until_height {
			if chain_tip < until {
				return badarg!("vtxo {} is banned until block {}", self.vtxo_id, until);
			}
		}
		Ok(())
	}

	/// Like [Self::check_spendable] but tolerates a vtxo that was already
	/// OOR-spent by the same `oor_txid` (idempotent cosign retry).
	pub fn check_spendable_for_oor(&self, chain_tip: BlockHeight, oor_txid: Txid) -> anyhow::Result<()> {
		let idempotent = self.spend_state == SpendState::Spent
			&& self.oor_spent_txid == Some(oor_txid);
		if !idempotent {
			self.check_spendable(chain_tip)?;
		}
		Ok(())
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
			confirmed_height: row.get::<_, Option<i32>>("confirmed_height")
				.map(|h| BlockHeight::try_from(h))
				.transpose()
				.context("invalid confirmed_height in DB")?,
			spend_state: SpendState::from_str(row.get::<_, &str>("spend_state"))?,
			created_at: row.get("created_at"),
			updated_at: row.get("updated_at"),
		})
	}
}

impl<P: Policy + ProtocolEncoding> TryFrom<Row> for VtxoState<Bare, P> {
	type Error = anyhow::Error;

	fn try_from(row: Row) -> Result<Self, Self::Error> {
		let vtxo_id = VtxoId::from_str(row.get::<_, &str>("vtxo_id"))?;
		let point = vtxo_id.to_point();

		let exit_delta = check_block_delta(row.get::<_, i32>("exit_delta"))
			.context("invalid exit_delta in DB")?;
		let policy = P::deserialize(row.get::<_, &[u8]>("policy"))?;
		let server_pubkey = PublicKey::from_str(row.get::<_, &str>("server_pubkey"))?;
		let amount = Amount::from_sat(row.get::<_, i64>("amount") as u64);
		let anchor_point = OutPoint::from_str(row.get::<_, &str>("anchor_point"))
			.context("invalid anchor_point")?;
		let expiry = check_block_height(row.get::<_, i32>("expiry"))
			.context("invalid expiry in DB")?;

		let vtxo = Vtxo::new(
			point, policy, amount, expiry, server_pubkey, exit_delta, anchor_point,
		);

		Ok(Self {
			id: row.get("id"),
			vtxo_id,
			vtxo,
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
			confirmed_height: row.get::<_, Option<i32>>("confirmed_height")
				.map(|h| BlockHeight::try_from(h))
				.transpose()
				.context("invalid confirmed_height in DB")?,
			spend_state: SpendState::from_str(row.get::<_, &str>("spend_state"))?,
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
}

impl<'a> VirtualTransaction<'a> {
	pub fn signed_tx(&self) -> Option<&Transaction> {
		self.signed_tx.as_deref()
	}

	pub fn new_unsigned(txid: Txid) -> Self {
		Self { txid, signed_tx: None, is_funding: false }
	}

	pub fn new_signed_ref(tx: &'a Transaction) -> Self {
		Self {
			txid: tx.compute_txid(),
			signed_tx: Some(Cow::Borrowed(tx)),
			is_funding: false,
		}
	}

	pub fn new_signed_owned(tx: Transaction) -> VirtualTransaction<'static> {
		VirtualTransaction {
			txid: tx.compute_txid(),
			signed_tx: Some(Cow::Owned(tx)),
			is_funding: false,
		}
	}

	pub fn as_funding(mut self) -> Self {
		self.is_funding = true;
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

		Ok(Self { txid, signed_tx, is_funding })
	}
}

pub struct BannedVtxo {
	pub vtxo_id: VtxoId,
	pub banned_until_height: BlockHeight,
}

impl TryFrom<Row> for BannedVtxo {
	type Error = anyhow::Error;

	fn try_from(row: Row) -> Result<Self, Self::Error> {
		let vtxo_id = VtxoId::from_str(row.get::<_, &str>("vtxo_id"))?;
		let banned_until_height = u32::try_from(row.get::<_, i32>("banned_until_height"))
			.context("banned_until_height out of range for u32")?;

		Ok(Self { vtxo_id, banned_until_height })
	}
}

#[cfg(test)]
mod test {
	use super::*;

	use bitcoin::hashes::Hash;

	use ark::test_util::VTXO_VECTORS;

	fn state(vtxo: Vtxo<Full, VtxoPolicy>) -> VtxoState {
		VtxoState {
			id: 0,
			vtxo_id: vtxo.id(),
			vtxo,
			oor_spent_txid: None,
			spent_in_round: None,
			offboarded_in: None,
			banned_until_height: None,
			confirmed_height: None,
			spend_state: SpendState::Spendable,
			created_at: Local::now(),
			updated_at: Local::now(),
		}
	}

	/// A spendable, unbanned pubkey vtxo state for testing.
	fn spendable() -> VtxoState {
		state(VTXO_VECTORS.board_vtxo.clone())
	}

	/// A spendable, unbanned htlc-send vtxo, the shape a lightning payment
	/// funds itself with.
	fn htlc_send() -> VtxoState {
		state(VTXO_VECTORS.arkoor_htlc_out_vtxo.clone())
	}

	/// A spendable, unbanned htlc-recv vtxo. Its real spend state is
	/// `htlc-recv-unclaimed`, but the policy gate must not depend on that.
	fn htlc_recv() -> VtxoState {
		state(VTXO_VECTORS.round2_vtxo.clone())
	}

	#[test]
	fn spendable_unbanned_is_spendable() {
		let v = spendable();
		assert!(v.check_spendable(100).is_ok());
	}

	#[test]
	fn unregistered_is_not_spendable() {
		let mut v = spendable();
		v.spend_state = SpendState::Unregistered;
		let err = v.check_spendable(100).unwrap_err();
		assert!(format!("{err}").contains("unregistered"), "got: {err}");
	}

	#[test]
	fn unregistered_is_valid_anti_dos_proof() {
		let mut v = spendable();
		v.spend_state = SpendState::Unregistered;
		assert!(v.check_valid_anti_dos_proof(100).is_ok());
	}

	#[test]
	fn spent_is_not_valid_anti_dos_proof() {
		let mut v = spendable();
		v.spend_state = SpendState::Spent;
		v.oor_spent_txid = Some(Txid::all_zeros());
		assert!(v.check_valid_anti_dos_proof(100).is_err());
	}

	#[test]
	fn exited_is_not_spendable() {
		let mut v = spendable();
		v.confirmed_height = Some(90);
		let err = v.check_spendable(100).unwrap_err();
		assert!(format!("{err}").contains("exited"), "got: {err}");
	}

	#[test]
	fn exited_is_not_valid_anti_dos_proof() {
		let mut v = spendable();
		v.confirmed_height = Some(90);
		let err = v.check_valid_anti_dos_proof(100).unwrap_err();
		assert!(format!("{err}").contains("exited"), "got: {err}");
	}

	#[test]
	fn banned_is_not_valid_anti_dos_proof() {
		let mut v = spendable();
		v.spend_state = SpendState::Unregistered;
		v.banned_until_height = Some(200);
		assert!(v.check_valid_anti_dos_proof(100).is_err());
		assert!(v.check_valid_anti_dos_proof(200).is_ok());
	}

	#[test]
	fn spent_is_not_spendable() {
		let mut v = spendable();
		v.spend_state = SpendState::Spent;
		v.oor_spent_txid = Some(Txid::all_zeros());
		assert!(v.check_spendable(100).is_err());
	}

	#[test]
	fn banned_is_not_spendable() {
		let mut v = spendable();
		v.banned_until_height = Some(200);
		assert!(v.check_spendable(100).is_err());
		// At tip == 200 the ban has expired (not strictly greater).
		assert!(v.check_spendable(200).is_ok());
	}

	#[test]
	fn oor_spent_same_tx_is_spendable_for_oor() {
		let mut v = spendable();
		let txid = Txid::all_zeros();
		v.spend_state = SpendState::Spent;
		v.oor_spent_txid = Some(txid);
		// check_spendable rejects it
		assert!(v.check_spendable(100).is_err());
		// but check_spendable_for_oor allows it when the txid matches
		assert!(v.check_spendable_for_oor(100, txid).is_ok());
	}

	#[test]
	fn oor_spent_different_tx_is_not_spendable_for_oor() {
		let mut v = spendable();
		v.spend_state = SpendState::Spent;
		v.oor_spent_txid = Some(Txid::all_zeros());
		let other_txid = "0000000000000000000000000000000000000000000000000000000000000001"
			.parse().unwrap();
		assert!(v.check_spendable_for_oor(100, other_txid).is_err());
	}

	#[test]
	fn unregistered_is_not_spendable_for_oor() {
		let mut v = spendable();
		v.spend_state = SpendState::Unregistered;
		assert!(v.check_spendable_for_oor(100, Txid::all_zeros()).is_err());
	}

	#[test]
	fn htlc_vtxos_are_never_generically_spendable() {
		for (v, policy) in [
			(htlc_send(), "server-htlc-send-v1"),
			(htlc_recv(), "server-htlc-receive-v1"),
		] {
			let err = format!("{}", v.check_spendable(100).unwrap_err());
			assert!(err.contains("not spendable as a") && err.contains(policy), "got: {err}");
			// And the oor gate, which every arkoor path funnels through.
			let err = format!("{}", v.check_spendable_for_oor(100, Txid::all_zeros()).unwrap_err());
			assert!(err.contains("not spendable as a") && err.contains(policy), "got: {err}");
		}
	}

	#[test]
	fn htlc_send_is_spendable_by_the_lightning_send() {
		assert!(htlc_send().check_htlc_send_spendable(100).is_ok());
	}

	/// The lightning-send gate is not a way around the policy gate: it only
	/// takes the one policy it exists for.
	#[test]
	fn only_htlc_send_is_spendable_by_the_lightning_send() {
		for v in [spendable(), htlc_recv()] {
			let err = v.check_htlc_send_spendable(100).unwrap_err();
			assert!(format!("{err}").contains("not an htlc-send vtxo"), "got: {err}");
		}
	}

	/// State still gates the lightning send: a vtxo already consumed by a
	/// settled payment can't fund another one.
	#[test]
	fn spent_htlc_send_is_not_spendable_by_the_lightning_send() {
		let mut v = htlc_send();
		v.spend_state = SpendState::LnSpent;
		assert!(v.check_htlc_send_spendable(100).is_err());
		v.spend_state = SpendState::Spendable;
		v.banned_until_height = Some(200);
		assert!(v.check_htlc_send_spendable(100).is_err());
	}
}

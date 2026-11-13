//! Expiry payout transactions: the stored attempts of each payout, the
//! payout that each VTXO reports, and the locks that keep a watchman claim
//! from spending a decided tree.

use std::collections::{BTreeMap, BTreeSet};

use bitcoin::consensus::{deserialize, serialize};
use bitcoin::secp256k1::PublicKey;
use bitcoin::{Amount, FeeRate, ScriptBuf, Transaction, TxOut};

use ark::{ProtocolEncoding, ServerVtxo, VtxoId};
use bitcoin_ext::{BlockRef, TxOutExt};

use crate::database::Tx;
use crate::error::ExpiryPayoutRefusal;

/// The largest payout transaction that is still standard.
const MAX_PAYOUT_VSIZE: usize = 100_000;

/// The state of the expiry payout of a VTXO, as the wallet sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExpiryPayoutState {
	Pending,
	Paid,
	Forfeited,
}

/// The expiry payout decided for a VTXO.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ExpiryPayoutReceipt {
	pub state: ExpiryPayoutState,
	pub gross: Amount,
	pub fee: Amount,
	pub payout: Amount,
}

/// An expiry payout that is not confirmed and not conflicted.
pub struct PendingExpiryPayout {
	pub id: i64,
	pub inputs: Vec<ServerVtxo>,
	pub payouts: Vec<TxOut>,
	/// The latest stored attempt and its fee.
	pub latest: Option<(Transaction, Amount)>,
}

impl Tx<'_> {
	/// The payout decided for each VTXO in `owners`, which maps each VTXO to
	/// its owner mailbox. A payout to another mailbox, such as an arkoor
	/// output that the recipient never registered and that goes back to
	/// its sender, is not reported for the VTXO.
	pub(crate) async fn expiry_payout_receipts(&self, owners: &BTreeMap<VtxoId, PublicKey>)
		-> anyhow::Result<BTreeMap<VtxoId, ExpiryPayoutReceipt>>
	{
		if !self.expiry_payouts() || owners.is_empty() {
			return Ok(BTreeMap::new());
		}
		let ids = owners.keys().map(ToString::to_string).collect::<Vec<_>>();
		// The winning decision of each VTXO: a confirmed one, else the latest.
		let rows = self.query("SELECT DISTINCT ON (c.vtxo_id) c.vtxo_id,c.disposition,c.owner_mailbox, \
			c.gross_sat,c.fee_sat,c.payout_sat,a.status,v.confirmed_height IS NOT NULL AS exposed, \
			a.confirmed_height+5 <= (SELECT MAX(height) FROM watchmand_block) AS deep \
			FROM expiry_payout_vtxo c JOIN v_expiry_payout_state a ON a.id=c.expiry_payout_id \
			JOIN vtxo v ON v.vtxo_id=c.vtxo_id \
			WHERE c.vtxo_id=ANY($1) ORDER BY c.vtxo_id,(a.status='confirmed') DESC,c.expiry_payout_id DESC",
			&[&ids]).await?;
		let mut receipts = BTreeMap::new();
		for row in rows {
			let id: VtxoId = row.get::<_, &str>("vtxo_id").parse()?;
			let mailbox = row.get::<_, Option<&str>>("owner_mailbox").map(str::parse::<PublicKey>).transpose()?;
			if row.get::<_, &str>("disposition") != "owner" || mailbox.as_ref() != owners.get(&id) {
				continue;
			}
			// The owner exited the VTXO on-chain, so no payout follows.
			let status: &str = row.get("status");
			if status == "conflicted" && row.get::<_, bool>("exposed") { continue; }
			let amount = |column| -> anyhow::Result<Amount> {
				Ok(Amount::from_sat(u64::try_from(row.get::<_, i64>(column))?))
			};
			let payout = amount("payout_sat")?;
			let state = if status != "confirmed" || row.get::<_, Option<bool>>("deep") != Some(true) {
				ExpiryPayoutState::Pending
			} else if payout > Amount::ZERO { ExpiryPayoutState::Paid } else { ExpiryPayoutState::Forfeited };
			receipts.insert(id, ExpiryPayoutReceipt { state, gross: amount("gross_sat")?, fee: amount("fee_sat")?, payout });
		}
		Ok(receipts)
	}

	/// The owner outputs of an expiry payout: the total of each mailbox `M`,
	/// paid to `tr(M)`.
	async fn expiry_owner_outputs(&self, id: i64) -> anyhow::Result<BTreeMap<ScriptBuf, Amount>> {
		self.query("SELECT owner_mailbox,SUM(payout_sat)::BIGINT AS amount_sat FROM expiry_payout_vtxo \
			WHERE expiry_payout_id=$1 AND disposition='owner' GROUP BY owner_mailbox HAVING SUM(payout_sat)>0",
			&[&id]).await?.into_iter().map(|row| Ok((
				ark::expiry_payout::payout_script(row.get::<_, &str>("owner_mailbox").parse()?),
				Amount::from_sat(u64::try_from(row.get::<_, i64>("amount_sat"))?),
			))).collect()
	}

	/// The pending expiry payouts, in the order of their expiry.
	pub async fn pending_expiry_payouts(&self) -> anyhow::Result<Vec<PendingExpiryPayout>> {
		let rows = self.query("SELECT a.id,p.signed_tx,p.fee_sat FROM v_expiry_payout_state a \
			LEFT JOIN expiry_payout_attempt p ON p.expiry_payout_id=a.id AND p.txid=a.payout_txid \
			WHERE a.status='pending' ORDER BY a.expiry_height,a.id", &[]).await?;
		let mut ret = Vec::with_capacity(rows.len());
		for row in rows {
			let id: i64 = row.get("id");
			let inputs = self.query("
				SELECT v.vtxo
				FROM expiry_payout_input i JOIN vtxo v ON v.vtxo_id=i.vtxo_id
				WHERE i.expiry_payout_id=$1
				ORDER BY v.vtxo_id
			", &[&id]).await?
				.into_iter().map(|r| ServerVtxo::deserialize(r.get("vtxo"))).collect::<Result<Vec<_>, _>>()?;
			let payouts = self.expiry_owner_outputs(id).await?.into_iter()
				.map(|(script_pubkey, value)| TxOut { script_pubkey, value }).collect();
			let latest = match row.get::<_, Option<&[u8]>>("signed_tx") {
				Some(tx) => Some((deserialize(tx)?, Amount::from_sat(u64::try_from(row.get::<_, i64>("fee_sat"))?))),
				None => None,
			};
			ret.push(PendingExpiryPayout { id, inputs, payouts, latest });
		}
		Ok(ret)
	}

	/// Store a signed payout attempt before it is broadcast, after checking
	/// it again against the stored payout. Every attempt is kept, because
	/// an older one can still confirm.
	pub async fn store_expiry_attempt(
		&self, view: BlockRef, id: i64, payout: &Transaction,
		fee: Amount, operator_spk: &ScriptBuf, max_fee_rate: FeeRate,
	) -> anyhow::Result<()> {
		self.lock_watchman_tip(view).await?;
		self.query_one("SELECT id FROM expiry_payout WHERE id=$1 FOR UPDATE", &[&id]).await?;
		let state = self.query_one("SELECT status FROM v_expiry_payout_state WHERE id = $1", &[&id]).await?;
		ensure!(state.get::<_, &str>("status") == "pending", "expiry payout is not pending");
		ensure!(payout.version == bitcoin::transaction::Version::TWO
			&& payout.vsize() <= MAX_PAYOUT_VSIZE
			&& payout.input.iter().any(|input| input.sequence.to_consensus_u32() <= 0xFFFFFFFD)
			&& payout.output.iter().all(TxOutExt::is_standard),
			"expiry payout attempt is nonstandard or lacks RBF");
		let roots = self.query("SELECT v.vtxo FROM expiry_payout_input i \
			JOIN vtxo v ON v.vtxo_id=i.vtxo_id WHERE i.expiry_payout_id=$1", &[&id]).await?
			.into_iter().map(|row| ServerVtxo::deserialize(row.get("vtxo")))
			.collect::<Result<Vec<ServerVtxo>, _>>()?;
		let expired_tree = roots.iter().map(|root| root.point()).collect::<BTreeSet<_>>();
		let spent = payout.input.iter().map(|input| input.previous_output)
			.collect::<BTreeSet<_>>();
		ensure!(!expired_tree.is_empty() && expired_tree.is_subset(&spent)
			&& spent.len() == payout.input.len(),
			"expiry payout attempt omits or duplicates allocated expired tree");
		let expected = self.expiry_owner_outputs(id).await?;
		ensure!(!expected.contains_key(operator_spk),
			"operator drain aliases an owner script");
		let owner_outputs = payout.output.iter().filter(|out| expected.contains_key(&out.script_pubkey))
			.collect::<Vec<_>>();
		ensure!(owner_outputs.len() == expected.len() && owner_outputs.iter().all(|out|
			expected.get(&out.script_pubkey) == Some(&out.value)),
			"expiry payout attempt changes owner outputs");
		// The owners are paid from the roots only. Watchman inputs can pay
		// the mining fee, never an owner.
		let swept = roots.iter().try_fold(Amount::ZERO, |sum, root| sum.checked_add(root.amount()));
		let owed = expected.values().try_fold(Amount::ZERO, |sum, value| sum.checked_add(*value));
		ensure!(owed.zip(swept).is_some_and(|(owed, swept)| owed <= swept),
			"expiry payout attempt pays owners more than its roots hold");
		let other = payout.output.iter().filter(|out| !expected.contains_key(&out.script_pubkey))
			.collect::<Vec<_>>();
		ensure!(other.len() <= 1 && other.iter().all(|out| &out.script_pubkey == operator_spk),
			"expiry payout attempt pays an unknown script");
		let txid = payout.compute_txid().to_string();
		let raw = serialize(payout);
		let fee_sat = i64::try_from(fee.to_sat())?;
		if let Some(same) = self.query_opt("SELECT signed_tx,fee_sat FROM expiry_payout_attempt \
			WHERE expiry_payout_id=$1 AND txid=$2", &[&id,&txid]).await? {
			ensure!(same.get::<_, &[u8]>("signed_tx") == raw.as_slice() && same.get::<_, i64>("fee_sat") == fee_sat,
				"stored expiry payout attempt changed bytes or fee");
			return Ok(());
		}
		// Watchman inputs pay the fee, so a bad fee estimate must not drain
		// the watchman wallet.
		ensure!(max_fee_rate.fee_wu(payout.weight()).is_some_and(|max| fee <= max),
			"expiry payout attempt fee {} for {} vB exceeds the {} sat/vB ceiling",
			fee, payout.vsize(), max_fee_rate.to_sat_per_vb_ceil());
		let prior_fee = self.query_one("SELECT MAX(fee_sat) FROM expiry_payout_attempt WHERE expiry_payout_id=$1",
			&[&id]).await?.get::<_, Option<i64>>(0);
		ensure!(prior_fee.is_none_or(|prior| fee_sat > prior),
			"expiry payout replacement does not raise the absolute fee");
		self.execute("INSERT INTO expiry_payout_attempt(expiry_payout_id,txid,signed_tx,fee_sat) \
			VALUES($1,$2,$3,$4)", &[&id,&txid,&raw,&fee_sat]).await?;
		Ok(())
	}

	/// Record when the payout was first seen in the mempool or a block.
	pub async fn mark_expiry_payout_broadcast(&self, id: i64) -> anyhow::Result<()> {
		self.execute("UPDATE expiry_payout SET broadcast_at = COALESCE(broadcast_at, NOW()) WHERE id = $1",
			&[&id]).await?;
		Ok(())
	}

	/// Lock the inputs of a watchman claim through its broadcast.
	pub async fn lock_watchman_claim_inputs(&self, vtxos: &[ServerVtxo]) -> anyhow::Result<()> {
		if !self.expiry_payouts() { return Ok(()); }
		let ids = vtxos.iter().map(|vtxo| vtxo.id()).collect::<Vec<_>>();
		self.lock_unallocated_watchman_inputs(&ids).await
	}

	/// Lock the inputs of a watchman claim through its broadcast, and refuse
	/// a claim of a tree that an expiry payout spends. The locks are taken
	/// in VTXO id order, as the decision takes them.
	pub async fn lock_unallocated_watchman_inputs(&self, ids: &[ark::VtxoId]) -> anyhow::Result<()> {
		if !self.expiry_payouts() { return Ok(()); }
		let ids = ids.iter().map(ToString::to_string).collect::<Vec<_>>();
		self.query("SELECT vtxo_id FROM vtxo WHERE vtxo_id=ANY($1) ORDER BY vtxo_id FOR UPDATE", &[&ids]).await?;
		// A root stays taken while its payout is pending or confirmed. An
		// operator decision stays taken until all its payouts conflicted. An
		// owner decision stays taken after a conflict too.
		if let Some(row) = self.query_opt("SELECT vtxo_id FROM ( \
			SELECT i.vtxo_id FROM expiry_payout_input i JOIN v_expiry_payout_state a ON a.id=i.expiry_payout_id \
				WHERE i.vtxo_id=ANY($1) AND a.status<>'conflicted' \
			UNION SELECT c.vtxo_id FROM expiry_payout_vtxo c JOIN v_expiry_payout_state a ON a.id=c.expiry_payout_id \
				WHERE c.vtxo_id=ANY($1) AND (a.status<>'conflicted' OR c.disposition='owner')) guarded \
			ORDER BY vtxo_id LIMIT 1", &[&ids]).await? {
			return Err(ExpiryPayoutRefusal::DecidedForPayout(row.get::<_, &str>("vtxo_id").parse()?).into());
		}
		Ok(())
	}
}

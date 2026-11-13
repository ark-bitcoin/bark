//! Decide the payout of each expired tree. The watchman plans the payout of
//! a root in a read without locks, then commits it in a short write that
//! checks every fact of the plan again under its locks.

use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;

use anyhow::Context;
use bitcoin::{Amount, Txid};
use bitcoind_async_client::traits::Reader;
use chrono::{DateTime, Local};
use tokio_postgres::Row;

use ark::vtxo::{Bare, Full, VtxoValidationError};
use ark::{ProtocolDecodingError, ProtocolEncoding, ServerVtxo, ServerVtxoPolicy, VtxoId};
use bitcoin_ext::{BlockHeight, BlockRef};

use crate::database::{BlockTable, SpendState, Tx, VtxoState};

use super::allocation::{allocate, OwnerLeaf};
use super::ownership::{OwnershipDisposition, OwnershipEvidence, OwnershipProposal};

/// Check that the watchman tip is still in the best chain of bitcoind.
pub(crate) async fn verify_expiry_tip(point: BlockRef, client: &bitcoind_async_client::Client) -> anyhow::Result<()> {
	ensure!(client.get_block_hash(point.height.into()).await? == point.hash,
		"published watchman tip is not in the best chain");
	Ok(())
}

impl Tx<'_> {
	/// Lock the watchman block table against a reorg until the transaction
	/// ends, and check that its tip is still `point`.
	pub async fn lock_watchman_tip(&self, point: BlockRef) -> anyhow::Result<()> {
		self.lock_watchman_blocks().await?;
		ensure!(self.get_highest_block(BlockTable::Watchmand).await? == Some(point), "published watchman tip changed");
		Ok(())
	}

	/// Lock the watchman block table against a reorg until the transaction
	/// ends.
	pub(crate) async fn lock_watchman_blocks(&self) -> anyhow::Result<()> {
		// A reorg never removes the lowest row, so a lock on that row
		// orders the decisions and the reorgs.
		self.query("SELECT height FROM watchmand_block ORDER BY height ASC LIMIT 1 FOR SHARE", &[]).await?;
		Ok(())
	}
}

/// A VTXO of an expired tree, with its chain state.
#[derive(Clone)]
pub struct ExpiredTreeVtxo {
	pub state: VtxoState<Bare, ServerVtxoPolicy>,
	/// The VTXO with its path, if the stored encoding has the full path.
	/// This does not prove that the path is signed.
	pub full_vtxo: Option<ServerVtxo<Full>>,
	pub onchain_spent_height: Option<BlockHeight>,
	pub onchain_spent_txid: Option<Txid>,
	pub lightning_htlc_subscription_id: Option<i64>,
}

/// The VTXOs of the trees under the roots `$1`: each root, and the arkoor
/// outputs that spend them, down to the VTXOs that a round or an offboard
/// spends.
const SNAPSHOT: &str = "
WITH RECURSIVE current_branch AS (
	SELECT vtxo_id,oor_spent_txid,spent_in_round,offboarded_in FROM vtxo
	WHERE vtxo_id=ANY($1)
	UNION
	SELECT v.vtxo_id,v.oor_spent_txid,v.spent_in_round,v.offboarded_in
	FROM vtxo v JOIN current_branch p ON v.vtxo_txid=p.oor_spent_txid
	WHERE p.spent_in_round IS NULL AND p.offboarded_in IS NULL
)
SELECT vtxo_id,anchor_point,id,vtxo,expiry,exit_delta,policy,server_pubkey,amount,
	oor_spent_txid,spent_in_round,offboarded_in,
	banned_until_height,confirmed_height,spend_state::TEXT,created_at,updated_at,
	EXISTS(SELECT 1 FROM expiry_payout_vtxo d WHERE d.vtxo_id=v.vtxo_id) AS decided_for_payout,
	onchain_spent_height,onchain_spent_txid,lightning_htlc_subscription_id
FROM vtxo v WHERE vtxo_id IN (SELECT vtxo_id FROM current_branch)
ORDER BY vtxo_id";

impl Tx<'_> {
	/// The VTXOs of the expired trees under `roots`.
	pub async fn expired_tree_snapshot(&self, roots: &[ServerVtxo]) -> anyhow::Result<Vec<ExpiredTreeVtxo>> {
		let selected = roots.iter().map(|root| root.id().to_string()).collect::<Vec<_>>();
		let rows = self.query(SNAPSHOT, &[&selected]).await?;
		let mut ret = Vec::with_capacity(rows.len());
		for row in rows {
			let onchain_spent_height = optional_height(&row, "onchain_spent_height")?;
			let onchain_spent_txid = row.get::<_, Option<&str>>("onchain_spent_txid").map(Txid::from_str).transpose()?;
			let lightning_htlc_subscription_id = row.get("lightning_htlc_subscription_id");
			let full_vtxo = decode_genesis(row.get("vtxo"))?;
			let state = VtxoState::<Bare, ServerVtxoPolicy>::try_from(row)?;
			ret.push(ExpiredTreeVtxo { state, full_vtxo, onchain_spent_height, onchain_spent_txid,
				lightning_htlc_subscription_id });
		}
		Ok(ret)
	}
}

fn decode_genesis(bytes: &[u8]) -> anyhow::Result<Option<ServerVtxo<Full>>> {
	match ServerVtxo::<Full>::deserialize(bytes) {
		Ok(full) => Ok(Some(full)),
		Err(ProtocolDecodingError::Invalid { source: Some(source), .. })
			if matches!(source.downcast_ref::<VtxoValidationError>(), Some(VtxoValidationError::MissingGenesisItems)) =>
		{
			Ok(None)
		},
		Err(error) => Err(error.into()),
	}
}

fn optional_height(row: &Row, column: &str) -> anyhow::Result<Option<BlockHeight>> {
	row.get::<_, Option<i32>>(column).map(BlockHeight::try_from).transpose().context("invalid snapshot chain height")
}

/// The planned payout of one expired root. The commit writes it only if
/// every fact that it rests on is unchanged under the commit's locks.
pub struct ExpiryRootPlan {
	root: ServerVtxo,
	vtxos: Vec<OwnershipProposal>,
	branch: ExpiryBranchState,
	decided: BTreeSet<VtxoId>,
}

/// The VTXO rows of a tree, and every round participation and lightning
/// attempt that spends them. Any change to a VTXO row sets its updated_at.
#[derive(PartialEq)]
struct ExpiryBranchState {
	rows: Vec<(VtxoId, DateTime<Local>, SpendState, Option<BlockHeight>, Option<Txid>)>,
	parts: Vec<i64>,
	attempts: Vec<(i64, Option<i64>)>,
}

impl Tx<'_> {
	async fn expiry_branch_state(&self, roots: &[ServerVtxo]) -> anyhow::Result<(Vec<ExpiredTreeVtxo>, ExpiryBranchState)> {
		let snapshot = self.expired_tree_snapshot(roots).await?;
		let mut ids = snapshot.iter().map(|fact| fact.state.vtxo_id.to_string()).collect::<Vec<_>>();
		let hashes = snapshot.iter().filter_map(|fact| fact.full_vtxo.as_ref().and_then(|vtxo| vtxo.unlock_hash()))
			.map(|hash| hash.to_string()).collect::<Vec<_>>();
		let parts = self.query("SELECT DISTINCT p.id FROM round_participation p \
			LEFT JOIN round_part_input i ON i.participation_id=p.id \
			WHERE i.vtxo_id=ANY($1) OR p.unlock_hash=ANY($2) ORDER BY p.id", &[&ids, &hashes]).await?
			.into_iter().map(|row| row.get::<_, i64>("id")).collect::<Vec<_>>();
		ids.extend(self.query("SELECT vtxo_id FROM round_part_input WHERE participation_id=ANY($1)", &[&parts]).await?
			.into_iter().map(|row| row.get::<_, String>("vtxo_id")));
		let attempts = self.query("
			SELECT DISTINCT a.id,a.lightning_htlc_subscription_id
			FROM lightning_payment_attempt a
			JOIN lightning_payment_attempt_htlc_vtxo i ON i.lightning_payment_attempt_id = a.id
			WHERE i.vtxo_id = ANY($1)
			ORDER BY a.id
		", &[&ids]).await?.into_iter().map(|row| (row.get(0), row.get(1))).collect();
		let rows = snapshot.iter().map(|fact| (fact.state.vtxo_id, fact.state.updated_at, fact.state.spend_state,
			fact.onchain_spent_height, fact.onchain_spent_txid)).collect();
		Ok((snapshot, ExpiryBranchState { rows, parts, attempts }))
	}

	/// `None` if the VTXO was never decided, else whether a new decision
	/// can take it: every expiry payout that holds it has conflicted.
	async fn earlier_decision_free(&self, id: VtxoId) -> anyhow::Result<Option<bool>> {
		Ok(self.query_opt("SELECT BOOL_AND(a.status='conflicted') AS free FROM expiry_payout_vtxo c \
			JOIN v_expiry_payout_state a ON a.id=c.expiry_payout_id WHERE c.vtxo_id=$1 HAVING COUNT(*)>0",
			&[&id.to_string()]).await?.map(|row| row.get("free")))
	}

	/// Plan the payout of a root in one consistent read, without locks.
	/// `None` if the root is not ready.
	pub async fn plan_expiry_root(
		&self, view: BlockRef, root: ServerVtxo,
	) -> anyhow::Result<Option<ExpiryRootPlan>> {
		self.batch_execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ").await?;
		ensure!(root.expiry_height() <= view.height, "expiry root is not mature");
		let mut decided = BTreeSet::new();
		let current = self.query_opt("SELECT vtxo_id FROM vtxo WHERE vtxo_id=$1 AND frontier_at IS NOT NULL \
			AND confirmed_height<=$2 AND onchain_spent_height IS NULL AND onchain_spent_txid IS NULL",
			&[&root.id().to_string(), &i32::try_from(view.height.to_u32())?]).await?;
		if current.is_none() { return Ok(None); }
		let snapshot = self.expired_tree_snapshot(std::slice::from_ref(&root)).await?;
		let mut vtxos = Vec::new();
		let mut valid = true;
		for fact in &snapshot {
			if fact.onchain_spent_height.is_some() || fact.onchain_spent_txid.is_some() {
				valid = false;
				break;
			}
			// A VTXO spent off-chain is decided through its children. A
			// co-signed board without registration has no child, so its
			// funding output is decided. Any other spend without a child is
			// held below.
			let spent_offchain = fact.state.oor_spent_txid
				.filter(|_| fact.state.offboarded_in.is_none() && fact.state.spent_in_round.is_none());
			if spent_offchain.is_some_and(|txid| snapshot.iter().any(|child| child.state.vtxo.point().txid == txid)) {
				continue;
			}
			let ownership = self.propose_expiry_ownership(fact, view.height).await?;
			if let OwnershipDisposition::Unresolved(reason) = ownership.disposition {
				slog!(ExpiryHoldObserved, vtxo_id: ownership.id, reason: reason.to_owned());
				valid = false;
				continue;
			}
			if let Some(free) = self.earlier_decision_free(ownership.id).await? {
				valid &= free;
				decided.insert(ownership.id);
			}
			vtxos.push(ownership);
		}
		// The owners are paid from the value of the root only.
		let owed = vtxos.iter().filter(|vtxo| matches!(vtxo.disposition, OwnershipDisposition::Owner { .. }))
			.try_fold(Amount::ZERO, |sum, vtxo| sum.checked_add(vtxo.gross)).context("expiry branch amount overflow")?;
		ensure!(owed <= root.amount(), "expiry branch owes its owners more than its root holds");
		if vtxos.is_empty() {
			slog!(ExpiryHoldObserved, vtxo_id: root.id(), reason: "tree has no VTXO to decide".to_owned());
		}
		if valid && !vtxos.is_empty() {
			let cancellations = vtxos.iter().flat_map(|vtxo| vtxo.cancellations.iter().copied()).collect::<Vec<_>>();
			valid = self.can_cancel_expiry_participations(&cancellations).await?;
		}
		if !valid || vtxos.is_empty() { return Ok(None); }
		let (_, branch) = self.expiry_branch_state(std::slice::from_ref(&root)).await?;
		Ok(Some(ExpiryRootPlan { root, vtxos, branch, decided }))
	}

	/// Lock the tree of the root, check every fact of the plan again under
	/// those locks, then store the payout and cancel the participations it
	/// takes. Returns the id of the expiry payout.
	pub async fn commit_expiry_root(
		&self, view: BlockRef, plan: ExpiryRootPlan,
	) -> anyhow::Result<i64> {
		let ExpiryRootPlan { root, vtxos, branch, decided } = plan;
		self.lock_watchman_tip(view).await?;
		let ids = branch.rows.iter().map(|row| row.0.to_string()).collect::<Vec<_>>();
		self.query("SELECT vtxo_id FROM vtxo WHERE vtxo_id=ANY($1) ORDER BY vtxo_id FOR UPDATE", &[&ids]).await?;
		let (snapshot, current) = self.expiry_branch_state(std::slice::from_ref(&root)).await?;
		ensure!(current == branch, "expiry branch changed during analysis");
		let lightning = vtxos.iter()
			.filter(|vtxo| vtxo.evidence.as_ref().is_some_and(OwnershipEvidence::is_lightning))
			.collect::<Vec<_>>();
		if !lightning.is_empty() {
			self.lock_htlc_settlements().await?;
			let mut subscriptions = branch.attempts.iter().filter_map(|attempt| attempt.1)
				.chain(snapshot.iter().filter_map(|fact| fact.lightning_htlc_subscription_id)).collect::<Vec<_>>();
			subscriptions.sort_unstable();
			subscriptions.dedup();
			self.query("SELECT id FROM lightning_htlc_subscription WHERE id = ANY($1) ORDER BY id FOR SHARE",
				&[&subscriptions]).await?;
			for vtxo in lightning {
				let fact = snapshot.iter().find(|fact| fact.state.vtxo_id == vtxo.id)
					.context("expiry VTXO left its branch")?;
				ensure!(self.propose_expiry_ownership(fact, view.height).await? == *vtxo,
					"expiry lightning facts changed during analysis");
			}
		}
		for vtxo in &vtxos {
			ensure!(self.earlier_decision_free(vtxo.id).await? == decided.contains(&vtxo.id).then_some(true),
				"earlier expiry decision changed during analysis");
		}
		// Each owner pays one fee for this root, even if other trees expire
		// at the same height.
		let leaves = vtxos.iter().filter_map(|c| match c.disposition {
			OwnershipDisposition::Owner { mailbox } => Some(OwnerLeaf {
				id: c.id, script: ark::expiry_payout::payout_script(mailbox), amount: c.gross,
			}),
			_ => None,
		}).collect();
		let amounts = allocate(leaves)?;

		// The checks above write nothing. If a cancellation now fails, the
		// whole decision rolls back.
		let cancellations = vtxos.iter().flat_map(|c| c.cancellations.iter().copied()).collect::<Vec<_>>();
		ensure!(self.cancel_expiry_participations(&cancellations).await?,
			"selected expiry cancellation changed under its locks");
		let amounts = amounts.iter().map(|a| (a.id, a)).collect::<BTreeMap<_, _>>();
		let id: i64 = self.query_one("INSERT INTO expiry_payout(expiry_height) VALUES($1) RETURNING id",
			&[&i32::try_from(root.expiry_height().to_u32())?]).await?.get(0);
		self.execute("INSERT INTO expiry_payout_input (expiry_payout_id, vtxo_id) VALUES ($1, $2)",
			&[&id, &root.id().to_string()]).await?;
		for proposal in &vtxos {
			let evidence = proposal.evidence.as_ref().context("ready ownership lacks evidence")?;
			let allocation = amounts.get(&proposal.id);
			let fee = allocation.map_or(Amount::ZERO, |a| a.fee).to_sat();
			let payout = allocation.map_or(Amount::ZERO, |a| a.payout).to_sat();
			let (disposition, mailbox) = match proposal.disposition {
				OwnershipDisposition::Owner { mailbox } => ("owner", Some(mailbox.to_string())),
				OwnershipDisposition::Operator => ("operator", None),
				OwnershipDisposition::Unresolved(_) => bail!("expiry payout ownership is unresolved"),
			};
			self.execute("
				INSERT INTO expiry_payout_vtxo (expiry_payout_id, vtxo_id, owner_mailbox, disposition,
					gross_sat, fee_sat, payout_sat, replannable)
				VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
			",
				&[
					&id,
					&proposal.id.to_string(),
					&mailbox,
					&disposition,
					&i64::try_from(proposal.gross.to_sat())?,
					&i64::try_from(fee)?,
					&i64::try_from(payout)?,
					&evidence.replannable(),
				]).await?;
			self.execute("UPDATE vtxo SET spend_state = 'spent', updated_at = NOW() WHERE vtxo_id = $1",
				&[&proposal.id.to_string()]).await?;
		}
		Ok(id)
	}
}

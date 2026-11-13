//! The owner of each VTXO: the owner mailbox recorded when the VTXO was
//! created, and the decision of who gets the value of an expired VTXO.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::str::FromStr;

use anyhow::Context;
use bitcoin::{Amount, OutPoint};
use bitcoin::secp256k1::PublicKey;

use ark::{ServerVtxoPolicy, VtxoId, VtxoPolicy};
use ark::lightning::PaymentHash;
use ark::mailbox::MailboxIdentifier;
use bitcoin_ext::BlockHeight;

use crate::database::{AdvisoryLock, SpendState, Tx};
use crate::database::htlc_vtxo::{self, HtlcDirection, HtlcResolution, HtlcVtxo};
use crate::database::ln::{LightningHtlcSubscriptionStatus, LightningPaymentStatus};
use crate::round::UNSPENDABLE;

use super::decision::ExpiredTreeVtxo;

/// The owner mailboxes of a write differ from the new VTXOs that need one.
/// The write stores nothing, so its caller can drop it: a round with such
/// an output fails, and the server keeps running rounds.
#[derive(Debug)]
pub struct OwnerBindingMismatch;

impl fmt::Display for OwnerBindingMismatch {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str("mailbox binding set differs from the owner VTXOs")
	}
}

impl std::error::Error for OwnerBindingMismatch {}

impl Tx<'_> {
	/// The owner mailbox recorded for each VTXO when it was created. The
	/// VTXO ids that a mailbox holder stores for recovery are not in it.
	pub async fn vtxo_owner_mailboxes(&self, ids: &[VtxoId]) -> anyhow::Result<BTreeMap<VtxoId, PublicKey>> {
		let ids = ids.iter().map(ToString::to_string).collect::<Vec<_>>();
		self.query("SELECT vtxo_id,mailbox_pk FROM vtxo_owner_mailbox WHERE vtxo_id=ANY($1)", &[&ids]).await?
			.into_iter().map(|row| Ok((row.get::<_, &str>(0).parse()?,
				row.get::<_, &str>(1).parse()?))).collect()
	}

	/// In payout mode, refuse to post VTXOs to a mailbox that is not the
	/// owner mailbox of each of them.
	pub(crate) async fn check_owner_mailbox(&self, mailbox: MailboxIdentifier, ids: &[VtxoId]) -> anyhow::Result<()> {
		if !self.expiry_payouts() {
			return Ok(());
		}
		let owners = self.vtxo_owner_mailboxes(ids).await?;
		for id in ids {
			if owners.get(id) != Some(&mailbox.as_pubkey()) {
				return badarg!("vtxo {} does not belong to the provided mailbox", id);
			}
		}
		Ok(())
	}

	/// Store the owner mailbox of each new VTXO in `owned`. `bindings` must
	/// hold the mailbox registered for each of them, and no other VTXO. A
	/// VTXO that is inserted again must have the mailbox it has already.
	pub(crate) async fn store_vtxo_owner_mailboxes(
		&self,
		owned: &[VtxoId],
		bindings: &BTreeMap<VtxoId, PublicKey>,
	) -> anyhow::Result<()> {
		let mut ids = Vec::with_capacity(owned.len());
		let mut mailboxes = Vec::with_capacity(owned.len());
		for id in owned {
			let mailbox = bindings.get(id).ok_or(OwnerBindingMismatch)
				.with_context(|| format!("owner VTXO {id} has no registered mailbox"))?;
			ids.push(id.to_string());
			mailboxes.push(mailbox.to_string());
		}
		if bindings.len() != owned.len() {
			return Err(OwnerBindingMismatch.into());
		}
		self.execute("INSERT INTO vtxo_owner_mailbox (vtxo_id, mailbox_pk) \
			SELECT u.vtxo_id, u.mailbox_pk FROM UNNEST($1::TEXT[], $2::TEXT[]) AS u(vtxo_id, mailbox_pk) \
			ON CONFLICT (vtxo_id) DO NOTHING", &[&ids, &mailboxes]).await?;
		let stored = self.vtxo_owner_mailboxes(owned).await?;
		for id in owned {
			ensure!(stored.get(id) == bindings.get(id), "owner VTXO {id} has a conflicting mailbox binding");
		}
		Ok(())
	}

	/// The owner mailbox of the user VTXOs that an unregistered arkoor output
	/// spends, found through the registered arkoor spends. All of them must
	/// have the same mailbox. The sender keeps a value that the recipient
	/// never registered.
	pub(crate) async fn expiry_input_owner(&self, id: VtxoId) -> anyhow::Result<Option<PublicKey>> {
		let mut pending = vec![id];
		let mut seen = BTreeSet::from([id]);
		let mut mailboxes = BTreeSet::new();
		while let Some(current_id) = pending.pop() {
			let current = self.get_server_vtxo_by_id(current_id).await?.vtxo;
			let Some(last) = current.transactions().last() else { return Ok(None); };
			if last.tx.input.is_empty() { return Ok(None); }
			for input in &last.tx.input {
				let parent = VtxoId::from(input.previous_output);
				if !seen.insert(parent) { return Ok(None); }
				let Some(row) = self.query_opt("SELECT v.vtxo_id,c.mailbox_pk FROM vtxo v \
					LEFT JOIN vtxo_owner_mailbox c ON c.vtxo_id=v.vtxo_id \
					WHERE v.vtxo_id=$1 AND v.oor_spent_txid=$2",
					&[&parent.to_string(), &current.point().txid.to_string()]).await? else { return Ok(None); };
				let source = self.get_server_vtxo_by_id(parent).await?.vtxo;
				match source.policy() {
					ServerVtxoPolicy::Checkpoint(_) => pending.push(parent),
					ServerVtxoPolicy::User(_) => {
						let Some(mailbox) = row.get::<_, Option<&str>>("mailbox_pk") else { return Ok(None); };
						mailboxes.insert(PublicKey::from_str(mailbox)?);
					},
					_ => return Ok(None),
				}
			}
		}
		if mailboxes.len() != 1 { return Ok(None); }
		Ok(mailboxes.pop_first())
	}
}

/// What the payment attempts of an HTLC-send VTXO did with it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LightningSourceState {
	Unattempted,
	Failed,
	Pending,
	Discharged,
}

/// Fold the attempts of one source, each with whether the receive it was
/// initiated against is canceled.
///
/// An open attempt on a canceled receive counts as failed: a canceled receive
/// refuses every claim, so that attempt can never succeed, and nothing fails
/// it if the server stopped between canceling the receive and failing it.
fn source_state(attempts: impl IntoIterator<Item = (LightningPaymentStatus, bool)>) -> LightningSourceState {
	let mut state = LightningSourceState::Unattempted;
	for (status, receive_canceled) in attempts {
		match status {
			LightningPaymentStatus::Succeeded => return LightningSourceState::Discharged,
			LightningPaymentStatus::Requested | LightningPaymentStatus::Submitted if !receive_canceled => {
				state = LightningSourceState::Pending;
			},
			_ if state == LightningSourceState::Unattempted => state = LightningSourceState::Failed,
			_ => {},
		}
	}
	state
}

impl Tx<'_> {
	/// Hold off any new HTLC settlement until this transaction ends, so a
	/// decision made while no preimage is stored stays valid at commit.
	pub(crate) async fn lock_htlc_settlements(&self) -> anyhow::Result<()> {
		self.execute("SELECT pg_advisory_xact_lock_shared($1)",
			&[&(AdvisoryLock::HtlcSettlementWrite as i64)]).await?;
		Ok(())
	}

	/// What the payment attempts that spend `source` for `hash` did with it.
	pub(crate) async fn lightning_source_state(
		&self, source: VtxoId, hash: PaymentHash,
	) -> anyhow::Result<LightningSourceState> {
		let rows = self.query("SELECT a.status, COALESCE(s.status='canceled', FALSE) AS receive_canceled \
			FROM lightning_payment_attempt a \
			JOIN lightning_payment_attempt_htlc_vtxo l ON l.lightning_payment_attempt_id=a.id \
			LEFT JOIN lightning_htlc_subscription s ON s.id=a.lightning_htlc_subscription_id \
			WHERE l.vtxo_id=$1 AND a.payment_hash=$2", &[&source.to_string(), &hash.to_string()]).await?;
		Ok(source_state(rows.into_iter().map(|row| (row.get("status"), row.get("receive_canceled")))))
	}

	/// Whether the intra-Ark receive that a failed source paid cannot be
	/// claimed any more: it is canceled, and every grant it issued is past its
	/// expiry, or six blocks deep if the operator took it back on-chain.
	///
	/// `None` if the source paid no receive that issued grants. `htlcs` are
	/// all the HTLCs of the payment hash, which has at most one receive.
	pub(crate) async fn internal_receive_closed(
		&self, source: VtxoId, hash: PaymentHash, htlcs: &[HtlcVtxo], tip: BlockHeight,
	) -> anyhow::Result<Option<bool>> {
		let row = self.query_one("SELECT COUNT(*) AS linked, \
			COUNT(*) FILTER (WHERE s.status<>'canceled') AS open \
			FROM lightning_payment_attempt a \
			JOIN lightning_payment_attempt_htlc_vtxo l ON l.lightning_payment_attempt_id=a.id \
			JOIN lightning_htlc_subscription s ON s.id=a.lightning_htlc_subscription_id \
			WHERE l.vtxo_id=$1 AND a.payment_hash=$2", &[&source.to_string(), &hash.to_string()]).await?;
		if row.get::<_, i64>("linked") == 0 || !htlcs.iter().any(|h| h.direction() == HtlcDirection::Outgoing) {
			return Ok(None);
		}
		Ok(Some(row.get::<_, i64>("open") == 0
			&& payout_htlc_recvs_expired(htlcs, tip, Some(tip))))
	}
}

/// Who gets the value of an expired VTXO. An owner is paid to `tr(M)`,
/// with `M` the owner mailbox recorded when the VTXO was created.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OwnershipDisposition {
	Owner { mailbox: PublicKey },
	Operator,
	Unresolved(&'static str),
}

/// The fact that a disposition rests on. A fact that comes from the chain is
/// read again after a reorg.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OwnershipEvidence {
	Pubkey,
	Board,
	PriorDecision,
	InputOwner,
	Pool,
	Padding,
	Forfeit,
	Offboard,
	Participation,
	HtlcOffchain,
	HtlcStoredPreimage,
	HtlcSourceDischarged,
	/// No payment was attempted, and both daemons passed the HTLC expiry.
	HtlcUnattemptedExpired,
	HtlcExternalFailed,
	/// The intra-Ark receive that the source paid is closed on-chain.
	HtlcInternalGrantsReclaimed,
	/// A receive grant that is not settled, is past its HTLC expiry and is
	/// not spent on-chain. The operator takes its value with the payout of
	/// its tree. A later preimage spend conflicts with that payout.
	HtlcRecvExpired,
}

impl OwnershipEvidence {
	/// A decision that rests on a lightning payment is made again after a
	/// conflict. Any other decision is repeated as it is.
	pub fn replannable(&self) -> bool {
		matches!(self, Self::HtlcOffchain | Self::HtlcStoredPreimage
			| Self::HtlcInternalGrantsReclaimed | Self::HtlcRecvExpired)
	}

	/// Whether the decision rests on the state of a lightning payment.
	pub fn is_lightning(&self) -> bool {
		matches!(self, Self::HtlcOffchain | Self::HtlcStoredPreimage | Self::HtlcSourceDischarged
			| Self::HtlcUnattemptedExpired | Self::HtlcExternalFailed | Self::HtlcInternalGrantsReclaimed
			| Self::HtlcRecvExpired)
	}
}

/// The proposed decision for one VTXO of an expired tree.
#[derive(Debug, Clone, PartialEq)]
pub struct OwnershipProposal {
	pub id: VtxoId,
	pub gross: Amount,
	pub disposition: OwnershipDisposition,
	pub evidence: Option<OwnershipEvidence>,
	/// The round participations that the decision cancels. The commit of
	/// the decision cancels them in the same transaction, never before.
	pub cancellations: Vec<i64>,
}

impl OwnershipProposal {
	fn pending(fact: &ExpiredTreeVtxo, reason: &'static str) -> Self {
		Self {
			id: fact.state.vtxo_id, gross: fact.state.vtxo.amount(),
			disposition: OwnershipDisposition::Unresolved(reason), evidence: None,
			cancellations: Vec::new(),
		}
	}
}

impl Tx<'_> {
	/// The owner key and the owner mailbox of a co-signed board that was
	/// never registered. Its funding output owes the owner a payout. Once
	/// the board is registered, its VTXO has the owner instead.
	pub(crate) async fn unregistered_board_owner(&self, id: VtxoId)
		-> anyhow::Result<Option<(PublicKey, PublicKey)>>
	{
		let Some(row) = self.query_opt("SELECT b.user_pubkey,b.owner_mailbox,b.funding_spk \
			FROM board_exit b JOIN vtxo v ON v.vtxo_id=b.funding_outpoint \
			WHERE b.funding_outpoint=$1 AND b.exit_txid=v.oor_spent_txid \
			AND v.spend_state='spent' AND b.user_pubkey IS NOT NULL \
			AND b.owner_mailbox IS NOT NULL AND NOT EXISTS (SELECT 1 FROM vtxo child \
			WHERE child.anchor_point=b.funding_outpoint AND child.vtxo_id<>b.funding_outpoint)",
			&[&id.to_string()]).await? else { return Ok(None); };
		let root = self.get_server_vtxo_by_id(id).await?.vtxo;
		let user_pubkey: PublicKey = row.get::<_, &str>("user_pubkey").parse()?;
		let combined = ark::musig::combine_keys([user_pubkey, root.server_pubkey()])
			.x_only_public_key().0;
		if root.point() != root.chain_anchor()
			|| root.policy() != &ServerVtxoPolicy::new_expiry(combined)
			|| root.txout().script_pubkey.as_bytes() != row.get::<_, &[u8]>("funding_spk") {
			return Ok(None);
		}
		Ok(Some((user_pubkey,
			row.get::<_, &str>("owner_mailbox").parse()?)))
	}

	/// The one owner mailbox of the VTXOs `ids`. A spend of VTXOs that
	/// belong to different owners is refused.
	pub(crate) async fn single_owner_mailbox(&self, ids: &[VtxoId]) -> anyhow::Result<PublicKey> {
		let owners = self.vtxo_owner_mailboxes(ids).await?;
		let first = *ids.first().and_then(|id| owners.get(id)).context("input has no payout mailbox")?;
		if ids.iter().any(|id| owners.get(id) != Some(&first)) {
			return badarg!("inputs have mixed payout mailboxes");
		}
		Ok(first)
	}

	/// Bind the owner key and the owner mailbox of a board to its exit
	/// binding. A board that has an owner already must keep it.
	pub(crate) async fn bind_board_owner(
		&self,
		funding_outpoint: OutPoint,
		user_pubkey: PublicKey,
		owner_mailbox: PublicKey,
	) -> anyhow::Result<()> {
		let outpoint = funding_outpoint.to_string();
		let (user_key, mailbox) = (user_pubkey.to_string(), owner_mailbox.to_string());
		self.execute("UPDATE board_exit SET user_pubkey = $2, owner_mailbox = $3 \
			WHERE funding_outpoint = $1 AND owner_mailbox IS NULL", &[&outpoint, &user_key, &mailbox]).await?;
		let row = self.query_one("SELECT user_pubkey, owner_mailbox FROM board_exit WHERE funding_outpoint = $1",
			&[&outpoint]).await?;
		if row.get::<_, Option<&str>>("user_pubkey") != Some(user_key.as_str())
			|| row.get::<_, Option<&str>>("owner_mailbox") != Some(mailbox.as_str())
		{
			return badarg!("board output already has another owner or payout mailbox");
		}
		Ok(())
	}

	/// The owner mailbox bound to a board when this server co-signed it.
	pub(crate) async fn board_owner_mailbox(
		&self,
		funding_outpoint: OutPoint,
		user_pubkey: PublicKey,
	) -> anyhow::Result<PublicKey> {
		let row = self.query_one("SELECT user_pubkey, owner_mailbox FROM board_exit WHERE funding_outpoint = $1",
			&[&funding_outpoint.to_string()]).await?;
		if row.get::<_, Option<&str>>("user_pubkey") != Some(user_pubkey.to_string().as_str()) {
			return badarg!("board output has another owner key");
		}
		Ok(row.get::<_, Option<&str>>("owner_mailbox").context("board exit has no payout mailbox")?.parse()?)
	}

	/// Forget the funding output of a board that was co-signed in payout
	/// mode but did not confirm by its expiry and was never registered, so
	/// the watchman does not load it on every block. The owner keeps the
	/// co-signed exit, and a registration inserts the output again.
	pub async fn drop_unconfirmed_board_roots(&self, tip: BlockHeight) -> anyhow::Result<u64> {
		Ok(self.execute("DELETE FROM vtxo v USING board_exit b \
			WHERE v.frontier_at IS NOT NULL AND v.onchain_spent_height IS NULL \
			AND v.confirmed_height IS NULL AND v.expiry<=$1 AND v.vtxo_id=b.funding_outpoint \
			AND NOT EXISTS (SELECT 1 FROM vtxo child WHERE child.vtxo_txid=b.exit_txid)",
			&[&i32::try_from(tip.to_u32())?]).await?)
	}

	/// Whether a board co-sign for the funding output is a retry: this
	/// server co-signed a board exit for it and stored its funding
	/// transaction.
	pub(crate) async fn board_cosign_retry(&self, funding_outpoint: OutPoint) -> anyhow::Result<bool> {
		let known = self.get_virtual_transaction_by_txid(funding_outpoint.txid).await?;
		if !known.is_some_and(|tx| tx.is_funding) {
			return Ok(false);
		}
		Ok(self.query_opt("SELECT exit_txid FROM board_exit WHERE funding_outpoint = $1",
			&[&funding_outpoint.to_string()]).await?.is_some())
	}

	/// Whether a lightning payment attempt exists for the signed send intent.
	pub(crate) async fn send_intent_used(&self, intent_id: &str) -> anyhow::Result<bool> {
		Ok(self.query_opt("SELECT id FROM lightning_payment_attempt WHERE intent_id = $1",
			&[&intent_id]).await?.is_some())
	}

	/// The owner of a VTXO. A VTXO without an owner mailbox is held, not an
	/// error, so that the other roots are still decided.
	async fn vtxo_owner(&self, id: VtxoId) -> anyhow::Result<OwnershipDisposition> {
		Ok(match self.vtxo_owner_mailboxes(&[id]).await?.remove(&id) {
			Some(mailbox) => OwnershipDisposition::Owner { mailbox },
			None => OwnershipDisposition::Unresolved("owner mailbox unknown"),
		})
	}

	/// Propose who gets the value of one VTXO of an expired tree, from the
	/// snapshot of the tree that the caller read.
	pub async fn propose_expiry_ownership(
		&self,
		fact: &ExpiredTreeVtxo,
		tip: BlockHeight,
	) -> anyhow::Result<OwnershipProposal> {
		let mut proposal = OwnershipProposal::pending(fact, "owner unknown");
		let full = &fact.state.vtxo;
		let state = &fact.state;
		if let Some((_, mailbox)) = self.unregistered_board_owner(state.vtxo_id).await? {
			proposal.disposition = OwnershipDisposition::Owner { mailbox };
			proposal.evidence = Some(OwnershipEvidence::Board);
			return Ok(proposal);
		}

		if let Some(txid) = state.offboarded_in {
			ensure!(self.query_opt("SELECT txid FROM offboards WHERE txid=$1", &[&txid.to_string()]).await?.is_some(),
				"expiry offboard reference has no durable transaction");
			// The owner keeps the value until the offboard transaction has six
			// confirmations in the chain that both daemons see.
			let confirmed_before = i32::try_from(tip.to_u32().saturating_sub(5))?;
			let paid = self.query_opt("SELECT n.txid FROM nursery_tx n \
				JOIN captaind_block c ON c.height=n.confirmed_at_height \
				JOIN watchmand_block w ON w.height=c.height AND w.hash=c.hash \
				WHERE n.txid=$1 AND n.kind='offboard' AND n.confirmed_at_height BETWEEN 0 AND $2",
				&[&txid.to_string(), &confirmed_before]).await?.is_some();
			if !paid {
				return Ok(OwnershipProposal::pending(fact, "offboard not confirmed"));
			}
			proposal.disposition = OwnershipDisposition::Operator;
			proposal.evidence = Some(OwnershipEvidence::Offboard);
			return Ok(proposal);
		}

		// After a conflict, a VTXO is decided again. Its first decision still
		// gives the owner, because that decision itself set the VTXO spent.
		if state.spend_state == SpendState::Spent {
			if let Some(row) = self.query_opt("
				SELECT c.disposition,c.owner_mailbox,c.replannable
				FROM expiry_payout_vtxo c WHERE c.vtxo_id=$1 ORDER BY c.expiry_payout_id LIMIT 1
			", &[&state.vtxo_id.to_string()]).await? {
				if !row.get::<_, bool>("replannable") {
					// The table allows only these two dispositions.
					proposal.disposition = match row.get::<_, &str>("disposition") {
						"owner" => OwnershipDisposition::Owner { mailbox: row.get::<_, &str>("owner_mailbox").parse()? },
						_ => OwnershipDisposition::Operator,
					};
					proposal.evidence = Some(OwnershipEvidence::PriorDecision);
					return Ok(proposal);
				}
			}
		}

		// Only the participation of the round that spends this VTXO counts. A
		// superseded participation that was cancelled does not block it.
		let parts = self.query(
			"
				SELECT p.id, p.unlock_hash, p.forfeited_at IS NOT NULL AS forfeited,
				EXISTS(SELECT 1 FROM round_part_input i2 WHERE i2.participation_id=p.id
					AND i2.signed_forfeit_tx IS NOT NULL) AS any_forfeit
			FROM round_part_input i JOIN round_participation p ON p.id=i.participation_id
			LEFT JOIN round r ON r.funding_txid=p.round_id
			WHERE i.vtxo_id=$1 AND (p.round_id IS NULL OR r.id=$2) ORDER BY p.id DESC LIMIT 2
			",
			&[&state.vtxo_id.to_string(), &state.spent_in_round],
		).await?;
		ensure!(parts.len() <= 1, "expiry input has conflicting round participations");
		if let Some(part) = parts.first() {
			let forfeited = part.get::<_, bool>("forfeited");
			if !forfeited && part.get::<_, bool>("any_forfeit") {
				proposal.disposition = OwnershipDisposition::Unresolved("forfeits partly stored");
				return Ok(proposal);
			}
			let id = part.get::<_, i64>("id");
			proposal.evidence = Some(OwnershipEvidence::Participation);
			if forfeited {
				proposal.disposition = OwnershipDisposition::Operator;
			} else if full.clone().try_into_user_vtxo().is_ok() {
				proposal.disposition = self.vtxo_owner(state.vtxo_id).await?;
				proposal.cancellations.push(id);
			}
			return Ok(proposal);
		}

		if state.spend_state == SpendState::Pool {
			// Only the server's own pool issuance sets this state.
			proposal.disposition = OwnershipDisposition::Operator;
			proposal.evidence = Some(OwnershipEvidence::Pool);
			return Ok(proposal);
		}
		let forfeit = matches!(state.spend_state,
			SpendState::RoundForfeit | SpendState::OffboardForfeit | SpendState::OffboardConnector);
		if forfeit {
			proposal.disposition = OwnershipDisposition::Operator;
			proposal.evidence = Some(OwnershipEvidence::Forfeit);
			return Ok(proposal);
		}
		let Ok(user) = full.clone().try_into_user_vtxo() else { return Ok(proposal); };
		if state.spend_state == SpendState::Unregistered {
			if fact.full_vtxo.is_some() {
				if let Some(mailbox) = self.expiry_input_owner(state.vtxo_id).await? {
					proposal.disposition = OwnershipDisposition::Owner { mailbox };
					proposal.evidence = Some(OwnershipEvidence::InputOwner);
				}
			}
			return Ok(proposal);
		}
		if state.spend_state == SpendState::Unclaimed {
			// Round padding has no owner. An arkoor output with the same key
			// is not round padding: it has an owner as any other output.
			if matches!(user.policy(), VtxoPolicy::Pubkey(policy) if policy.user_pubkey == *UNSPENDABLE) {
				proposal.disposition = OwnershipDisposition::Operator;
				proposal.evidence = Some(OwnershipEvidence::Padding);
				return Ok(proposal);
			}
			let Some(hash) = fact.full_vtxo.as_ref().and_then(|vtxo| vtxo.unlock_hash()) else { return Ok(proposal); };
			let part = self.query_opt("SELECT id, forfeited_at IS NOT NULL AS forfeited \
				FROM round_participation WHERE unlock_hash = $1", &[&hash.to_string()]).await?;
			if let Some(part) = part {
				let id = part.get::<_, i64>("id");
				let forfeited = part.get::<_, bool>("forfeited");
				proposal.disposition = if forfeited { self.vtxo_owner(state.vtxo_id).await? }
					else { proposal.cancellations.push(id); OwnershipDisposition::Operator };
				proposal.evidence = Some(OwnershipEvidence::Participation);
			} else if self.participation_cancelled_for_payout(hash).await? {
				// A superseded participation can be deleted, but its tombstone
				// stays. The tombstone keeps the unlock preimage from release,
				// so the unclaimed output goes to the operator.
				proposal.disposition = OwnershipDisposition::Operator;
				proposal.evidence = Some(OwnershipEvidence::Participation);
			}
			return Ok(proposal);
		}
		if state.oor_spent_txid.is_some() {
			proposal.disposition = OwnershipDisposition::Unresolved("VTXO has registered children");
			return Ok(proposal);
		}
		if let Some((hash, _, _)) = htlc_terms(user.policy()) {
			let htlcs = htlc_vtxo::get_htlc_vtxo_states_by_payment_hash(self, hash).await?;
			let Some(htlc) = htlcs.iter().find(|h| h.vtxo.vtxo_id == proposal.id) else { return Ok(proposal); };
			let has_stored_preimage = self.get_htlc_settlement_by_payment_hash(hash).await?.is_some();
			let source = if htlc.direction() == HtlcDirection::Incoming {
				self.lightning_source_state(state.vtxo_id, hash).await?
			} else { LightningSourceState::Pending };
			let expired_contract = htlc.htlc.htlc_expiry <= tip
				&& fact.onchain_spent_height.is_none() && fact.onchain_spent_txid.is_none();
			let Some(resolution) = htlc.htlc.resolution() else {
				if htlc.direction() == HtlcDirection::Outgoing {
					let Some(subscription_id) = fact.lightning_htlc_subscription_id else { return Ok(proposal); };
					let Some(subscription) = self.get_htlc_subscription_by_id(subscription_id).await? else {
						return Ok(proposal);
					};
					if subscription.payment_hash != hash { return Ok(proposal); }
					match subscription.status {
						LightningHtlcSubscriptionStatus::Settled => {
							// Until its claim output is registered, the grant
							// goes to its own owner mailbox: the receiver's.
							proposal.disposition = self.vtxo_owner(state.vtxo_id).await?;
							proposal.evidence = Some(OwnershipEvidence::HtlcStoredPreimage);
						},
						LightningHtlcSubscriptionStatus::Canceled if expired_contract => {
							proposal.disposition = OwnershipDisposition::Operator;
							proposal.evidence = Some(OwnershipEvidence::HtlcRecvExpired);
						},
						LightningHtlcSubscriptionStatus::HtlcsReady if expired_contract && !has_stored_preimage => {
							proposal.disposition = OwnershipDisposition::Operator;
							proposal.evidence = Some(OwnershipEvidence::HtlcRecvExpired);
						},
						_ => proposal.disposition = OwnershipDisposition::Unresolved("lightning receive open"),
					}
					return Ok(proposal);
				}
				if source == LightningSourceState::Discharged {
					proposal.disposition = OwnershipDisposition::Operator;
					proposal.evidence = Some(OwnershipEvidence::HtlcSourceDischarged);
					return Ok(proposal);
				}
				if source == LightningSourceState::Failed && fact.onchain_spent_height.is_none()
					&& fact.onchain_spent_txid.is_none() && htlc.htlc.chain_resolution.is_none() {
					// An intra-Ark receive that issued grants keeps the source
					// until the operator takes back every grant, also after the
					// HTLC expiry of the source.
					match self.internal_receive_closed(state.vtxo_id, hash, &htlcs, tip).await? {
						Some(true) => {
							proposal.disposition = self.vtxo_owner(state.vtxo_id).await?;
							proposal.evidence = Some(OwnershipEvidence::HtlcInternalGrantsReclaimed);
							return Ok(proposal);
						},
						Some(false) => {
							proposal.disposition = OwnershipDisposition::Unresolved("receive grants not reclaimed");
							return Ok(proposal);
						},
						None => {},
					}
				}
				// A stored preimage next to a failed payment through the
				// lightning node can mean that the payment went through. Hold
				// the source unless another payment or a settled receive
				// explains the preimage. A source that went only to an
				// intra-Ark receive, or to no node, cannot have paid.
				if source == LightningSourceState::Failed && has_stored_preimage
					&& self.query_one("SELECT EXISTS(SELECT 1 FROM lightning_payment_attempt a \
						JOIN lightning_payment_attempt_htlc_vtxo l ON l.lightning_payment_attempt_id=a.id \
						WHERE l.vtxo_id=$1 AND a.payment_hash=$2 AND a.status='failed' \
						AND a.lightning_htlc_subscription_id IS NULL) \
						AND NOT EXISTS(SELECT 1 FROM lightning_payment_attempt a \
							WHERE a.payment_hash=$2 AND a.status='succeeded') \
						AND NOT EXISTS(SELECT 1 FROM lightning_htlc_subscription s \
							WHERE s.payment_hash=$2 AND s.status='settled')",
						&[&state.vtxo_id.to_string(), &hash.to_string()]).await?.get::<_, bool>(0) {
					proposal.disposition = OwnershipDisposition::Unresolved("failed lightning payment has a stored preimage");
					return Ok(proposal);
				}
				// A receive on the same hash that another source paid cannot
				// keep the value of this sender. Open attempts still wait.
				if matches!(source, LightningSourceState::Unattempted | LightningSourceState::Failed)
					&& fact.onchain_spent_height.is_none() && htlc.htlc.chain_resolution.is_none()
					&& htlc.htlc.htlc_expiry <= tip {
					proposal.disposition = self.vtxo_owner(state.vtxo_id).await?;
					proposal.evidence = Some(match source {
						LightningSourceState::Failed => OwnershipEvidence::HtlcExternalFailed,
						_ => OwnershipEvidence::HtlcUnattemptedExpired,
					});
				} else {
					proposal.disposition = OwnershipDisposition::Unresolved("lightning settlement pending");
				}
				return Ok(proposal);
			};
			if htlc.direction() == HtlcDirection::Outgoing && resolution == HtlcResolution::Revoked
				&& !payout_htlc_recvs_expired(&htlcs, tip, Some(tip)) {
				proposal.disposition = OwnershipDisposition::Unresolved("lightning receive grants not final");
				return Ok(proposal);
			}
			if htlc.htlc.chain_resolution.is_some() { return Ok(proposal); }
			proposal.evidence = Some(OwnershipEvidence::HtlcOffchain);
			proposal.disposition = match (htlc.direction(), resolution) {
				(HtlcDirection::Incoming, HtlcResolution::Fulfilled)
					| (HtlcDirection::Outgoing, HtlcResolution::Revoked) => OwnershipDisposition::Operator,
				_ => self.vtxo_owner(state.vtxo_id).await?,
			};
			return Ok(proposal);
		}
		if state.spend_state != SpendState::Spendable {
			proposal.disposition = OwnershipDisposition::Unresolved("spend state not final");
			return Ok(proposal);
		}
		proposal.disposition = self.vtxo_owner(state.vtxo_id).await?;
		proposal.evidence = Some(OwnershipEvidence::Pubkey);
		Ok(proposal)
	}
}

/// The payment hash and the HTLC expiry of an HTLC policy, and whether it
/// is an HTLC send.
pub(super) fn htlc_terms(policy: &VtxoPolicy) -> Option<(PaymentHash, BlockHeight, bool)> {
	match policy {
		VtxoPolicy::ServerHtlcSend(p) => Some((p.payment_hash, p.htlc_expiry, true)),
		VtxoPolicy::ServerHtlcSend_v0(p) => Some((p.payment_hash, p.htlc_expiry, true)),
		VtxoPolicy::ServerHtlcRecv(p) => Some((p.payment_hash, p.htlc_expiry, false)),
		VtxoPolicy::ServerHtlcRecv_v0(p) => Some((p.payment_hash, p.htlc_expiry, false)),
		VtxoPolicy::Pubkey(_) => None,
	}
}

/// The payout-mode form of [crate::ln::htlc_recvs_expired]. A collected
/// grant never expires, and a grant that the operator took back on-chain
/// counts only when that spend is six blocks deep, so a reorg cannot both
/// refund the sender and let the receiver claim.
pub(crate) fn payout_htlc_recvs_expired(
	htlc_vtxos: &[HtlcVtxo],
	tip: BlockHeight,
	watchman_tip: Option<BlockHeight>,
) -> bool {
	let Some(watchman_tip) = watchman_tip else {
		return false;
	};
	let height = std::cmp::min(tip, watchman_tip);
	let htlc_recvs = htlc_vtxos.iter()
		.filter(|h| h.direction() == HtlcDirection::Outgoing)
		.collect::<Vec<_>>();
	!htlc_recvs.is_empty() && htlc_recvs.iter().all(|h| {
		if h.htlc.resolution() == Some(HtlcResolution::Fulfilled) || height <= h.htlc_expiry() {
			return false;
		}
		match h.htlc.chain_resolution {
			// Resolution heights roll back with a reorg, so six blocks deep
			// in both daemons' views is final.
			Some(HtlcResolution::Revoked) => h.htlc.chain_resolution_height.is_some_and(|block|
				height.to_u32().checked_sub(block.to_u32()).is_some_and(|depth| depth >= 5)),
			None => !h.vtxo.is_exited(),
			Some(HtlcResolution::Fulfilled) => false,
		}
	})
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn ownership_uses_only_existing_attempt_states() {
		use LightningPaymentStatus::*;
		let open = |statuses: &[LightningPaymentStatus]| source_state(statuses.iter().map(|s| (*s, false)));
		assert_eq!(open(&[]), LightningSourceState::Unattempted);
		assert_eq!(open(&[Failed]), LightningSourceState::Failed);
		assert_eq!(open(&[Failed, Submitted]), LightningSourceState::Pending);
		assert_eq!(open(&[Requested, Failed]), LightningSourceState::Pending);
		assert_eq!(open(&[Failed, Succeeded]), LightningSourceState::Discharged);
		// An open attempt on a canceled receive can never succeed.
		assert_eq!(source_state([(Requested, true)]), LightningSourceState::Failed);
		assert_eq!(source_state([(Requested, true), (Submitted, false)]), LightningSourceState::Pending);
		assert_eq!(source_state([(Succeeded, true)]), LightningSourceState::Discharged);
	}

	use crate::database::htlc_vtxo::Htlc;

	#[test]
	fn fulfilled_grants_never_expire_and_revoked_grants_wait_for_six_blocks() {
		let vtxo = ark::test_util::VTXO_VECTORS.board_vtxo.clone();
		let now = chrono::Local::now();
		let mut grant = HtlcVtxo {
			htlc: Htlc { payment_hash: ark::lightning::PaymentHash::from([1; 32]),
				htlc_expiry: BlockHeight::new(100), direction: HtlcDirection::Outgoing,
				offchain_resolution: Some(HtlcResolution::Fulfilled),
				chain_resolution: None, chain_resolution_height: None },
			vtxo: crate::database::VtxoState { id: 1, vtxo_id: vtxo.id(), vtxo: vtxo,
				oor_spent_txid: None, spent_in_round: None, offboarded_in: None,
				banned_until_height: None, spend_state: crate::database::SpendState::Spendable,
				decided_for_payout: false, confirmed_height: None, created_at: now, updated_at: now },
		};
		assert!(!payout_htlc_recvs_expired(std::slice::from_ref(&grant), BlockHeight::new(150), Some(BlockHeight::new(150))));
		grant.htlc.offchain_resolution = None;
		assert!(payout_htlc_recvs_expired(std::slice::from_ref(&grant), BlockHeight::new(150), Some(BlockHeight::new(150))));
		grant.vtxo.confirmed_height = Some(BlockHeight::new(110));
		grant.htlc.chain_resolution = Some(HtlcResolution::Revoked);
		grant.htlc.chain_resolution_height = Some(BlockHeight::new(120));
		for (server, watchman, expected) in [(124, Some(124), false), (125, Some(125), true),
			(150, Some(124), false), (124, Some(150), false), (150, None, false)] {
			assert_eq!(payout_htlc_recvs_expired(std::slice::from_ref(&grant), BlockHeight::new(server),
				watchman.map(BlockHeight::new)), expected);
		}
		grant.htlc.chain_resolution = Some(HtlcResolution::Fulfilled);
		assert!(!payout_htlc_recvs_expired(std::slice::from_ref(&grant), BlockHeight::new(150), Some(BlockHeight::new(150))));
	}
}

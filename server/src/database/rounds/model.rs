
use std::str::FromStr;

use anyhow::Context;
use bitcoin::Transaction;
use bitcoin::consensus::deserialize;
use chrono::{DateTime, Local};
use tokio_postgres::Row;

use ark::{ProtocolEncoding, VtxoId, VtxoRequest};
use ark::mailbox::MailboxIdentifier;
use ark::rounds::{RoundId, RoundSeq};
use ark::tree::signed::{CachedSignedVtxoTree, SignedVtxoTreeSpec, UnlockHash, UnlockPreimage};
use bitcoin_ext::BlockHeight;

use crate::secret::Secret;


/// Output in a stored round participation.
#[derive(Debug, Clone)]
pub struct StoredRoundOutput {
	pub vtxo_request: VtxoRequest,
	pub unblinded_mailbox_id: Option<MailboxIdentifier>,
}

impl AsRef<VtxoRequest> for StoredRoundOutput {
	fn as_ref(&self) -> &VtxoRequest {
		&self.vtxo_request
	}
}

#[derive(Debug)]
pub struct StoredRoundInput {
	pub vtxo_id: VtxoId,
	pub signed_forfeit_tx: Option<Transaction>,
}

impl StoredRoundInput {
	/// Whether this input was succesfully forfeited
	pub fn is_forfeited(&self) -> bool {
		self.signed_forfeit_tx.is_some()
	}
}

#[derive(Debug)]
pub struct StoredRoundParticipation {
	pub unlock_hash: UnlockHash,
	pub unlock_preimage: Secret<UnlockPreimage>,
	pub inputs: Vec<StoredRoundInput>,
	pub outputs: Vec<StoredRoundOutput>,
	pub round_id: Option<RoundId>,
	pub forfeited_at: Option<DateTime<Local>>,
	/// Block height at which the refresh is scheduled,
	/// [None] for the next round.
	pub scheduled_height: Option<BlockHeight>,
}

#[derive(Debug, Clone)]
pub struct StoredRound {
	pub id: i64,
	pub seq: RoundSeq,
	pub funding_txid: RoundId,
	pub funding_tx: Transaction,
	pub signed_tree: SignedVtxoTreeSpec,
	pub expiry_height: BlockHeight,
	pub swept_at: Option<DateTime<Local>>,
	pub created_at: DateTime<Local>,
}

impl StoredRound {
	/// Convert the signed tree into a cached tree, detecting the hashlock
	/// version it was signed with.
	///
	/// Stored rounds can predate the v1 hashlock clauses and the tree
	/// encoding doesn't record the version, so it has to be recovered from
	/// the cosign signatures before any transactions or VTXOs are rebuilt
	/// from the tree. Rebuilding with the wrong version yields txids and
	/// VTXO ids that don't match what was cosigned in the round.
	pub fn into_cached_tree(self) -> anyhow::Result<CachedSignedVtxoTree> {
		let tree = self.signed_tree.with_detected_hashlock_version()
			.with_context(|| format!("corrupt signed tree for round {}", self.funding_txid))?;
		Ok(tree.into_cached_tree())
	}
}

impl TryFrom<Row> for StoredRound {
	type Error = anyhow::Error;

	fn try_from(row: Row) -> Result<Self, Self::Error> {
		let funding_txid = RoundId::from_str(&row.get::<_, &str>("funding_txid"))?;
		let funding_tx = deserialize::<Transaction>(row.get("funding_tx"))?;
		debug_assert_eq!(funding_tx.compute_txid(), funding_txid.as_round_txid());

		Ok(Self {
			id: row.get("id"),
			funding_txid,
			funding_tx,
			seq: RoundSeq::new(row.get::<_, i64>("seq") as u64),
			signed_tree: SignedVtxoTreeSpec::deserialize(row.get("signed_tree"))?,
			expiry_height: row.get::<_, i32>("expiry") as BlockHeight,
			swept_at: row.get("swept_at"),
			created_at: row.get("created_at"),
		})
	}
}

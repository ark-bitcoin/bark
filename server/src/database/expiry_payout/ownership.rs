//! The owner of each VTXO: the owner mailbox recorded when the VTXO was
//! created.

use std::collections::BTreeMap;

use anyhow::Context;
use bitcoin::OutPoint;
use bitcoin::secp256k1::PublicKey;

use ark::VtxoId;

use crate::database::Tx;

impl Tx<'_> {
	/// The owner mailbox recorded for each VTXO when it was created. The
	/// VTXO ids that a mailbox holder stores for recovery are not in it.
	pub async fn vtxo_owner_mailboxes(&self, ids: &[VtxoId]) -> anyhow::Result<BTreeMap<VtxoId, PublicKey>> {
		let ids = ids.iter().map(ToString::to_string).collect::<Vec<_>>();
		self.query("SELECT vtxo_id,mailbox_pk FROM vtxo_owner_mailbox WHERE vtxo_id=ANY($1)", &[&ids]).await?
			.into_iter().map(|row| Ok((row.get::<_, &str>(0).parse()?,
				row.get::<_, &str>(1).parse()?))).collect()
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
			let mailbox = bindings.get(id)
				.with_context(|| format!("owner VTXO {id} has no registered mailbox"))?;
			ids.push(id.to_string());
			mailboxes.push(mailbox.to_string());
		}
		ensure!(bindings.len() == owned.len(), "mailbox binding set differs from the owner VTXOs");
		self.execute("INSERT INTO vtxo_owner_mailbox (vtxo_id, mailbox_pk) \
			SELECT u.vtxo_id, u.mailbox_pk FROM UNNEST($1::TEXT[], $2::TEXT[]) AS u(vtxo_id, mailbox_pk) \
			ON CONFLICT (vtxo_id) DO NOTHING", &[&ids, &mailboxes]).await?;
		let stored = self.vtxo_owner_mailboxes(owned).await?;
		for id in owned {
			ensure!(stored.get(id) == bindings.get(id), "owner VTXO {id} has a conflicting mailbox binding");
		}
		Ok(())
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
}

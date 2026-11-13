//! The owner mailbox of each VTXO that a board creates in payout mode.

use bitcoin::Txid;
use bitcoin::secp256k1::PublicKey;

use ark::ServerVtxo;
use ark::vtxo::Full;

use crate::database::tree::VtxoTreeUpdate;

impl crate::Server {
	/// Record the owner of a board that this server co-signs, and put its
	/// funding output on the frontier. From now on the funding output owes
	/// its owner a payout, even if the owner never registers the board.
	pub(crate) async fn record_board_owner(
		&self,
		root: ServerVtxo<Full>,
		exit_txid: Txid,
		user_pubkey: PublicKey,
		owner_mailbox: PublicKey,
	) -> anyhow::Result<()> {
		let utxo = root.point();
		self.db.write(async |t| {
			t.bind_board_owner(utxo, user_pubkey, owner_mailbox).await?;
			let update = VtxoTreeUpdate::new()
				.upsert_unsigned_funding_tx(utxo.txid)
				.upsert_unsigned_tx([exit_txid])
				.insert_oor_spent_vtxos([(root, exit_txid)]);
			t.execute_vtxo_tree_update(update).await?;
			t.add_funding_vtxos_to_frontier(utxo.txid, None).await
		}).await
	}
}

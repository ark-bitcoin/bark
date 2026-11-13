//! Expiry payouts.
//!
//! A server in expiry payout mode records an owner mailbox key `M` for every
//! VTXO it co-signs. When the tree of a VTXO expires, the server pays the
//! VTXO to `tr(M)`, minus a payout fee. The wallet sends its mailbox in every
//! request that makes a VTXO.
//!
//! The wallet is in expiry payout mode when it negotiated
//! [server_rpc::pver::PROTOCOL_VERSION_SCUTTLE_EXPIRY_PAYOUT] with the server.
//! In any other mode, the functions here do nothing.

use bitcoin::ScriptBuf;
use server_rpc::ServerConnection;

use crate::Wallet;

impl Wallet {
	/// Whether the wallet is connected to a server in expiry payout mode.
	///
	/// This does not connect: it is `false` while the wallet has no
	/// connection.
	pub(crate) async fn expiry_payouts(&self) -> bool {
		match self.inner.server.get() {
			Some(srv) => srv.expiry_payouts().await,
			None => false,
		}
	}

	/// Store the mailbox key of this wallet when it first connects to a
	/// server in expiry payout mode.
	pub(crate) async fn store_mailbox_key(&self, srv: &ServerConnection) -> anyhow::Result<()> {
		if !srv.expiry_payouts().await {
			return Ok(());
		}
		if self.properties().await?.mailbox_pubkey.is_none() {
			self.inner.db.set_mailbox_key(self.mailbox_keypair().public_key()).await?;
		}
		Ok(())
	}

	/// The payout script `tr(M)` of this wallet's mailbox key `M`. A server in
	/// expiry payout mode pays the expired VTXOs of this wallet to it.
	pub fn payout_script(&self) -> ScriptBuf {
		ark::expiry_payout::payout_script(self.mailbox_keypair().public_key())
	}

	/// The owner mailbox of a board VTXO, sent only to a server in expiry
	/// payout mode.
	pub(crate) async fn board_owner_mailbox(&self) -> Option<Vec<u8>> {
		if !self.expiry_payouts().await {
			return None;
		}
		Some(self.mailbox_keypair().public_key().serialize().to_vec())
	}
}

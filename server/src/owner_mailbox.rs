//! The owner mailbox of each VTXO that a board or an arkoor creates in
//! payout mode.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{bail, Context};
use bitcoin::Txid;
use bitcoin::secp256k1::{Keypair, PublicKey};

use ark::{ProtocolEncoding, ServerVtxo, VtxoId, VtxoPolicy};
use ark::arkoor::package::ArkoorPackageBuilder;
use ark::arkoor::state::ServerCanCosign;
use ark::mailbox::{BlindedMailboxIdentifier, MailboxIdentifier};
use ark::vtxo::Full;
use server_rpc::protos;

use crate::database::tree::VtxoTreeUpdate;
use crate::error::ContextExt;
use crate::rpcserver::ToStatusResult;

/// The owner mailbox of each output key of one arkoor request. The map
/// lives only as long as the request.
#[derive(Default)]
pub struct DestinationBindings {
	mailboxes: BTreeMap<PublicKey, PublicKey>,
	/// Whether the request can create HTLC-send VTXOs.
	htlc_send: bool,
}

impl DestinationBindings {
	/// Unblind the mailbox of each output of the request. Empty if the
	/// server is not in payout mode (`required` is false).
	pub(crate) fn from_arkoor_parts(
		parts: &[protos::ArkoorCosignRequest], required: bool,
		server_mailbox_key: &Keypair,
	) -> anyhow::Result<Self> {
		if !required { return Ok(Self::default()); }
		// The request conversion, which runs after this, has the same limit.
		if parts.len() > server_rpc::MAX_NB_VTXO_IDS { bail!("too many parts in cosign request"); }
		let mut ret = Self::default();
		for output in parts.iter().flat_map(|part| part.outputs.iter().chain(&part.isolated_outputs)) {
			let policy = VtxoPolicy::deserialize(&output.policy).context("invalid arkoor output policy")?;
			let key = policy.user_pubkey();
			if output.blinded_mailbox_id.is_empty() {
				bail!("arkoor output {key} has no payout destination");
			}
			let point = PublicKey::from_slice(&output.blinded_mailbox_id)
				.context("invalid blinded arkoor mailbox")?;
			let blinded = BlindedMailboxIdentifier::from_pubkey(point);
			let mailbox = MailboxIdentifier::from_blinded(blinded, key, server_mailbox_key)
				.context("invalid arkoor recipient mailbox")?;
			ret.insert(key, mailbox.as_pubkey())?;
		}
		Ok(ret)
	}

	fn insert(&mut self, key: PublicKey, mailbox: PublicKey) -> anyhow::Result<()> {
		if let Some(previous) = self.mailboxes.get(&key) {
			if *previous != mailbox {
				bail!("output {key} has conflicting payout mailboxes");
			}
			return Ok(());
		}
		self.mailboxes.insert(key, mailbox);
		Ok(())
	}

	/// The same bindings for a Lightning send, the only arkoor that can
	/// create HTLC-send VTXOs. The server caps the HTLC expiry of these.
	pub(crate) fn for_lightning_send(&self) -> Self {
		DestinationBindings { mailboxes: self.mailboxes.clone(), htlc_send: true }
	}

	/// The owner mailbox of each VTXO that the arkoor package creates. Every
	/// output needs a mailbox, and every mailbox must name an output.
	///
	/// Every output must also have a pubkey policy. The payout of a tree
	/// waits until each HTLC VTXO in it resolves, and only the Lightning
	/// payment that created an HTLC VTXO resolves it. A Lightning send can
	/// create HTLC-send VTXOs, because their HTLC expiry is capped.
	pub(crate) fn bindings_for_package(
		&self, builder: &ArkoorPackageBuilder<ServerCanCosign>, required: bool,
	) -> anyhow::Result<Vec<(VtxoId, PublicKey)>> {
		if !required { return Ok(Vec::new()); }
		let mut keys = BTreeSet::new();
		let mut bindings = Vec::new();
		for vtxo in builder.build_unsigned_vtxos() {
			match vtxo.policy() {
				VtxoPolicy::Pubkey(_) => {},
				VtxoPolicy::ServerHtlcSend(_) if self.htlc_send => {},
				policy => return badarg!("an arkoor output cannot have a {} policy", policy.policy_type()),
			}
			let key = vtxo.policy().user_pubkey();
			keys.insert(key);
			let mailbox = *self.mailboxes.get(&key)
				.with_context(|| format!("output {key} has no registered payout destination"))?;
			bindings.push((vtxo.id(), mailbox));
		}
		if self.mailboxes.keys().any(|key| !keys.contains(key)) {
			bail!("payout destination names no actual output");
		}
		Ok(bindings)
	}
}

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

	/// The owner mailbox of every output of an arkoor co-sign request.
	pub(crate) fn arkoor_destinations(&self, parts: &[protos::ArkoorCosignRequest])
		-> Result<DestinationBindings, tonic::Status>
	{
		DestinationBindings::from_arkoor_parts(parts, self.config.expiry_payouts, self.mailbox_key.leak_ref())
			.badarg("invalid payout destination").to_status()
	}
}

#[cfg(test)]
mod tests {
	use bitcoin::secp256k1::{Secp256k1, SecretKey};

	use super::*;

	#[test]
	fn missing_blinded_mailbox_is_not_an_arkoor_destination() {
		let secp = Secp256k1::new();
		let server = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[3; 32]).unwrap());
		let recipient = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[4; 32]).unwrap());
		let part = protos::ArkoorCosignRequest {
			outputs: vec![protos::ArkoorDestination {
				policy: VtxoPolicy::new_pubkey(recipient.public_key()).serialize(),
				..Default::default()
			}], ..Default::default()
		};
		assert!(DestinationBindings::from_arkoor_parts(&[part], true, &server).is_err());
		let malformed = protos::ArkoorCosignRequest {
			outputs: vec![protos::ArkoorDestination {
				policy: VtxoPolicy::new_pubkey(recipient.public_key()).serialize(),
				blinded_mailbox_id: vec![0xff; 33],
				..Default::default()
			}], ..Default::default()
		};
		assert!(DestinationBindings::from_arkoor_parts(&[malformed], true, &server).is_err());
	}
}

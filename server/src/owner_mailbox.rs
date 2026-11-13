//! The owner mailbox of each VTXO that a board, an arkoor, a round or the
//! VTXO pool creates in payout mode.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{bail, Context};
use bitcoin::{Amount, Transaction, Txid};
use bitcoin::secp256k1::{schnorr, Keypair, PublicKey};

use ark::{ProtocolEncoding, ServerVtxo, Vtxo, VtxoId, VtxoPolicy};
use ark::arkoor::package::ArkoorPackageBuilder;
use ark::arkoor::state::ServerCanCosign;
use ark::attestations::LightningSendIntent;
use ark::lightning::Invoice;
use ark::mailbox::{BlindedMailboxIdentifier, MailboxIdentifier};
use ark::tree::signed::{CachedSignedVtxoTree, VtxoLeafSpec};
use ark::vtxo::Full;
use server_rpc::protos;

use crate::database::{SpendState, VtxoState};
use crate::database::rounds::StoredRoundOutput;
use crate::database::tree::VtxoTreeUpdate;
use crate::error::ContextExt;
use crate::round::UNSPENDABLE;
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

/// Refuse a requested round output with the key of round padding. The
/// server records no owner for such an output and pays its value to the
/// operator at expiry, so it cannot bind the output to the mailbox of the
/// participation.
pub(crate) fn refuse_padding_outputs<'a>(
	policies: impl IntoIterator<Item = &'a VtxoPolicy>,
) -> anyhow::Result<()> {
	let padding = VtxoPolicy::new_pubkey(*UNSPENDABLE);
	if policies.into_iter().any(|policy| *policy == padding) {
		return badarg!("a round output cannot have the key of round padding");
	}
	Ok(())
}

/// Refuse a stored delegated participation with an output that a round
/// cannot bind to an owner mailbox. The submission is checked the same way,
/// but the round checks the stored outputs again: one output that it cannot
/// bind fails the whole round, and the participation would join each next
/// round. The round drops a participation that this refuses.
pub(crate) fn check_stored_round_outputs(outputs: &[StoredRoundOutput], required: bool) -> anyhow::Result<()> {
	if !required { return Ok(()); }
	if outputs.iter().any(|output| output.unblinded_mailbox_id.is_none()) {
		bail!("a round output has no payout mailbox");
	}
	refuse_padding_outputs(outputs.iter().map(|output| &output.vtxo_request.policy))
}

/// The owner mailbox of each output of a round. Each output must match its
/// leaf spec, and each output that an owner holds must have a mailbox.
/// Round padding has no owner.
pub(crate) fn round_owner_bindings(
	tree: &CachedSignedVtxoTree,
	specs: &[VtxoLeafSpec],
	mailboxes: &[Option<MailboxIdentifier>],
) -> anyhow::Result<Vec<(VtxoId, PublicKey)>> {
	let outputs = tree.output_vtxos().collect::<Vec<_>>();
	ensure!(outputs.len() == mailboxes.len() && outputs.len() == specs.len(),
		"round output/mailbox count differs");
	let mut ret = Vec::new();
	for ((vtxo, spec), mailbox) in outputs.iter().zip(specs).zip(mailboxes) {
		ensure!(vtxo.policy() == &spec.vtxo.policy && vtxo.amount() == spec.vtxo.amount,
			"round output/mailbox order differs");
		match mailbox {
			Some(mailbox) => ret.push((vtxo.id(), mailbox.as_pubkey())),
			None if vtxo.policy() == &VtxoPolicy::new_pubkey(*UNSPENDABLE) => {},
			None => bail!("round owner output {} has no payout mailbox", vtxo.id()),
		}
	}
	Ok(ret)
}

/// The tree update of a pool issuance in payout mode. The cached tree holds
/// the hArk leaf transactions unsigned, but the finalized pool VTXOs carry
/// their signatures and unlock preimage. The watchman must be able to
/// publish the path of a receive grant that a pool VTXO funds, so the
/// update stores that signed path and the finalized VTXOs.
pub(crate) fn pool_tree_update(
	funding_tx: &Transaction,
	tree: &CachedSignedVtxoTree,
	vtxos: &[Vtxo<Full>],
) -> anyhow::Result<VtxoTreeUpdate> {
	// Pool VTXOs share ancestors, and one insert must not write a txid twice.
	let mut signed_txs = BTreeMap::new();
	for vtxo in vtxos {
		vtxo.validate(funding_tx).context("finalized pool VTXO has an invalid signed path")?;
		for step in vtxo.transactions() {
			let txid = step.tx.compute_txid();
			if let Some(old) = signed_txs.insert(txid, step.tx.clone()) {
				ensure!(old == step.tx, "finalized pool paths disagree on a shared transaction");
			}
		}
	}
	Ok(VtxoTreeUpdate::new()
		.upsert_funding_tx(funding_tx)
		.upsert_signed_tx(signed_txs.into_values())
		.insert_oor_spent_vtxos(tree.internal_vtxos())
		.insert_unspent_vtxos(vtxos.iter().cloned().map(ServerVtxo::from), SpendState::Pool))
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

	/// Verify that the key that owns every source signed this exact lightning
	/// send, so nobody else can spend the HTLCs that the owner co-signed.
	/// Returns the id of the send intent, or `None` if an attempt with this
	/// id exists: the intent id commits to every field of the request, so
	/// the request was sent before.
	pub(crate) async fn verify_send_intent(
		&self,
		invoice: &Invoice,
		amount: Amount,
		source_ids: &[VtxoId],
		sources: &[VtxoState],
		mailbox_id: Option<MailboxIdentifier>,
		retry_for_secs: Option<u32>,
		nonce: Option<Vec<u8>>,
		signature: &[u8],
	) -> anyhow::Result<Option<String>> {
		if source_ids.is_empty() {
			return badarg!("a lightning send needs a source");
		}
		let signature = schnorr::Signature::from_slice(signature)
			.badarg("invalid lightning source owner signature")?;
		if source_ids.iter().collect::<BTreeSet<_>>().len() != source_ids.len() {
			return badarg!("duplicate lightning source");
		}
		let nonce: [u8; 32] = nonce.badarg("missing lightning send intent nonce")?
			.try_into().map_err(|_| badarg_err!("lightning send intent nonce must be 32 bytes"))?;
		let intent = LightningSendIntent::new(
			nonce, self.server_pubkey, self.config.network, invoice, amount, source_ids, mailbox_id, retry_for_secs,
		);
		for id in source_ids {
			let source = sources.iter().find(|source| source.vtxo_id == *id)
				.context("lightning source is missing")?;
			intent.verify(&signature, source.vtxo.user_pubkey())
				.badarg("lightning source owner signature does not match payment intent")?;
		}
		let intent_id = intent.id().to_string();
		if self.db.read(async |t| t.send_intent_used(&intent_id).await).await? {
			return Ok(None);
		}
		Ok(Some(intent_id))
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

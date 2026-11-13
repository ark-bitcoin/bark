//! Expiry payouts.
//!
//! A server in expiry payout mode records an owner mailbox key `M` for every
//! VTXO it co-signs. When the tree of a VTXO expires, the server pays the
//! VTXO to `tr(M)`, minus a payout fee. The wallet sends its mailbox in every
//! request that makes a VTXO, and checks the owner mailbox of every VTXO that
//! it receives.
//!
//! The wallet is in expiry payout mode when it negotiated
//! [server_rpc::pver::PROTOCOL_VERSION_SCUTTLE_EXPIRY_PAYOUT] with the server.
//! In any other mode, the functions here do nothing.

use std::collections::{HashMap, HashSet};

use anyhow::Context;
use bitcoin::ScriptBuf;
use bitcoin::secp256k1::Keypair;
use log::{debug, warn};

use ark::{ProtocolEncoding, Vtxo, VtxoId, VtxoPolicy};
use ark::address::VtxoDelivery;
use ark::mailbox::BlindedMailboxIdentifier;
use ark::vtxo::{Full, VtxoRef};
use server_rpc::ServerConnection;
use server_rpc::protos::{self, VtxoSpendState};

use crate::Wallet;
use crate::mailbox::{MAILBOX_PROCESSING_LOCK_KEY, MAILBOX_PROCESSING_LOCK_TIMEOUT};
use crate::round::RoundParticipation;
use crate::vtxo::{VtxoLockHolder, VtxoState, VtxoStateKind};

/// The status of a VTXO from a server in expiry payout mode.
pub(crate) struct ServerVtxoStatus {
	pub state: VtxoSpendState,
	/// Whether the owner mailbox of the VTXO is the mailbox of this wallet.
	pub own_mailbox: bool,
}

impl ServerVtxoStatus {
	/// Whether the VTXO is spent on the server.
	fn is_spent(&self) -> bool {
		self.state == VtxoSpendState::Spent
	}
}

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

	/// Set the blinded owner mailbox of every arkoor output for a server in
	/// expiry payout mode.
	///
	/// An output to `recipient` gets the blinded mailbox of the address.
	/// Any other output must have a key of this wallet, and gets the mailbox
	/// of this wallet blinded with that key.
	pub(crate) async fn bind_output_mailboxes(
		&self,
		parts: &mut [protos::ArkoorCosignRequest],
		recipient: Option<&ark::Address>,
	) -> anyhow::Result<()> {
		let (srv, ark_info) = self.require_server().await?;
		if !srv.expiry_payouts().await {
			return Ok(());
		}

		for part in parts.iter_mut() {
			for output in part.outputs.iter_mut().chain(part.isolated_outputs.iter_mut()) {
				let policy = VtxoPolicy::deserialize(&output.policy)?;
				let recipient_mailbox = match recipient {
					Some(address) if *address.policy() == policy => server_mailbox(address),
					_ => None,
				};
				let blinded_id = match recipient_mailbox {
					Some(blinded_id) => blinded_id,
					None => {
						let (_, keypair) = self.pubkey_keypair(&policy.user_pubkey()).await?
							.context("arkoor output to another wallet has no recipient mailbox")?;
						self.mailbox_identifier().to_blinded(ark_info.mailbox_pubkey, &keypair)?
					},
				};
				output.blinded_mailbox_id = blinded_id.as_ref().to_vec();
			}
		}
		Ok(())
	}

	/// Whether `address` belongs to this wallet: its key, and for a server in
	/// expiry payout mode also its mailbox.
	pub(crate) async fn is_own_address(&self, address: &ark::Address) -> anyhow::Result<bool> {
		let Some((_, keypair)) = self.pubkey_keypair(&address.policy().user_pubkey()).await? else {
			return Ok(false);
		};
		if !self.expiry_payouts().await {
			return Ok(true);
		}

		let (_, ark_info) = self.require_server().await?;
		let blinded_id = self.mailbox_identifier().to_blinded(ark_info.mailbox_pubkey, &keypair)?;
		Ok(server_mailbox(address) == Some(blinded_id))
	}

	/// The status of each VTXO in `queries` from a server in expiry payout
	/// mode. A VTXO without a usable answer is absent from the result.
	async fn fetch_server_vtxo_statuses(
		&self,
		queries: &[(VtxoId, &Keypair)],
	) -> anyhow::Result<(HashMap<VtxoId, ServerVtxoStatus>, HashSet<VtxoId>)> {
		let mailbox = self.mailbox_keypair().public_key().serialize();
		let mut ret = HashMap::with_capacity(queries.len());
		let (statuses, answered) = self.fetch_vtxo_statuses(queries).await?;
		for (id, status) in statuses {
			let Ok(state) = VtxoSpendState::try_from(status.spend_state) else {
				warn!("Server returned an unusable status for vtxo {id}; this wallet may need updating");
				continue;
			};
			let own_mailbox = status.owner_mailbox == mailbox;
			ret.insert(id, ServerVtxoStatus { state, own_mailbox });
		}
		Ok((ret, answered))
	}

	/// The status of a VTXO whose owner mailbox must be this wallet's.
	async fn fetch_own_vtxo_status(
		&self,
		vtxo_id: VtxoId,
		keypair: &Keypair,
	) -> anyhow::Result<ServerVtxoStatus> {
		let (mut statuses, _) = self.fetch_server_vtxo_statuses(&[(vtxo_id, keypair)]).await?;
		let status = statuses.remove(&vtxo_id)
			.with_context(|| format!("the server returned no status for VTXO {vtxo_id}"))?;
		ensure!(status.own_mailbox, "the owner mailbox of VTXO {vtxo_id} is another mailbox");
		Ok(status)
	}

	/// [Wallet::fetch_vtxo_spend_state], which on a server in expiry payout
	/// mode also refuses a VTXO whose owner mailbox is not this wallet's.
	pub(crate) async fn fetch_own_vtxo_spend_state(
		&self,
		vtxo_id: VtxoId,
		keypair: &Keypair,
	) -> anyhow::Result<VtxoSpendState> {
		let (srv, _) = self.require_server().await?;
		if !srv.expiry_payouts().await {
			return self.fetch_vtxo_spend_state(vtxo_id, keypair).await;
		}
		Ok(self.fetch_own_vtxo_status(vtxo_id, keypair).await?.state)
	}

	/// [Wallet::fetch_vtxo_spend_states], which on a server in expiry payout
	/// mode also returns the VTXOs whose owner mailbox is not this wallet's.
	/// Those VTXOs are not in the spend states.
	pub(crate) async fn fetch_own_vtxo_spend_states(
		&self,
		queries: &[(VtxoId, &Keypair)],
	) -> anyhow::Result<(HashMap<VtxoId, VtxoSpendState>, Vec<VtxoId>, HashSet<VtxoId>)> {
		let (srv, _) = self.require_server().await?;
		if !srv.expiry_payouts().await {
			let (states, answered) = self.fetch_vtxo_spend_states(queries).await?;
			return Ok((states, Vec::new(), answered));
		}

		let mut states = HashMap::with_capacity(queries.len());
		let mut foreign = Vec::new();
		let (statuses, answered) = self.fetch_server_vtxo_statuses(queries).await?;
		for (id, status) in statuses {
			if status.own_mailbox {
				states.insert(id, status.state);
			} else {
				foreign.push(id);
			}
		}
		Ok((states, foreign, answered))
	}

	/// Release the round outputs that the server reports bound to this
	/// wallet's mailbox.
	///
	/// Does nothing unless the server is in expiry payout mode.
	pub async fn sync_expiry_payouts(&self) -> anyhow::Result<()> {
		let (srv, _) = self.require_server().await?;
		if !srv.expiry_payouts().await {
			return Ok(());
		}

		for vtxo in self.inner.db.get_all_vtxos().await? {
			if vtxo.state == (VtxoState::Locked { holder: Some(VtxoLockHolder::RoundPayoutCheck) }) {
				if let Err(e) = self.release_round_output(&vtxo.vtxo).await {
					warn!("Round output {} stays locked until the server reports its owner \
						mailbox: {:#}", vtxo.id(), e);
				}
			}
		}
		Ok(())
	}

	/// [Wallet::sync_expiry_payouts] as a step of [Wallet::sync], which does
	/// not connect to the server. An error is only logged.
	pub(crate) async fn sync_expiry_payouts_if_connected(&self) {
		if !self.expiry_payouts().await {
			return;
		}
		if let Err(e) = self.sync_expiry_payouts().await {
			warn!("Error releasing round outputs for expiry payouts: {:#}", e);
		}
	}

	/// Check VTXOs received by arkoor with a server in expiry payout mode.
	///
	/// Returns the VTXOs that the server reports spendable and bound to this
	/// wallet's mailbox. Stores a VTXO that the server reports spent as spent,
	/// and a VTXO that it does not report spendable yet as locked.
	pub(crate) async fn verify_received_arkoor_vtxos(
		&self,
		vtxos: Vec<Vtxo<Full>>,
	) -> anyhow::Result<Vec<Vtxo<Full>>> {
		let (srv, _) = self.require_server().await?;
		if !srv.expiry_payouts().await {
			return Ok(vtxos);
		}

		let mut spendable = Vec::with_capacity(vtxos.len());
		for vtxo in vtxos {
			let key = self.get_vtxo_key(&vtxo).await?;
			let status = self.fetch_own_vtxo_status(vtxo.id(), &key).await?;
			if status.is_spent() {
				self.store_vtxos([&vtxo], &VtxoState::Spent).await?;
			} else if status.state == VtxoSpendState::Spendable {
				spendable.push(vtxo);
			} else {
				warn!("Received arkoor VTXO {} is not spendable on the server ({:?}); \
					it stays locked", vtxo.id(), status.state);
				let holder = Some(VtxoLockHolder::MailboxReceive);
				self.store_vtxos([&vtxo], &VtxoState::Locked { holder }).await?;
			}
		}
		Ok(spendable)
	}

	/// Check again the VTXOs received by arkoor that the server did not report
	/// spendable, and credit the ones that it reports spendable.
	pub(crate) async fn credit_pending_arkoor_receives(&self) -> anyhow::Result<()> {
		let (srv, _) = self.require_server().await?;
		if !srv.expiry_payouts().await {
			return Ok(());
		}

		let _guard = self.inner.lock_manager.lock(
			MAILBOX_PROCESSING_LOCK_KEY, MAILBOX_PROCESSING_LOCK_TIMEOUT,
		).await.context("failed to acquire mailbox processing lock")?;
		let holder = VtxoState::Locked { holder: Some(VtxoLockHolder::MailboxReceive) };
		let vtxo_ids = self.inner.db.get_vtxos_by_state(&[VtxoStateKind::Locked]).await?
			.into_iter()
			.filter(|v| v.state == holder)
			.map(|v| v.id())
			.collect::<Vec<_>>();
		if vtxo_ids.is_empty() {
			return Ok(());
		}

		let mut spendable = Vec::new();
		for vtxo in self.inner.db.get_full_vtxos(&vtxo_ids).await? {
			if let Err(e) = self.register_vtxo_transactions_with_server(&[&vtxo]).await {
				debug!("Received arkoor VTXO {} still does not register: {:#}", vtxo.id(), e);
			}
			let key = self.get_vtxo_key(&vtxo).await?;
			let status = self.fetch_own_vtxo_status(vtxo.id(), &key).await?;
			if status.is_spent() {
				self.mark_vtxos_as_spent([vtxo.id()]).await?;
			} else if status.state == VtxoSpendState::Spendable {
				spendable.push(vtxo);
			}
		}
		if spendable.is_empty() {
			return Ok(());
		}

		let spendable_ids = spendable.iter().map(|v| v.id()).collect::<Vec<_>>();
		self.unlock_vtxos(spendable_ids, Some(VtxoLockHolder::MailboxReceive)).await?;
		self.credit_received_arkoor_vtxos(&spendable).await
	}

	/// Check that every output of a round participation has a key of this
	/// wallet. A server in expiry payout mode records this wallet's mailbox
	/// as the owner mailbox of every output.
	pub(crate) async fn check_round_output_keys(
		&self,
		participation: &RoundParticipation,
	) -> anyhow::Result<()> {
		let (srv, _) = self.require_server().await?;
		if !srv.expiry_payouts().await {
			return Ok(());
		}
		for output in &participation.outputs {
			let key = output.policy.user_pubkey();
			ensure!(self.pubkey_keypair(&key).await?.is_some(),
				"keypair {} not found for requested round output", key);
		}
		Ok(())
	}

	/// Store the outputs of a finished round. With a server in expiry payout
	/// mode, they stay locked until the server reports them bound to this
	/// wallet's mailbox, see [Wallet::release_round_outputs].
	pub(crate) async fn store_round_outputs(&self, outputs: &[Vtxo<Full>]) -> anyhow::Result<()> {
		if self.expiry_payouts().await {
			self.store_locked_vtxos(outputs, Some(VtxoLockHolder::RoundPayoutCheck)).await
		} else {
			self.store_spendable_vtxos(outputs).await
		}
	}

	/// Release the round outputs that the server reports bound to this
	/// wallet's mailbox. [Wallet::sync_expiry_payouts] tries again for the
	/// others.
	pub(crate) async fn release_round_outputs(&self, outputs: &[Vtxo<Full>]) {
		if !self.expiry_payouts().await {
			return;
		}
		for output in outputs {
			if let Err(e) = self.release_round_output(output).await {
				warn!("Round output {} stays locked until the server reports its owner \
					mailbox: {:#}", output.id(), e);
			}
		}
	}

	async fn release_round_output(&self, output: impl VtxoRef + Copy) -> anyhow::Result<()> {
		let key = self.get_vtxo_key(output).await?;
		let status = self.fetch_own_vtxo_status(output.vtxo_id(), &key).await?;
		ensure!(status.state == VtxoSpendState::Spendable,
			"the server does not report the round output spendable");
		self.unlock_vtxos([output.vtxo_id()], Some(VtxoLockHolder::RoundPayoutCheck)).await
	}
}

/// The blinded mailbox of an address with exactly one server mailbox delivery.
fn server_mailbox(address: &ark::Address) -> Option<BlindedMailboxIdentifier> {
	match address.delivery() {
		[VtxoDelivery::ServerMailbox { blinded_id }] => Some(*blinded_id),
		_ => None,
	}
}

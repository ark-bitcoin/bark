//! Expiry payouts.
//!
//! A server in expiry payout mode records an owner mailbox key `M` for every
//! VTXO it co-signs. When the tree of a VTXO expires, the server pays the
//! VTXO to `tr(M)`, minus a payout fee. The wallet sends its mailbox in every
//! request that makes a VTXO, checks the owner mailbox of every VTXO that it
//! receives, and records the payout that the server reports for an expired
//! VTXO.
//!
//! The wallet is in expiry payout mode when it negotiated
//! [server_rpc::pver::PROTOCOL_VERSION_SCUTTLE_EXPIRY_PAYOUT] with the server.
//! In any other mode, the functions here do nothing.

use std::collections::{HashMap, HashSet};
use std::str::FromStr;

use anyhow::Context;
use bitcoin::{Amount, ScriptBuf, SignedAmount};
use bitcoin::secp256k1::Keypair;
use log::{debug, warn};
use serde::{Deserialize, Serialize};

use ark::{ProtocolEncoding, Vtxo, VtxoId, VtxoPolicy};
use ark::address::VtxoDelivery;
use ark::attestations::LightningSendIntent;
use ark::lightning::Bolt11InvoiceExt;
use ark::mailbox::BlindedMailboxIdentifier;
use ark::vtxo::{Full, VtxoRef};
use server_rpc::ServerConnection;
use server_rpc::protos::{self, VtxoSpendState};

use crate::Wallet;
use crate::actions::WalletAction;
use crate::actions::lightning::{pay, receive};
use crate::actions::offboard::{self, Offboard};
use crate::mailbox::{MAILBOX_PROCESSING_LOCK_KEY, MAILBOX_PROCESSING_LOCK_TIMEOUT};
use crate::movement::MovementStatus;
use crate::movement::update::MovementUpdate;
use crate::round::RoundParticipation;
use crate::vtxo::{VtxoLockHolder, VtxoState, VtxoStateKind};
use crate::vtxo::selection::InputSelection;

/// The state of the expiry payout of a VTXO, as the server reports it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExpiryPayoutState {
	/// The payout transaction is less than six blocks deep.
	Pending,
	/// The payout transaction is at least six blocks deep.
	Paid,
	/// The payout fee is not less than the VTXO amount, so the server pays
	/// nothing.
	Forfeited,
}

impl ExpiryPayoutState {
	pub fn as_str(self) -> &'static str {
		match self {
			Self::Pending => "pending",
			Self::Paid => "paid",
			Self::Forfeited => "forfeited",
		}
	}

	/// The wallet state of a VTXO that has an expiry payout. The server no
	/// longer accepts the VTXO, so it is spent, unless the wallet exited it.
	pub(crate) fn vtxo_state(current: &VtxoState) -> VtxoState {
		match current {
			VtxoState::Exited => VtxoState::Exited,
			_ => VtxoState::Spent,
		}
	}
}

impl FromStr for ExpiryPayoutState {
	type Err = anyhow::Error;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		match s {
			"pending" => Ok(Self::Pending),
			"paid" => Ok(Self::Paid),
			"forfeited" => Ok(Self::Forfeited),
			_ => bail!("unknown expiry payout state: {}", s),
		}
	}
}

/// The expiry payout of a VTXO, as the server reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpiryPayout {
	pub status: ExpiryPayoutState,
	/// The amount of the VTXO.
	pub gross: Amount,
	/// The payout fee.
	pub fee: Amount,
	/// The amount paid on-chain, zero for a forfeited VTXO.
	pub payout: Amount,
	/// The payout address of this wallet, `tr(M)` of its mailbox key `M`.
	pub address: bitcoin::Address,
}

/// The status of a VTXO from a server in expiry payout mode.
pub(crate) struct ServerVtxoStatus {
	pub state: VtxoSpendState,
	/// Whether the owner mailbox of the VTXO is the mailbox of this wallet.
	pub own_mailbox: bool,
	pub payout: Option<ExpiryPayoutState>,
}

impl ServerVtxoStatus {
	/// Whether the VTXO is spent on the server.
	fn is_spent(&self) -> bool {
		self.payout.is_some() || self.state == VtxoSpendState::Spent
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

	/// Leave VTXOs at or past their expiry out of a payment on a server in
	/// expiry payout mode. The server pays such a VTXO to its owner and
	/// refuses a payment that spends it, so selecting one only makes the
	/// payment fail. A refresh does not use this selection and can still
	/// take an expired VTXO before the server decides its payout.
	pub(crate) async fn skip_expired_inputs(&self, selection: InputSelection) -> anyhow::Result<InputSelection> {
		if !self.expiry_payouts().await {
			return Ok(selection);
		}
		Ok(selection.expires_after(self.inner.chain.tip().await?))
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

	/// Sign a Lightning payment request for a server in expiry payout mode.
	///
	/// That server pays an invoice only for a request that the owner of the
	/// HTLC VTXOs signs. The nonce of the send makes the request unique, and a
	/// retry sends the same request again.
	pub(crate) async fn sign_lightning_payment(
		&self,
		send: &pay::LightningSend,
		htlcs: &pay::Htlcs,
		req: &mut protos::InitiateLightningPaymentRequest,
	) -> anyhow::Result<()> {
		let nonce = send.intent_nonce.context("the Lightning send has no request nonce")?;
		let (_, keypair) = self.pubkey_keypair(&send.htlc_key).await?
			.context("the HTLC key of the Lightning send is not in this wallet")?;
		let ark_info = self.require_ark_info().await?;

		let intent = LightningSendIntent::new(
			nonce, ark_info.server_pubkey, ark_info.network, &send.invoice, send.payment_amount,
			&htlcs.vtxo_ids, Some(htlcs.mailbox_id), req.retry_for_secs,
		);
		req.intent_nonce = Some(nonce.to_vec());
		req.source_owner_signature = intent.sign(&keypair).serialize().to_vec();
		Ok(())
	}

	/// The expiry payout that the server decided for a VTXO of this wallet,
	/// or `None` if it decided none.
	///
	/// This is what the server reports. Confirm the payout on-chain at the
	/// payout address before you count it as received.
	pub async fn expiry_payout(&self, vtxo_id: VtxoId) -> anyhow::Result<Option<ExpiryPayout>> {
		let vtxo = self.get_vtxo_by_id(vtxo_id).await?;
		let key = self.get_vtxo_key(&vtxo).await?;
		let (mut statuses, _) = self.fetch_vtxo_statuses(&[(vtxo_id, &key)]).await?;
		let status = statuses.remove(&vtxo_id)
			.with_context(|| format!("the server returned no status for VTXO {vtxo_id}"))?;
		let Some(payout) = status.expiry_payout else {
			return Ok(None);
		};
		ensure!(status.owner_mailbox == self.mailbox_keypair().public_key().serialize(),
			"the expiry payout of VTXO {vtxo_id} goes to another mailbox",
		);

		let network = self.network().await?;
		Ok(Some(ExpiryPayout {
			status: expiry_payout_state(&payout)?,
			gross: Amount::from_sat(payout.gross_sat),
			fee: Amount::from_sat(payout.fee_sat),
			payout: Amount::from_sat(payout.payout_sat),
			address: bitcoin::Address::from_script(&self.payout_script(), network)?,
		}))
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
			let state = VtxoSpendState::try_from(status.spend_state);
			let payout = status.expiry_payout.as_ref().map(expiry_payout_state).transpose();
			let (Ok(state), Ok(payout)) = (state, payout) else {
				warn!("Server returned an unusable status for vtxo {id}; this wallet may need updating");
				continue;
			};
			let own_mailbox = status.owner_mailbox == mailbox;
			ret.insert(id, ServerVtxoStatus { state, own_mailbox, payout });
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

	/// The status of a VTXO received by arkoor. `None` if the server answers
	/// without a status that this wallet can use, or with another owner
	/// mailbox.
	///
	/// The server delivers a VTXO only to its owner mailbox, so neither is
	/// expected. The wallet keeps such a VTXO locked: an error would stop it
	/// from reading the rest of its mailbox.
	async fn fetch_received_vtxo_status(
		&self,
		vtxo: &Vtxo<Full>,
	) -> anyhow::Result<Option<ServerVtxoStatus>> {
		let key = self.get_vtxo_key(vtxo).await?;
		let (mut statuses, answered) = self.fetch_server_vtxo_statuses(&[(vtxo.id(), &key)]).await?;
		ensure!(answered.contains(&vtxo.id()), "the server returned no status for VTXO {}", vtxo.id());
		Ok(statuses.remove(&vtxo.id()).filter(|status| status.own_mailbox))
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

	/// Ask the server whether it decided an expiry payout for any of these
	/// stored VTXOs, and mark each VTXO that it did as spent. A VTXO whose
	/// owner mailbox is this wallet's also gets its payout state.
	///
	/// Returns whether the server decided a payout for any of the VTXOs.
	pub(crate) async fn check_expiry_payout(&self, vtxo_ids: &[VtxoId]) -> anyhow::Result<bool> {
		if vtxo_ids.is_empty() || !self.expiry_payouts().await {
			return Ok(false);
		}

		let mut keys = Vec::with_capacity(vtxo_ids.len());
		for id in vtxo_ids {
			let vtxo = self.get_vtxo_by_id(*id).await?;
			keys.push((*id, self.get_vtxo_key(&vtxo).await?));
		}
		let queries = keys.iter().map(|(id, key)| (*id, key)).collect::<Vec<_>>();
		let (statuses, _) = self.fetch_server_vtxo_statuses(&queries).await?;

		let mut decided = false;
		for id in vtxo_ids {
			let Some(status) = statuses.get(id) else { continue };
			let Some(payout) = status.payout else { continue };
			if status.own_mailbox {
				self.inner.db.set_vtxo_expiry_payout_state(*id, payout).await?;
			} else {
				self.mark_vtxos_as_spent([*id]).await?;
			}
			decided = true;
		}
		Ok(decided)
	}

	/// [Wallet::check_expiry_payout], and whether every one of these VTXOs is
	/// spent after it. An action that holds them has nothing left to do.
	async fn check_expiry_payout_all_spent(&self, vtxo_ids: &[VtxoId]) -> anyhow::Result<bool> {
		if !self.check_expiry_payout(vtxo_ids).await? {
			return Ok(false);
		}
		for id in vtxo_ids {
			if self.get_vtxo_by_id(*id).await?.state.kind() != VtxoStateKind::Spent {
				return Ok(false);
			}
		}
		Ok(true)
	}

	/// [Wallet::check_expiry_payout] for VTXOs that the wallet just stored as
	/// spent. An error is only logged.
	pub(crate) async fn record_expiry_payouts(&self, vtxo_ids: impl IntoIterator<Item = VtxoId>) {
		let vtxo_ids = vtxo_ids.into_iter().collect::<Vec<_>>();
		if let Err(e) = self.check_expiry_payout(&vtxo_ids).await {
			warn!("Could not check {} spent VTXOs for an expiry payout: {:#}", vtxo_ids.len(), e);
		}
	}

	/// Check the expired VTXOs that this wallet still holds and the VTXOs
	/// with a pending payout for an expiry payout. Also release the round
	/// outputs that the server reports bound to this wallet's mailbox.
	///
	/// Does nothing unless the server is in expiry payout mode.
	pub async fn sync_expiry_payouts(&self) -> anyhow::Result<()> {
		let (srv, _) = self.require_server().await?;
		if !srv.expiry_payouts().await {
			return Ok(());
		}

		let tip = self.chain().tip().await?;
		let mut vtxo_ids = Vec::new();
		for vtxo in self.inner.db.get_all_vtxos().await? {
			if vtxo.state == (VtxoState::Locked { holder: Some(VtxoLockHolder::RoundPayoutCheck) }) {
				if let Err(e) = self.release_round_output(&vtxo.vtxo).await {
					warn!("Round output {} stays locked until the server reports its owner \
						mailbox: {:#}", vtxo.id(), e);
				}
			}
			let held = vtxo.expiry_height() <= tip
				&& VtxoStateKind::UNSPENT_STATES.contains(&vtxo.state.kind());
			if held || vtxo.expiry_payout_state == Some(ExpiryPayoutState::Pending) {
				vtxo_ids.push(vtxo.id());
			}
		}
		self.check_expiry_payout(&vtxo_ids).await?;
		Ok(())
	}

	/// [Wallet::sync_expiry_payouts] as a step of [Wallet::sync] or of a
	/// daemon pass, which do not connect to the server. An error is only
	/// logged.
	pub(crate) async fn sync_expiry_payouts_if_connected(&self) {
		if !self.expiry_payouts().await {
			return;
		}
		if let Err(e) = self.sync_expiry_payouts().await {
			warn!("Error checking expired VTXOs for an expiry payout: {:#}", e);
		}
	}

	/// Check VTXOs received by arkoor with a server in expiry payout mode.
	///
	/// Returns the VTXOs that the server reports spendable and bound to this
	/// wallet's mailbox. Stores a VTXO that the server already paid out as
	/// spent, and any other VTXO as locked.
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
			match self.fetch_received_vtxo_status(&vtxo).await? {
				Some(status) if status.is_spent() => {
					// The server can pay out a VTXO before this wallet reads it.
					self.store_vtxos([&vtxo], &VtxoState::Spent).await?;
					if let Some(payout) = status.payout {
						self.inner.db.set_vtxo_expiry_payout_state(vtxo.id(), payout).await?;
					}
				},
				Some(status) if status.state == VtxoSpendState::Spendable => spendable.push(vtxo),
				status => {
					warn!("Received arkoor VTXO {} is not spendable on the server ({:?}); \
						it stays locked", vtxo.id(), status.map(|status| status.state));
					let holder = Some(VtxoLockHolder::MailboxReceive);
					self.store_vtxos([&vtxo], &VtxoState::Locked { holder }).await?;
				},
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
			let Some(status) = self.fetch_received_vtxo_status(&vtxo).await? else {
				continue;
			};
			if status.is_spent() {
				self.mark_vtxos_as_spent([vtxo.id()]).await?;
				if let Some(payout) = status.payout {
					self.inner.db.set_vtxo_expiry_payout_state(vtxo.id(), payout).await?;
				}
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

	/// Whether the server decided an expiry payout for an input of a round
	/// participation. The server then cancels the participation and accepts
	/// no forfeit for it.
	pub(crate) async fn has_expiry_payout_input(
		&self,
		participation: &RoundParticipation,
	) -> anyhow::Result<bool> {
		for input in &participation.inputs {
			if let Some(vtxo) = self.inner.db.get_wallet_vtxo(input.id()).await? {
				if vtxo.expiry_payout_state.is_some() {
					return Ok(true);
				}
			}
		}
		Ok(false)
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
		ensure!(status.state == VtxoSpendState::Spendable && status.payout.is_none(),
			"the server does not report the round output spendable");
		self.unlock_vtxos([output.vtxo_id()], Some(VtxoLockHolder::RoundPayoutCheck)).await
	}

	/// Whether a server in expiry payout mode refunds an arkoor to its sender
	/// on-chain. It does when an output expires before its registration.
	pub(crate) async fn is_refunded_arkoor(&self, outputs: &[Vtxo<Full>]) -> anyhow::Result<bool> {
		if !self.expiry_payouts().await {
			return Ok(false);
		}
		let tip = self.inner.chain.tip().await?;
		Ok(outputs.iter().any(|v| v.expiry_height() <= tip))
	}

	/// Whether the server paid out a VTXO of an offboard that is not
	/// broadcast yet. The server refuses the forfeit of such a VTXO, so the
	/// offboard cannot complete.
	pub(crate) async fn is_paid_out_offboard(&self, offboard: &Offboard) -> anyhow::Result<bool> {
		match offboard.progress {
			offboard::Progress::ArkoorRegistrationRequired { .. }
				| offboard::Progress::ReadyForOffboard { prior_txid: Some(_), .. }
				| offboard::Progress::OffboardTxPrepared { .. }
			=> self.check_expiry_payout(&offboard.pending_balance_vtxo_ids()).await,
			_ => Ok(false),
		}
	}

	/// Finish a Lightning send whose HTLC VTXOs the server paid out. Such
	/// HTLCs cannot be revoked, and the payout goes to the payout address
	/// of this wallet.
	///
	/// Returns whether the send is finished.
	pub(crate) async fn finish_paid_out_lightning_send(
		&self,
		htlcs: &pay::Htlcs,
	) -> anyhow::Result<bool> {
		if !self.check_expiry_payout_all_spent(&htlcs.vtxo_ids).await? {
			return Ok(false);
		}
		self.inner.movements.finish_movement_with_update(
			htlcs.movement_id,
			MovementStatus::Failed,
			MovementUpdate::new().effective_balance(SignedAmount::ZERO).fee(Amount::ZERO),
		).await?;
		Ok(true)
	}

	/// Finish a Lightning receive whose HTLC VTXOs the server paid out
	/// instead of honouring the claim. The payout goes to the payout address
	/// of this wallet or of the claim destination.
	///
	/// Returns whether the receive is finished. An error is only logged.
	pub(crate) async fn finish_paid_out_lightning_receive(
		&self,
		recv: &receive::LightningReceive,
	) -> bool {
		let receive::Progress::PreimageRevealed(htlcs) = &recv.progress else {
			return false;
		};
		let res = async {
			if !self.check_expiry_payout_all_spent(&htlcs.vtxo_ids).await? {
				return Ok(false);
			}
			// The settled record goes first, see claim_lightning_receive_htlcs.
			let amount = recv.invoice.get_payment_amount(None)
				.context("the invoice of the receive has no amount")?;
			self.inner.db.record_settled_lightning_receive(
				recv.payment_hash, recv.payment_preimage, &recv.invoice, amount,
			).await?;
			self.inner.movements.finish_movement_with_update(
				htlcs.movement_id,
				MovementStatus::Successful,
				MovementUpdate::new().effective_balance(SignedAmount::ZERO),
			).await?;
			anyhow::Ok(true)
		}.await;
		res.unwrap_or_else(|e| {
			warn!("Could not check lightning receive {} for an expiry payout: {:#}",
				recv.payment_hash, e,
			);
			false
		})
	}
}

/// The blinded mailbox of an address with exactly one server mailbox delivery.
fn server_mailbox(address: &ark::Address) -> Option<BlindedMailboxIdentifier> {
	match address.delivery() {
		[VtxoDelivery::ServerMailbox { blinded_id }] => Some(*blinded_id),
		_ => None,
	}
}

fn expiry_payout_state(payout: &protos::ExpiryPayout) -> anyhow::Result<ExpiryPayoutState> {
	match protos::ExpiryPayoutState::try_from(payout.state) {
		Ok(protos::ExpiryPayoutState::Pending) => Ok(ExpiryPayoutState::Pending),
		Ok(protos::ExpiryPayoutState::Paid) => Ok(ExpiryPayoutState::Paid),
		Ok(protos::ExpiryPayoutState::Forfeited) => Ok(ExpiryPayoutState::Forfeited),
		_ => bail!("unknown expiry payout state {}", payout.state),
	}
}

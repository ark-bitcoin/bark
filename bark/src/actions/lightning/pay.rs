//! State machine for outgoing lightning payments.
//!
//! Identity (`invoice`, `original_payment_method`) and the parameters
//! fixed at the start (inputs, amounts, htlc key, expiry) live on the
//! action as top-level fields; the mutable bit is [`Progress`], a small
//! enum that names the four phases of the state machine and only carries
//! the fields the phase actually has.
//!
//! Transition functions take `&LightningSend` and return the new phase
//! output. The [`WalletAction`](crate::actions::WalletAction) impl
//! pattern-matches on progress and dispatches; persistence is the
//! executor's job.

use std::time::Duration;

use anyhow::Context;
use bitcoin::hex::DisplayHex;
use bitcoin::secp256k1::PublicKey;
use bitcoin::{Amount, SignedAmount};
use log::{debug, error, info, trace, warn};

use ark::arkoor::ArkoorDestination;
use ark::arkoor::package::{ArkoorPackageBuilder, ArkoorPackageCosignResponse};
use ark::lightning::{Invoice, PaymentHash, PaymentStatus, Preimage};
use ark::mailbox::MailboxIdentifier;
use ark::util::IteratorExt;
use ark::{ProtocolEncoding, VtxoId, VtxoPolicy};
use bitcoin_ext::BlockHeight;
use server_rpc::protos::{self, lightning_payment_status};

use crate::Wallet;
use crate::actions::{Advance, AdvanceError, WalletAction, WalletActionId, park_with_backoff};
use crate::movement::update::MovementUpdate;
use crate::movement::{MovementDestination, MovementId, MovementStatus, PaymentMethod};
use crate::persist::models::PaidInvoice;
use crate::subsystem::{LightningMovement, LightningSendMovement, Subsystem};
use crate::vtxo::VtxoLockHolder;

const LN_PAY_NAMESPACE: &str = "ln_pay";

pub(crate) fn ln_pay_action_id(payment_hash: PaymentHash) -> WalletActionId {
	format!("{LN_PAY_NAMESPACE}.{payment_hash}")
}

/// Outcome of a lightning send lookup by payment hash.
///
/// `Paid` records come from `bark_paid_invoice` and are kept forever.
/// `InProgress` records come from `bark_wallet_action_checkpoint`.
/// `Unknown` means the wallet has no memory of this payment hash.
#[derive(Debug, Clone)]
pub enum LightningSendState {
	Unknown,
	InProgress(LightningSend),
	Paid(PaidInvoice),
}

/// An outgoing lightning payment, persisted as a single checkpoint row
/// and driven across crashes by the executor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LightningSend {
	// Set at start, immutable thereafter:
	pub invoice: Invoice,
	pub original_payment_method: PaymentMethod,
	pub input_vtxo_ids: Vec<VtxoId>,
	pub payment_amount: Amount,
	pub fee: Amount,

	/// Used as both the HTLC output's locked pubkey and as the change
	/// pubkey (reused to avoid a second key derivation).
	pub htlc_key: PublicKey,
	pub htlc_expiry: BlockHeight,

	// Mutable state:
	pub progress: Progress,
}

impl LightningSend {
	pub fn id(&self) -> WalletActionId {
		ln_pay_action_id(self.invoice.payment_hash())
	}

	pub fn total_amount(&self) -> Amount {
		self.payment_amount + self.fee
	}

	/// Returns whether the HTLCs are near expiry. It also returns true
	/// if the HTLCs are actually expired.
	pub async fn is_htlc_near_expiry(&self, wallet: &Wallet) -> anyhow::Result<bool> {
		let tip = wallet.inner.chain.tip().await?;
		Ok(tip > self.htlc_expiry
			.saturating_sub(wallet.config().vtxo_refresh_expiry_threshold))
	}
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl WalletAction for LightningSend {
	fn id(&self) -> WalletActionId { LightningSend::id(self) }

	async fn advance(self, wallet: &Wallet) -> Result<Advance<Self>, AdvanceError> {
		let new_progress = match self.progress.clone() {
			Progress::Start => {
				let htlcs = request_lightning_send_htlcs(wallet, &self).await?;
				Progress::HtlcReceived(htlcs)
			},
			Progress::HtlcReceived(htlcs) => {
				initiate_lightning_send_payment(wallet, &self, &htlcs).await?;
				Progress::PaymentInitiated(htlcs)
			},
			Progress::PaymentInitiated(htlcs) => {
				let wait = false;
				match check_lightning_send_payment_status(
					wallet, &self, &htlcs, wait,
				).await? {
					PaymentStatus::Success(preimage) => {
						settle_lightning_send_payment(wallet, &self, &htlcs, preimage).await?;
						return Ok(Advance::Done);
					},
					PaymentStatus::Failed => {
						let revocation = fail_lightning_send_payment(wallet, &self).await?;
						Progress::RevocableHtlcs { htlcs, revocation }
					},
					PaymentStatus::Pending => {
						if self.is_htlc_near_expiry(wallet).await? {
							let revocation = fail_lightning_send_payment(wallet, &self).await?;
							Progress::RevocableHtlcs { htlcs, revocation }
						} else {
							return Ok(Advance::Park {
								state: LightningSend {
									progress: Progress::PaymentInitiated(htlcs),
									..self
								},
								wake_after: Some(PAYMENT_PENDING_POLL_INTERVAL),
								error: None,
							});
						}
					},
				}
			},
			Progress::RevocableHtlcs { htlcs, revocation } => {
				handle_lightning_send_htlcs_revocation(wallet, &self, &htlcs, &revocation).await?;
				return Ok(Advance::Done);
			},
		};

		Ok(Advance::Next(LightningSend { progress: new_progress, ..self }))
	}

	async fn on_retry(self, wallet: &Wallet, retries: u32) -> anyhow::Result<Advance<Self>> {
		if self.is_htlc_near_expiry(wallet).await? {
			match self.progress.clone() {
				Progress::Start => {
					let err = anyhow!("Could not start lightning send and HTLCs are near expiry");
					return Ok(Advance::Failed(err));
				},
				Progress::HtlcReceived(htlcs) |
				Progress::PaymentInitiated(htlcs) => {
					let revocation = fail_lightning_send_payment(wallet, &self).await?;
					let next = LightningSend {
						progress: Progress::RevocableHtlcs { htlcs, revocation },
						..self
					};
					return Ok(Advance::Next(next));
				},
				Progress::RevocableHtlcs { htlcs, .. } => {
					// TODO: maybe we don't want to exit but rather log VTXOs
					exit_lightning_send_htlcs(wallet, &self, &htlcs).await?;
					let err = anyhow!("We could not revoke HTLCs and they are near expiry, exiting");
					return Ok(Advance::Failed(err));
				},
			}
		}

		Ok(park_with_backoff(self, retries))
	}

	async fn on_rejection(self, wallet: &Wallet, error: AdvanceError) -> anyhow::Result<Advance<Self>> {
		match self.progress.clone() {
			// Nothing committed server-side: drop the locks and the row
			// ourselves, then bail. We can't rely on the executor's
			// `Advance::Done` path because we want the original error
			// surfaced to the caller.
			Progress::Start => {
				let id = self.id();
				error!("Could not start lightning send {}: {:?}", id, error);
				if let Err(cancel_err) = wallet.stop_wallet_action(&id).await {
					warn!("could not cancel start-phase lightning send {}: {:#}", id, cancel_err);
				}
				Ok(Advance::Failed(error.into()))
			},
			Progress::HtlcReceived(htlcs) |
			Progress::PaymentInitiated(htlcs) => {
				let revocation = fail_lightning_send_payment(wallet, &self).await?;
				let next = LightningSend {
					progress: Progress::RevocableHtlcs { htlcs, revocation },
					..self
				};
				Ok(Advance::Next(next))
			},
			Progress::RevocableHtlcs { htlcs, .. } => {
				// TODO: maybe we don't want to exit but rather log VTXOs
				exit_lightning_send_htlcs(wallet, &self, &htlcs).await?;
				return Ok(Advance::Failed(anyhow!("Server refused to revoke HTLCs, exiting")));
			},
		}
	}
}

/// The four phases of an outgoing lightning send. The enum tag is the
/// phase; each variant carries only the data that exists by that
/// phase, so impossible combinations are unrepresentable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Progress {
	/// Inputs are locked, no server interaction yet.
	Start,
	/// Server cosigned the HTLC outputs; vtxos and movement persisted.
	HtlcReceived(Htlcs),
	/// Server has been told to pay; outcome is pending.
	PaymentInitiated(Htlcs),
	/// Payment failed; HTLCs must be revoked back to a spendable vtxo.
	RevocableHtlcs { htlcs: Htlcs, revocation: Revocation },
}

/// The HTLC vtxos the server cosigned for us, plus the movement they
/// belong to and the mailbox the server will push notifications to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Htlcs {
	pub vtxo_ids: Vec<VtxoId>,
	#[serde(with = "ark::encode::serde")]
	pub mailbox_id: MailboxIdentifier,
	pub movement_id: MovementId,
}

/// Revocation keypair derived when a payment is determined to have
/// failed; the public key is used to ask the server to cosign a claim
/// back to us.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Revocation {
	pub key: PublicKey,
}

/// How long to sleep between poll attempts when the server reports `Pending`.
const PAYMENT_PENDING_POLL_INTERVAL: Duration = Duration::from_secs(2);

/// Build a fresh [`LightningSend`] in `Progress::Start`: pick inputs,
/// lock them, derive the htlc key, snapshot expiry.
///
/// The executor persists the returned state. Idempotent under re-run
/// only if no checkpoint exists yet for this invoice (the caller is
/// responsible for the existence check).
pub(crate) async fn start_lightning_send(
	wallet: &Wallet,
	invoice: Invoice,
	user_amount: Option<Amount>,
	original_payment_method: PaymentMethod,
) -> anyhow::Result<LightningSend> {
	let (_, ark_info) = wallet.require_server().await?;
	let tip = wallet.inner.chain.tip().await?;

	let properties = wallet.inner.db.read_properties().await?.context("Missing config")?;
	if invoice.network() != properties.network {
		bail!("Invoice is for wrong network: {}", invoice.network());
	}

	invoice.check_signature()?;

	let payment_amount = invoice.get_payment_amount(user_amount)?;
	if payment_amount == Amount::ZERO {
		bail!("Cannot pay invoice for 0 sats (0 sat invoices are not any-amount invoices)");
	}

	let (inputs, fee) = wallet.select_vtxos_to_cover_with_fee(
		payment_amount,
		|a, v| ark_info.fees.lightning_send.calculate(a, v).context("fee overflowed"),
	).await.context("Could not find enough suitable VTXOs to cover lightning payment")?;

	let action_id = ln_pay_action_id(invoice.payment_hash());
	wallet.lock_vtxos(
		&inputs,
		Some(crate::vtxo::VtxoLockHolder::Action { id: action_id }),
	).await?;

	let (change_keypair, _) = wallet.derive_store_next_keypair().await?;

	let htlc_expiry = tip + ark_info.htlc_send_expiry_delta as BlockHeight;

	Ok(LightningSend {
		invoice,
		original_payment_method,
		input_vtxo_ids: inputs.iter().map(|v| v.id()).collect(),
		payment_amount,
		fee,
		htlc_key: change_keypair.public_key(),
		htlc_expiry,
		progress: Progress::Start,
	})
}

/// Start -> HtlcReceived. Server cosigns the HTLC outputs; the wallet
/// records the resulting vtxos and movement.
///
/// Server-side contract: `request_lightning_pay_htlc_cosign` is
/// idempotent on payment_hash and returns a fresh partial signature for
/// each set of user nonces. Re-driving generates new nonces, which the
/// server combines into a new valid response.
pub(crate) async fn request_lightning_send_htlcs(
	wallet: &Wallet,
	send: &LightningSend,
) -> Result<Htlcs, AdvanceError> {
	let (mut srv, _) = wallet.require_server().await?;

	let full_inputs = wallet.inner.db.get_full_vtxos(&send.input_vtxo_ids).await
		.context("failed to hydrate lightning-send input vtxos")?;

	// Ensure inputs are fully registered server-side before the cosign.
	wallet.register_vtxo_transactions_with_server(&full_inputs).await
		.context("failed to register lightning-send input vtxo transactions with server")?;

	let mut input_keypairs = Vec::with_capacity(full_inputs.len());
	for input in full_inputs.iter() {
		input_keypairs.push(wallet.get_vtxo_key(input).await?);
	}

	let policy = VtxoPolicy::new_server_htlc_send(
		send.htlc_key, send.invoice.payment_hash(), send.htlc_expiry,
	);
	let total_amount = send.total_amount();
	let input_amount = full_inputs.iter().map(|v| v.amount()).sum::<Amount>();
	let pay_dest = ArkoorDestination { total_amount, policy };
	let outputs = if input_amount == total_amount {
		vec![pay_dest]
	} else {
		let change_dest = ArkoorDestination {
			total_amount: input_amount - total_amount,
			policy: VtxoPolicy::new_pubkey(send.htlc_key),
		};
		vec![pay_dest, change_dest]
	};

	let builder = ArkoorPackageBuilder::new_with_checkpoints(
		full_inputs.clone(),
		outputs,
	)
		.context("Failed to construct arkoor package")?
		.generate_user_nonces(&input_keypairs)
		.context("invalid nb of keypairs")?;

	let cosign_request = protos::LightningPayHtlcCosignRequest {
		parts: protos::ArkoorPackageCosignRequest::from(builder.cosign_request()).parts,
	};
	let response = srv.client.request_lightning_pay_htlc_cosign(cosign_request).await
		.map_err(AdvanceError::Server)?.into_inner();
	let cosign_responses = ArkoorPackageCosignResponse::try_from(response)
		.context("Failed to parse cosign response from server")?;

	let vtxos = builder
		.user_cosign(&input_keypairs, cosign_responses)
		.context("Failed to cosign vtxos")?
		.build_signed_vtxos();

	let (htlc_vtxos, change_vtxos) = vtxos.clone().into_iter()
		.partition::<Vec<_>, _>(|v| matches!(v.policy(), VtxoPolicy::ServerHtlcSend(_)));

	let mut effective_balance = Amount::ZERO;
	for vtxo in &htlc_vtxos {
		wallet.validate_vtxo(vtxo).await?;
		effective_balance += vtxo.amount();
	}
	for change in &change_vtxos {
		let last_input = full_inputs.last().context("no inputs provided")?;
		let tx = wallet.inner.chain.get_tx(&last_input.chain_anchor().txid).await?;
		let tx = tx.with_context(|| format!(
			"input vtxo chain anchor not found for lightning change vtxo: {}",
			last_input.chain_anchor().txid,
		))?;
		change.validate(&tx).context("invalid lightning change vtxo")?;
	}

	if let Err(e) = wallet.register_vtxo_transactions_with_server(&vtxos).await {
		warn!("failed to register lightning-send output vtxo transactions with server: {:#}", e);
	}

	let movement_id = wallet.inner.movements.new_movement_with_update(
		Subsystem::LIGHTNING_SEND,
		LightningSendMovement::Send.to_string(),
		MovementUpdate::new()
			.intended_balance(-send.payment_amount.to_signed().context("payment amount out of range")?)
			.effective_balance(-effective_balance.to_signed().context("effective balance out of range")?)
			.fee(send.fee)
			.consumed_vtxos(&full_inputs)
			.sent_to([MovementDestination::new(send.original_payment_method.clone(), send.payment_amount)])
			.metadata(LightningMovement::metadata(send.invoice.payment_hash(), &htlc_vtxos, None))
	).await.context("failed to create movement")?;
	wallet.store_locked_vtxos(
		&htlc_vtxos,
		Some(VtxoLockHolder::Movement { id: movement_id })
	).await?;
	wallet.mark_vtxos_as_spent(&send.input_vtxo_ids).await?;
	wallet.store_spendable_vtxos(&change_vtxos).await?;
	wallet.inner.movements.update_movement(
		movement_id,
		MovementUpdate::new()
			.produced_vtxos(change_vtxos)
			.metadata(LightningMovement::metadata(send.invoice.payment_hash(), &htlc_vtxos, None))
	).await.context("failed to update movement")?;

	Ok(Htlcs {
		vtxo_ids: htlc_vtxos.iter().map(|v| v.id()).collect(),
		mailbox_id: wallet.mailbox_identifier(),
		movement_id,
	})
}

/// HtlcReceived -> PaymentInitiated. Tells the server to actually pay
/// the invoice. Server-side `initiate_lightning_payment` is idempotent
/// on payment_hash.
pub(crate) async fn initiate_lightning_send_payment(
	wallet: &Wallet,
	send: &LightningSend,
	htlcs: &Htlcs,
) -> Result<(), AdvanceError> {
	let (mut srv, _) = wallet.require_server().await?;

	let req = protos::InitiateLightningPaymentRequest {
		invoice: send.invoice.to_string(),
		htlc_vtxo_ids: htlcs.vtxo_ids.iter().map(|v| v.to_bytes().to_vec()).collect(),
		payment_amount_sat: send.payment_amount.to_sat(),
		mailbox_id: Some(htlcs.mailbox_id.serialize()),
	};
	srv.client.initiate_lightning_payment(req).await
		.map_err(AdvanceError::Server)?;

	Ok(())
}

/// Poll the server for payment status. Treats expired HTLCs as failed
/// (server response of Pending plus tip past expiry collapses to Failed
/// so the caller can revoke).
pub(crate) async fn check_lightning_send_payment_status(
	wallet: &Wallet,
	send: &LightningSend,
	htlcs: &Htlcs,
	wait: bool,
) -> anyhow::Result<PaymentStatus> {
	let (mut srv, _) = wallet.require_server().await?;
	let payment_hash = send.invoice.payment_hash();

	let mut htlc_vtxos = Vec::with_capacity(htlcs.vtxo_ids.len());
	for id in htlcs.vtxo_ids.iter() {
		htlc_vtxos.push(wallet.get_vtxo_by_id(*id).await?);
	}

	let policy = htlc_vtxos.iter()
		.all_same(|v| v.vtxo.policy())
		.context("All lightning htlc should have the same policy")?;
	let policy = policy.as_server_htlc_send().context("VTXO is not an HTLC send")?;
	if policy.payment_hash != payment_hash {
		bail!("Payment hash mismatch on stored HTLC policy");
	}

	let tip = wallet.inner.chain.tip().await?;
	let expired = tip > policy.htlc_expiry;
	let pending_status = if expired { PaymentStatus::Failed } else { PaymentStatus::Pending };

	let req = protos::CheckLightningPaymentRequest {
		hash: payment_hash.to_vec(),
		wait,
	};
	// NB: don't early-return on transport errors; collapse to
	// expired-or-pending so the executor can revoke when appropriate.
	let response = srv.client.check_lightning_payment(req).await
		.map(|r| r.into_inner().payment_status);

	match response {
		Ok(Some(lightning_payment_status::PaymentStatus::Success(s))) => {
			match Preimage::try_from(s.preimage) {
				Ok(preimage) if preimage.compute_payment_hash() == payment_hash => {
					Ok(PaymentStatus::Success(preimage))
				},
				other => {
					error!(
						"Server reported success but returned an invalid preimage for {}: {:?}",
						payment_hash, other,
					);
					Ok(pending_status)
				},
			}
		},
		Ok(Some(lightning_payment_status::PaymentStatus::Failed(_))) => {
			Ok(PaymentStatus::Failed)
		},
		Ok(Some(lightning_payment_status::PaymentStatus::Pending(_))) => {
			trace!("Payment {} is still pending", payment_hash);
			Ok(pending_status)
		},
		Ok(None) | Err(_) => Ok(pending_status),
	}
}

/// Terminal success: mark HTLC vtxos spent, finalise the movement with
/// the preimage, and persist the replay-protection record.
pub(crate) async fn settle_lightning_send_payment(
	wallet: &Wallet,
	send: &LightningSend,
	htlcs: &Htlcs,
	preimage: Preimage,
) -> anyhow::Result<()> {
	let payment_hash = send.invoice.payment_hash();
	if preimage.compute_payment_hash() != payment_hash {
		bail!("preimage does not match payment hash {}", payment_hash);
	}
	info!(
		"Lightning payment succeeded! Preimage: {}. Payment hash: {}",
		preimage.as_hex(), payment_hash.as_hex(),
	);

	wallet.inner.db.record_paid_invoice(payment_hash, preimage).await?;
	wallet.mark_vtxos_as_spent(&htlcs.vtxo_ids).await?;
	wallet.inner.movements.finish_movement_with_update(
		htlcs.movement_id,
		MovementStatus::Successful,
		MovementUpdate::new().metadata([(
			"payment_preimage".into(),
			serde_json::to_value(preimage).expect("payment preimage can serde"),
		)]),
	).await?;

	Ok(())
}

/// PaymentInitiated -> RevocableHtlcs. Derives a revocation keypair;
/// the actual server-side cosign happens in
/// [`revoke_lightning_send_htlcs`].
pub(crate) async fn fail_lightning_send_payment(
	wallet: &Wallet,
	send: &LightningSend,
) -> anyhow::Result<Revocation> {
	info!("Lightning payment {} failed, preparing to revoke", send.invoice.payment_hash());
	let (revocation_keypair, _) = wallet.derive_store_next_keypair().await?;
	Ok(Revocation { key: revocation_keypair.public_key() })
}

/// Cosign the revocation with the server, mark the HTLC vtxos spent
/// and the revocation outputs spendable, and finish the movement as
/// failed.
pub(crate) async fn revoke_lightning_send_htlcs(
	wallet: &Wallet,
	send: &LightningSend,
	htlcs: &Htlcs,
	revocation: &Revocation,
) -> Result<(), AdvanceError> {
	let (mut srv, _) = wallet.require_server().await?;

	debug!("Revoking {} HTLC vtxos for payment {}",
		htlcs.vtxo_ids.len(), send.invoice.payment_hash());

	let mut htlc_keypairs = Vec::with_capacity(htlcs.vtxo_ids.len());
	let mut htlc_vtxos = Vec::with_capacity(htlcs.vtxo_ids.len());
	for id in htlcs.vtxo_ids.iter() {
		let vtxo = wallet.inner.db.get_full_vtxo(*id).await?
			.with_context(|| format!("htlc vtxo with id {} not found", id))?;
		htlc_keypairs.push(wallet.get_vtxo_key(&vtxo).await?);
		htlc_vtxos.push(vtxo);
	}

	let revocation_claim_policy = VtxoPolicy::new_pubkey(revocation.key);
	let builder = ArkoorPackageBuilder::new_claim_all_with_checkpoints(
		htlc_vtxos.iter().cloned(),
		revocation_claim_policy,
	)
		.context("Failed to construct arkoor package")?
		.generate_user_nonces(&htlc_keypairs)
		.context("failed to generate user nonces")?;

	let cosign_request = protos::ArkoorPackageCosignRequest::from(builder.cosign_request());
	let response = srv.client
		.request_lightning_pay_htlc_revocation(cosign_request).await
		.map_err(AdvanceError::Server)?.into_inner();
	let cosign_resp = ArkoorPackageCosignResponse::try_from(response)
		.context("Failed to parse cosign response from server")?;

	let vtxos = builder
		.user_cosign(&htlc_keypairs, cosign_resp)
		.context("Failed to cosign vtxos")?
		.build_signed_vtxos();

	let revoked = vtxos.iter().map(|v| v.amount()).sum::<Amount>();
	let effective = -send.total_amount().to_signed().context("total amount out of range")? +
		revoked.to_signed().context("revoked amount out of range")?;
	if effective != SignedAmount::ZERO {
		warn!(
			"Movement {} should have fee of zero, but got {}: total = {}, revoked = {}",
			htlcs.movement_id, effective, send.total_amount(), revoked,
		);
	}
	wallet.inner.movements.finish_movement_with_update(
		htlcs.movement_id,
		MovementStatus::Failed,
		MovementUpdate::new()
			.effective_balance(effective)
			.fee(effective.unsigned_abs())
			.produced_vtxos(&vtxos),
	).await.context("failed to update movement")?;
	wallet.store_spendable_vtxos(&vtxos).await?;
	wallet.mark_vtxos_as_spent(&htlc_vtxos).await?;

	Ok(())
}

/// Escalation: when revocation has failed and the HTLC vtxos are about
/// to expire, mark them for unilateral exit and finish the movement
/// as failed.
pub(crate) async fn exit_lightning_send_htlcs(
	wallet: &Wallet,
	send: &LightningSend,
	htlcs: &Htlcs,
) -> anyhow::Result<()> {
	let payment_hash = send.invoice.payment_hash();
	warn!("HTLC VTXOs for payment {} are near expiry, marking to exit", payment_hash);

	let mut vtxos = Vec::with_capacity(htlcs.vtxo_ids.len());
	for id in htlcs.vtxo_ids.iter() {
		vtxos.push(wallet.get_vtxo_by_id(*id).await?.vtxo);
	}

	wallet.inner.exit.start_exit_for_vtxos(&vtxos).await?;

	let exited = vtxos.iter().map(|v| v.amount()).sum::<Amount>();
	let effective = -send.total_amount().to_signed()? + exited.to_signed()?;
	if effective != SignedAmount::ZERO {
		warn!(
			"Movement {} should have fee of zero, but got {}: total = {}, exited = {}",
			htlcs.movement_id, effective, send.total_amount(), exited,
		);
	}
	wallet.inner.movements.finish_movement_with_update(
		htlcs.movement_id,
		MovementStatus::Failed,
		MovementUpdate::new()
			.effective_balance(effective)
			.fee(effective.unsigned_abs())
			.exited_vtxos(&vtxos),
	).await?;

	Ok(())
}

/// Drives revocation forward: tries to revoke, escalates to exit if
/// the vtxos are close to expiry. Returns `Ok(())` if either path
/// finished cleanly, otherwise propagates the revocation error so the
/// executor can retry later.
pub(crate) async fn handle_lightning_send_htlcs_revocation(
	wallet: &Wallet,
	send: &LightningSend,
	htlcs: &Htlcs,
	revocation: &Revocation,
) -> Result<(), AdvanceError> {
	let payment_hash = send.invoice.payment_hash();
	let tip = wallet.inner.chain.tip().await?;

	debug!("Revoking HTLC VTXOs for payment {} (tip: {}, expiry: {})",
		payment_hash, tip, send.htlc_expiry);


	revoke_lightning_send_htlcs(wallet, send, htlcs, revocation).await
		.inspect_err(|e| {
			warn!("Failed to revoke HTLC VTXOs for payment {}: {:#}", payment_hash, e);
		})
}

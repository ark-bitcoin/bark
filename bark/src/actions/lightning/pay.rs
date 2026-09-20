//! State machine for outgoing lightning payments.
//!
//! Identity (`invoice`, `original_payment_method`) and the parameters
//! fixed at the start (inputs, amounts, htlc key, expiry) live on the
//! action as top-level fields; the mutable bit is [`Progress`], a small
//! enum that names the four phases of the state machine and only carries
//! the fields the phase actually has.
//!
//! Transition functions take `&LightningSend` and return the new phase
//! output. The [`WalletAction`] impl
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
use crate::actions::{
	abort, or_retry, Advance, AdvanceError, AdvanceResultExt, IntoAdvanceResult,
	RetryUnlessRejected, WalletAction, WalletActionId,
};
use crate::arkoor::{resolve_change_pieces, split_change_amount};
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
#[derive(Debug, Clone, PartialEq)]
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

	/// Change piece amounts fixed at start. `None` when persisted by a
	/// pre-split bark, meaning one whole change output.
	#[serde(default, with = "crate::utils::serde::opt_amount_vec_sat")]
	pub change_pieces: Option<Vec<Amount>>,

	/// Used as both the HTLC output's locked pubkey and as the change
	/// pubkey (reused to avoid a second key derivation).
	pub htlc_key: PublicKey,
	pub htlc_expiry: BlockHeight,

	/// Movement recording this payment, created up front in
	/// `start_lightning_send` so re-driving `Start` reuses it rather than
	/// creating a duplicate. `None` for checkpoints predating this field.
	#[serde(default)]
	pub movement_id: Option<MovementId>,

	/// HTLC revocation key, pre-derived at start (like `htlc_key`) so the
	/// failure step is idempotent. `None` for checkpoints predating this field.
	#[serde(default)]
	pub revocation_key: Option<PublicKey>,

	/// How long the server should keep trying to pay the invoice. `None`
	/// leaves it to the server, and for checkpoints predating this field.
	#[serde(default)]
	pub retry_for: Option<Duration>,

	// Mutable state:
	pub progress: Progress,
	/// Unless a developer allows it, we will not auto-exit the HTLCs if revocation fails.
	pub allow_exit_of_htlcs: bool,
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

	/// Returns whether the lightning payment has failed to revoke HTLCs after a failed payment.
	/// Previously these would be auto-exited when approaching expiry, instead developers can use
	/// [`crate::Wallet::allow_lightning_send_to_exit`] to control this behaviour.
	pub fn has_failed_revocation(&self) -> bool {
		matches!(self.progress, Progress::RevocationStuck { .. })
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
				).await.retry()? {
					PaymentStatus::Success(preimage) => {
						settle_lightning_send_payment(wallet, &self, &htlcs, preimage).await?;
						return Ok(Advance::Done);
					},
					PaymentStatus::Failed => {
						let revocation = fail_lightning_send_payment(wallet, &self).await?;
						Progress::RevocableHtlcs { htlcs, revocation }
					},
					PaymentStatus::Pending => {
						if self.is_htlc_near_expiry(wallet).await.retry()? {
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
			Progress::RevocableHtlcs { htlcs, revocation } |
			Progress::RevocationStuck { htlcs, revocation } => {
				handle_lightning_send_htlcs_revocation(wallet, &self, &htlcs, &revocation).await?;
				return Ok(Advance::Done);
			},
		};

		Ok(Advance::Next(LightningSend { progress: new_progress, ..self }))
	}

	/// The inputs until the server has cosigned the HTLCs, the HTLCs after
	/// that. A send that learns the preimage settles and holds nothing.
	fn pending_balance_vtxo_ids(&self) -> Vec<VtxoId> {
		match &self.progress {
			Progress::Start => self.input_vtxo_ids.clone(),
			Progress::HtlcReceived(h)
				| Progress::PaymentInitiated(h)
				| Progress::RevocableHtlcs { htlcs: h, .. }
				| Progress::RevocationStuck { htlcs: h, .. }
			=> h.vtxo_ids.clone(),
		}
	}

	/// The step failed transiently. Retry it, unless the HTLCs are
	/// running out of time, in which case move on to revoking (or
	/// exiting) them.
	async fn on_retry(self, wallet: &Wallet, error: anyhow::Error) -> Advance<Self> {
		match &self.progress {
			Progress::Start => {
				if or_retry!(self, self.is_htlc_near_expiry(wallet).await) {
					Advance::Failed(error.context(
						"Could not start lightning send and HTLCs are near expiry",
					))
				} else {
					Advance::Retry { state: self, error }
				}
			},
			Progress::HtlcReceived(htlcs) | Progress::PaymentInitiated(htlcs) => {
				if or_retry!(self, self.is_htlc_near_expiry(wallet).await) {
					let htlcs = htlcs.clone();
					let revocation = or_retry!(self,
						fail_lightning_send_payment(wallet, &self).await.into_anyhow(),
					);
					Advance::Next(LightningSend {
						progress: Progress::RevocableHtlcs { htlcs, revocation },
						..self
					})
				} else {
					Advance::Retry { state: self, error }
				}
			},
			Progress::RevocableHtlcs { htlcs, revocation } => {
				warn!("We could not revoke HTLCs, will continue retrying but the attempt will be marked as such");
				let progress = Progress::RevocationStuck {
					htlcs: htlcs.clone(), revocation: revocation.clone(),
				};
				Advance::Next(LightningSend { progress, ..self })
			},
			Progress::RevocationStuck { htlcs, .. } => {
				if self.allow_exit_of_htlcs && or_retry!(self, self.is_htlc_near_expiry(wallet).await) {
					or_retry!(self, exit_lightning_send_htlcs(wallet, &self, htlcs).await.into_anyhow());
					Advance::Done
				} else {
					// Just keep retrying...
					Advance::Retry { state: self, error }
				}
			},
		}
	}

	/// The step can't be completed as-is: the server rejected the request
	/// or our own state is inconsistent.
	async fn on_abort(self, wallet: &Wallet, error: anyhow::Error) -> Advance<Self> {
		match &self.progress {
			// Nothing committed server-side: the executor releases the
			// input locks and removes the row when the action fails.
			Progress::Start => {
				error!("Could not start lightning send {}: {:?}", self.id(), error);
				Advance::Failed(error)
			},
			Progress::HtlcReceived(htlcs) | Progress::PaymentInitiated(htlcs) => {
				let htlcs = htlcs.clone();
				let revocation = or_retry!(self,
					fail_lightning_send_payment(wallet, &self).await.into_anyhow(),
				);
				Advance::Next(LightningSend {
					progress: Progress::RevocableHtlcs { htlcs, revocation },
					..self
				})
			},
			Progress::RevocableHtlcs { htlcs, revocation } => {
				warn!("We could not revoke HTLCs, will continue retrying but the attempt will be marked as such");
				let progress = Progress::RevocationStuck {
					htlcs: htlcs.clone(), revocation: revocation.clone(),
				};
				Advance::Next(LightningSend { progress, ..self })
			},
			Progress::RevocationStuck { htlcs, .. } => {
				if self.allow_exit_of_htlcs && or_retry!(self, self.is_htlc_near_expiry(wallet).await) {
					or_retry!(self, exit_lightning_send_htlcs(wallet, &self, htlcs).await.into_anyhow());
					Advance::Failed(error.context("Server refused to revoke HTLCs, exiting"))
				} else {
					// Park instead of looping: re-driving immediately would just
					// hit the same server rejection. Surface the original error
					// so callers driving `UntilParkOrDone` see why we stopped.
					Advance::Park { state: self, wake_after: None, error: Some(error) }
				}
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
	/// We've tried to revoke the HTLCs previously and failed, the user
	/// should consider forcing an exit. This step will keep retrying
	/// until automatic exit is permissible when the HTLCs are near expiry,
	/// provided [Wallet::allow_lightning_send_to_exit] is called.
	RevocationStuck { htlcs: Htlcs, revocation: Revocation },
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
	retry_for: Option<Duration>,
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

	let (inputs, fee) = wallet.select_any_vtxos_to_cover_with_fee(
		payment_amount,
		|a, v| ark_info.fees.lightning_send.calculate(a, v).context("fee overflowed"),
	).await.context("Could not find enough suitable VTXOs to cover lightning payment")?;

	let input_total = inputs.iter().map(|v| v.amount()).sum::<Amount>();
	let change = input_total.checked_sub(payment_amount + fee)
		.context("selected inputs don't cover payment and fee")?;

	let action_id = ln_pay_action_id(invoice.payment_hash());
	wallet.lock_vtxos(
		&inputs,
		Some(crate::vtxo::VtxoLockHolder::Action { id: action_id }),
	).await?;

	let (change_keypair, _) = wallet.derive_store_next_keypair().await?;
	let (revocation_keypair, _) = wallet.derive_store_next_keypair().await?;

	let htlc_expiry = tip + ark_info.htlc_send_expiry_delta;

	let movement_id = wallet.inner.movements.new_movement_with_update(
		Subsystem::LIGHTNING_SEND,
		LightningSendMovement::Send.to_string(),
		MovementUpdate::new()
			.intended_balance(-payment_amount.to_signed().context("payment amount out of range")?)
			.fee(fee)
			.consumed_vtxos(&inputs)
			.sent_to([MovementDestination::new(original_payment_method.clone(), payment_amount)])
			.metadata(LightningMovement::metadata(invoice.payment_hash(), Vec::<VtxoId>::new(), None))
	).await.context("failed to create lightning-send movement")?;

	Ok(LightningSend {
		invoice,
		original_payment_method,
		input_vtxo_ids: inputs.iter().map(|v| v.id()).collect(),
		payment_amount,
		fee,
		change_pieces: Some(split_change_amount(
			change, payment_amount + fee, wallet.config().change_vtxo_split_factor,
		)),
		htlc_key: change_keypair.public_key(),
		htlc_expiry,
		movement_id: Some(movement_id),
		revocation_key: Some(revocation_keypair.public_key()),
		retry_for,
		allow_exit_of_htlcs: false,
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
async fn request_lightning_send_htlcs(
	wallet: &Wallet,
	send: &LightningSend,
) -> Result<Htlcs, AdvanceError> {
	let (mut srv, _) = wallet.require_server().await.retry()?;

	let full_inputs = wallet.inner.db.get_full_vtxos(&send.input_vtxo_ids).await
		.context("failed to hydrate lightning-send input vtxos").retry()?;

	// Ensure inputs are fully registered server-side before the cosign.
	wallet.register_vtxo_transactions_with_server(&full_inputs).await
		.context("failed to register lightning-send input vtxo transactions with server")
		.retry()?;

	let mut input_keypairs = Vec::with_capacity(full_inputs.len());
	for input in full_inputs.iter() {
		input_keypairs.push(wallet.get_vtxo_key(input).await.retry()?);
	}

	let policy = VtxoPolicy::new_server_htlc_send(
		send.htlc_key, send.invoice.payment_hash(), send.htlc_expiry,
	);
	let total_amount = send.total_amount();
	let input_amount = full_inputs.iter().map(|v| v.amount()).sum::<Amount>();
	let change_amount = input_amount.checked_sub(total_amount)
		.context("input vtxos don't cover payment and fee").abort()?;

	let mut outputs = vec![ArkoorDestination { total_amount, policy }];
	for piece in resolve_change_pieces(send.change_pieces.clone(), change_amount).abort()? {
		outputs.push(ArkoorDestination {
			total_amount: piece,
			policy: VtxoPolicy::new_pubkey(send.htlc_key),
		});
	}

	let builder = ArkoorPackageBuilder::new_with_checkpoints(
		full_inputs.clone(),
		outputs,
	)
		.context("Failed to construct arkoor package").abort()?
		.generate_user_nonces(&input_keypairs)
		.context("invalid nb of keypairs").abort()?;

	let cosign_request = protos::LightningPayHtlcCosignRequest {
		parts: protos::ArkoorPackageCosignRequest::from(builder.cosign_request()).parts,
	};
	let response = srv.client.request_lightning_pay_htlc_cosign(cosign_request).await
		.retry_unless_rejected()?.into_inner();

	// The server has cosigned the HTLCs by now, so from here on only retry:
	// the cosign RPC is idempotent on payment hash and `abort` would
	// release inputs the server considers spent.

	let cosign_responses = ArkoorPackageCosignResponse::try_from(response)
		.context("Failed to parse cosign response from server").retry()?;

	let vtxos = builder
		.user_cosign(&input_keypairs, cosign_responses)
		.context("Failed to cosign vtxos").retry()?
		.build_signed_vtxos();

	let (htlc_vtxos, change_vtxos) = vtxos.clone().into_iter()
		.partition::<Vec<_>, _>(|v| matches!(v.policy(), VtxoPolicy::ServerHtlcSend(_)));

	let mut effective_balance = Amount::ZERO;
	for vtxo in &htlc_vtxos {
		//TODO(stevenroose) distinguish chain-source from invalid input
		wallet.validate_vtxo(vtxo).await.retry()?;
		effective_balance += vtxo.amount();
	}
	// Change pieces can descend from different inputs, so validate each
	// against its own chain anchor.
	for change in &change_vtxos {
		let anchor_txid = change.chain_anchor().txid;
		let tx = wallet.inner.chain.get_tx(&anchor_txid).await.retry()?;
		let tx = tx.with_context(|| format!(
			"chain anchor not found for lightning change vtxo: {}", anchor_txid,
		)).retry()?;
		change.validate(&tx).context("invalid lightning change vtxo").retry()?;
	}

	if let Err(e) = wallet.register_vtxo_transactions_with_server(&vtxos).await {
		warn!("failed to register lightning-send output vtxo transactions with server: {:#}", e);
	}

	// The movement was created up front in `start_lightning_send` and its id
	// carried on the action, so re-driving `Start` updates that same movement
	// rather than creating a duplicate. Legacy checkpoints predating the field
	// have `None`; create one on demand to preserve the old behaviour.
	// TODO: remove this `None` fallback (and make `movement_id` non-optional)
	// after v0.2.6 ships, once no pre-v0.2.6 checkpoints can remain in flight.
	let movement_id = match send.movement_id {
		Some(id) => id,
		None => wallet.inner.movements.new_movement_with_update(
			Subsystem::LIGHTNING_SEND,
			LightningSendMovement::Send.to_string(),
			MovementUpdate::new()
				.intended_balance(-send.payment_amount.to_signed()
					.context("payment amount out of range").retry()?)
				.fee(send.fee)
				.consumed_vtxos(&full_inputs)
				.sent_to([MovementDestination::new(send.original_payment_method.clone(), send.payment_amount)])
		).await.context("failed to create lightning-send movement").retry()?,
	};
	wallet.store_locked_vtxos(
		&htlc_vtxos,
		Some(VtxoLockHolder::Action { id: send.id() })
	).await.retry()?;
	wallet.mark_vtxos_as_spent(&send.input_vtxo_ids).await.retry()?;
	wallet.store_spendable_vtxos(&change_vtxos).await.retry()?;
	wallet.inner.movements.update_movement(
		movement_id,
		MovementUpdate::new()
			.effective_balance(-effective_balance.to_signed()
				.context("effective balance out of range").retry()?)
			.produced_vtxos(change_vtxos)
			.metadata(LightningMovement::metadata(send.invoice.payment_hash(), &htlc_vtxos, None))
	).await.context("failed to update lightning-send movement").retry()?;

	// Sort for a deterministic checkpoint across re-drives.
	let mut vtxo_ids = htlc_vtxos.iter().map(|v| v.id()).collect::<Vec<_>>();
	vtxo_ids.sort_unstable();

	Ok(Htlcs {
		vtxo_ids,
		mailbox_id: wallet.mailbox_identifier(),
		movement_id,
	})
}

/// HtlcReceived -> PaymentInitiated. Tells the server to actually pay
/// the invoice. Server-side `initiate_lightning_payment` is idempotent
/// on payment_hash.
async fn initiate_lightning_send_payment(
	wallet: &Wallet,
	send: &LightningSend,
	htlcs: &Htlcs,
) -> Result<(), AdvanceError> {
	let (mut srv, _) = wallet.require_server().await.retry()?;

	let req = protos::InitiateLightningPaymentRequest {
		invoice: send.invoice.to_string(),
		htlc_vtxo_ids: htlcs.vtxo_ids.iter().map(|v| v.to_bytes().to_vec()).collect(),
		payment_amount_sat: send.payment_amount.to_sat(),
		mailbox_id: Some(htlcs.mailbox_id.serialize()),
		// The server caps it to its own maximum.
		retry_for_secs: send.retry_for.map(|d| d.as_secs().try_into().unwrap_or(u32::MAX)),
	};
	// A rejection aborts: `abort` then revokes the HTLCs.
	srv.client.initiate_lightning_payment(req).await.retry_unless_rejected()?;

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
) -> Result<(), AdvanceError> {
	let payment_hash = send.invoice.payment_hash();
	if preimage.compute_payment_hash() != payment_hash {
		abort!("preimage does not match payment hash {}", payment_hash);
	}
	info!("Lightning payment succeeded! Payment hash: {}", payment_hash.as_hex());

	wallet.inner.db.record_paid_invoice(payment_hash, preimage).await.retry()?;
	wallet.mark_vtxos_as_spent(&htlcs.vtxo_ids).await.retry()?;
	wallet.inner.movements.finish_movement_with_update(
		htlcs.movement_id,
		MovementStatus::Successful,
		MovementUpdate::new().metadata([(
			"payment_preimage".into(),
			serde_json::to_value(preimage).expect("payment preimage can serde"),
		)]),
	).await.retry()?;

	Ok(())
}

/// PaymentInitiated -> RevocableHtlcs. Derives a revocation keypair;
/// the actual server-side cosign happens in
/// [`revoke_lightning_send_htlcs`].
pub(crate) async fn fail_lightning_send_payment(
	wallet: &Wallet,
	send: &LightningSend,
) -> Result<Revocation, AdvanceError> {
	info!("Lightning payment {} failed, preparing to revoke", send.invoice.payment_hash());
	// Use the key pre-derived at start so re-driving is idempotent; older
	// checkpoints without it (`None`) derive on demand.
	// TODO: remove this `None` fallback (and make `revocation_key` non-optional)
	// after v0.2.6 ships, once no pre-v0.2.6 checkpoints can remain in flight.
	let key = match send.revocation_key {
		Some(key) => key,
		None => wallet.derive_store_next_keypair().await.retry()?.0.public_key(),
	};
	Ok(Revocation { key })
}

/// Cosign the revocation with the server, mark the HTLC vtxos spent
/// and the revocation outputs spendable, and finish the movement as
/// failed.
async fn revoke_lightning_send_htlcs(
	wallet: &Wallet,
	send: &LightningSend,
	htlcs: &Htlcs,
	revocation: &Revocation,
) -> Result<(), AdvanceError> {
	let (mut srv, _) = wallet.require_server().await.retry()?;

	debug!("Revoking {} HTLC vtxos for payment {}",
		htlcs.vtxo_ids.len(), send.invoice.payment_hash());

	let mut htlc_keypairs = Vec::with_capacity(htlcs.vtxo_ids.len());
	let mut htlc_vtxos = Vec::with_capacity(htlcs.vtxo_ids.len());
	for id in htlcs.vtxo_ids.iter() {
		let vtxo = wallet.inner.db.get_full_vtxo(*id).await.retry()?
			.with_context(|| format!("htlc vtxo with id {} not found", id)).retry()?;
		htlc_keypairs.push(wallet.get_vtxo_key(&vtxo).await.retry()?);
		htlc_vtxos.push(vtxo);
	}

	let revocation_claim_policy = VtxoPolicy::new_pubkey(revocation.key);
	let builder = ArkoorPackageBuilder::new_claim_all_with_checkpoints(
		htlc_vtxos.iter().cloned(),
		revocation_claim_policy,
	)
		.context("Failed to construct arkoor package").abort()?
		.generate_user_nonces(&htlc_keypairs)
		.context("failed to generate user nonces").abort()?;

	let cosign_request = protos::ArkoorPackageCosignRequest::from(builder.cosign_request());
	let response = srv.client
		.request_lightning_pay_htlc_revocation(cosign_request).await
		.retry_unless_rejected()?.into_inner();

	// The server has cosigned the revocation by now, so from here on only
	// retry: the request replays with fresh nonces.

	let cosign_resp = ArkoorPackageCosignResponse::try_from(response)
		.context("Failed to parse cosign response from server").retry()?;

	let vtxos = builder
		.user_cosign(&htlc_keypairs, cosign_resp)
		.context("Failed to cosign vtxos").retry()?
		.build_signed_vtxos();

	// Ensure revocation vtxos are fully registered server-side before the cosign.
	if let Err(e) = wallet.register_vtxo_transactions_with_server(&vtxos).await {
		warn!("failed to register lightning-send revocation vtxo transactions with server: {:#}", e);
	}

	let revoked = vtxos.iter().map(|v| v.amount()).sum::<Amount>();
	let effective = match (send.total_amount().to_signed(), revoked.to_signed()) {
		(Ok(send), Ok(revoked)) => revoked - send,
		_ => abort!("invalid send/revoked amounts"),
	};
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
	).await.context("failed to update movement").retry()?;
	wallet.store_spendable_vtxos(&vtxos).await.retry()?;
	wallet.mark_vtxos_as_spent(&htlc_vtxos).await.retry()?;

	Ok(())
}

/// Escalation: when revocation has failed and the HTLC vtxos are about
/// to expire, mark them for unilateral exit and finish the movement
/// as failed.
pub(crate) async fn exit_lightning_send_htlcs(
	wallet: &Wallet,
	send: &LightningSend,
	htlcs: &Htlcs,
) -> Result<(), AdvanceError> {
	let payment_hash = send.invoice.payment_hash();
	warn!("HTLC VTXOs for payment {} are near expiry, marking to exit", payment_hash);

	let mut vtxos = Vec::with_capacity(htlcs.vtxo_ids.len());
	for id in htlcs.vtxo_ids.iter() {
		vtxos.push(wallet.get_vtxo_by_id(*id).await.retry()?.vtxo);
	}

	wallet.inner.exit.start_exit_for_vtxos(&vtxos).await.retry()?;

	let exited = vtxos.iter().map(|v| v.amount()).sum::<Amount>();
	let effective = match (send.total_amount().to_signed(), exited.to_signed()) {
		(Ok(send), Ok(exited)) => exited - send,
		_ => abort!("invalid send/revoked amounts"),
	};
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
	).await.retry()?;

	Ok(())
}

/// Drives revocation forward: tries to revoke, escalates to exit if
/// the vtxos are close to expiry. Returns `Ok(())` if either path
/// finished cleanly, otherwise propagates the revocation error so the
/// executor can retry later.
async fn handle_lightning_send_htlcs_revocation(
	wallet: &Wallet,
	send: &LightningSend,
	htlcs: &Htlcs,
	revocation: &Revocation,
) -> Result<(), AdvanceError> {
	let payment_hash = send.invoice.payment_hash();
	let tip = wallet.inner.chain.tip().await.retry()?;

	debug!("Revoking HTLC VTXOs for payment {} (tip: {}, expiry: {})",
		payment_hash, tip, send.htlc_expiry);


	revoke_lightning_send_htlcs(wallet, send, htlcs, revocation).await
		.inspect_err(|e| {
			warn!("Failed to revoke HTLC VTXOs for payment {}: {:#}", payment_hash, e);
		})
}

//! Arkoor send wallet action.
//!
//! Identity (`id`, `destination`, `amount`) and immutable parameters live
//! on [`ArkoorSend`] as top-level fields; the mutable bit is the [`Progress`] enum.

use std::time::Duration;

use anyhow::Context;
use bitcoin::Amount;
use log::{error, warn};

use ark::{ProtocolEncoding, Vtxo};
use ark::address::VtxoDelivery;
use ark::arkoor::ArkoorDestination;
use ark::vtxo::{Full, VtxoId};
use server_rpc::protos;

use crate::Wallet;
use crate::actions::{Advance, AdvanceError, WalletAction, WalletActionId};
use crate::arkoor::ArkoorCreateError;
use crate::movement::{MovementDestination, MovementId, MovementStatus};
use crate::movement::update::MovementUpdate;
use crate::subsystem::{ArkoorMovement, Subsystem};

/// How long to wait before re-attempting delivery in the
/// [`Progress::Delivery`] park path.
const DELIVERY_RETRY_BACKOFF: Duration = Duration::from_secs(60);

/// An in-flight arkoor payment to an [`ark::Address`], persisted
/// as a single checkpoint row and driven across crashes by the
/// executor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArkoorSend {
	// Immutable State:
	pub id: WalletActionId,
	pub destination: ark::Address,
	#[serde(with = "bitcoin::amount::serde::as_sat")]
	pub amount: Amount,
	pub input_vtxo_ids: Vec<VtxoId>,
	pub change_key_index: u32,

	// Mutable state:
	pub progress: Progress,
}

impl ArkoorSend {
	pub fn id(&self) -> WalletActionId {
		self.id.clone()
	}
}

/// The four phases of an outgoing arkoor send.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Progress {
	/// Inputs are locked and the change keypair is reserved.
	Cosigning,
	/// Cosign succeeded and the movement is recorded; pending registration of
	/// the signed vtxo transactions with the server.
	Registration {
		movement_id: MovementId,
		#[serde(with = "ark::encode::serde::vec")]
		signed_destination_vtxos: Vec<Vtxo<Full>>,
		#[serde(with = "ark::encode::serde::vec")]
		signed_change_vtxos: Vec<Vtxo<Full>>,
	},
	/// Registration succeeded; pending delivery of the signed vtxos to the
	/// recipient via the destination's mailbox mechanisms.
	Delivery {
		movement_id: MovementId,
		#[serde(with = "ark::encode::serde::vec")]
		signed_destination_vtxos: Vec<Vtxo<Full>>,
		#[serde(with = "ark::encode::serde::vec")]
		signed_change_vtxos: Vec<Vtxo<Full>>,
		/// Most recent reason a delivery pass parked. `None` until the first
		/// pass in which no mailbox accepted the post.
		last_park_error: Option<String>,
	},
	/// At least one delivery succeeded or the action was salvaged
	/// after retry exhaustion.
	Finalizing {
		movement_id: MovementId,
		#[serde(with = "ark::encode::serde::vec")]
		signed_change_vtxos: Vec<Vtxo<Full>>,
		/// `true` if at least one delivery mechanism acked the message,
		/// `false` if we are finalizing post-retry-exhaustion to salvage
		/// the change.
		delivery_succeeded: bool,
	},
}

impl From<ArkoorCreateError> for AdvanceError {
	fn from(e: ArkoorCreateError) -> Self {
		match e {
			// Keep the cosign status typed so `is_server_rejection` can tell a
			// rejection (InvalidArgument/NotFound) from a transient failure.
			ArkoorCreateError::Cosign(status) => AdvanceError::Server(status),
			ArkoorCreateError::Other(err) => AdvanceError::Other(err),
		}
	}
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl WalletAction for ArkoorSend {
	fn id(&self) -> WalletActionId { ArkoorSend::id(self) }

	async fn advance(self, wallet: &Wallet) -> Result<Advance<Self>, AdvanceError> {
		let new_progress = match self.progress.clone() {
			Progress::Cosigning => run_cosign(wallet, &self).await?,
			Progress::Registration {
				movement_id, signed_destination_vtxos, signed_change_vtxos,
			} => {
				run_registration(
					wallet, &signed_destination_vtxos, &signed_change_vtxos,
				).await?;
				Progress::Delivery {
					movement_id,
					signed_destination_vtxos,
					signed_change_vtxos,
					last_park_error: None,
				}
			},
			Progress::Delivery {
				movement_id, signed_destination_vtxos, signed_change_vtxos,
				last_park_error: _,
			} => {
				match attempt_delivery(
					wallet, &self.destination, &signed_destination_vtxos,
				).await? {
					DeliveryOutcome::AnySucceeded => Progress::Finalizing {
						movement_id,
						signed_change_vtxos,
						delivery_succeeded: true,
					},
					DeliveryOutcome::AllFailed { summary } => {
						return Ok(Advance::Park {
							state: ArkoorSend {
								progress: Progress::Delivery {
									movement_id, signed_destination_vtxos,
									signed_change_vtxos,
									last_park_error: Some(summary.clone()),
								},
								..self
							},
							wake_after: Some(DELIVERY_RETRY_BACKOFF),
							error: Some(AdvanceError::Other(anyhow!(summary))),
						});
					},
				}
			},
			Progress::Finalizing { movement_id, signed_change_vtxos, delivery_succeeded } => {
				finalize_arkoor_send(
					wallet, &self.input_vtxo_ids, movement_id,
					&signed_change_vtxos, delivery_succeeded,
				).await?;
				return Ok(Advance::Done);
			},
		};

		Ok(Advance::Next(ArkoorSend { progress: new_progress, ..self }))
	}

	async fn on_rejection(
		self,
		wallet: &Wallet,
		error: AdvanceError,
	) -> anyhow::Result<Advance<Self>> {
		match self.progress.clone() {
			Progress::Cosigning => {
				let id = self.id.clone();
				error!("arkoor send {} rejected during cosign: {:?}", id, error);
				if let Err(cancel_err) = wallet.stop_wallet_action(&id).await {
					warn!(
						"could not stop arkoor send action {} after rejection: {:#}",
						id, cancel_err,
					);
				}
				Ok(Advance::Failed(error.into()))
			},
			// Cosign already burned the inputs server-side and inserted the
			// destination vtxos as `Unregistered`. Registration is what flips
			// them to `Spendable` on the server; a stable rejection here means
			// the recipient can't spend via the server either. They CAN still
			// emergency exit from the signed transaction chain we hold, so
			// fall through to Delivery rather than foreclose that recovery
			// path by skipping the mailbox post.
			Progress::Registration {
				movement_id, signed_destination_vtxos, signed_change_vtxos,
			} => {
				Ok(Advance::Next(ArkoorSend {
					progress: Progress::Delivery {
						movement_id,
						signed_destination_vtxos,
						signed_change_vtxos,
						last_park_error: None,
					},
					..self
				}))
			},
			Progress::Delivery { movement_id, signed_change_vtxos, .. } => {
				// Defensive: `attempt_delivery` collects per-method failures into
				// the park summary rather than returning `AdvanceError::Server`,
				// so this arm is unreachable today. Kept as a safe fallback so
				// that if a future change starts surfacing per-method rejections
				// we still salvage the change instead of looping.
				Ok(Advance::Next(ArkoorSend {
					progress: Progress::Finalizing {
						movement_id,
						signed_change_vtxos,
						delivery_succeeded: false,
					},
					..self
				}))
			},
			Progress::Finalizing { .. } => {
				// Finalizing only touches local state, so a server-rejection here
				// would be a bug. Surface as Failed rather than loop.
				Ok(Advance::Failed(error.into()))
			},
		}
	}
}

/// Cosigning -> Registration. Cosigns the arkoor with the server and
/// records the movement.
async fn run_cosign(wallet: &Wallet, send: &ArkoorSend) -> Result<Progress, AdvanceError> {
	let _ = wallet.require_server().await?;

	let locked = wallet.get_vtxos_locked_by_action(&send.id).await?;
	if locked.len() != send.input_vtxo_ids.len() {
		return Err(anyhow!(
			"action {}: expected {} locked inputs, found {}",
			send.id, send.input_vtxo_ids.len(), locked.len(),
		).into());
	}
	for expected in &send.input_vtxo_ids {
		if !locked.iter().any(|v| v.id() == *expected) {
			return Err(anyhow!(
				"action {}: locked input {} missing from set", send.id, expected,
			).into());
		}
	}

	let change_keypair = wallet.peek_keypair(send.change_key_index).await
		.with_context(|| format!(
			"action {}: stored change_key_index {} not in keystore",
			send.id, send.change_key_index,
		))?;

	let dest = ArkoorDestination {
		total_amount: send.amount,
		policy: send.destination.policy().clone(),
	};
	let neg_amount = -send.amount.to_signed().context("amount out-of-range")?;

	// `?` converts via `From<ArkoorCreateError>` below: a cosign failure
	// becomes `AdvanceError::Server` so the executor can route a genuine
	// rejection to on_rejection instead of retrying forever.
	let arkoor = wallet.create_checkpointed_arkoor_with_vtxos(
		dest, locked.into_iter(), change_keypair,
	).await?;

	let initial_update = MovementUpdate::new()
		.intended_and_effective_balance(neg_amount)
		.consumed_vtxos(&arkoor.inputs)
		.sent_to([MovementDestination::ark(send.destination.clone(), send.amount)]);
	let movement_id = wallet.inner.movements.new_movement_with_update(
		Subsystem::ARKOOR,
		ArkoorMovement::Send.to_string(),
		initial_update,
	).await.context("failed to create arkoor movement")?;

	Ok(Progress::Registration {
		movement_id,
		signed_destination_vtxos: arkoor.created,
		signed_change_vtxos: arkoor.change,
	})
}

/// Registration -> Delivery. Push the signed transaction chains for the
/// cosigned output vtxos to the server so receivers don't have to re-register
/// them on receive and spends don't have to lazily retry the registration.
async fn run_registration(
	wallet: &Wallet,
	signed_destination_vtxos: &[Vtxo<Full>],
	signed_change_vtxos: &[Vtxo<Full>],
) -> Result<(), AdvanceError> {
	let serialized: Vec<Vec<u8>> = signed_destination_vtxos.iter()
		.chain(signed_change_vtxos.iter())
		.map(|v| v.serialize().to_vec())
		.collect();
	if serialized.is_empty() {
		return Ok(());
	}

	let (mut srv, _) = wallet.require_server().await?;
	// Call the RPC directly rather than going through
	// `wallet.register_vtxo_transactions_with_server` so we preserve the typed
	// `tonic::Status` for `is_server_rejection`, instead of letting it get
	// wrapped in an opaque `anyhow::Error` that would always retry.
	srv.client.register_vtxo_transactions(protos::RegisterVtxoTransactionsRequest {
		vtxos: serialized,
	}).await.map_err(AdvanceError::Server)?;
	Ok(())
}

/// Outcome of one [`attempt_delivery`] pass.
enum DeliveryOutcome {
	AnySucceeded,
	/// No mailbox accepted the post. `summary` describes why and is captured
	/// in both the park error and `Progress::Delivery::last_park_error`.
	AllFailed { summary: String },
}

/// Post the signed arkoor vtxos to every server-mailbox delivery method on
/// the destination. Mailbox posts are idempotent on the server, so we retry
/// the full set each pass without tracking per-method status.
///
/// Any-success semantics: one accepted post is enough to advance, since the
/// recipient only needs the signed chain to arrive once. BOAT-001 frames
/// `delivery` mechanisms as alternatives provided by the recipient (a sender
/// SHOULD refuse only if none are usable), so treating a single success as
/// sufficient is consistent with the spec. See
/// <https://github.com/ark-protocol/boats/blob/e328d8a3a49a41df79424c132db13e38a6fd4d44/boat-0001.md?plain=1#L96-L101>.
async fn attempt_delivery(
	wallet: &Wallet,
	destination: &ark::Address,
	signed_destination_vtxos: &[Vtxo<Full>],
) -> Result<DeliveryOutcome, AdvanceError> {
	let (mut srv, _) = wallet.require_server().await?;

	let serialized = signed_destination_vtxos.iter()
		.map(|v| v.serialize().to_vec())
		.collect::<Vec<_>>();

	let mut any_succeeded = false;
	let mut failures: Vec<String> = Vec::new();
	for method in destination.delivery() {
		let blinded_id = match method {
			VtxoDelivery::ServerMailbox { blinded_id } => blinded_id,
			_ => continue,
		};
		let req = protos::mailbox_server::PostArkoorMessageRequest {
			blinded_id: blinded_id.as_ref().to_vec(),
			vtxos: serialized.clone(),
		};
		match srv.mailbox_client.post_arkoor_message(req).await {
			Ok(_) => any_succeeded = true,
			Err(e) => {
				let reason = format!("{:#}", e);
				error!("failed to post arkoor vtxos to mailbox: {}", reason);
				failures.push(reason);
			},
		}
	}

	if any_succeeded {
		return Ok(DeliveryOutcome::AnySucceeded);
	}
	let summary = if failures.is_empty() {
		"no mailbox delivery mechanism configured on destination".to_string()
	} else {
		format!("no delivery mechanism accepted the arkoor vtxos: {}", failures.join("; "))
	};
	Ok(DeliveryOutcome::AllFailed { summary })
}

/// Finalize the send. All steps are idempotent.
async fn finalize_arkoor_send(
	wallet: &Wallet,
	input_vtxo_ids: &[VtxoId],
	movement_id: MovementId,
	signed_change_vtxos: &[Vtxo<Full>],
	delivery_succeeded: bool,
) -> Result<(), AdvanceError> {
	wallet.mark_vtxos_as_spent(input_vtxo_ids).await?;

	if !signed_change_vtxos.is_empty() {
		wallet.store_spendable_vtxos(signed_change_vtxos.iter()).await?;
		let change_ids = signed_change_vtxos.iter()
			.map(|v| v.id())
			.collect::<Vec<_>>();
		wallet.inner.movements.update_movement(
			movement_id,
			MovementUpdate::new().produced_vtxos(&change_ids),
		).await.context("failed to record arkoor change vtxos on movement")?;
	}

	let final_status = if delivery_succeeded {
		MovementStatus::Successful
	} else {
		MovementStatus::Failed
	};
	wallet.inner.movements.finish_movement(movement_id, final_status).await
		.context("failed to finalize arkoor movement")?;

	Ok(())
}

#[cfg(test)]
mod test {
	use super::*;

	/// A cosign rejection must reach the executor as `AdvanceError::Server`
	/// so `is_server_rejection` routes it to `on_rejection` instead of the
	/// transient-retry path. Guards against regressing to a `.context(..)?`
	/// that would flatten the status into `Other`.
	#[test]
	fn cosign_rejection_classified_as_server_rejection() {
		let status = tonic::Status::new(tonic::Code::InvalidArgument, "vtxo already spent");
		let advance: AdvanceError = ArkoorCreateError::Cosign(status).into();
		assert!(matches!(advance, AdvanceError::Server(_)));
		assert!(advance.is_server_rejection());
	}

	/// A transient cosign failure is still a `Server` error but must NOT be
	/// classified as a rejection, so the executor retries it.
	#[test]
	fn transient_cosign_failure_is_not_a_rejection() {
		let status = tonic::Status::new(tonic::Code::Unavailable, "server restarting");
		let advance: AdvanceError = ArkoorCreateError::Cosign(status).into();
		assert!(matches!(advance, AdvanceError::Server(_)));
		assert!(!advance.is_server_rejection());
	}

	/// Non-cosign failures stay opaque `Other` (transient-retry path).
	#[test]
	fn other_create_error_is_not_a_rejection() {
		let advance: AdvanceError = ArkoorCreateError::Other(anyhow!("db error")).into();
		assert!(matches!(advance, AdvanceError::Other(_)));
		assert!(!advance.is_server_rejection());
	}
}

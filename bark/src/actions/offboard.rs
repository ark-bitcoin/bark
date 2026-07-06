//! State machine for outgoing offboards (offboard whole vtxos *and*
//! arkoor-prep-then-offboard for [`Wallet::send_onchain`]).
//!
//! Identity (`id`, `destination`, `fee_rate`, `kind`) and the parameters
//! fixed at the start (inputs, amounts) live on the action as top-level
//! fields; the mutable bit is [`Progress`], a small enum that names the
//! phases of the state machine and only carries the fields the phase
//! actually has.
//!
//! Both entry points share the same skeleton:
//! - [`start_offboard`] selects inputs and derives the offboard key (both
//!   for `SendOnchain` only), validates fee and dust constraints, and
//!   returns the action in [`Progress::Start`]; [`lock_vtxos`] then locks
//!   the inputs under the action id.
//! - For `SendOnchain` only, [`arkoor_split_offboard`] runs an arkoor to
//!   produce an exact-sized offboard vtxo plus change, which
//!   [`register_arkoor_split`] registers with the server.
//! - Both kinds converge in [`prepare_offboard`], which has the server
//!   build the offboard tx and validates it
//!   ([`Progress::OffboardTxPrepared`]), and [`finish_offboard`], which
//!   signs our forfeits and trades them for the signed offboard tx
//!   ([`Progress::ReadyForBroadcast`]).
//! - [`broadcast_offboard`] publishes the signed tx
//!   ([`Progress::AwaitingConfirmations`]).
//! - [`settle_offboard`] marks the vtxos spent and finalises the movement
//!   once the tx has enough confirmations.

use std::collections::HashSet;
use std::iter;

use anyhow::Context;
use bitcoin::hex::DisplayHex;
use bitcoin::{Amount, FeeRate, SignedAmount, Transaction, Txid};
use log::{error, info};

use ark::{musig, ProtocolEncoding, VtxoPolicy, VtxoId, fees};
use ark::arkoor::ArkoorDestination;
use ark::attestations::OffboardRequestAttestation;
use ark::fees::VtxoFeeInfo;
use ark::offboard::{OffboardForfeitContext, OffboardRequest};
use ark::vtxo::VtxoRef;
use server_rpc::{protos, TryFromBytes};

use crate::{Wallet, WalletVtxo};
use crate::actions::{Advance, AdvanceError, WalletAction, WalletActionId, BASE_RETRY_BACKOFF};
use crate::movement::update::MovementUpdate;
use crate::movement::{MovementDestination, MovementId, MovementStatus};
use crate::subsystem::{OffboardMovement, Subsystem};
use crate::vtxo::VtxoLockHolder;
use crate::vtxo::selection::InputSelection;

/// An outgoing offboard, persisted as a single checkpoint row and
/// driven across crashes by the executor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Offboard {
	// Set at start, immutable thereafter:
	pub id: WalletActionId,
	pub destination: bitcoin::Address<bitcoin::address::NetworkUnchecked>,
	#[serde(with = "bitcoin::amount::serde::as_sat")]
	pub onchain_output_amount: Amount,
	#[serde(with = "bitcoin::amount::serde::as_sat")]
	pub committed_fee: Amount,
	pub committed_fee_rate: FeeRate,
	pub kind: OffboardKind,

	// Mutable state:
	pub progress: Progress,
}

impl Offboard {
	pub fn id(&self) -> WalletActionId {
		self.id.clone()
	}

	pub fn check_destination(&self, network: bitcoin::Network) -> anyhow::Result<bitcoin::Address> {
		Ok(self.destination.clone().require_network(network)?)
	}
}

/// Which flavour of offboard this action drives.
///
/// `OffboardWhole` is reached from [`Wallet::offboard`] / [`Wallet::offboard_all`]
/// / [`Wallet::offboard_vtxos`]: the inputs are forfeited directly to
/// the offboard tx, fees come out of the gross amount.
///
/// `SendOnchain` is reached from [`Wallet::send_onchain`]: the user gives an
/// amount and the wallet must first arkoor-split its vtxos into an
/// exact-sized output (held by `offboard_pubkey`) plus change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OffboardKind {
	/// Forfeit the listed vtxos as-is to the offboard tx.
	OffboardWhole {
		input_vtxo_ids: Vec<VtxoId>,
	},
	/// Run an arkoor first; offboard the resulting exact-sized vtxo.
	SendOnchain {
		input_vtxo_ids: Vec<VtxoId>,
		/// Holds the arkoor-output (offboard input) vtxo.
		arkoor_key_index: u32,
		/// Holds the arkoor change. Must differ from `arkoor_key_index`: the
		/// arkoor builder refuses a change output paying the destination.
		change_key_index: u32,
	},
}

impl OffboardKind {
	fn deduct_fees_from_gross_amount(&self) -> bool {
		match self {
			OffboardKind::OffboardWhole { .. } => true,
			OffboardKind::SendOnchain { .. } => false,
		}
	}

	fn vtxo_ids(&self) -> &Vec<VtxoId> {
		match self {
			OffboardKind::OffboardWhole { input_vtxo_ids } => input_vtxo_ids,
			OffboardKind::SendOnchain { input_vtxo_ids, .. } => input_vtxo_ids,
		}
	}
}

/// The phases of offboarding.
///
/// `SplitWithArkoor` and `ArkoorRegistrationRequired` are only reached from
/// the `SendOnchain` kind; the `OffboardWhole` kind transitions directly
/// from `Start` to `ReadyForOffboard`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Progress {
	/// Inputs need locking, but we have selected VTXOs to offboard.
	Start,
	/// `SendOnchain` intermediate: We need to perform an arkoor to split the VTXOs so we can
	/// offboard the exact amount requested.
	SplitWithArkoor,
	/// `SendOnchain` intermediate: arkoor done, yet to be registered with the server.
	/// Both the offboard vtxos and the change are held locked until registration
	/// succeeds; only then is the change released as spendable.
	ArkoorRegistrationRequired {
		offboard_vtxo_ids: Vec<VtxoId>,
		change_vtxo_ids: Vec<VtxoId>,
	},
	/// VTXOs are locked, (potential) split is done, now we can start the actual offboard.
	ReadyForOffboard {
		/// In the case of `SendOnchain` this is the arkoor VTXOs we just created, in the case
		/// of `OffboardWhole` this is the VTXOs we selected to offboard.
		offboard_vtxo_ids: Vec<VtxoId>,
	},
	/// Offboard tx built by the server and validated by us; our forfeits
	/// are not signed yet — that happens inside the finish step, with
	/// fresh nonces on every attempt, so that this checkpoint stays
	/// value-deterministic across re-drives.
	OffboardTxPrepared {
		offboard_vtxo_ids: Vec<VtxoId>,
		#[serde(with = "bitcoin_ext::serde::encodable")]
		offboard_tx: Transaction,
		/// The server's forfeit cosign nonces from the prepare response;
		/// stable across prepare replays.
		forfeit_cosign_nonces: Vec<musig::PublicNonce>,
		movement_id: MovementId,
	},
	ReadyForBroadcast {
		offboard_vtxo_ids: Vec<VtxoId>,
		#[serde(with = "bitcoin_ext::serde::encodable")]
		signed_offboard_tx: Transaction,
		movement_id: MovementId,
	},
	/// Offboard tx broadcast; waiting for confirmation.
	AwaitingConfirmations {
		offboard_vtxo_ids: Vec<VtxoId>,
		offboard_txid: Txid,
		#[serde(with = "bitcoin_ext::serde::encodable")]
		offboard_tx: Transaction,
		movement_id: MovementId,
		created_at: chrono::DateTime<chrono::Utc>,
	},
}

/// User-level spec passed to [`start_offboard`] describing which
/// flavour of offboard is being launched.
pub enum StartOffboardSpec {
	/// Forfeit whole VTXOs as-is. Caller picks the vtxos; fees are
	/// deducted from the gross amount.
	OffboardWhole { vtxos: Vec<WalletVtxo> },
	/// Send a specific amount on-chain. The wallet picks inputs and
	/// runs an arkoor first to produce an exact-sized vtxo.
	SendOnchain { amount: Amount },
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl WalletAction for Offboard {
	fn id(&self) -> WalletActionId { Offboard::id(self) }

	async fn advance(self, wallet: &Wallet) -> Result<Advance<Self>, AdvanceError> {
		let new_progress = match self.progress.clone() {
			Progress::Start => {
				lock_vtxos(wallet, &self).await?
			},
			Progress::SplitWithArkoor => {
				arkoor_split_offboard(wallet, &self).await?
			}
			Progress::ArkoorRegistrationRequired { offboard_vtxo_ids, change_vtxo_ids } => {
				register_arkoor_split(wallet, offboard_vtxo_ids, change_vtxo_ids).await?
			},
			Progress::ReadyForOffboard { offboard_vtxo_ids } => {
				prepare_offboard(wallet, &self, offboard_vtxo_ids).await?
			},
			// Temporary while the stages land one commit at a time; the
			// last stage commit removes this.
			progress => return Err(anyhow!(
				"offboard stage {:?} not implemented yet", progress,
			).into()),
		};

		Ok(Advance::Next(Offboard { progress: new_progress, ..self }))
	}

	async fn on_retry(
		self,
		_wallet: &Wallet,
		attempts: u32,
		err: AdvanceError,
	) -> anyhow::Result<Advance<Self>> {
		match self.progress {
			Progress::Start => {
				let error = anyhow::Error::from(err).context("Unable to lock VTXOs");
				return Ok(Advance::Failed(error));
			},
			Progress::SplitWithArkoor |
			Progress::ArkoorRegistrationRequired { .. } |
			Progress::ReadyForOffboard { .. } |
			Progress::OffboardTxPrepared { .. } |
			Progress::ReadyForBroadcast { .. } |
			Progress::AwaitingConfirmations { .. } => {},
		}
		// Park with backoff like the default, but surface the error: the
		// user-facing offboard call drives UntilParkOrDone and should report
		// what actually failed (e.g. the server being short on confirmed
		// funds), not a generic "parked" message. The checkpoint still
		// persists and the sync loop retries regardless.
		let delay = attempts.pow(2) * BASE_RETRY_BACKOFF;
		Ok(Advance::Park { state: self, wake_after: Some(delay), error: Some(err) })
	}

	async fn on_rejection(
		self,
		wallet: &Wallet,
		error: AdvanceError,
	) -> anyhow::Result<Advance<Self>> {
		match &self.progress {
			Progress::SplitWithArkoor => {
				// We can safely unlock our VTXOs.
				fail_offboard_movement(wallet, &self).await?;
				Ok(Advance::Failed(error.into()))
			}
			Progress::ArkoorRegistrationRequired { offboard_vtxo_ids, .. } => {
				// TODO: should we auto-exit here ?
				error!("Server rejected VTXOs, consider exiting: {:?}", offboard_vtxo_ids);
				Ok(Advance::Park {
					state: self.clone(),
					wake_after: None,
					error: Some(error.into())
				})
			},
			Progress::ReadyForOffboard { .. } => {
				// Arkoor are spendable at this point, it is safe to fail here on rejection
				fail_offboard_movement(wallet, &self).await?;
				Ok(Advance::Failed(error.into()))
			},
			// Temporary while the stages land one commit at a time; each
			// stage commit adds its rejection handling.
			progress => bail!(
				"offboard stage {:?} rejection handling not implemented yet: {:#}",
				progress, error,
			),
		}
	}
}

/// Build a fresh [`Offboard`] in [`Progress::Start`]: pick inputs (for
/// `SendOnchain`), derive the offboard key (for `SendOnchain`), validate fee/dust
/// constraints, and lock the inputs under the new action id.
///
/// The executor persists the returned state. Idempotent under re-run
/// only if no checkpoint exists yet for this offboard (the caller is
/// responsible for the existence check).
pub(crate) async fn start_offboard(
	wallet: &Wallet,
	destination: bitcoin::Address,
	spec: StartOffboardSpec,
) -> anyhow::Result<Offboard> {
	let (srv, ark) = wallet.require_server().await?;
	let offboard_feerate = srv.offboard_feerate().await?;
	let tip = wallet.inner.chain.tip().await?;
	let destination_spk = destination.script_pubkey();
	let dust = destination_spk.minimal_non_dust();
	let id = {
		let bytes: [u8; 16] = rand::random();
		bytes.as_hex().to_string()
	};

	let (net_amount, fee, kind) = match spec {
		StartOffboardSpec::OffboardWhole { vtxos } => {
			if vtxos.len() > srv.ark_info().await.max_offboard_inputs {
				bail!(
					"max inputs for offboard is {}, {} were provided",
					srv.ark_info().await.max_offboard_inputs, vtxos.len(),
				);
			}
			let vtxos_amount = vtxos.iter().map(|v| v.amount()).sum::<Amount>();
			let fee = ark.fees.offboard.calculate(
				&destination_spk, vtxos_amount, offboard_feerate,
				vtxos.iter().map(|v| VtxoFeeInfo::from_vtxo_and_tip(v, tip)),
			).context("error calculating offboard fee")?;
			let net_amount = fees::validate_and_subtract_fee_min_dust(vtxos_amount, fee, dust)
				.context("offboard fee leaves dust")?;

			(net_amount, fee, OffboardKind::OffboardWhole {
				input_vtxo_ids: vtxos.iter().map(|v| v.id()).collect(),
			})
		},
		StartOffboardSpec::SendOnchain { amount } => {
			if amount < dust {
				bail!("the minimum you can send to {} is {}", destination, dust);
			}
			let (vtxos, fee) = InputSelection::new()
				.max_inputs(srv.ark_info().await.max_offboard_inputs)
				.fee_scheme(wallet.chain().tip().await?, |a, v| {
					ark.fees.offboard.calculate(&destination_spk, a, offboard_feerate, v)
						.ok_or_else(|| anyhow!("failed to calculate offboard fee for {}", a))
				})
				.select(wallet.spendable_vtxos().await?, amount)?;

			let (_, arkoor_key_index) = wallet.derive_store_next_keypair().await
				.context("failed to create new keypair")?;
			let (_, change_key_index) = wallet.derive_store_next_keypair().await
				.context("failed to create new change keypair")?;

			(amount, fee, OffboardKind::SendOnchain {
				input_vtxo_ids: vtxos.iter().map(|v| v.id()).collect(),
				arkoor_key_index,
				change_key_index,
			})
		},
	};

	// Duplicate inputs would break forfeit signing (one nonce per input) and
	// are rejected by the server; catch them before we lock anything.
	let input_vtxo_ids_len = kind.vtxo_ids().len();
	let unique = kind.vtxo_ids().iter().collect::<HashSet<_>>();
	if input_vtxo_ids_len != unique.len() {
		bail!("offboard inputs must not contain duplicates");
	}

	Ok(Offboard {
		id,
		kind,
		destination: destination.into_unchecked(),
		onchain_output_amount: net_amount,
		committed_fee: fee,
		committed_fee_rate: offboard_feerate,
		progress: Progress::Start,
	})
}

/// Locks the VTXOs, ready for the next step which differs based on the [OffboardKind].
async fn lock_vtxos(
	wallet: &Wallet,
	action: &Offboard,
) -> Result<Progress, AdvanceError> {
	wallet.lock_vtxos(
		action.kind.vtxo_ids(),
		Some(VtxoLockHolder::Action { id: action.id.clone() }),
	).await?;
	match &action.kind {
		OffboardKind::OffboardWhole { input_vtxo_ids } => {
			Ok(Progress::ReadyForOffboard {
				offboard_vtxo_ids: input_vtxo_ids.clone(),
			})
		},
		OffboardKind::SendOnchain { .. } => {
			Ok(Progress::SplitWithArkoor)
		},
	}
}

/// Split the inputs into an exact-sized offboard vtxo plus change and record the `SendOnchain`
/// movement.
async fn arkoor_split_offboard(
	wallet: &Wallet,
	action: &Offboard,
) -> Result<Progress, AdvanceError> {
	let OffboardKind::SendOnchain {
		input_vtxo_ids, arkoor_key_index, change_key_index,
	} = &action.kind
	else {
		return Err(anyhow!("arkoor_split_offboard called for non-SendOnchain kind").into());
	};

	let mut inputs = Vec::with_capacity(input_vtxo_ids.len());
	for id in input_vtxo_ids {
		inputs.push(wallet.get_vtxo_by_id(*id).await
			.context("failed to load offboard input vtxo")?);
	}

	// VTXO creation is deterministic and idempotent due to the previously derived keypairs.
	let required_amount = action.onchain_output_amount + action.committed_fee;
	let keypair = wallet.peek_keypair(*arkoor_key_index).await
		.context("failed to load keypair for offboard action")?;
	let change_keypair = wallet.peek_keypair(*change_key_index).await
		.context("failed to load change keypair for offboard action")?;
	let split_destination = ArkoorDestination {
		total_amount: required_amount,
		policy: VtxoPolicy::new_pubkey(keypair.public_key()),
	};
	let arkoor = wallet
		.create_checkpointed_arkoor_with_vtxos(split_destination, inputs.into_iter(), change_keypair)
		.await
		.context("error preparing offboard vtxos with arkoor")?;

	// The server has marked our VTXOs as spent, so we must update accordingly.
	// Both the offboard vtxo and the change are held under the action until
	// the registration step registers their tx chains with the server; only
	// then is the change released as spendable (the offboard vtxo stays
	// locked until it is forfeited).
	wallet.store_locked_vtxos(
		&arkoor.change,
		Some(VtxoLockHolder::Action { id: action.id.clone() }),
	).await.context("error storing change vtxos from preparatory arkoor")?;
	wallet.store_locked_vtxos(
		&arkoor.created,
		Some(VtxoLockHolder::Action { id: action.id.clone() }),
	).await.context("error storing offboard vtxos from preparatory arkoor")?;
	wallet.mark_vtxos_as_spent(&arkoor.inputs).await
		.context("error marking offboard inputs as spent")?;

	// Create the movement early since we just performed an operation.
	let offboard_vtxo_ids = arkoor.created.iter().map(|v| v.id()).collect::<Vec<_>>();
	let change_vtxo_ids = arkoor.change.iter().map(|v| v.id()).collect::<Vec<_>>();
	get_or_create_movement(
		wallet, action, &offboard_vtxo_ids, change_vtxo_ids.iter().copied(),
	).await?;

	Ok(Progress::ArkoorRegistrationRequired { offboard_vtxo_ids, change_vtxo_ids })
}

/// Registers the new arkoor VTXOs (both the offboard vtxos and the change)
/// with the server, then releases the change as spendable. The offboard
/// vtxos stay locked until they are forfeited.
async fn register_arkoor_split(
	wallet: &Wallet,
	offboard_vtxo_ids: Vec<VtxoId>,
	change_vtxo_ids: Vec<VtxoId>,
) -> Result<Progress, AdvanceError> {
	let to_register = offboard_vtxo_ids.iter().chain(&change_vtxo_ids).copied().collect::<Vec<_>>();
	let full_vtxos = wallet.inner.db.get_full_vtxos(&to_register).await
		.context("failed to hydrate arkoor split vtxos")?;

	wallet.register_vtxo_transactions_with_server(&full_vtxos).await
		.context("failed to register arkoor split vtxo transactions with server")?;

	// Registration succeeded, so the change is safe to spend now.
	wallet.unlock_vtxos(&change_vtxo_ids).await
		.context("failed to unlock change vtxos after registration")?;

	Ok(Progress::ReadyForOffboard { offboard_vtxo_ids })
}

/// `ReadyForOffboard -> OffboardTxPrepared`: have the server build the
/// offboard tx, validate it and record the movement (for `SendOnchain`
/// it already exists from the arkoor split).
///
/// Server-side `prepare_offboard` is idempotent as long as we re-send the exact same request
/// (inputs, amounts, fee rate): the server replays its pending session, returning the same
/// unsigned tx and the same cosign nonces.
async fn prepare_offboard(
	wallet: &Wallet,
	action: &Offboard,
	mut offboard_vtxo_ids: Vec<VtxoId>,
) -> Result<Progress, AdvanceError> {
	let (mut srv, _) = wallet.require_server().await?;

	// Ensure the request remains deterministic and thus reentrant by sorting the offboard inputs.
	offboard_vtxo_ids.sort_unstable();
	debug_assert!(
		offboard_vtxo_ids.windows(2).all(|w| w[0] != w[1]),
		"offboard inputs must not contain duplicates",
	);
	let vtxos = wallet.inner.db.get_wallet_vtxos(&offboard_vtxo_ids).await
		.context("failed to load offboard input vtxos")?;
	debug_assert!(
		vtxos.iter().map(|v| v.id()).eq(offboard_vtxo_ids.iter().copied()),
		"get_wallet_vtxos should return inputs in the exact same order",
	);

	// Build the request, we can skip recalculating fees because the user already committed to a
	// fee structure, the server will reject invalid fees so we can safely unlock our inputs if
	// our numbers differ later on. This will fail the payment and the user can try again if they
	// find the new fees acceptable.
	let destination = action.check_destination(wallet.network().await?)?;
	let destination_spk = destination.script_pubkey();
	let req = OffboardRequest {
		script_pubkey: destination_spk,
		net_amount: action.onchain_output_amount,
		deduct_fees_from_gross_amount: action.kind.deduct_fees_from_gross_amount(),
		fee_rate: action.committed_fee_rate,
	};
	let attestation = {
		let mut attestations = Vec::with_capacity(vtxos.len());
		for v in &vtxos {
			let key = wallet.get_vtxo_key(v).await?;
			let att = OffboardRequestAttestation::new(&req, &offboard_vtxo_ids, &key).serialize();
			attestations.push(att);
		}
		attestations
	};

	// Finally, we can make the request; this is idempotent ONLY if our request is deterministic. If
	// the server rejects this, we can safely unlock our funds.
	let prep_resp = srv.client.prepare_offboard(protos::PrepareOffboardRequest {
		offboard: Some(req.clone().into()),
		input_vtxo_ids: offboard_vtxo_ids.iter()
			.map(|id| id.to_bytes().to_vec())
			.collect(),
		attestation,
	}).await.map_err(AdvanceError::Server)?.into_inner();

	let unsigned_tx = bitcoin::consensus::deserialize::<Transaction>(&prep_resp.offboard_tx)
		.with_context(|| format!("received invalid unsigned offboard tx from server: {}",
			prep_resp.offboard_tx.as_hex(),
		))?;
	let offboard_txid = unsigned_tx.compute_txid();
	let ctx = OffboardForfeitContext::new(&vtxos, &unsigned_tx);
	ctx.validate_offboard_tx(&req).context("received invalid offboard tx from server")?;
	info!("Received unsigned offboard tx {} from server", offboard_txid);

	// A replayed prepare returns the same cosign nonces, so this
	// checkpoint is identical no matter how often the step re-runs.
	let forfeit_cosign_nonces = prep_resp.forfeit_cosign_nonces.into_iter().map(|n| {
		musig::PublicNonce::from_bytes(&n)
			.context("received invalid public cosign nonce from server")
	}).collect::<anyhow::Result<Vec<_>>>()?;

	// We can safely ignore the change in the movement because `SendOnchain` has already had a
	// movement created for it.
	let movement_id = get_or_create_movement(
		wallet, action, &offboard_vtxo_ids, iter::empty::<VtxoId>(),
	).await?;
	Ok(Progress::OffboardTxPrepared {
		offboard_vtxo_ids,
		offboard_tx: unsigned_tx,
		forfeit_cosign_nonces,
		movement_id,
	})
}

/// Creates a movement for the offboard action based on the [OffboardKind].
async fn get_or_create_movement(
	wallet: &Wallet,
	action: &Offboard,
	offboard_vtxo_ids: &Vec<VtxoId>,
	change: impl IntoIterator<Item = impl VtxoRef>,
) -> anyhow::Result<MovementId> {
	let destination = action.check_destination(wallet.network().await?)?;
	let net = action.onchain_output_amount;
	let required = net.checked_add(action.committed_fee).context("overflow")?;
	match &action.kind {
		OffboardKind::OffboardWhole { .. } => {
			let effective_amt = -SignedAmount::try_from(required)
				.context("can't have this many vtxo sats")?;
			wallet.inner.movements.get_or_create_movement_with_action(
				Subsystem::OFFBOARD,
				OffboardMovement::Offboard.to_string(),
				&action.id,
				MovementUpdate::new()
					.intended_balance(effective_amt)
					.effective_balance(effective_amt)
					.fee(action.committed_fee)
					.consumed_vtxos(offboard_vtxo_ids)
					.sent_to([MovementDestination::bitcoin(destination, net)]),
			).await.context("failed to create offboard movement")
		},
		OffboardKind::SendOnchain { input_vtxo_ids, .. } => {
			wallet.inner.movements.get_or_create_movement_with_action(
				Subsystem::OFFBOARD,
				OffboardMovement::SendOnchain.to_string(),
				&action.id,
				MovementUpdate::new()
					.intended_balance(-net.to_signed().context("amount out of range")?)
					.effective_balance(-required.to_signed().context("required amount out of range")?)
					.fee(action.committed_fee)
					.consumed_vtxos(input_vtxo_ids)
					.produced_vtxos(change)
					.metadata([(
						"offboard_vtxos".into(),
						serde_json::to_value(offboard_vtxo_ids).expect("offboard_vtxos can serde"),
					)])
					.sent_to([MovementDestination::bitcoin(destination, net)]),
			).await.context("failed to create send-onchain movement")
		}
	}
}

/// Record the action's movement as failed before the action fails
/// terminally; without this, `Advance::Failed` removes the checkpoint but
/// leaves the movement pending forever.
///
/// The movement is keyed by the action id, so an attempt that had already
/// created one (`SendOnchain` after its arkoor, `OffboardWhole` after
/// prepare) finds it back; an attempt that hadn't gets a failed movement
/// recording what it tried to do. Both make this re-entrant.
async fn fail_offboard_movement(
	wallet: &Wallet,
	action: &Offboard,
) -> anyhow::Result<()> {
	let offboard_vtxo_ids = action.kind.vtxo_ids();
	let movement_id = get_or_create_movement(
		wallet, action, offboard_vtxo_ids, iter::empty::<VtxoId>(),
	).await?;
	// The balance didn't actually change: we only fail on paths where no
	// forfeit was signed and nothing was broadcast, so every vtxo the
	// action locked goes back to spendable.
	wallet.inner.movements.finish_movement_with_update(
		movement_id,
		MovementStatus::Failed,
		MovementUpdate::new().effective_balance(SignedAmount::ZERO),
	).await.context("failed to mark offboard movement as failed")
}

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

use anyhow::Context;
use bitcoin::hex::DisplayHex;
use bitcoin::{Amount, FeeRate, Transaction, Txid};

use ark::{musig, VtxoId, fees};
use ark::fees::VtxoFeeInfo;

use crate::{Wallet, WalletVtxo};
use crate::actions::{Advance, AdvanceError, WalletAction, WalletActionId, BASE_RETRY_BACKOFF};
use crate::movement::MovementId;
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
	ArkoorRegistrationRequired { offboard_vtxo_ids: Vec<VtxoId> },
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
		// Temporary while the stages land one commit at a time; each
		// stage commit adds its rejection handling.
		bail!("offboard stage {:?} rejection handling not implemented yet: {:#}",
			self.progress, error)
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

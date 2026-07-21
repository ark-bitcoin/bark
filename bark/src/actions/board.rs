//! Board wallet action.
//!
//! Boarding moves on-chain BTC into the Ark/VTXO world. Server cosign and
//! vtxo construction need the user keypair and the on-chain wallet, neither of
//! which is reachable from [`WalletAction::advance`], so those happen
//! synchronously in [`crate::Wallet::board_tx`]. This action takes over at the
//! first point funds become committed (broadcast) and owns the durable part of
//! the lifecycle: broadcast -> confirm -> register, plus the near-expiry exit
//! salvage path. Identity (`id`, `funding_tx`, `vtxo_id`, `amount`,
//! `movement_id`) lives on [`Board`] as top-level fields; the mutable bit is the
//! [`Progress`] enum.

use anyhow::Context;
use bitcoin::{Amount, OutPoint, SignedAmount, Transaction};
use log::{error, info, warn};

use ark::{ProtocolEncoding, Vtxo};
use ark::board::BOARD_FUNDING_TX_VTXO_VOUT;
use ark::vtxo::{Full, VtxoId};
use bitcoin_ext::{BlockHeight, TxStatus};
use server_rpc::protos;

use crate::Wallet;
use crate::actions::{Advance, AdvanceError, WalletAction, WalletActionId};
use crate::chain::BroadcastError;
use crate::movement::{MovementId, MovementStatus};
use crate::movement::update::MovementUpdate;
use crate::vtxo::{VtxoState, VtxoStateKind};

/// An in-flight board, persisted as a single checkpoint row and driven across
/// crashes by the executor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Board {
	// Immutable state:
	pub id: WalletActionId,
	/// The signed funding transaction. Carried so (re-)broadcast is re-drivable
	/// without the on-chain wallet, which isn't available inside `advance`.
	#[serde(with = "bitcoin_ext::serde::encodable")]
	pub funding_tx: Transaction,
	/// The board vtxo produced by the cosign, built before this checkpoint
	/// exists. The full vtxo is reloaded from the db when needed.
	pub vtxo_id: VtxoId,
	#[serde(with = "bitcoin::amount::serde::as_sat")]
	pub amount: Amount,
	/// Created up front in `board_tx` so re-driving never duplicates a movement.
	pub movement_id: MovementId,

	// Mutable state:
	pub progress: Progress,
}

impl Board {
	pub fn id(&self) -> WalletActionId {
		self.id.clone()
	}
}

/// The phases of an in-flight board.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Progress {
	/// Vtxo cosigned and built but not yet persisted. Store it (locked under the
	/// action id) and broadcast the funding tx. Carries the signed vtxo because
	/// it isn't in the vtxo table until this step stores it.
	Broadcasting {
		#[serde(with = "ark::encode::serde")]
		signed_vtxo: Vtxo<Full>,
	},
	/// Funding tx broadcast. Each pass waits for `required_board_confirmations`,
	/// registers with the server once confirmed, and kicks off an exit if the
	/// vtxo nears expiry unregistered (salvage). This mirrors the pre-action
	/// `sync_pending_boards` loop body so registration keeps being retried (with
	/// the vtxo left Locked) until it succeeds, the board exits, or it expires.
	Confirming {
		/// Most recent reason a registration attempt failed, for diagnostics.
		last_park_error: Option<String>,
	},
}

/// Stable action id derived from the funding outpoint. Known before broadcast
/// and unique because a given funding output can only board once.
///
/// Uses `.` rather than the `txid:vout` colon since action ids double as lock
/// keys, which only permit ASCII alphanumerics, `-`, `_` and `.`.
pub(crate) fn board_action_id(utxo: OutPoint) -> WalletActionId {
	format!("board.{}.{}", utxo.txid, utxo.vout)
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl WalletAction for Board {
	fn id(&self) -> WalletActionId { Board::id(self) }

	async fn advance(self, wallet: &Wallet) -> Result<Advance<Self>, AdvanceError> {
		match self.progress.clone() {
			Progress::Broadcasting { signed_vtxo } => {
				run_broadcast(wallet, &self, signed_vtxo).await?;
				Ok(Advance::Next(Board {
					progress: Progress::Confirming { last_park_error: None },
					..self
				}))
			},
			Progress::Confirming { .. } => run_confirm(wallet, self).await,
		}
	}

	async fn on_rejection(
		self,
		_wallet: &Wallet,
		error: AdvanceError,
	) -> anyhow::Result<Advance<Self>> {
		// The funding tx is already on-chain by the time the action runs, so we
		// can never safely fail-and-release. Registration failures are handled
		// inline in `Confirming` (kept retrying, vtxo left Locked), so a
		// rejection reaching here is unexpected; re-evaluate from `Confirming`
		// rather than tearing the board down.
		warn!("board {} hit an unexpected rejection, re-evaluating: {:#}", self.id, error);
		// Keep `Broadcasting` so its `signed_vtxo` survives for the next drive.
		let progress = match self.progress {
			broadcasting @ Progress::Broadcasting { .. } => broadcasting,
			Progress::Confirming { .. } => Progress::Confirming { last_park_error: None },
		};
		Ok(Advance::Park {
			state: Board { progress, ..self },
			wake_after: None,
			error: None,
		})
	}
}

/// `Broadcasting -> Confirming`. Store the cosigned vtxo locked under the action
/// and broadcast the funding tx. Both steps are idempotent: `store_locked_vtxos`
/// no-ops if the vtxo exists, and we skip the broadcast if the tx is already
/// known to the chain.
async fn run_broadcast(
	wallet: &Wallet,
	board: &Board,
	signed_vtxo: Vtxo<Full>,
) -> Result<(), AdvanceError> {
	// The server doesn't know this vtxo until `register_board`, so skip the
	// recovery-mailbox post `store_locked_vtxos` would do (it would fail the
	// mailbox FK to `vtxo`); `register_board` posts it once accepted.
	wallet.store_vtxos(
		[&signed_vtxo],
		&VtxoState::Locked {
			holder: Some(crate::vtxo::VtxoLockHolder::Movement { id: board.movement_id }),
		},
	).await?;

	let utxo = OutPoint::new(board.funding_tx.compute_txid(), BOARD_FUNDING_TX_VTXO_VOUT);
	// Skip the broadcast only on a positive "already on-chain" signal. A
	// not-yet-broadcast funding tx is unknown to the chain source, and some
	// backends report that by erroring rather than returning `NotFound`, so
	// treat anything but a confirmed/mempool hit as "still needs broadcasting".
	let already_known = matches!(
		wallet.inner.chain.tx_status(utxo.txid).await,
		Ok(TxStatus::Mempool) | Ok(TxStatus::Confirmed(_)),
	);
	if !already_known {
		wallet.inner.chain.broadcast_tx(&board.funding_tx).await?;
		info!("Board {} funding tx broadcasted", board.id);
	}
	Ok(())
}

/// `Confirming`. Mirrors the pre-action `sync_pending_boards` loop body, run
/// once per drive: tear down if the vtxo has exited, re-broadcast if the funding
/// tx dropped (or fail the board if it was double-spent), register once
/// sufficiently confirmed, and kick off an exit near expiry (keeping the board
/// around so registration can still win while the exit is abortable).
async fn run_confirm(wallet: &Wallet, board: Board) -> Result<Advance<Board>, AdvanceError> {
	let (_, ark_info) = wallet.require_server().await?;
	let current_height = wallet.inner.chain.tip().await?;
	let required = ark_info.required_board_confirmations as BlockHeight;

	let vtxo = wallet.get_vtxo_by_id(board.vtxo_id).await?;

	// If an exit has progressed beyond the abortable stage, server-side
	// registration can no longer succeed: finish the movement and stop.
	if vtxo.state.kind() == VtxoStateKind::Exited {
		wallet.inner.movements.finish_movement(board.movement_id, MovementStatus::Failed).await
			.context("failed to finalize exited board movement")?;
		return Ok(Advance::Done);
	}

	// A previous drive already observed a confirmed double-spend of a funding
	// tx input and marked the vtxo spent (see the `Fatal` arm below), but was
	// interrupted before tearing the board down: finish the teardown.
	if vtxo.state.kind() == VtxoStateKind::Spent {
		wallet.inner.movements.finish_movement_with_update(
			board.movement_id, MovementStatus::Failed,
			MovementUpdate::new().effective_balance(SignedAmount::ZERO),
		).await.context("failed to finalize double-spent board movement")?;
		return Ok(Advance::Done);
	}

	let mut last_park_error = None;
	let anchor = vtxo.chain_anchor();
	let confs = match wallet.inner.chain.tx_status(anchor.txid).await {
		Ok(TxStatus::Confirmed(block_ref)) =>
			Some(current_height.saturating_sub(block_ref.height).saturating_add(1)),
		Ok(TxStatus::Mempool) => Some(0),
		// Dropped from the mempool before confirming. Probe for a conflicting
		// spend of the funding inputs: if one has confirmed the funding tx can
		// never confirm, so the board is dead and re-broadcasting would strand
		// it in a park-and-retry loop forever.
		Ok(TxStatus::NotFound) => {
			match funding_conflict(wallet, &board).await? {
				FundingConflict::Fatal => {
					warn!("Board {} funding input was spent by a confirmed \
						conflicting tx, failing the board", board.id);
					wallet.inner.db.update_vtxo_state_checked(
						board.vtxo_id, VtxoState::Spent, &[VtxoStateKind::Locked],
					).await.context("failed to mark double-spent board vtxo as spent")?;
					wallet.inner.movements.finish_movement_with_update(
						board.movement_id, MovementStatus::Failed,
						MovementUpdate::new().effective_balance(SignedAmount::ZERO),
					).await.context("failed to finalize double-spent board movement")?;
					return Ok(Advance::Done);
				},
				// The funding tx may still confirm: park and re-check next
				// drive.
				FundingConflict::Undecided(reason) => {
					return Ok(Advance::Park {
						state: Board {
							progress: Progress::Confirming {
								last_park_error: Some(reason),
							},
							..board
						},
						wake_after: None,
						error: None,
					});
				},
				// Nothing conflicts: the probe already put the funding tx back
				// in the mempool, so a single eviction doesn't strand the board
				// forever (the old flow never did).
				FundingConflict::None => Some(0),
			}
		},
		Err(_) => None,
	};

	if confs.is_some_and(|c| c >= required) {
		// Attempt registration inline. A failure here (the server can't see
		// enough confirmations yet, or refuses) is not terminal: leave the vtxo
		// Locked and retry next drive, exactly like the old loop. The funding tx
		// is already on-chain, so we must never fail-and-release.
		match run_register(wallet, &board).await {
			Ok(()) => return Ok(Advance::Done),
			Err(e) => {
				let reason = format!("{:#}", e);
				warn!("Failed to register board {}: {}", board.id, reason);
				last_park_error = Some(reason);
			},
		}
	}

	// Near expiry without registration: kick off an exit so the funds at least
	// come back on-chain, but keep retrying registration while the exit is still
	// abortable. The top-of-function `Exited` check tears the action down once
	// the exit commits.
	//
	// I know this if is collapsible, but it reads better like this...
	if vtxo.expiry_height() < current_height.saturating_add(required) {
		if !wallet.exit_mgr().is_exiting(vtxo.id()).await {
			warn!("Board {} expired before confirmation, marking VTXO for exit", board.id);
			wallet.inner.exit.start_exit_for_vtxos(&[vtxo.vtxo.clone()]).await?;
		}
		// Record unconditionally (idempotent): a crash after `start_exit_for_vtxos`
		// would otherwise leave `is_exiting` true and never record the exit.
		wallet.inner.movements.update_movement(
			board.movement_id, MovementUpdate::new().exited_vtxo(board.vtxo_id),
		).await.context("failed to record board exit on movement")?;
	}

	Ok(Advance::Park {
		state: Board { progress: Progress::Confirming { last_park_error }, ..board },
		wake_after: None,
		error: None,
	})
}

/// Register the board with the server, mark the vtxo spendable and finalize the
/// movement. All steps are idempotent: the server tolerates an already-registered
/// board and the state update is gated on the unspent states.
async fn run_register(wallet: &Wallet, board: &Board) -> anyhow::Result<()> {
	let (mut srv, _) = wallet.require_server().await?;

	// Get the full vtxo (including the genesis chain) since we send the
	// serialized bytes to the server.
	let vtxo = wallet.get_full_vtxo(board.vtxo_id).await
		.with_context(|| format!("board vtxo doesn't exist: {}", board.vtxo_id))?;

	srv.client.register_board_vtxo(protos::BoardVtxoRequest {
		board_vtxo: vtxo.serialize(),
	}).await.context("error registering board with the Ark server")?;

	wallet.inner.db.update_vtxo_state_checked(
		vtxo.id(), crate::vtxo::VtxoState::Spendable, VtxoStateKind::UNSPENT_STATES,
	).await?;

	// Post vtxo ID for recovery (non-critical, just log errors). Done here
	// rather than in `store_locked_vtxos` because the server only has the
	// vtxo row after `register_board_vtxo` above, so the mailbox FK would
	// otherwise fail.
	if let Err(e) = wallet.post_recovery_vtxo_ids([vtxo.id()]).await {
		error!("Failed to post recovery vtxo ID to server: {:#}", e);
	}

	// TODO(pc): Cancel any pending exits for the VTXO once we support doing so.
	wallet.inner.movements.finish_movement(board.movement_id, MovementStatus::Successful).await
		.context("failed to finalize board movement")?;

	info!("Registered board {}", vtxo.id());
	Ok(())
}

/// How the board funding tx fares after being dropped from the mempool.
enum FundingConflict {
	/// Nothing conflicts: the re-broadcast probe put the funding tx back into
	/// the mempool.
	None,
	/// The outcome is still open (a parent tx isn't visible yet, a competing
	/// unconfirmed spend is in the way, or the node rejected the re-broadcast
	/// transiently), so the funding tx may still confirm. Carries the park
	/// reason.
	Undecided(String),
	/// A funding input was spent by a confirmed conflicting tx, so the funding
	/// tx can never confirm: the board is dead.
	Fatal,
}

/// Classify the board funding tx after it dropped out of the mempool, without
/// scanning the chain (a full block scan from the vtxo's creation height is
/// prohibitively slow against Bitcoin Core).
///
/// First confirm every funding input's parent tx is visible on-chain or in the
/// mempool. A missing parent is not fatal: an evicted ancestor can re-enter the
/// mempool once a cluster/package limit clears, so we park and wait. Once all
/// parents are present, re-broadcasting the funding tx reveals whether its
/// inputs are still spendable: a `missing or spent inputs` rejection then means
/// a confirmed conflict consumed one of them and the board is dead. Any other
/// rejection (a competing unconfirmed spend, an RBF fee shortfall, or a
/// transient node error) leaves the outcome open, so we park.
async fn funding_conflict(wallet: &Wallet, board: &Board) -> anyhow::Result<FundingConflict> {
	for input in &board.funding_tx.input {
		let parent = input.previous_output.txid;
		match wallet.inner.chain.tx_status(parent).await? {
			TxStatus::Confirmed(_) | TxStatus::Mempool => {},
			TxStatus::NotFound => return Ok(FundingConflict::Undecided(format!(
				"funding input parent tx {} not yet visible on chain", parent,
			))),
		}
	}

	match wallet.inner.chain.broadcast_package(std::slice::from_ref(&board.funding_tx)).await {
		Ok(()) | Err(BroadcastError::AlreadyKnown) => Ok(FundingConflict::None),
		Err(BroadcastError::MissingOrSpentInputs) => Ok(FundingConflict::Fatal),
		Err(e) => Ok(FundingConflict::Undecided(
			format!("funding tx re-broadcast rejected: {}", e),
		)),
	}
}

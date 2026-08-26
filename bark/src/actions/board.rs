//! Board wallet action.
//!
//! Boarding moves on-chain BTC into the Ark/VTXO world. Server cosign and
//! vtxo construction need the user keypair and the on-chain wallet, neither of
//! which is reachable from [`WalletAction::advance`], so those happen
//! synchronously in [`crate::Wallet::board_psbt`]. This action takes over at the
//! first point funds become committed (broadcast) and owns the durable part of
//! the lifecycle: broadcast -> confirm -> register, plus the near-expiry exit
//! salvage path. Identity (the funding tx, `id`, `vtxo_id`, `amount`,
//! `movement_id`) lives on [`Board`] as top-level fields; the mutable bit is the
//! [`Progress`] enum.

use anyhow::Context;
use bitcoin::{Amount, OutPoint, Psbt, SignedAmount, Transaction, Txid};
use log::{error, info, warn};

use ark::{ProtocolEncoding, Vtxo};
use ark::vtxo::{Full, VtxoId};
use bitcoin_ext::{BlockHeight, TxStatus};
use server_rpc::protos;

use crate::Wallet;
use crate::actions::{Advance, AdvanceError, WalletAction, WalletActionId};
use crate::chain::BroadcastError;
use crate::movement::{MovementId, MovementStatus};
use crate::movement::update::MovementUpdate;
use crate::vtxo::{VtxoState, VtxoStateKind};

/// Whether every input has a final witness or scriptSig.
///
/// [Psbt::extract_tx] fills missing witnesses with empty ones rather than failing,
/// so finalisation has to be checked before extracting.
pub(crate) fn psbt_is_finalized(psbt: &Psbt) -> bool {
	psbt.inputs.iter().all(|i| i.final_script_sig.is_some() || i.final_script_witness.is_some())
}

/// An in-flight board, persisted as a single checkpoint row and driven across
/// crashes by the executor.
///
/// The funding transaction is carried so (re-)broadcast is re-drivable without the
/// on-chain wallet, which isn't available inside `advance`. It sits in `funding_tx`
/// or `funding_psbt`, exactly one of which is set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Board {
	// Immutable state:
	pub id: WalletActionId,
	/// The funding transaction of a board checkpointed before `funding_psbt`
	/// existed. Read, never written: a transaction records its inputs' outpoints but
	/// not their values, so the `witness_utxo` a PSBT needs cannot be recovered.
	/// Always finalised, those boards having been broadcast on creation.
	#[serde(default, skip_serializing_if = "Option::is_none",
		with = "bitcoin_ext::serde::encodable::opt")]
	pub funding_tx: Option<Transaction>,
	/// The funding proposal. Broadcast once finalised, watched for until then.
	#[serde(default, skip_serializing_if = "Option::is_none",
		with = "bitcoin_ext::serde::psbt::opt")]
	pub funding_psbt: Option<Psbt>,
	/// The board vtxo produced by the cosign, built before this checkpoint
	/// exists. The full vtxo is reloaded from the db when needed.
	pub vtxo_id: VtxoId,
	#[serde(with = "bitcoin::amount::serde::as_sat")]
	pub amount: Amount,
	/// Created up front in `board_psbt` so re-driving never duplicates a movement.
	pub movement_id: MovementId,

	// Mutable state:
	pub progress: Progress,
}

impl Board {
	pub fn id(&self) -> WalletActionId {
		self.id.clone()
	}

	/// The funding transaction, signed or not. For inspection only; broadcasting
	/// goes through [Board::to_broadcast].
	pub fn funding(&self) -> anyhow::Result<&Transaction> {
		self.funding_tx.as_ref()
			.or(self.funding_psbt.as_ref().map(|psbt| &psbt.unsigned_tx))
			.context("board checkpoint has no funding transaction")
	}

	/// The funding txid, which the board cosign commits to and is therefore fixed
	/// before the signatures exist.
	pub fn funding_txid(&self) -> anyhow::Result<Txid> {
		Ok(self.funding()?.compute_txid())
	}

	/// The funding transaction, but only if we hold the signatures for it. The only
	/// route from a [Board] to the chain source.
	pub fn to_broadcast(&self) -> anyhow::Result<Option<Transaction>> {
		if let Some(tx) = &self.funding_tx {
			return Ok(Some(tx.clone()));
		}
		let psbt = self.funding_psbt.as_ref()
			.context("board checkpoint has no funding transaction")?;
		if !psbt_is_finalized(psbt) {
			return Ok(None);
		}
		// `extract_tx` fee-checks, so it needs each input's value; a stored proposal
		// always carries `witness_utxo`.
		Ok(Some(psbt.clone().extract_tx().context("failed to extract board funding tx")?))
	}
}

/// The phases of an in-flight board.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Progress {
	/// Vtxo cosigned and built but not yet persisted. Store it (locked under the
	/// action id) and broadcast the funding tx if it is ours to broadcast.
	/// Carries the signed vtxo because it isn't in the vtxo table until this step
	/// stores it.
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
/// and broadcast the funding tx if we hold its signatures. Both steps are
/// idempotent: `store_locked_vtxos` no-ops if the vtxo exists, and we skip the
/// broadcast if the tx is already known to the chain.
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

	// Skip the broadcast only on a positive "already on-chain" signal. A
	// not-yet-broadcast funding tx is unknown to the chain source, and some
	// backends report that by erroring rather than returning `NotFound`, so
	// treat anything but a confirmed/mempool hit as "still needs broadcasting".
	let already_known = matches!(
		wallet.inner.chain.tx_status(board.funding_txid()?).await,
		Ok(TxStatus::Mempool) | Ok(TxStatus::Confirmed(_)),
	);
	match board.to_broadcast()? {
		// Broadcasting is up to whoever holds the missing signatures, so watch for
		// the transaction rather than pushing it.
		None => {
			if already_known {
				info!("Board {} funding tx is not ours to broadcast, awaiting it", board.id)
			}
		},
		Some(tx) => {
			if !already_known {
				wallet.inner.chain.broadcast_tx(&tx).await?;
				info!("Board {} funding tx broadcasted", board.id);
			}
		},
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
/// mempool once a cluster/package limit clears, so we park and wait. An input
/// whose parent is confirmed is then checked for a confirmed spend, which the
/// funding tx can never outrace. Finally, re-broadcasting the funding tx reveals
/// whether its inputs are still spendable: a `missing or spent inputs` rejection
/// means a confirmed conflict consumed one of them and the board is dead. Any
/// other rejection (a competing unconfirmed spend, an RBF fee shortfall, or a
/// transient node error) leaves the outcome open, so we park. A chain source
/// error on either probe is likewise left open rather than propagated: it says
/// nothing about the funding tx itself.
async fn funding_conflict(wallet: &Wallet, board: &Board) -> anyhow::Result<FundingConflict> {
	for input in &board.funding()?.input {
		let parent = input.previous_output.txid;
		match wallet.inner.chain.tx_status(parent).await {
			// The caller only reaches here while the funding tx itself is absent
			// from chain and mempool, so a confirmed spend of one of its inputs
			// belongs to another transaction and this board can never confirm.
			Ok(TxStatus::Confirmed(_)) => {
				match wallet.inner.chain.outpoint_spent_confirmed(input.previous_output).await {
					Ok(true) => return Ok(FundingConflict::Fatal),
					Ok(false) => {},
					Err(e) => return Ok(FundingConflict::Undecided(format!(
						"failed to check funding input parent tx {} for a confirmed spend: {:#}",
						parent, e,
					))),
				}
			},
			Ok(TxStatus::Mempool) => {},
			Ok(TxStatus::NotFound) => return Ok(FundingConflict::Undecided(format!(
				"funding input parent tx {} not yet visible on chain", parent,
			))),
			Err(e) => return Ok(FundingConflict::Undecided(format!(
				"failed to fetch status of funding input parent tx {}: {:#}", parent, e,
			))),
		}
	}

	let Some(tx) = board.to_broadcast()? else {
		// Without the signatures there is nothing to probe with: a transaction we
		// cannot complete would be rejected on its own merits and tell us nothing
		// about its inputs. No input is spent by a confirmed tx, so the outcome is
		// still open and the party holding the signatures may yet broadcast.
		return Ok(FundingConflict::Undecided("awaiting external funding broadcast".into()));
	};
	match wallet.inner.chain.broadcast_package(std::slice::from_ref(&tx)).await {
		Ok(()) | Err(BroadcastError::AlreadyKnown) => Ok(FundingConflict::None),
		Err(BroadcastError::MissingOrSpentInputs) => Ok(FundingConflict::Fatal),
		Err(e) => Ok(FundingConflict::Undecided(
			format!("funding tx re-broadcast rejected: {}", e),
		)),
	}
}

#[cfg(test)]
mod test {
	use bitcoin::{ScriptBuf, Sequence, TxIn, TxOut, Witness, consensus};
	use bitcoin::locktime::absolute::LockTime;
	use bitcoin::transaction::Version;

	use super::*;

	fn unsigned_tx() -> Transaction {
		Transaction {
			version: Version::TWO,
			lock_time: LockTime::ZERO,
			input: vec![TxIn {
				previous_output: OutPoint::null(),
				script_sig: ScriptBuf::new(),
				sequence: Sequence::MAX,
				witness: Witness::new(),
			}],
			output: vec![TxOut {
				value: Amount::from_sat(1_000_000),
				script_pubkey: ScriptBuf::new_op_return(&[0u8; 4]),
			}],
		}
	}

	/// An unfinalised PSBT for [unsigned_tx]. `witness_utxo` is set because
	/// [Psbt::extract_tx] fee-checks, so it fails without the input value.
	fn psbt() -> Psbt {
		let mut psbt = Psbt::from_unsigned_tx(unsigned_tx()).unwrap();
		psbt.inputs[0].witness_utxo = Some(TxOut {
			value: Amount::from_sat(1_001_000),
			script_pubkey: ScriptBuf::new_op_return(&[1u8; 4]),
		});
		psbt
	}

	fn finalized_psbt() -> Psbt {
		let mut psbt = psbt();
		psbt.inputs[0].final_script_witness = Some(Witness::from_slice(&[[0u8; 64]]));
		psbt
	}

	fn board(funding_tx: Option<Transaction>, funding_psbt: Option<Psbt>) -> Board {
		Board {
			id: "board.test.0".to_string(),
			funding_tx,
			funding_psbt,
			vtxo_id: VtxoId::from(OutPoint::null()),
			amount: Amount::from_sat(1_000_000),
			movement_id: MovementId(7),
			progress: Progress::Confirming { last_park_error: None },
		}
	}

	/// A board is broadcastable exactly when its proposal is finalised.
	#[test]
	fn broadcast_follows_psbt_finalisation() {
		let unfinalized = board(None, Some(psbt()));
		assert!(unfinalized.to_broadcast().unwrap().is_none());
		// Still knows which transaction to watch for.
		assert_eq!(unfinalized.funding_txid().unwrap(), psbt().unsigned_tx.compute_txid());

		let finalized = board(None, Some(finalized_psbt()));
		let tx = finalized.to_broadcast().unwrap().expect("finalised proposal is ours to send");
		assert_eq!(tx.compute_txid(), finalized.funding_txid().unwrap());
		assert!(!tx.input[0].witness.is_empty(), "extracted tx must carry the witness");
	}

	/// A checkpoint with neither field has no funding transaction, so it errors
	/// rather than yielding a board that can never confirm.
	#[test]
	fn board_without_funding_is_an_error() {
		let board = board(None, None);
		assert!(board.funding().is_err());
		assert!(board.funding_txid().is_err());
		assert!(board.to_broadcast().is_err());
	}

	/// A checkpoint predating `funding_psbt` stays readable and re-broadcastable.
	#[test]
	fn legacy_funding_tx_is_read_and_broadcastable() {
		let tx = {
			let mut tx = unsigned_tx();
			tx.input[0].witness = Witness::from_slice(&[[0u8; 64]]);
			tx
		};
		let legacy = serde_json::json!({
			"id": "board.test.0",
			"funding_tx": consensus::encode::serialize_hex(&tx),
			"vtxo_id": VtxoId::from(OutPoint::null()),
			"amount": 1_000_000,
			"movement_id": 7,
			"progress": { "Confirming": { "last_park_error": null } },
		});
		let board: Board = serde_json::from_value(legacy).unwrap();
		assert_eq!(board.funding_tx.as_ref(), Some(&tx));
		assert_eq!(board.funding_psbt, None);
		assert_eq!(board.to_broadcast().unwrap(), Some(tx));
	}

	/// Boards are written with `funding_psbt` only, as BIP-174 hex.
	#[test]
	fn checkpoint_writes_only_funding_psbt() {
		let psbt = psbt();
		let json = serde_json::to_value(board(None, Some(psbt.clone()))).unwrap();
		assert_eq!(json["funding_psbt"], psbt.serialize_hex());
		assert!(json.get("funding_tx").is_none(), "funding_tx is never written: {json}");

		let board: Board = serde_json::from_value(json).unwrap();
		assert_eq!(board.funding_psbt, Some(psbt));
		assert_eq!(board.funding_tx, None);
	}

	/// Both on-disk shapes of a board checkpoint deserialise, into the field each
	/// names. This is what lets the two coexist without a migration: rows written
	/// while the funding transaction was a plain [Transaction] keep their `funding_tx`
	/// key, and rows written since carry `funding_psbt`.
	#[test]
	fn both_checkpoint_versions_deserialise() {
		fn payload(funding_key: &str, funding_hex: String) -> serde_json::Value {
			serde_json::json!({
				"id": "board.test.0",
				funding_key: funding_hex,
				"vtxo_id": VtxoId::from(OutPoint::null()),
				"amount": 1_000_000,
				"movement_id": 7,
				"progress": { "Confirming": { "last_park_error": null } },
			})
		}

		let tx = finalized_psbt().extract_tx().unwrap();
		let v1: Board = serde_json::from_value(
			payload("funding_tx", consensus::encode::serialize_hex(&tx)),
		).expect("a funding_tx checkpoint must still deserialise");
		assert_eq!(v1.funding_tx, Some(tx.clone()));
		assert_eq!(v1.funding_psbt, None);

		let psbt = psbt();
		let v2: Board = serde_json::from_value(
			payload("funding_psbt", psbt.serialize_hex()),
		).expect("a funding_psbt checkpoint must deserialise");
		assert_eq!(v2.funding_psbt, Some(psbt));
		assert_eq!(v2.funding_tx, None);

		// Both name the same funding transaction, so the rest of the action reads
		// them identically.
		assert_eq!(v1.funding_txid().unwrap(), v2.funding_txid().unwrap());
	}
}

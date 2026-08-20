use anyhow::Context;
use bdk_esplora::esplora_client::Amount;
use bitcoin::key::Keypair;
use bitcoin::{Address, OutPoint, Psbt};
use log::{info, warn};

use ark::board::BoardBuilder;
use ark::fees::validate_and_subtract_fee;
use bitcoin_ext::BlockHeight;
use server_rpc::{protos, MAX_NB_BOARD_FUNDING_INPUTS};

use crate::{Wallet, WalletVtxo};
use crate::actions::DriveMode;
use crate::actions::board::{Board, Progress, board_action_id};
use crate::movement::update::MovementUpdate;
use crate::persist::models::PendingBoard;
use crate::subsystem::{BoardMovement, Subsystem};
use crate::vtxo::VtxoStateKind;

impl Wallet {
	/// Board a [ark::Vtxo] with the given amount.
	///
	/// NB we will spend a little more onchain to cover fees.
	///
	/// Returns an error if no onchain wallet is configured.
	pub async fn board_amount(&self, amount: Amount) -> anyhow::Result<PendingBoard> {
		let (user_keypair, _) = self.derive_store_next_keypair().await?;
		self.board(Some(amount), user_keypair).await
	}

	/// Board a [ark::Vtxo] with all the funds in your onchain wallet.
	///
	/// Returns an error if no onchain wallet is configured.
	pub async fn board_all(&self) -> anyhow::Result<PendingBoard> {
		let (user_keypair, _) = self.derive_store_next_keypair().await?;
		self.board(None, user_keypair).await
	}

	pub async fn pending_boards(&self) -> anyhow::Result<Vec<PendingBoard>> {
		self.boards_in_progress().await?
			.into_iter()
			.map(|b| Ok(PendingBoard {
				funding_tx: b.funding()?.clone(),
				vtxos: vec![b.vtxo_id],
				amount: b.amount,
				movement_id: b.movement_id,
			}))
			.collect()
	}

	/// Returns every in-progress board checkpoint.
	pub(crate) async fn boards_in_progress(&self) -> anyhow::Result<Vec<Board>> {
		Ok(self.inner.db.get_all_wallet_action_checkpoints().await?
			.into_iter()
			.filter_map(|cp| cp.into_board())
			.collect())
	}

	/// Queries the database for any VTXO that is an unregistered board whose funding
	/// transaction has reached the chain. There is a lag time between when a board is
	/// created and when it becomes spendable.
	///
	/// A board bark does not broadcast itself is left out until its funding
	/// transaction shows up: nothing has moved on-chain yet, and the party holding the
	/// signatures may never send it.
	///
	/// See [ark::ArkInfo::required_board_confirmations] and [Wallet::sync_pending_boards].
	pub async fn pending_board_vtxos(&self) -> anyhow::Result<Vec<WalletVtxo>> {
		let boards = self.boards_in_progress().await?;

		let mut vtxos = Vec::with_capacity(boards.len());
		for board in boards {
			// A board still in `Broadcasting` has not been seen on the network, so
			// nothing has moved and its vtxo may not even be stored yet.
			if matches!(board.progress, Progress::Broadcasting { .. }) {
				continue;
			}
			let vtxo_id = board.vtxo_id;
			let vtxo = self.get_vtxo_by_id(vtxo_id).await?;
			// We can silently filter out exited VTXOs, next time we sync they will be dropped from
			// the pending list. A spent one means the funding tx was double-spent and the board
			// action is being torn down, which will likewise drop it from the pending list.
			match vtxo.state.kind() {
				VtxoStateKind::Locked => vtxos.push(vtxo),
				VtxoStateKind::Exited | VtxoStateKind::Spent => continue,
				VtxoStateKind::Spendable => {
					warn!("Pending board VTXO {} has unexpected state: {:?}", vtxo_id, vtxo.state);
					debug_assert!(false, "all pending board vtxos should be locked, spent or exited");
				}
			}
		}

		Ok(vtxos)
	}

	/// Drives every in-progress board forward by one step or to its next park.
	///
	/// Each board is a [`Board`] wallet action that broadcasts the funding tx,
	/// waits for [ark::ArkInfo::required_board_confirmations], registers with the
	/// server, and salvages via exit near expiry. See [`crate::actions::board`].
	pub async fn sync_pending_boards(&self) -> anyhow::Result<()> {
		let pending = self.boards_in_progress().await?;
		if pending.is_empty() {
			return Ok(());
		}

		info!("Syncing {} pending boards", pending.len());
		for board in pending {
			let id = board.id();
			if let Err(e) = self.drive_action(board, DriveMode::UntilParkOrDone).await {
				warn!("Failed to sync board {}: {:#}", id, e);
			}
		}
		Ok(())
	}

	async fn board(
		&self,
		amount: Option<Amount>,
		user_keypair: Keypair,
	) -> anyhow::Result<PendingBoard> {
		let onchain = self.inner.onchain.as_ref()
			.ok_or_else(|| anyhow!("no onchain wallet configured; cannot board"))?;

		let (addr, expiry_height) = self.board_funding_address(&user_keypair).await?;
		let fee_rate = self.inner.chain.fee_rates().await.regular;

		let signed_psbt = {
			let mut wallet = onchain.write().await;
			let board_psbt = if let Some(amount) = amount {
				wallet.prepare_tx(&[(addr, amount)], fee_rate).await?
			} else {
				wallet.prepare_drain_tx(addr, fee_rate).await?
			};

			if board_psbt.inputs.len() > MAX_NB_BOARD_FUNDING_INPUTS {
				bail!("We need {} inputs to board, exceeding the limit of {}",
					board_psbt.inputs.len(), MAX_NB_BOARD_FUNDING_INPUTS,
				);
			}

			wallet.finish_psbt(board_psbt).await?
		};

		self.board_psbt(signed_psbt, user_keypair, expiry_height).await
	}

	/// Returns the funding address for a board with the given keypair.
	///
	/// The caller can use this address to build a funding transaction, then pass it
	/// to [Wallet::board_psbt] to complete the board setup.
	pub async fn board_funding_address(
		&self,
		user_keypair: &Keypair,
	) -> anyhow::Result<(Address, BlockHeight)> {
		let (_, ark_info) = self.require_server().await?;
		let properties = self.inner.db.read_properties().await?.context("Missing config")?;
		let current_height = self.inner.chain.tip().await?;

		let expiry_height = current_height + ark_info.vtxo_lifetime as BlockHeight;
		let builder = BoardBuilder::new(
			user_keypair.public_key(),
			expiry_height,
			ark_info.server_pubkey,
			ark_info.vtxo_exit_delta,
		);

		let addr = bitcoin::Address::from_script(
			&builder.funding_script_pubkey(),
			properties.network,
		)?;

		Ok((addr, expiry_height))
	}

	#[deprecated(note = "use board_psbt instead")]
	pub async fn board_tx(
		&self,
		board_psbt: Psbt,
		user_keypair: Keypair,
		expiry_height: BlockHeight,
	) -> anyhow::Result<PendingBoard> {
		self.board_psbt(board_psbt, user_keypair, expiry_height).await
	}

	/// Board a [ark::Vtxo] from a funding PSBT.
	///
	/// The PSBT must pay to the address returned by [Wallet::board_funding_address].
	/// It may have been built anywhere: the board output is found by matching the
	/// [BoardBuilder] funding script-pubkey, so it may sit at any index alongside
	/// any other outputs.
	///
	/// Broadcasting follows from the PSBT rather than being chosen by the caller. A
	/// finalised PSBT bark broadcasts itself; an unfinalised one leaves the missing
	/// signatures, and so the broadcast, with another party, and bark waits for the
	/// transaction to appear.
	///
	/// The vtxo commits to `psbt.unsigned_tx.compute_txid()` and bark watches for
	/// nothing else, so a transaction paying the same board output under a different
	/// txid — added input, fee bump, payjoin sender falling back to its original —
	/// goes unnoticed: the board waits forever while the funds land in an output no
	/// vtxo tracks. The other party must therefore report any change, and the caller
	/// call this again with the updated PSBT and the same `user_keypair` and
	/// `expiry_height`; the abandoned board stays pending until its vtxo expires.
	///
	/// A receiver contributing its own input, signed `SIGHASH_ALL`, would bind the
	/// sender to the boarded transaction
	///
	/// Inputs that are not natively segwit gain a scriptSig when finalised, changing
	/// the txid, so a PSBT carrying one cannot be boarded here.
	pub async fn board_psbt(
		&self,
		board_psbt: Psbt,
		user_keypair: Keypair,
		expiry_height: BlockHeight,
	) -> anyhow::Result<PendingBoard> {
		let (mut srv, ark_info) = self.require_server().await?;

		let builder = BoardBuilder::new(
			user_keypair.public_key(),
			expiry_height,
			ark_info.server_pubkey,
			ark_info.vtxo_exit_delta,
		);

		// The server caps funding inputs. `board` checks this for txs we build; a
		// tx built elsewhere has to be checked here too.
		ensure!(board_psbt.unsigned_tx.input.len() <= MAX_NB_BOARD_FUNDING_INPUTS,
			"funding tx has {} inputs, exceeding the limit of {}",
			board_psbt.unsigned_tx.input.len(), MAX_NB_BOARD_FUNDING_INPUTS,
		);

		// Locate the board output by script-pubkey rather than a fixed vout: a tx
		// built elsewhere orders its outputs freely. Ours puts it at vout 0. Paying
		// the script twice is refused rather than resolved to the first match, which
		// would board one output and leave the other tracked by nothing.
		let expected_script = builder.funding_script_pubkey();
		let mut board_outputs = board_psbt.unsigned_tx.output.iter().enumerate()
			.filter(|(_, o)| o.script_pubkey == expected_script);
		let (vout, board_output) = board_outputs.next()
			.context("PSBT output does not pay to the expected board funding address")?;
		ensure!(board_outputs.next().is_none(),
			"PSBT pays to the board funding address more than once",
		);
		let vout = vout as u32;

		let amount = board_output.value;
		ensure!(amount >= ark_info.min_board_amount,
			"board amount of {amount} is less than minimum board amount required by server ({})",
			ark_info.min_board_amount,
		);
		let fee = ark_info.fees.board.calculate(amount).context("fee overflowed")?;
		validate_and_subtract_fee(amount, fee)?;

		let utxo = OutPoint::new(board_psbt.unsigned_tx.compute_txid(), vout);
		let builder = builder
			.set_funding_details(amount, fee, utxo)
			.context("error setting funding details for board")?
			.generate_user_nonces();

		let cosign_resp = srv.client.request_board_cosign(protos::BoardCosignRequest {
			amount: amount.to_sat(),
			utxo: bitcoin::consensus::serialize(&utxo), //TODO(stevenroose) change to own
			expiry_height,
			user_pubkey: user_keypair.public_key().serialize().to_vec(),
			pub_nonce: builder.user_pub_nonce().serialize().to_vec(),
			funding_tx: bitcoin::consensus::serialize(&board_psbt.unsigned_tx),
		}).await.context("error requesting board cosign")?
			.into_inner().try_into().context("invalid cosign response from server")?;

		ensure!(builder.verify_cosign_response(&cosign_resp),
				"invalid board cosignature received from server",
			);

		// Cosign and vtxo construction need the user keypair (and the funding
		// PSBT came from the on-chain wallet), neither of which the action can
		// reach. Do them here, then hand the rest of the lifecycle (store +
		// broadcast + confirm + register) to a crash-safe wallet action.
		let vtxo = builder.build_vtxo(&cosign_resp, &user_keypair)?;

		let onchain_fee = board_psbt.fee()?;
		let movement_id = self.inner.movements.new_movement_with_update(
			Subsystem::BOARD,
			BoardMovement::Board.to_string(),
			MovementUpdate::new()
				.intended_balance(amount.to_signed()?)
				.effective_balance(vtxo.amount().to_signed()?)
				.fee(fee)
				.produced_vtxo(&vtxo)
				.metadata(BoardMovement::metadata(utxo, onchain_fee)),
		).await?;

		let vtxo_id = vtxo.id();
		// The board amount net of the board fee, i.e. the vtxo value. This is
		// what `PendingBoard` has always reported (not the gross funding output).
		let vtxo_amount = vtxo.amount();

		// `Broadcasting` broadcasts only a finalised proposal, so boards bark won't
		// send start here too. `funding_tx` is never written: it exists to read
		// checkpoints from before `funding_psbt`, which a bark that predates it cannot
		// read in turn.
		let board = Board {
			id: board_action_id(utxo),
			funding_tx: None,
			funding_psbt: Some(board_psbt),
			vtxo_id,
			amount: vtxo_amount,
			movement_id,
			progress: Progress::Broadcasting { signed_vtxo: vtxo },
		};

		// Persist the checkpoint before any vtxo lock so a crash between here and
		// `drive_action` leaves something to resume (the action stores the vtxo
		// and broadcasts), rather than an orphaned lock.
		self.inner.db.upsert_wallet_action_checkpoint(&board.id, &board.clone().into()).await?;

		let pending = PendingBoard {
			funding_tx: board.funding()?.clone(),
			vtxos: vec![vtxo_id],
			amount: vtxo_amount,
			movement_id,
		};

		// The checkpoint above is durable, so the board is accepted: sync will
		// drive it to completion. The initial drive is best-effort, so don't
		// propagate its error (a retry would fund a duplicate board).
		match self.drive_action(board, DriveMode::UntilParkOrDone).await {
			Ok(()) => info!("Board accepted"),
			Err(e) => warn!("Initial board drive failed, sync will retry: {:#}", e),
		}
		Ok(pending)
	}
}

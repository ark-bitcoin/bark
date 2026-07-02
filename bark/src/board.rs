use anyhow::Context;
use bdk_esplora::esplora_client::Amount;
use bitcoin::key::Keypair;
use bitcoin::{Address, OutPoint, Psbt};
use log::{info, warn};

use ark::board::{BoardBuilder, BOARD_FUNDING_TX_VTXO_VOUT};
use ark::fees::validate_and_subtract_fee;
use bitcoin_ext::BlockHeight;
use server_rpc::protos;

use crate::{onchain, Wallet, WalletVtxo};
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
	pub async fn board_amount(
		&self,
		onchain: &mut dyn onchain::Board,
		amount: Amount,
	) -> anyhow::Result<PendingBoard> {
		let (user_keypair, _) = self.derive_store_next_keypair().await?;
		self.board(onchain, Some(amount), user_keypair).await
	}

	/// Board a [ark::Vtxo] with all the funds in your onchain wallet.
	pub async fn board_all(
		&self,
		onchain: &mut dyn onchain::Board,
	) -> anyhow::Result<PendingBoard> {
		let (user_keypair, _) = self.derive_store_next_keypair().await?;
		self.board(onchain, None, user_keypair).await
	}

	pub async fn pending_boards(&self) -> anyhow::Result<Vec<PendingBoard>> {
		Ok(self.boards_in_progress().await?
			.into_iter()
			.map(|b| PendingBoard {
				funding_tx: b.funding_tx,
				vtxos: vec![b.vtxo_id],
				amount: b.amount,
				movement_id: b.movement_id,
			})
			.collect())
	}

	/// Returns every in-progress board checkpoint.
	async fn boards_in_progress(&self) -> anyhow::Result<Vec<Board>> {
		Ok(self.inner.db.get_all_wallet_action_checkpoints().await?
			.into_iter()
			.filter_map(|cp| cp.into_board())
			.collect())
	}

	/// Queries the database for any VTXO that is an unregistered board. There is a lag time between
	/// when a board is created and when it becomes spendable.
	///
	/// See [ark::ArkInfo::required_board_confirmations] and [Wallet::sync_pending_boards].
	pub async fn pending_board_vtxos(&self) -> anyhow::Result<Vec<WalletVtxo>> {
		let boards = self.boards_in_progress().await?;

		let mut vtxos = Vec::with_capacity(boards.len());
		for board in boards {
			let vtxo_id = board.vtxo_id;
			let vtxo = match self.get_vtxo_by_id(vtxo_id).await {
				Ok(vtxo) => vtxo,
				// `Broadcasting` hasn't stored its vtxo yet, so skip it; later
				// states must have one, so a lookup error is real and propagates.
				Err(e) => match board.progress {
					Progress::Broadcasting { .. } => continue,
					Progress::Confirming { .. } => return Err(e),
				},
			};
			// We can silently filter out exited VTXOs, next time we sync they will be dropped from
			// the pending list.
			match vtxo.state.kind() {
				VtxoStateKind::Locked => vtxos.push(vtxo),
				VtxoStateKind::Exited => continue,
				VtxoStateKind::Spendable | VtxoStateKind::Spent => {
					warn!("Pending board VTXO {} has unexpected state: {:?}", vtxo_id, vtxo.state);
					debug_assert!(false, "all pending board vtxos should be locked or exited");
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
		wallet: &mut dyn onchain::Board,
		amount: Option<Amount>,
		user_keypair: Keypair,
	) -> anyhow::Result<PendingBoard> {
		let (addr, expiry_height) = self.board_funding_address(&user_keypair).await?;
		let fee_rate = self.inner.chain.fee_rates().await.regular;

		let board_psbt = if let Some(amount) = amount {
			wallet.prepare_tx(&[(addr, amount)], fee_rate)?
		} else {
			wallet.prepare_drain_tx(addr, fee_rate)?
		};

		let signed_psbt = wallet.finish_psbt(board_psbt).await?;
		self.board_tx(signed_psbt, user_keypair, expiry_height).await
	}

	/// Returns the funding address for a board with the given keypair.
	///
	/// The caller can use this address to build a funding transaction, then pass it
	/// to [Wallet::board_tx] to complete the board setup.
	pub async fn board_funding_address(
		&self,
		user_keypair: &Keypair,
	) -> anyhow::Result<(Address, BlockHeight)> {
		let (_, ark_info) = self.require_server().await?;
		let properties = self.inner.db.read_properties().await?.context("Missing config")?;
		let current_height = self.inner.chain.tip().await?;

		let expiry_height = current_height + ark_info.vtxo_expiry_delta as BlockHeight;
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

	/// Board a [ark::Vtxo] using a signed funding PSBT.
	///
	/// The PSBT must be signed and send funds to the address returned by
	/// [Wallet::board_funding_address] at output index [BOARD_FUNDING_TX_VTXO_VOUT].
	pub async fn board_tx(
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

		let board_output = board_psbt.unsigned_tx.output.get(BOARD_FUNDING_TX_VTXO_VOUT as usize)
			.context("PSBT does not have output at board funding vout index")?;
		let expected_script = builder.funding_script_pubkey();
		ensure!(
			board_output.script_pubkey == expected_script,
			"PSBT output does not pay to the expected board funding address",
		);

		let amount = board_output.value;
		ensure!(amount >= ark_info.min_board_amount,
			"board amount of {amount} is less than minimum board amount required by server ({})",
			ark_info.min_board_amount,
		);
		let fee = ark_info.fees.board.calculate(amount).context("fee overflowed")?;
		validate_and_subtract_fee(amount, fee)?;

		let utxo = OutPoint::new(board_psbt.unsigned_tx.compute_txid(), BOARD_FUNDING_TX_VTXO_VOUT);
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

		let tx = board_psbt.extract_tx()?;
		let vtxo_id = vtxo.id();
		// The board amount net of the board fee, i.e. the vtxo value. This is
		// what `PendingBoard` has always reported (not the gross funding output).
		let vtxo_amount = vtxo.amount();
		let board = Board {
			id: board_action_id(utxo),
			funding_tx: tx,
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
			funding_tx: board.funding_tx.clone(),
			vtxos: vec![vtxo_id],
			amount: vtxo_amount,
			movement_id,
		};

		// The checkpoint above is durable, so the board is accepted: sync will
		// drive it to completion. The initial drive is best-effort, so don't
		// propagate its error (a retry would fund a duplicate board).
		match self.drive_action(board, DriveMode::UntilParkOrDone).await {
			Ok(()) => info!("Board broadcasted"),
			Err(e) => warn!("Initial board drive failed, sync will retry: {:#}", e),
		}
		Ok(pending)
	}
}

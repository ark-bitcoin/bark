use anyhow::Context;
use bdk_esplora::esplora_client::Amount;
use bitcoin::key::Keypair;
use bitcoin::{Address, OutPoint, Psbt};
use log::{debug, error, info, trace, warn};

use ark::{ProtocolEncoding, VtxoId};
use ark::board::{BoardBuilder, BOARD_FUNDING_TX_VTXO_VOUT};
use ark::fees::validate_and_subtract_fee;
use bitcoin_ext::{BlockHeight, TxStatus};
use server_rpc::protos;

use crate::{onchain, Wallet, WalletVtxo};
use crate::movement::MovementStatus;
use crate::movement::update::MovementUpdate;
use crate::persist::models::PendingBoard;
use crate::subsystem::{BoardMovement, Subsystem};
use crate::vtxo::{VtxoState, VtxoStateKind};

impl Wallet {
	/// Board a `Vtxo` with the given amount.
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

	/// Board a `Vtxo` with all the funds in your onchain wallet.
	pub async fn board_all(
		&self,
		onchain: &mut dyn onchain::Board,
	) -> anyhow::Result<PendingBoard> {
		let (user_keypair, _) = self.derive_store_next_keypair().await?;
		self.board(onchain, None, user_keypair).await
	}

	pub async fn pending_boards(&self) -> anyhow::Result<Vec<PendingBoard>> {
		let boarding_vtxo_ids = self.inner.db.get_all_pending_board_ids().await?;
		let mut boards = Vec::with_capacity(boarding_vtxo_ids.len());
		for vtxo_id in boarding_vtxo_ids {
			let board = self.inner.db.get_pending_board_by_vtxo_id(vtxo_id).await?
				.expect("id just retrieved from db");
			boards.push(board);
		}
		Ok(boards)
	}

	/// Queries the database for any VTXO that is an unregistered board. There is a lag time between
	/// when a board is created and when it becomes spendable.
	///
	/// See [ark::ArkInfo::required_board_confirmations] and [Wallet::sync_pending_boards].
	pub async fn pending_board_vtxos(&self) -> anyhow::Result<Vec<WalletVtxo>> {
		let vtxo_ids = self.pending_boards().await?.into_iter()
			.flat_map(|b| b.vtxos.into_iter())
			.collect::<Vec<_>>();

		let mut vtxos = Vec::with_capacity(vtxo_ids.len());
		for vtxo_id in vtxo_ids {
			let vtxo = self.get_vtxo_by_id(vtxo_id).await
				.expect("vtxo id just got retrieved from db");
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

	/// Attempts to register all pendings boards with the Ark server. A board transaction must have
	/// sufficient confirmations before it will be registered. For more details see
	/// [ark::ArkInfo::required_board_confirmations].
	pub async fn sync_pending_boards(&self) -> anyhow::Result<()> {
		let (_, ark_info) = self.require_server().await?;
		let current_height = self.inner.chain.tip().await?;
		let unregistered_boards = self.pending_boards().await?;
		let mut registered_boards = 0;

		if unregistered_boards.is_empty() {
			return Ok(());
		}

		trace!("Attempting registration of sufficiently confirmed boards");

		for board in unregistered_boards {
			let [vtxo_id] = board.vtxos.try_into()
				.map_err(|_| anyhow!("multiple board vtxos is not supported yet"))?;

			// If we've kicked off an exit and it's progressed beyond the abortable stage,
			// server-side registration can no longer succeed — the underlying outpoint is
			// now committed to the exit chain. Drop the pending_board entry so we stop
			// burning RPC calls on it.
			let vtxo = self.get_vtxo_by_id(vtxo_id).await?;
			if vtxo.state.kind() == VtxoStateKind::Exited {
				debug!("Removing pending_board for exited VTXO {}", vtxo_id);
				self.inner.db.remove_pending_board(&vtxo_id).await?;
				self.inner.movements.finish_movement(
					board.movement_id, MovementStatus::Failed,
				).await?;
				continue;
			}

			let anchor = vtxo.chain_anchor();
			let confs = match self.inner.chain.tx_status(anchor.txid).await {
				Ok(TxStatus::Confirmed(block_ref)) => Some(current_height - (block_ref.height - 1)),
				Ok(TxStatus::Mempool) => Some(0),
				Ok(TxStatus::NotFound) => None,
				Err(_) => None,
			};

			if let Some(confs) = confs {
				if confs >= ark_info.required_board_confirmations as BlockHeight {
					if let Err(e) = self.register_board(vtxo.id()).await {
						warn!("Failed to register board {}: {:#}", vtxo.id(), e);
					} else {
						info!("Registered board {}", vtxo.id());
						registered_boards += 1;
						continue;
					}
				}
			}

			// Near expiry without registration — kick off an exit so the funds at least
			// come back onchain, but keep the pending_board entry around so we keep
			// retrying registration while the exit is still in its abortable
			// Start/Processing window. If the server becomes available before the exit
			// commits, `register_board` will succeed and tear down the entry; otherwise
			// the top-of-loop check above will tear it down once the exit progresses.
			if vtxo.expiry_height() < current_height + ark_info.required_board_confirmations as BlockHeight {
				let is_exiting = self.exit_mgr().is_exiting(vtxo.id()).await;
				if !is_exiting {
					warn!("VTXO {} expired before its board was confirmed, marking VTXO for exit", vtxo.id());
					self.inner.exit.start_exit_for_vtxos(&[vtxo.vtxo]).await?;
					self.inner.movements.update_movement(
						board.movement_id, MovementUpdate::new().exited_vtxo(vtxo_id),
					).await?;
				}
			}
		};

		if registered_boards > 0 {
			info!("Registered {registered_boards} sufficiently confirmed boards");
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

	/// Board a [Vtxo] using a signed funding PSBT.
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

		// Store vtxo first before we actually make the on-chain tx.
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
		self.store_locked_vtxos(
			[&vtxo],
			Some(crate::vtxo::VtxoLockHolder::Movement { id: movement_id }),
		).await?;

		let tx = board_psbt.extract_tx()?;
		self.inner.db.store_pending_board(&vtxo, &tx, movement_id).await?;

		trace!("Broadcasting board tx: {}", bitcoin::consensus::encode::serialize_hex(&tx));
		self.inner.chain.broadcast_tx(&tx).await?;

		info!("Board broadcasted");
		Ok(self.inner.db.get_pending_board_by_vtxo_id(vtxo.id()).await?.expect("board should be stored"))
	}

	/// Registers a board to the Ark server
	async fn register_board(&self, vtxo_id: VtxoId) -> anyhow::Result<()> {
		trace!("Attempting to register board {} to server", vtxo_id);
		let (mut srv, _) = self.require_server().await?;

		// Get the full vtxo (including the genesis chain) since we send the
		// serialized bytes to the server.
		let vtxo = self.inner.db.get_full_vtxo(vtxo_id).await?
			.with_context(|| format!("VTXO doesn't exist: {}", vtxo_id))?;

		// Register the vtxo with the server
		srv.client.register_board_vtxo(protos::BoardVtxoRequest {
			board_vtxo: vtxo.serialize(),
		}).await.context("error registering board with the Ark server")?;

		// Remember that we have stored the vtxo
		// No need to complain if the vtxo is already registered
		self.inner.db.update_vtxo_state_checked(
			vtxo.id(), VtxoState::Spendable, &VtxoStateKind::UNSPENT_STATES,
		).await?;

		// Post vtxo ID to server for recovery (non-critical, just log errors)
		if let Err(e) = self.post_recovery_vtxo_ids([vtxo.id()]).await {
			error!("Failed to post recovery vtxo ID to server: {:#}", e);
		}

		let board = self.inner.db.get_pending_board_by_vtxo_id(vtxo.id()).await?
			.context("pending board not found")?;

		// TODO(pc): Cancel any pending exits for the VTXO once we support doing so.
		self.inner.movements.finish_movement(board.movement_id, MovementStatus::Successful).await?;
		self.inner.db.remove_pending_board(&vtxo.id()).await?;

		Ok(())
	}
}

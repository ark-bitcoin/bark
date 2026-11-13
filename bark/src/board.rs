use anyhow::Context;
use bdk_esplora::esplora_client::Amount;
use bitcoin::address::NetworkUnchecked;
use bitcoin::secp256k1::PublicKey;
use bitcoin::{Address, OutPoint, Psbt};
use log::{info, warn};

use ark::ArkInfo;
use ark::board;
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

/// Where to send the funding transaction of a board, and what the board commits to.
///
/// Created by [BoardBuilder::funding_address] and passed unchanged to
/// [Wallet::board_psbt]. Fund it immediately: the vtxo's lifetime started when the
/// address was made, and once it expires the server can sweep the funding output
/// alone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoardFundingAddress {
	address: Address<NetworkUnchecked>,
	user_pubkey: PublicKey,
	expiry_height: BlockHeight,
}

impl BoardFundingAddress {
	pub fn address(&self) -> &Address {
		self.address.assume_checked_ref()
	}

	pub fn expiry_height(&self) -> BlockHeight {
		self.expiry_height
	}
}

/// Configures a board, created by [Wallet::board].
///
/// Set [BoardBuilder::amount] or [BoardBuilder::all] and call [BoardBuilder::build] to
/// fund the board from the on-chain wallet, or call [BoardBuilder::funding_address] to
/// fund it elsewhere.
///
/// ```no_run
/// # async fn example(wallet: bark::Wallet, other_wallet_psbt: bitcoin::Psbt) -> anyhow::Result<()> {
/// use bitcoin::Amount;
/// use bitcoin_ext::BlockDelta;
///
/// // Fund from the on-chain wallet, expiring after roughly one day.
/// let tip = wallet.chain().tip().await?;
/// let board = wallet.board()
/// 	.expiry(tip + BlockDelta::new(144))
/// 	.amount(Amount::from_sat(100_000))
/// 	.build().await?;
///
/// // Fund from another wallet, e.g. as a payjoin receiver. Persist `funding` (it
/// // implements serde) until the PSBT arrives, and fund it right away.
/// let funding = wallet.board().funding_address().await?;
/// let address = funding.address();
/// // ... the other wallet builds `other_wallet_psbt` paying `address` ...
/// let board = wallet.board_psbt(other_wallet_psbt, &funding).await?;
/// # Ok(())
/// # }
/// ```
pub struct BoardBuilder<'a> {
	wallet: &'a Wallet,
	amount: Option<BoardAmount>,
	expiry_height: Option<BlockHeight>,
}

enum BoardAmount {
	Exact(Amount),
	All,
}

impl<'a> BoardBuilder<'a> {
	/// The block height at which the vtxo expires.
	///
	/// Defaults to [Config::board_lifetime](crate::Config::board_lifetime) blocks
	/// from the tip, capped at the server's [ArkInfo::vtxo_lifetime]. An expiry
	/// further out than the server's vtxo lifetime is an error.
	pub fn expiry(mut self, expiry_height: BlockHeight) -> Self {
		self.expiry_height = Some(expiry_height);
		self
	}

	/// Board the given amount from the on-chain wallet.
	///
	/// NB we will spend a little more onchain to cover fees.
	pub fn amount(mut self, amount: Amount) -> Self {
		self.amount = Some(BoardAmount::Exact(amount));
		self
	}

	/// Board all the funds in the on-chain wallet.
	pub fn all(mut self) -> Self {
		self.amount = Some(BoardAmount::All);
		self
	}

	/// Fund the board from the on-chain wallet and board it.
	///
	/// Returns an error if neither [BoardBuilder::amount] nor [BoardBuilder::all] is
	/// set, or if no onchain wallet is configured.
	pub async fn build(self) -> anyhow::Result<PendingBoard> {
		let wallet = self.wallet;
		let amount = self.amount.as_ref()
			.context("set an amount or all() before building a board")?;
		let onchain = wallet.inner.onchain.as_ref()
			.ok_or_else(|| anyhow!("no onchain wallet configured; cannot board"))?;

		let funding = self.make_funding_address().await?;
		let addr = funding.address().clone();
		let fee_rate = wallet.inner.chain.fee_rates().await.regular;

		let signed_psbt = {
			let mut onchain = onchain.write().await;
			let board_psbt = match amount {
				BoardAmount::Exact(amount) => onchain.prepare_tx(&[(addr, *amount)], fee_rate).await?,
				BoardAmount::All => onchain.prepare_drain_tx(addr, fee_rate).await?,
			};

			if board_psbt.inputs.len() > MAX_NB_BOARD_FUNDING_INPUTS {
				bail!("We need {} inputs to board, exceeding the limit of {}",
					board_psbt.inputs.len(), MAX_NB_BOARD_FUNDING_INPUTS,
				);
			}

			// Sign only: a board that fails here must leave the wallet untouched.
			onchain.sign_psbt(board_psbt).await?
		};

		wallet.board_psbt(signed_psbt, &funding).await
	}

	/// Derive a fresh key and return the address to fund the board with.
	///
	/// Build a funding transaction paying it and pass both to [Wallet::board_psbt].
	/// The funding transaction decides the amount, so setting one is an error.
	pub async fn funding_address(self) -> anyhow::Result<BoardFundingAddress> {
		ensure!(self.amount.is_none(),
			"a board funded through funding_address() takes its amount from the funding tx",
		);
		self.make_funding_address().await
	}

	async fn make_funding_address(&self) -> anyhow::Result<BoardFundingAddress> {
		let (_, ark_info) = self.wallet.require_server().await?;
		let tip = self.wallet.inner.chain.tip().await?;
		let expiry_height = self.expiry_height.unwrap_or(
			tip + self.wallet.inner.config.board_lifetime.min(ark_info.vtxo_lifetime),
		);
		ensure!(expiry_height <= tip + ark_info.vtxo_lifetime,
			"board expiry height {} is more than the server's vtxo lifetime of {} blocks \
			past the tip {}", expiry_height, ark_info.vtxo_lifetime, tip,
		);
		let remaining = expiry_height.to_u32().saturating_sub(tip.to_u32());
		let min_lifetime = self.wallet.min_board_lifetime(&ark_info);
		ensure!(remaining > min_lifetime,
			"board expiry height {} is only {} blocks past the tip {}, it must be more than {}",
			expiry_height, remaining, tip, min_lifetime,
		);

		let (user_keypair, _) = self.wallet.derive_store_next_keypair().await?;
		self.wallet.make_board_funding_address(
			&ark_info, user_keypair.public_key(), expiry_height,
		).await
	}
}

impl Wallet {
	/// Start configuring a board. See [BoardBuilder].
	pub fn board(&self) -> BoardBuilder<'_> {
		BoardBuilder { wallet: self, amount: None, expiry_height: None }
	}

	/// Board a [ark::Vtxo] with the given amount.
	///
	/// Shorthand for `self.board().amount(amount).build()`.
	pub async fn board_amount(&self, amount: Amount) -> anyhow::Result<PendingBoard> {
		self.board().amount(amount).build().await
	}

	/// Board a [ark::Vtxo] with all the funds in your onchain wallet.
	///
	/// Shorthand for `self.board().all().build()`.
	pub async fn board_all(&self) -> anyhow::Result<PendingBoard> {
		self.board().all().build().await
	}

	/// Rebuilds the [BoardFundingAddress] of a funding address created before it
	/// existed, from the user pubkey and expiry height stored alongside it.
	///
	/// Only for boards funded through the removed `board_funding_address`. If the
	/// server's key or exit delta changed since, the rebuilt address won't match and
	/// [Wallet::board_psbt] refuses the PSBT.
	#[deprecated(note = "only for funding addresses created before BoardFundingAddress")]
	pub async fn legacy_board_funding_address(
		&self,
		user_pubkey: PublicKey,
		expiry_height: BlockHeight,
	) -> anyhow::Result<BoardFundingAddress> {
		let (_, ark_info) = self.require_server().await?;
		self.pubkey_keypair(&user_pubkey).await?
			.context("board funding address key is not from this wallet")?;
		self.make_board_funding_address(&ark_info, user_pubkey, expiry_height).await
	}

	async fn make_board_funding_address(
		&self,
		ark_info: &ArkInfo,
		user_pubkey: PublicKey,
		expiry_height: BlockHeight,
	) -> anyhow::Result<BoardFundingAddress> {
		let properties = self.inner.db.read_properties().await?.context("Missing config")?;
		let builder = board::BoardBuilder::new(
			user_pubkey,
			expiry_height,
			ark_info.server_pubkey,
			ark_info.vtxo_exit_delta,
		).context("invalid board parameters")?;

		let address = Address::from_script(&builder.funding_script_pubkey(), properties.network)?;

		Ok(BoardFundingAddress { address: address.into_unchecked(), user_pubkey, expiry_height })
	}

	/// Blocks a board needs to confirm its funding tx before it has to be exited.
	fn min_board_lifetime(&self, ark_info: &ArkInfo) -> u32 {
		self.inner.config.vtxo_exit_margin.to_u32() + ark_info.required_board_confirmations as u32
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

	/// Drives every in-progress board until it parks, a step fails, or it finishes.
	///
	/// An error on one board is logged and does not stop the others.
	/// It skips any board that another caller is already driving.
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
			if let Err(e) = self.drive_action::<Board>(&id, DriveMode::UntilParkOrDone).await {
				warn!("Failed to sync board {}: {:#}", id, e);
			}
		}
		Ok(())
	}

	/// Board a [ark::Vtxo] from a funding PSBT.
	///
	/// The PSBT must pay to `funding`, made by [BoardBuilder::funding_address].
	/// It may have been built anywhere: the board output is found by matching the
	/// board funding script-pubkey, so it may sit at any index alongside
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
	/// call this again with the updated PSBT and the same `funding`; the abandoned
	/// board stays pending until its vtxo expires.
	///
	/// Refuses a `funding` too close to its expiry to confirm and register in time.
	///
	/// A receiver contributing its own input, signed `SIGHASH_ALL`, would bind the
	/// sender to the boarded transaction
	///
	/// Inputs that are not natively segwit gain a scriptSig when finalised, changing
	/// the txid, so a PSBT carrying one cannot be boarded here.
	pub async fn board_psbt(
		&self,
		board_psbt: Psbt,
		funding: &BoardFundingAddress,
	) -> anyhow::Result<PendingBoard> {
		let (mut srv, ark_info) = self.require_server().await?;

		let expiry_height = funding.expiry_height;
		let tip = self.inner.chain.tip().await?;
		let remaining = expiry_height.to_u32().saturating_sub(tip.to_u32());
		let min_lifetime = self.min_board_lifetime(&ark_info);
		ensure!(remaining > min_lifetime,
			"board funding address expires at height {} and only has {} blocks left, \
			it needs more than {}; use a new funding address",
			expiry_height, remaining, min_lifetime,
		);

		let (_, user_keypair) = self.pubkey_keypair(&funding.user_pubkey).await?
			.context("board funding address key is not from this wallet")?;

		let builder = board::BoardBuilder::new(
			user_keypair.public_key(),
			expiry_height,
			ark_info.server_pubkey,
			ark_info.vtxo_exit_delta,
		).context("invalid board parameters")?;

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
			expiry_height: expiry_height.into(),
			user_pubkey: user_keypair.public_key().serialize().to_vec(),
			pub_nonce: builder.user_pub_nonce().serialize().to_vec(),
			funding_tx: bitcoin::consensus::serialize(&board_psbt.unsigned_tx),
			owner_mailbox: self.board_owner_mailbox().await,
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

		let pending = PendingBoard {
			funding_tx: board.funding()?.clone(),
			vtxos: vec![vtxo_id],
			amount: vtxo_amount,
			movement_id,
		};

		// Persist the checkpoint before any vtxo lock so a crash between here and
		// `drive_checkpoint` leaves something to resume (the action stores the
		// vtxo and broadcasts), rather than an orphaned lock.
		let mut checkpoint = self.try_lock_action::<Board>(&board.id).await?
			.context("board already in progress")?;
		checkpoint.create(self, board).await?;

		// The checkpoint above is durable, so the board is accepted: sync will
		// drive it to completion. The initial drive is best-effort, so don't
		// propagate its error (a retry would fund a duplicate board).
		match self.drive_checkpoint(checkpoint, DriveMode::UntilParkOrDone).await {
			Ok(()) => info!("Board accepted"),
			Err(e) => warn!("Initial board drive failed, sync will retry: {:#}", e),
		}
		Ok(pending)
	}
}

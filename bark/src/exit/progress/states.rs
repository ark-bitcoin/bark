use log::{debug, error, info, trace, warn};
use tonic::async_trait;

use bitcoin_ext::{BlockHeight, P2TR_DUST};
use bitcoin_ext::rpc::TxStatus;
use json::exit::error::ExitError;
use json::exit::ExitState;
use json::exit::states::{
	ExitAwaitingDeltaState, ExitProcessingState, ExitSpendInProgressState, ExitSpendableState,
	ExitSpentState, ExitStartState, ExitTx, ExitTxOrigin, ExitTxStatus,
};

use crate::exit::progress::{ExitProgressError, ExitStateProgress, ProgressContext};
use crate::exit::progress::util::{count_broadcast, count_confirmed, estimate_exit_cost};
use crate::movement::{MovementArgs, MovementKind};
use crate::onchain::ExitUnilaterally;

#[async_trait]
impl ExitStateProgress for ExitState {
	async fn progress(
		self,
		ctx: &mut ProgressContext<'_>,
		onchain: &mut impl ExitUnilaterally,
	) -> anyhow::Result<ExitState, ExitProgressError> {
		match self {
			ExitState::Start(s) => s.progress(ctx, onchain).await,
			ExitState::Processing(s) => s.progress(ctx, onchain).await,
			ExitState::AwaitingDelta(s) => s.progress(ctx, onchain).await,
			ExitState::Spendable(s) => s.progress(ctx, onchain).await,
			ExitState::SpendInProgress(s) => s.progress(ctx, onchain).await,
			ExitState::Spent(s) => s.progress(ctx, onchain).await,
		}
	}
}

#[async_trait]
impl ExitStateProgress for ExitStartState {
	async fn progress(
		self,
		ctx: &mut ProgressContext<'_>,
		onchain: &mut impl ExitUnilaterally,
	) -> anyhow::Result<ExitState, ExitProgressError> {
		let id = ctx.vtxo.id();
		info!("Checking if VTXO can be exited: {}", id);

		// Ensure the VTXO has a valid amount
		if ctx.vtxo.amount() < P2TR_DUST {
			return Err(ExitError::DustLimit { vtxo: ctx.vtxo.amount(), dust: P2TR_DUST }.into());
		}

		// Ensure we can afford to exit this VTXO
		let total_fee = estimate_exit_cost([ctx.vtxo], ctx.fee_rate);
		let balance = onchain.get_balance();
		if balance < total_fee {
			return Err(ExitError::InsufficientFeeToStart {
				balance,
				total_fee,
				fee_rate: ctx.fee_rate
			}.into());
		}
		info!("Validated VTXO {}, exit process can now begin", id);

		// Register the coin movement in the database
		let recipient = ctx.vtxo_recipient()?.to_string();
		let movement = MovementArgs {
			kind: MovementKind::Exit,
			spends: &[ctx.vtxo],
			receives: &[],
			recipients: &[(&recipient, ctx.vtxo.amount())],
			fees: None,
		};
		debug!("Registering movement, spending VTXO: {}, recipient: {} to {}",
			ctx.vtxo.id(), ctx.vtxo.amount(), recipient,
		);
		ctx.persister.register_movement(movement)
			.map_err(|e| ExitError::MovementRegistrationFailure { error: e.to_string() })?;

		Ok(ExitState::new_processing(
			ctx.chain_source.tip().await.unwrap_or(self.tip_height),
			ctx.exit_txids.iter().cloned(),
		))
	}
}

#[async_trait]
impl ExitStateProgress for ExitProcessingState {
	async fn progress(
		self,
		ctx: &mut ProgressContext<'_>,
		onchain: &mut impl ExitUnilaterally,
	) -> anyhow::Result<ExitState, ExitProgressError> {
		assert_eq!(self.transactions.len(), ctx.exit_txids.len());

		let tip = ctx.tip_height().await?;
		let mut transactions = self.transactions.clone();

		for i in 0..transactions.len() {
			match progress_exit_tx(&transactions[i], ctx, onchain).await {
				Ok(status) => transactions[i].status = status,
				Err(e) => {
					// We may need to commit any changes we have
					if self.transactions != transactions {
						let state = ExitState::new_processing_from_transactions(tip, transactions);
						return Err(ExitProgressError {
							state: Some(state),
							error: e,
						});
					}
					return Err(e.into());
				},
			}
		}

		// Report the current status to the user
		let prev_confirmed = count_confirmed(&self.transactions);
		let now_confirmed = count_confirmed(&transactions);
		if now_confirmed == transactions.len() {
			info!("Exit for VTXO ({}) has been fully confirmed, waiting for funds to become spendable...", ctx.vtxo.id());
			let conf_block = transactions
				.iter()
				.filter_map(|exit| exit.status.confirmed_in())
				.max_by(|a, b| a.height.cmp(&b.height))
				.unwrap();
			let spendable = conf_block.height + BlockHeight::from(ctx.vtxo.exit_delta());
			return Ok(ExitState::new_awaiting_delta(tip, *conf_block, spendable));
		}
		if now_confirmed != prev_confirmed {
			info!("Exit for VTXO ({}) now has {} confirmed transactions with {} more required.",
				ctx.vtxo.id(), now_confirmed, transactions.len() - now_confirmed,
			);
		} else {
			let prev_broadcast = count_broadcast(&self.transactions);
			let now_broadcast = count_broadcast(&transactions);
			if now_broadcast == transactions.len() {
				info!("Exit for VTXO ({}) has been fully broadcast, waiting for {} transactions to confirm...",
					ctx.vtxo.id(), now_confirmed,
				);
			} else if prev_broadcast != now_broadcast {
				let remaining = transactions.len() - now_broadcast;
				if prev_broadcast > now_broadcast {
					warn!("An exit transaction for VTXO ({}) appears to have fallen out of the mempool", ctx.vtxo.id());
				}
				info!("Exit for VTXO ({}) now has {} broadcast transactions with {} more required.",
					ctx.vtxo.id(), now_broadcast, remaining,
				);
			}
		}

		if self.transactions != transactions {
			debug!("VTXO exit transactions updated: {:?}", transactions);
			Ok(ExitState::new_processing_from_transactions(tip, transactions))
		} else {
			Ok(self.into())
		}
	}
}

async fn progress_exit_tx<W: ExitUnilaterally>(
	exit: &ExitTx,
	ctx: &mut ProgressContext<'_>,
	onchain: &mut W,
) -> anyhow::Result<ExitTxStatus, ExitError> {
	match &exit.status {
		ExitTxStatus::VerifyInputs => {
			info!("Verifying inputs for exit tx {}", exit.txid);
			let inputs = ctx.get_unique_inputs(exit.txid).await?;
			ctx.check_status_from_inputs(exit, &inputs).await
		},
		ExitTxStatus::AwaitingInputConfirmation { txids } => {
			info!("Checking if the {} remaining inputs for exit tx {} have confirmed", txids.len(), exit.txid);
			ctx.check_status_from_inputs(exit, &txids).await
		}
		ExitTxStatus::NeedsSignedPackage => {
			// Before attempting to create a package, we should verify another party hasn't
			// already broadcast this transaction
			let new_status = ctx.get_exit_tx_status(exit).await?;
			if matches!(new_status, ExitTxStatus::NeedsSignedPackage) {
				info!("Creating exit package for exit tx {}", exit.txid);
				let child_tx = {
					let package = ctx.tx_manager.get_package(exit.txid)?;
					let guard = package.read().await;
					assert_eq!(guard.child, None);

					ctx.create_exit_cpfp_tx(&guard.exit.tx, onchain)?
				};

				let child_txid = ctx.tx_manager.update_child_tx(exit.txid, child_tx).await?;
				info!("CPFP created with txid {} for exit tx {}", child_txid, exit.txid);
				Ok(ExitTxStatus::NeedsBroadcasting { child_txid, origin: ExitTxOrigin::Wallet })
			} else {
				info!("Exit tx {} has likely been broadcast by another party", exit.txid);
				Ok(new_status)
			}
		}
		ExitTxStatus::NeedsBroadcasting { child_txid, .. } => {
			info!("Checking if exit tx {} has been broadcast with CPFP tx {}",
				exit.txid, child_txid,
			);
			let status = ctx.get_exit_child_status(&exit, *child_txid).await?;
			match status {
				ExitTxStatus::NeedsBroadcasting { child_txid: new_child_txid, .. } => {
					if new_child_txid != *child_txid {
						warn!("Exit tx {} has a different child txid. Expected: {} Found: {}",
							exit.txid, child_txid, new_child_txid,
						);
					}
					info!("Attempting to broadcast exit tx {} with child tx {}", exit.txid, child_txid);
					let package = ctx.tx_manager.get_package(exit.txid)?;
					ctx.tx_manager.broadcast_package(&*package.read().await).await?;
					ctx.get_exit_child_status(&exit, new_child_txid).await
				},
				_ => {
					info!("Exit tx {} needed broadcasting but has changed status to: {}", exit.txid, status);
					Ok(status)
				},
			}
		},
		ExitTxStatus::BroadcastWithCpfp { child_txid, .. } => {
			let new_status = ctx.get_exit_child_status(exit, *child_txid).await?;
			match new_status {
				ExitTxStatus::Confirmed { block, .. } => {
					info!("Exit tx {} confirmed at height {}", exit.txid, block.height);
				}
				_ => {}
			}
			Ok(new_status)
		},
		ExitTxStatus::Confirmed { child_txid, block, .. } => {
			// Handle cases where we might get a block-reorg so our transaction may unconfirm
			let new_status = ctx.get_exit_child_status(exit, *child_txid).await?;
			match &new_status {
				ExitTxStatus::Confirmed { child_txid: new_txid, block: new_block, .. } => {
					if new_block != block || new_txid != child_txid {
						warn!("Exit transaction {} was confirmed with block {} but it has been replaced by {} in block {}",
							exit.txid, block.hash, new_txid, new_block.hash
						);
					}
				},
				_ => {
					warn!("Exit transaction {} was confirmed at height {} but it's now unconfirmed",
						exit.txid, block.height
					);
				},
			}
			Ok(new_status)
		}
	}
}

#[async_trait]
impl ExitStateProgress for ExitAwaitingDeltaState {
	async fn progress(
		self,
		ctx: &mut ProgressContext<'_>,
		_onchain: &mut impl ExitUnilaterally,
	) -> anyhow::Result<ExitState, ExitProgressError> {
		let tip = ctx.tip_height().await?;

		// Ensure the exit transaction hasn't disappeared from the mempool due to a reorg
		if !ctx.check_confirmed(ctx.vtxo.point().txid).await {
			error!("Exit for VTXO ({}) is no longer confirmed, verifying all transactions...",
				ctx.vtxo.id(),
			);
			return Ok(ExitState::new_processing(
				tip, ctx.exit_txids.iter().cloned(),
			));
		}

		// Inform the user of any progress
		if tip >= self.spendable_height {
			info!("Exit for VTXO ({}) is spendable!", ctx.vtxo.id());
			let spendable_block = ctx.get_block_ref(self.spendable_height).await?;
			Ok(ExitState::new_spendable(tip, spendable_block, None))
		} else {
			info!("Waiting for {} more confirmations until exit for VTXO ({}) is spendable...",
				self.spendable_height - tip, ctx.vtxo.id(),
			);
			Ok(self.into())
		}
	}
}

#[async_trait]
impl ExitStateProgress for ExitSpendableState {
	async fn progress(
		self,
		ctx: &mut ProgressContext<'_>,
		_onchain: &mut impl ExitUnilaterally,
	) -> anyhow::Result<ExitState, ExitProgressError> {
		let tip = ctx.tip_height().await?;

		// We should verify the current block hasn't been reorganized.
		let spendable_block = ctx.get_block_ref(self.spendable_since.height).await?;
		if spendable_block.hash != self.spendable_since.hash {
			return Ok(ExitState::new_spendable(tip, spendable_block, None));
		}

		// We can avoid scanning the whole chain provided there hasn't been a re-org
		let scan_height = if let Some(block) = &self.last_scanned_block {
			// Double check we haven't had a re-org since the last scan
			if ctx.get_block_ref(block.height).await?.hash == block.hash {
				block.height
			} else {
				self.spendable_since.height
			}
		} else {
			self.spendable_since.height
		};

		// Check if the VTXO exit has been spent
		let point = ctx.vtxo.point();
		let result = ctx
			.chain_source
			.txs_spending_inputs(
				vec![point],
				scan_height,
			).await
			.map_err(|e| ExitError::TransactionRetrievalFailure {
				txid: ctx.vtxo.point().txid, error: e.to_string(),
			})?;

		if let Some((txid, status)) = result.get(&point) {
			match status {
				TxStatus::Confirmed(block) => {
					info!("Tx {} has successfully spent VTXO {}", txid, ctx.vtxo.id());
					Ok(ExitState::new_spent(tip, txid.clone(), *block))
				},
				TxStatus::Mempool => {
					info!("Tx {} is attempting to spend VTXO {}", txid, ctx.vtxo.id());
					Ok(ExitState::new_spend_in_progress(tip, self.spendable_since, txid.clone()))
				},
				TxStatus::NotFound => unreachable!(),
			}
		} else {
			// Make sure the wallet is aware of the exit
			debug!("VTXO is still spendable: {}", ctx.vtxo.id());
			let tip_block = Some(ctx.get_block_ref(tip).await?);
			Ok(ExitState::new_spendable(tip, self.spendable_since, tip_block))
		}
	}
}

#[async_trait]
impl ExitStateProgress for ExitSpendInProgressState {
	async fn progress(
		self,
		ctx: &mut ProgressContext<'_>,
		_onchain: &mut impl ExitUnilaterally,
	) -> anyhow::Result<ExitState, ExitProgressError> {
		// Wait for confirmation of the spending transaction
		let tip = ctx.tip_height().await?;
		match ctx.tx_manager.tx_status(self.spending_txid).await? {
			TxStatus::Confirmed(block) => {
				info!("Tx {} has successfully spent VTXO {}", self.spending_txid, ctx.vtxo.id());
				Ok(ExitState::new_spent(tip, self.spending_txid, block))
			},
			TxStatus::Mempool => {
				trace!("Still waiting for TX {} to be confirmed", self.spending_txid);
				Ok(self.into())
			},
			TxStatus::NotFound => {
				warn!("TX {} has dropped from the mempool, VTXO {} is spendable again",
					self.spending_txid, ctx.vtxo.id(),
				);
				Ok(ExitState::new_spendable(tip, self.spendable_since, None))
			},
		}
	}
}

#[async_trait]
impl ExitStateProgress for ExitSpentState {
	async fn progress(
		self,
		ctx: &mut ProgressContext<'_>,
		_onchain: &mut impl ExitUnilaterally,
	) -> anyhow::Result<ExitState, ExitProgressError> {
		trace!("Exit for VTXO {} is spent!", ctx.vtxo.id());
		Ok(self.into())
	}
}

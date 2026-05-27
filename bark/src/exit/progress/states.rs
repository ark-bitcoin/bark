use ark::vtxo::policy::signing::VtxoSigner;
use log::{debug, error, info, trace, warn};

use bitcoin_ext::{BlockDelta, P2TR_DUST, TxStatus};
use crate::exit::models::{
	ExitError, ExitAwaitingDeltaState, ExitProcessingState, ExitClaimInProgressState, ExitClaimableState,
	ExitClaimedState, ExitState, ExitStartState, ExitTx, ExitTxStatus,
};
use crate::exit::progress::{ExitProgressError, ExitStateProgress, ProgressContext};
use crate::exit::progress::util::{count_broadcast, count_confirmed};

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl ExitStateProgress for ExitState {
	async fn progress(
		self,
		ctx: &mut ProgressContext<'_>,
	) -> anyhow::Result<ExitState, ExitProgressError> {
		match self {
			ExitState::Start(s) => s.progress(ctx).await,
			ExitState::Processing(s) => s.progress(ctx).await,
			ExitState::AwaitingDelta(s) => s.progress(ctx).await,
			ExitState::Claimable(s) => s.progress(ctx).await,
			ExitState::ClaimInProgress(s) => s.progress(ctx).await,
			ExitState::Claimed(s) => s.progress(ctx).await,
		}
	}
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl ExitStateProgress for ExitStartState {
	async fn progress(
		self,
		ctx: &mut ProgressContext<'_>,
	) -> anyhow::Result<ExitState, ExitProgressError> {
		let id = ctx.vtxo.id();
		info!("Checking if VTXO can be exited: {}", id);

		if ctx.vtxo.amount() < P2TR_DUST {
			return Err(ExitError::DustLimit { vtxo: ctx.vtxo.amount(), dust: P2TR_DUST }.into());
		}

		info!("Validated VTXO {}, exit process can now begin", id);

		Ok(ExitState::new_processing(
			ctx.wallet.inner.chain.tip().await.unwrap_or(self.tip_height),
			ctx.exit_txids.iter().cloned(),
		))
	}
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl ExitStateProgress for ExitProcessingState {
	async fn progress(
		self,
		ctx: &mut ProgressContext<'_>,
	) -> anyhow::Result<ExitState, ExitProgressError> {
		assert_eq!(self.transactions.len(), ctx.exit_txids.len());

		let tip = ctx.tip_height().await?;
		let mut transactions = self.transactions.clone();

		for i in 0..transactions.len() {
			match progress_exit_tx(&transactions[i], ctx).await {
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
			info!("Exit for VTXO ({}) has been fully confirmed, waiting for funds to become \
				spendable...", ctx.vtxo.id(),
			);
			let conf_block = transactions
				.iter()
				.filter_map(|exit| exit.status.confirmed_in())
				.max_by(|a, b| a.height.cmp(&b.height))
				.unwrap();

			let clause = ctx.wallet.find_signable_clause(ctx.vtxo).await
				.ok_or_else(|| ExitError::ClaimMissingSignableClause { vtxo: ctx.vtxo.id() })?;

			let wait_delta = clause.sequence().map_or(0, |csv| csv.0) as BlockDelta;
			return Ok(ExitState::new_awaiting_delta(tip, *conf_block, wait_delta));
		}
		if now_confirmed != prev_confirmed {
			info!("Exit for VTXO ({}) now has {} confirmed transactions with {} more required.",
				ctx.vtxo.id(), now_confirmed, transactions.len() - now_confirmed,
			);
		} else {
			let prev_broadcast = count_broadcast(&self.transactions);
			let now_broadcast = count_broadcast(&transactions);
			if now_broadcast == transactions.len() {
				info!("Exit for VTXO ({}) has been fully broadcast, waiting for {} transactions \
					to confirm...", ctx.vtxo.id(), now_confirmed,
				);
			} else if prev_broadcast != now_broadcast {
				let remaining = transactions.len() - now_broadcast;
				if prev_broadcast > now_broadcast {
					warn!("An exit transaction for VTXO ({}) appears to have fallen out of the \
						mempool", ctx.vtxo.id(),
					);
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

async fn progress_exit_tx(
	exit: &ExitTx,
	ctx: &mut ProgressContext<'_>,
) -> anyhow::Result<ExitTxStatus, ExitError> {
	match &exit.status {
		ExitTxStatus::VerifyInputs => {
			debug!("Verifying inputs for exit tx {}", exit.txid);
			let inputs = ctx.get_unique_inputs(exit.txid).await?;
			ctx.check_status_from_inputs(exit, &inputs).await
		},
		ExitTxStatus::AwaitingInputConfirmation { txids } => {
			debug!("Checking if the {} remaining inputs for exit tx {} have confirmed",
				txids.len(), exit.txid,
			);
			ctx.check_status_from_inputs(exit, &txids).await
		}
		ExitTxStatus::AwaitingCpfpBroadcast => {
			// Check whether another party has already broadcast this transaction before
			// we pause and wait for the caller to provide a CPFP via provide_cpfp_tx.
			ctx.get_exit_tx_status(exit).await
		},
		ExitTxStatus::AwaitingConfirmation { child_txid, .. } => {
			let child_status = ctx.tx_manager.get_child_status(exit.txid).await?;
			match child_status {
				None => {
					error!("Exit CPFP tx {} for exit tx {} has disappeared", child_txid, exit.txid);
					Ok(ExitTxStatus::AwaitingCpfpBroadcast)
				},
				Some(ref c) if c.txid != *child_txid => {
					warn!("Exit CPFP tx {} for exit tx {} has been replaced by {}",
						child_txid, exit.txid, c.txid,
					);
					ctx.get_exit_tx_status(exit).await
				},
				Some(ref c) if c.status == TxStatus::NotFound => {
					debug!("Exit CPFP tx {} fell out of mempool, rebroadcasting", child_txid);
					let package = ctx.tx_manager.get_package(exit.txid)?;
					let guard = package.read().await;
					ctx.tx_manager.broadcast_package(&*guard).await?;
					ctx.get_exit_tx_status(exit).await
				},
				Some(_) => {
					ctx.get_exit_tx_status(exit).await
				},
			}
		},
		ExitTxStatus::Confirmed { child_txid, block, .. } => {
			// Handle cases where we might get a block-reorg so our transaction may unconfirm
			let new_status = ctx.get_exit_tx_status(exit).await?;
			match &new_status {
				ExitTxStatus::Confirmed { child_txid: new_txid, block: new_block, .. } => {
					if new_block != block || new_txid != child_txid {
						warn!("Exit transaction {} was confirmed with block {} but it has been \
							replaced by {} in block {}",
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

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl ExitStateProgress for ExitAwaitingDeltaState {
	async fn progress(
		self,
		ctx: &mut ProgressContext<'_>,
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
		if tip >= self.claimable_height {
			info!("Exit for VTXO ({}) is spendable!", ctx.vtxo.id());
			let spendable_block = ctx.get_block_ref(self.claimable_height).await?;
			Ok(ExitState::new_claimable(tip, spendable_block, None))
		} else {
			info!("Waiting for {} more confirmations until exit for VTXO ({}) is spendable...",
				self.claimable_height - tip, ctx.vtxo.id(),
			);
			Ok(self.into())
		}
	}
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl ExitStateProgress for ExitClaimableState {
	async fn progress(
		self,
		ctx: &mut ProgressContext<'_>,
	) -> anyhow::Result<ExitState, ExitProgressError> {
		let tip = ctx.tip_height().await?;

		// We should verify the current block hasn't been reorganized.
		let spendable_block = ctx.get_block_ref(self.claimable_since.height).await?;
		if spendable_block.hash != self.claimable_since.hash {
			return Ok(ExitState::new_claimable(tip, spendable_block, None));
		}

		// We can avoid scanning the whole chain provided there hasn't been a re-org
		let scan_height = if let Some(block) = &self.last_scanned_block {
			// Double check we haven't had a re-org since the last scan
			if ctx.get_block_ref(block.height).await?.hash == block.hash {
				block.height
			} else {
				self.claimable_since.height
			}
		} else {
			self.claimable_since.height
		};

		// Check if the VTXO exit has been spent
		let point = ctx.vtxo.point();
		let result = ctx.wallet.inner.chain
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
					debug!("Tx {} has successfully claimed VTXO {}", txid, ctx.vtxo.id());
					Ok(ExitState::new_claimed(tip, txid.clone(), *block))
				},
				TxStatus::Mempool => {
					debug!("Tx {} is attempting to claim VTXO {}", txid, ctx.vtxo.id());
					Ok(ExitState::new_claim_in_progress(tip, self.claimable_since, txid.clone()))
				},
				TxStatus::NotFound => unreachable!(),
			}
		} else {
			// Make sure the wallet is aware of the exit
			debug!("VTXO is still spendable: {}", ctx.vtxo.id());
			let tip_block = Some(ctx.get_block_ref(tip).await?);
			Ok(ExitState::new_claimable(tip, self.claimable_since, tip_block))
		}
	}
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl ExitStateProgress for ExitClaimInProgressState {
	async fn progress(
		self,
		ctx: &mut ProgressContext<'_>,
	) -> anyhow::Result<ExitState, ExitProgressError> {
		// Wait for confirmation of the spending transaction
		let tip = ctx.tip_height().await?;
		match ctx.tx_manager.tx_status(self.claim_txid).await? {
			TxStatus::Confirmed(block) => {
				debug!("Tx {} has successfully spent VTXO {}", self.claim_txid, ctx.vtxo.id());
				Ok(ExitState::new_claimed(tip, self.claim_txid, block))
			},
			TxStatus::Mempool => {
				trace!("Still waiting for TX {} to be confirmed", self.claim_txid);
				Ok(self.into())
			},
			TxStatus::NotFound => {
				warn!("TX {} has dropped from the mempool, VTXO {} is spendable again",
					self.claim_txid, ctx.vtxo.id(),
				);
				Ok(ExitState::new_claimable(tip, self.claimable_since, None))
			},
		}
	}
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl ExitStateProgress for ExitClaimedState {
	async fn progress(
		self,
		ctx: &mut ProgressContext<'_>,
	) -> anyhow::Result<ExitState, ExitProgressError> {
		trace!("Exit for VTXO {} is spent!", ctx.vtxo.id());
		Ok(self.into())
	}
}

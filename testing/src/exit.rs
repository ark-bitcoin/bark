
use bark_json::cli::ExitProgressStatus;
use bark_json::exit::ExitState;
use bark_json::exit::states::ExitTxStatus;
use bitcoincore_rpc::RpcApi;
use log::warn;

use bark_json::exit::error::ExitError;

use crate::{Bark, TestContext};

/// Progresses a bark's exits until all exit transactions have been confirmed
/// on-chain, i.e. until every exit is in the [ExitState::AwaitingDelta] state.
///
/// Unlike [complete_exit], this function stops as soon as the exit transactions
/// are confirmed and does NOT advance to the user's claimable height.  This is
/// useful for tests that need to observe watchman behaviour in the window between
/// "exit tx confirmed" and "user can claim".
pub async fn progress_exit_until_awaiting_delta(ctx: &TestContext, bark: &Bark) {
	let mut previous = None;
	let mut attempts = 0;
	while attempts < 30 {
		attempts += 1;
		let response = bark.progress_exit().await;

		let all_awaiting_delta = !response.exits.is_empty()
			&& response.exits.iter().all(|e| matches!(e.state, ExitState::AwaitingDelta(_)));
		if all_awaiting_delta {
			return;
		}

		if response.done {
			panic!("exit completed before reaching awaiting-delta state for {}", bark.name());
		}

		let mut generate_block = false;

		for exit in &response.exits {
			if let Some(e) = &exit.error {
				match e {
					ExitError::InsufficientConfirmedFunds { .. } => {
						generate_block = true;
					},
					ExitError::ExitPackageBroadcastFailure { txid, error } => {
						warn!("{} failed to broadcast exit {}: {}", bark.name(), txid, error);
					},
					_ => panic!("unexpected exit error: {:?}", e),
				}
			}
		}

		// Generate a block to confirm exit txs if they are in the processing state.
		// We do NOT generate blocks for AwaitingDelta — that would advance past
		// the point this function is meant to stop at.
		if response.exits.iter().any(|e| match &e.state {
			ExitState::Processing(s) => s.transactions.iter().any(|t| matches!(
				t.status,
				ExitTxStatus::AwaitingInputConfirmation { .. } | ExitTxStatus::BroadcastWithCpfp { .. }
			)),
			_ => false,
		}) {
			generate_block = true;
		}

		if generate_block {
			ctx.generate_blocks(1).await;
		}

		if let Some(ref prev) = previous {
			if response != *prev {
				attempts -= 1;
			}
		}
		previous = Some(response);
	}
	panic!("exit did not reach awaiting-delta state for {}", bark.name());
}

fn check_exit_requires_confirmations(exit: &ExitProgressStatus) -> bool {
	match &exit.state {
		ExitState::Processing(s) => {
			s.transactions.iter().any(|s| match s.status {
				ExitTxStatus::AwaitingInputConfirmation { .. } => true,
				ExitTxStatus::BroadcastWithCpfp { .. } => true,
				_ => false,
			})
		},
		ExitState::AwaitingDelta(_) => true,
		ExitState::ClaimInProgress(_) => true,
		_ => false,
	}
}

pub async fn complete_exit(ctx: &TestContext, bark: &Bark) {
	let mut flip = false;
	let mut previous = None;
	let mut attempts = 0;
	while attempts < 20 {
		attempts += 1;
		let response = bark.progress_exit().await;
		if response.done {
			return;
		}

		// Ideally, we would flip-flop between generating and not generating blocks unless we're
		// explicitly waiting for one
		let mut generate_block = flip;
		flip = !flip;

		// Panic early if an unexpected error occurs
		for exit in &response.exits {
			if let Some(e) = &exit.error {
				match e {
					ExitError::InsufficientConfirmedFunds { .. } => {
						generate_block = true;
					}
					ExitError::ExitPackageBroadcastFailure { txid, error } => {
						warn!("{} failed to broadcast exit {}: {}", bark.name(), txid, error);
					}
					_ => panic!("unexpected exit error: {:?}", e),
				}
			}
		}
		if response.exits.iter().any(check_exit_requires_confirmations) {
			generate_block = true;
		}

		// Fast-forward if we're just waiting for confirmations
		let blocks_to_generate = get_blocks_to_generate(
			ctx, generate_block, response.claimable_height,
		);
		if blocks_to_generate > 0 {
			ctx.generate_blocks(blocks_to_generate).await;
		}

		// Used to allow for an extra iteration if the status has changed
		if let Some(ref previous) = previous {
			if response != *previous {
				attempts -= 1;
			}
		}
		previous = Some(response);
	}
	panic!("failed to finish unilateral exit of bark {}", bark.name());
}

fn get_blocks_to_generate(
	ctx: &TestContext,
	should_generate_block: bool,
	claimable_height: Option<u32>,
) -> u32 {
	if let Some(height) = claimable_height {
		let current = ctx.bitcoind().sync_client().get_block_count().unwrap() as u32;
		if current < height {
			return height - current;
		}
	}
	if should_generate_block {
		1
	} else {
		0
	}
}

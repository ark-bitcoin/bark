
use bark_json::cli::ExitProgressStatus;
use bark_json::exit::ExitState;
use bark_json::exit::states::ExitTxStatus;
use bitcoincore_rpc::RpcApi;
use log::warn;

use bark_json::exit::error::ExitError;

use crate::{Bark, TestContext};

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
		if let Some(height) = response.claimable_height {
			let current = ctx.bitcoind().sync_client().get_block_count().unwrap() as u32;
			let blocks = if current > height { 0 } else { height - current };
			ctx.generate_blocks(blocks).await;
		} else if generate_block {
			ctx.generate_blocks(1).await;
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


use bitcoin::FeeRate;
use log::warn;

use crate::Wallet;
use crate::exit::{Exit, ExitProgressStatus};
use crate::onchain::{CpfpError, ExitUnilaterally, MakeCpfpFees};

impl Exit {
	/// Progress all ongoing exits, handling CPFP fee-bumping via an onchain wallet.
	///
	/// It calls [Exit::progress_exits], creates CPFP transactions via `onchain` for any
	/// exits in [ExitTxStatus::AwaitingCpfpBroadcast], then calls [Exit::progress_exits]
	/// again so those exits advance to [ExitTxStatus::AwaitingConfirmation].
	///
	/// Callers with external or hardware wallets should use [Exit::exits_needing_cpfp]
	/// and [Exit::provide_cpfp_tx] directly instead.
	pub async fn progress_exits_onchain(
		&self,
		wallet: &Wallet,
		onchain: &mut dyn ExitUnilaterally,
		fee_rate_override: Option<FeeRate>,
	) -> anyhow::Result<Option<Vec<ExitProgressStatus>>> {
		self.progress_exits(wallet).await?;

		let fee_rate = fee_rate_override.unwrap_or(wallet.chain().fee_rates().await.fast);
		for req in self.exits_needing_cpfp().await {
			let fees = match req.min_fee_for_rbf {
				None => MakeCpfpFees::Effective(fee_rate),
				Some((min_fee_rate, min_fee)) => {
					if fee_rate <= min_fee_rate {
						continue;
					}
					MakeCpfpFees::Rbf {
						min_effective_fee_rate: fee_rate,
						current_package_fee: min_fee,
					}
				},
			};
			let child_tx = match onchain.make_signed_p2a_cpfp(&req.exit_tx, fees) {
				Ok(tx) => tx,
				Err(CpfpError::InsufficientConfirmedFunds { needed, available }) => {
					warn!("Insufficient funds for exit CPFP: needed {} available {}", needed, available);
					continue;
				},
				Err(e) => return Err(e.into()),
			};
			onchain.store_signed_p2a_cpfp(&child_tx).await?;
			let exit_txid = req.exit_tx.compute_txid();
			self.provide_cpfp_tx(wallet, exit_txid, child_tx).await?;
		}

		self.progress_exits(wallet).await
	}
}

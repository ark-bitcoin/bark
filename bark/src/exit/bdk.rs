
use anyhow::Context;
use bitcoin::FeeRate;
use log::warn;

use crate::Wallet;
use crate::exit::{Exit, ExitProgressStatus};
use crate::onchain::{CpfpError, MakeCpfpFees};

impl Exit {
	/// Advance ongoing exits by one step, handling CPFP fee-bumping via the wallet's
	/// internal onchain wallet.
	///
	/// This makes progress on each exit but does not run an exit to completion — exits
	/// span many blocks (broadcasting, confirmations, CSV timelocks, claim spends), so
	/// this must be called repeatedly (e.g. once per block) until all exits reach a
	/// terminal state.
	///
	/// It calls [Exit::progress_exits], creates CPFP transactions for any exits in
	/// [crate::exit::ExitTxStatus::AwaitingCpfpBroadcast], then calls [Exit::progress_exits] again
	/// so those exits advance to [crate::exit::ExitTxStatus::AwaitingConfirmation].
	///
	/// Callers with external or hardware wallets should use [Exit::exits_needing_cpfp]
	/// and [Exit::provide_cpfp_tx] directly instead.
	///
	/// Returns an error if the wallet has no onchain wallet configured.
	pub async fn progress_exits_with_cpfp(
		&self,
		wallet: &Wallet,
		fee_rate_override: Option<FeeRate>,
	) -> anyhow::Result<Option<Vec<ExitProgressStatus>>> {
		let onchain_arc = wallet.inner.onchain.as_ref()
			.context("no onchain wallet configured; cannot progress exits")?;

		self.progress_exits(wallet).await?;

		let fee_rate = fee_rate_override.unwrap_or(wallet.chain().fee_rates().await.fast);
		for req in self.exits_needing_cpfp().await {
			let fees = match req.rbf_requirement {
				None => MakeCpfpFees::Effective(fee_rate),
				Some(rbf) => {
					// Only RBF if we can improve the fee rate; equal or lower rates are rejected
					// by Bitcoin Core's RBF policy ("new feerate must be strictly greater").
					if fee_rate <= rbf.min_fee_rate {
						warn!(
							"Skipping exit CPFP RBF: requested fee rate {} is not above current package rate {}",
							fee_rate, rbf.min_fee_rate,
						);
						continue;
					}
					MakeCpfpFees::Rbf {
						min_effective_fee_rate: fee_rate,
						current_package_fee: rbf.current_package_fee,
					}
				},
			};
			let child_tx = {
				let mut onchain = onchain_arc.write().await;
				let tx = match onchain.make_signed_p2a_cpfp(&req.exit_tx, fees).await {
					Ok(tx) => tx,
					Err(CpfpError::InsufficientConfirmedFunds { needed, available }) => {
						warn!("Insufficient funds for exit CPFP: needed {} available {}", needed, available);
						continue;
					},
					Err(e) => return Err(e.into()),
				};
				onchain.store_signed_p2a_cpfp(&tx).await?;
				tx
			};
			let exit_txid = req.exit_tx.compute_txid();
			self.provide_cpfp_tx(wallet, exit_txid, child_tx).await?;
		}

		self.progress_exits(wallet).await
	}
}

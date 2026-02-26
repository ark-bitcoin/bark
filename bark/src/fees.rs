//! Fee estimation for various wallet operations.

use anyhow::{Context, Result};
use bitcoin::Amount;

use ark::{Vtxo, VtxoId};
use ark::fees::VtxoFeeInfo;

use crate::Wallet;

/// Result of a fee estimation containing the total cost, fee amount, and VTXOs used. It's very
/// important to consider that fees can change over time, so you should expect to renew this
/// estimate frequently when presenting this information to users.
#[derive(Debug, Clone)]
pub struct FeeEstimate {
	/// The gross amount that will be received/sent
	pub gross_amount: Amount,
	/// The fee amount charged by the server.
	pub fee: Amount,
	/// The net amount that will be received/sent.
	pub net_amount: Amount,
	/// The VTXOs that would be used for this operation, if necessary.
	pub vtxos_spent: Vec<VtxoId>,
}

impl FeeEstimate {
	pub fn new(
		gross_amount: Amount,
		fee: Amount,
		net_amount: Amount,
		vtxos_spent: Vec<VtxoId>,
	) -> Self {
		Self {
			gross_amount,
			fee,
			net_amount,
			vtxos_spent,
		}
	}
}

impl Wallet {
	/// Estimate fees for a board operation. `FeeEstimate::net_amount` will be the amount of the
	/// newly boarded VTXO. Note: This doesn't include the onchain cost of creating the chain
	/// anchor transaction.
	pub async fn estimate_board_offchain_fee(&self, board_amount: Amount) -> Result<FeeEstimate> {
		let (_, ark_info) = self.require_server().await?;
		let fee = ark_info.fees.board.calculate(board_amount).context("fee overflowed")?;
		let net_amount = board_amount.checked_sub(fee).unwrap_or(Amount::ZERO);

		Ok(FeeEstimate::new(board_amount, fee, net_amount, vec![]))
	}

	/// Estimate fees for a lightning receive operation. `FeeEstimate::gross_amount` is the
	/// lightning payment amount, `FeeEstimate::net_amount` is how much the end user will receive.
	pub async fn estimate_lightning_receive_fee(&self, amount: Amount) -> Result<FeeEstimate> {
		let (_, ark_info) = self.require_server().await?;

		let fee = ark_info.fees.lightning_receive.calculate(amount).context("fee overflowed")?;
		let net_amount = amount.checked_sub(fee).unwrap_or(Amount::ZERO);

		Ok(FeeEstimate::new(amount, fee, net_amount, vec![]))
	}

	/// Estimate fees for a lightning send operation. `FeeEstimate::net_amount` is the amount to be
	/// paid to a given invoice/address.
	///
	/// Uses the same iterative approach as `make_lightning_payment` to account for
	/// VTXO expiry-based fees.
	///
	/// Will fail to estimate fees if there aren't enough funds in the wallet to make the payment.
	pub async fn estimate_lightning_send_fee(&self, amount: Amount) -> Result<FeeEstimate> {
		let (_, ark_info) = self.require_server().await?;

		let (inputs, fee) = self.select_vtxos_to_cover_with_fee(
			amount, |a, v| ark_info.fees.lightning_send.calculate(a, v).context("fee overflowed"),
		).await?;

		let total_cost = amount.checked_add(fee).unwrap_or(Amount::MAX);
		let vtxo_ids = inputs.into_iter().map(|v| v.id()).collect();

		Ok(FeeEstimate::new(total_cost, fee, amount, vtxo_ids))
	}

	/// Estimate fees for an offboard operation. `FeeEstimate::net_amount` is the onchain amount the
	/// user can expect to receive by offboarding `FeeEstimate::vtxos_used`.
	pub async fn estimate_offboard(
		&self,
		address: &bitcoin::Address,
		vtxos: impl IntoIterator<Item = impl AsRef<Vtxo>>,
	) -> Result<FeeEstimate> {
		let (_, ark_info) = self.require_server().await?;
		let script_buf = address.script_pubkey();
		let current_height = self.chain.tip().await?;

		let vtxos = vtxos.into_iter();
		let capacity = vtxos.size_hint().1.unwrap_or(vtxos.size_hint().0);
		let mut vtxo_ids = Vec::with_capacity(capacity);
		let mut fee_info = Vec::with_capacity(capacity);
		let mut amount = Amount::ZERO;
		for v in vtxos {
			vtxo_ids.push(v.as_ref().id());
			fee_info.push(VtxoFeeInfo::from_vtxo_and_tip(v.as_ref(), current_height));
			amount = amount + v.as_ref().amount();
		}

		let fee = ark_info.fees.offboard.calculate(
			&script_buf,
			amount,
			ark_info.offboard_feerate,
			fee_info,
		).context("Error whilst calculating offboard fee")?;

		let net_amount = amount.checked_sub(fee).unwrap_or(Amount::ZERO);
		Ok(FeeEstimate::new(amount, fee, net_amount, vtxo_ids))
	}

	/// Estimate fees for a refresh operation (round participation). `FeeEstimate::net_amount` is
	/// the sum of the newly refreshed VTXOs.
	pub async fn estimate_refresh_fee(
		&self,
		vtxos: impl IntoIterator<Item = impl AsRef<Vtxo>>,
	) -> Result<FeeEstimate> {
		let (_, ark_info) = self.require_server().await?;
		let current_height = self.chain.tip().await?;

		let vtxos = vtxos.into_iter();
		let capacity = vtxos.size_hint().1.unwrap_or(vtxos.size_hint().0);
		let mut vtxo_ids = Vec::with_capacity(capacity);
		let mut vtxo_fee_infos = Vec::with_capacity(capacity);
		let mut total_amount = Amount::ZERO;
		for vtxo in vtxos.into_iter() {
			let vtxo = vtxo.as_ref();
			vtxo_ids.push(vtxo.id());
			vtxo_fee_infos.push(VtxoFeeInfo::from_vtxo_and_tip(vtxo, current_height));
			total_amount = total_amount + vtxo.amount();
		}

		// Calculate refresh fees
		let fee = ark_info.fees.refresh.calculate(vtxo_fee_infos).context("fee overflowed")?;
		let output_amount = total_amount.checked_sub(fee).unwrap_or(Amount::ZERO);
		Ok(FeeEstimate::new(total_amount, fee, output_amount, vtxo_ids))
	}

	/// Estimate fees for a send-onchain operation. `FeeEstimate::net_amount` is the onchain amount
	/// the user will receive and `FeeEstimate::gross_amount` is the offchain amount the user will
	/// pay using `FeeEstimate::vtxos_used`.
	///
	/// Uses the same iterative approach as `send_onchain` to account for VTXO expiry-based fees.
	///
	/// Will fail to estimate fees if there aren't enough funds in the wallet to make the payment.
	pub async fn estimate_send_onchain(
		&self,
		address: &bitcoin::Address,
		amount: Amount,
	) -> Result<FeeEstimate> {
		let (_, ark_info) = self.require_server().await?;
		let script_buf = address.script_pubkey();

		let (inputs, fee) = self.select_vtxos_to_cover_with_fee(
			amount, |a, v|
				ark_info.fees.offboard.calculate(&script_buf, a, ark_info.offboard_feerate, v)
					.ok_or_else(|| anyhow!("Error whilst calculating fee"))
		).await?;

		let total_cost = amount.checked_add(fee).unwrap_or(Amount::MAX);
		let vtxo_ids = inputs.into_iter().map(|v| v.id()).collect();

		Ok(FeeEstimate::new(total_cost, fee, amount, vtxo_ids))
	}
}

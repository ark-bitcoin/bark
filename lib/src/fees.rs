use std::cmp::PartialOrd;
use std::ops;

use bitcoin::{Amount, FeeRate, ScriptBuf, Weight};

use bitcoin_ext::{BlockHeight, P2TR_DUST};

use crate::Vtxo;

/// Complete fee schedule for all operations.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize, Serialize)]
pub struct FeeSchedule {
	pub board: BoardFees,
	pub offboard: OffboardFees,
	pub refresh: RefreshFees,
	pub lightning_receive: LightningReceiveFees,
	pub lightning_send: LightningSendFees,
}

impl FeeSchedule {
	pub fn validate(&self) -> Result<(), FeeScheduleValidationError> {
		// Validate the order of the fee structs
		let tables = [
			("lightning_send", &self.lightning_send.ppm_expiry_table),
			("offboard", &self.offboard.ppm_expiry_table),
			("refresh", &self.refresh.ppm_expiry_table),
		];
		for (name, ppm_expiry_table) in tables {
			let mut prev_entry : Option<&PpmExpiryFeeEntry> = None;
			for current in ppm_expiry_table {
				if let Some(previous) = prev_entry {
					// Expiry blocks should be in ascending order.
					if current.expiry_blocks_threshold < previous.expiry_blocks_threshold {
						return Err(FeeScheduleValidationError::UnsortedPpmFeeTable {
							name: name.to_string(),
							current: current.expiry_blocks_threshold,
							previous: previous.expiry_blocks_threshold,
						})
					}
					// Ensuring the curve always increases means that we can avoid a whole host of
					// problems where the tip is different to that of the client. We prefer to
					// overpay slightly for a fee than to make operations brittle.
					if current.ppm < previous.ppm {
						return Err(FeeScheduleValidationError::IncorrectPpmFeeCurve {
							name: name.to_string(),
							current: current.ppm.0,
							previous: previous.ppm.0,
						});
					}
				}
				prev_entry = Some(current);
			}
		}
		Ok(())
	}
}

impl Default for FeeSchedule {
	/// Returns a fee schedule with zero fees.
	fn default() -> Self {
		let table = vec![PpmExpiryFeeEntry { expiry_blocks_threshold: 0, ppm: PpmFeeRate::ZERO }];
		Self {
			board: BoardFees {
				min_fee: Amount::ZERO,
				base_fee: Amount::ZERO,
				ppm: PpmFeeRate::ZERO,
			},
			offboard: OffboardFees {
				base_fee: Amount::ZERO,
				fixed_additional_vb: 0,
				ppm_expiry_table: table.clone(),
			},
			refresh: RefreshFees {
				base_fee: Amount::ZERO,
				ppm_expiry_table: table.clone(),
			},
			lightning_receive: LightningReceiveFees {
				base_fee: Amount::ZERO,
				ppm: PpmFeeRate::ZERO,
			},
			lightning_send: LightningSendFees {
				min_fee: Amount::ZERO,
				base_fee: Amount::ZERO,
				ppm_expiry_table: table.clone(),
			},
		}
	}
}

/// Error types for fee schedule validation.
#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq, Hash)]
pub enum FeeScheduleValidationError {
	#[error("{name} ppm expiry table must be sorted by expiry threshold in ascending order of expiry. {previous} is higher than {current}.")]
	UnsortedPpmFeeTable { name: String, current: u32, previous: u32 },

	#[error("{name} ppm expiry table fee curve must be in ascending order. {previous} is higher than {current}.")]
	IncorrectPpmFeeCurve { name: String, current: u64, previous: u64 },
}

/// Fees for boarding the ark.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize)]
pub struct BoardFees {
	/// Minimum fee to charge.
	#[serde(rename = "min_fee_sat", with = "bitcoin::amount::serde::as_sat")]
	pub min_fee: Amount,
	/// A fee applied to every transaction regardless of value.
	#[serde(rename = "base_fee_sat", with = "bitcoin::amount::serde::as_sat")]
	pub base_fee: Amount,
	/// PPM (parts per million) fee rate to apply based on the value of the transaction.
	#[serde(rename = "ppm")]
	pub ppm: PpmFeeRate,
}

impl BoardFees {
	/// Calculate the total fee for a board operation.
	/// Returns the maximum of the calculated fee (base_fee + ppm) and the minimum fee. `None` if an
	/// overflow occurs.
	pub fn calculate(&self, amount: Amount) -> Option<Amount> {
		let fee = self.ppm.checked_mul(amount)?.checked_add(self.base_fee)?;
		Some(fee.max(self.min_fee))
	}
}

/// Fees for offboarding from the ark.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize, Serialize)]
pub struct OffboardFees {
	/// A fee applied to every transaction regardless of value.
	#[serde(rename = "base_fee_sat", with = "bitcoin::amount::serde::as_sat")]
	pub base_fee: Amount,

	/// Fixed number of virtual bytes charged offboard on top of the output size.
	///
	/// The fee for an offboard will be this value, plus the offboard output virtual size,
	/// multiplied with the offboard fee rate, plus the `base_fee`, and plus the additional fee
	/// calculated with the `ppm_expiry_table`.
	pub fixed_additional_vb: u64,

	/// A table mapping how soon a VTXO will expire to a PPM (parts per million) fee rate.
	/// The table should be sorted by each `expiry_blocks_threshold` value in ascending order.
	pub ppm_expiry_table: Vec<PpmExpiryFeeEntry>,
}

impl OffboardFees {
	/// Returns the fee charged for the user to make an offboard given the fee rate.
	///
	/// Returns `None` in the calculation overflows because of insane destinations or fee rates.
	pub fn calculate(
		&self,
		destination: &ScriptBuf,
		amount: Amount,
		fee_rate: FeeRate,
		vtxos: impl IntoIterator<Item = VtxoFeeInfo>,
	) -> Option<Amount> {
		let weight_fee = self.fixed_additional_vb.checked_add(destination.as_script().len() as u64)
			.and_then(Weight::from_vb)
			.and_then(|w| fee_rate.checked_mul_by_weight(w))?;
		let ppm_fee = calc_ppm_expiry_fee(Some(amount), &self.ppm_expiry_table, vtxos)?;
		self.base_fee.checked_add(weight_fee)?.checked_add(ppm_fee)
	}
}

/// Fees for refresh operations.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize, Serialize)]
pub struct RefreshFees {
	/// A fee applied to every transaction regardless of value.
	#[serde(rename = "base_fee_sat", with = "bitcoin::amount::serde::as_sat")]
	pub base_fee: Amount,
	/// A table mapping how soon a VTXO will expire to a PPM (parts per million) fee rate.
	/// The table should be sorted by each `expiry_blocks_threshold` value in ascending order.
	pub ppm_expiry_table: Vec<PpmExpiryFeeEntry>,
}

impl RefreshFees {
	/// Calculate the total fee for a refresh operation.
	///
	/// Returns `None` if an overflow occurs.
	pub fn calculate(
		&self,
		vtxos: impl IntoIterator<Item = VtxoFeeInfo>,
	) -> Option<Amount> {
		self.base_fee.checked_add(self.calculate_no_base_fee(vtxos)?)
	}

	/// Calculate the fee for a refresh operation, excluding the base fee.
	///
	/// Returns `None` if an overflow occurs.
	pub fn calculate_no_base_fee(
		&self,
		vtxos: impl IntoIterator<Item = VtxoFeeInfo>,
	) -> Option<Amount> {
		calc_ppm_expiry_fee(None, &self.ppm_expiry_table, vtxos)
	}
}

/// Fees for lightning receive operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize)]
pub struct LightningReceiveFees {
	/// A fee applied to every transaction regardless of value.
	#[serde(rename = "base_fee_sat", with = "bitcoin::amount::serde::as_sat")]
	pub base_fee: Amount,
	/// PPM (parts per million) fee rate to apply based on the value of the transaction.
	pub ppm: PpmFeeRate,
}

impl LightningReceiveFees {
	/// Calculate the total fee for a lightning receive operation.
	///
	/// Returns `None` if an overflow occurs.
	pub fn calculate(&self, amount: Amount) -> Option<Amount> {
		self.base_fee.checked_add(self.ppm.checked_mul(amount)?)
	}
}

/// Fees for lightning send operations.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize, Serialize)]
pub struct LightningSendFees {
	/// Minimum fee to charge.
	#[serde(rename = "min_fee_sat", with = "bitcoin::amount::serde::as_sat")]
	pub min_fee: Amount,
	/// A fee applied to every transaction regardless of value.
	#[serde(rename = "base_fee_sat", with = "bitcoin::amount::serde::as_sat")]
	pub base_fee: Amount,
	/// A table mapping how soon a VTXO will expire to a PPM (parts per million) fee rate.
	/// The table should be sorted by each `expiry_blocks_threshold` value in ascending order.
	pub ppm_expiry_table: Vec<PpmExpiryFeeEntry>,
}

impl LightningSendFees {
	/// Calculate the total fee for a lightning send operation.
	///
	/// Returns `None` if an overflow occurs.
	pub fn calculate(
		&self,
		amount: Amount,
		vtxos: impl IntoIterator<Item = VtxoFeeInfo>,
	) -> Option<Amount> {
		let ppm = calc_ppm_expiry_fee(Some(amount), &self.ppm_expiry_table, vtxos)?;
		Some(self.base_fee.checked_add(ppm)?.max(self.min_fee))
	}
}

/// A very basic struct to hold information for use in calculating the fees of transactions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize)]
pub struct VtxoFeeInfo {
	/// The total amount of the VTXO.
	pub amount: Amount,
	/// Number of blocks until expiry.
	pub expiry_blocks: u32,
}

impl VtxoFeeInfo {
	/// Constructs a [VtxoFeeInfo] instance from the given [Vtxo] and tip [BlockHeight]
	pub fn from_vtxo_and_tip(vtxo: &Vtxo, tip: BlockHeight) -> Self {
		Self {
			amount: vtxo.amount,
			expiry_blocks: vtxo.expiry_height.saturating_sub(tip),
		}
	}
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Deserialize, Serialize)]
pub struct PpmFeeRate(pub u64);

impl PpmFeeRate {
	/// The zero amount.
	pub const ZERO: PpmFeeRate = PpmFeeRate(0);
	/// Represents a fee rate of 1%.
	pub const ONE_PERCENT: PpmFeeRate = PpmFeeRate(10_000);

	/// Multiplies the given amount by this fee rate. Returns `None` if the result overflows.
	pub fn checked_mul(self, other: Amount) -> Option<Amount> {
		let numerator = other.to_sat().checked_mul(self.0)?;
		Some(Amount::from_sat(numerator / 1_000_000))
	}
}

impl ops::Mul<PpmFeeRate> for Amount {
	type Output = Amount;

	/// Calculates a fee value for the current amount using a parts-per-million (PPM) rate.
	///
	/// # Returns
	///
	/// Returns the calculated fee as an `Amount`. The result is truncated using integer division,
	/// and any overflow is capped with u64::MAX.
	///
	/// # Example
	///
	/// ```rust
	/// use ark::fees::PpmFeeRate;
	/// use bitcoin::Amount;
	///
	/// let fee_chargeable_amount = Amount::from_sat(10_000);
	/// let ppm = PpmFeeRate(5_000); // 0.5%
	/// let fee = fee_chargeable_amount * ppm;
	/// assert_eq!(fee, Amount::from_sat(50)); // 10,000 * 5,000 / 1,000,000 = 50
	/// ```
	fn mul(self, ppm: PpmFeeRate) -> Self::Output {
		let numerator = self.to_sat().saturating_mul(ppm.0);
		Amount::from_sat(numerator / 1_000_000)
	}
}

/// Entry in a table to calculate the PPM (parts per million) fee rate of a transaction based on how
/// new a VTXO is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize)]
pub struct PpmExpiryFeeEntry {
	/// A threshold for the number of blocks until a VTXO expires for the `ppm` amount to apply.
	/// As an example, if this value is set to 50 and a VTXO expires in 60 blocks, this
	/// [PpmExpiryFeeEntry] will be used to calculate the fee unless another entry exists with an
	/// `expiry_blocks_threshold` with a value between 51 and 60 (inclusive).
	pub expiry_blocks_threshold: u32,
	/// PPM (parts per million) fee rate to apply for this expiry period.
	pub ppm: PpmFeeRate,
}

/// Error types for fee validation.
#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq, Hash)]
pub enum FeeValidationError {
	#[error("Fee ({fee}) exceeds amount ({amount})")]
	FeeExceedsAmount { amount: Amount, fee: Amount },

	#[error("Amount after fee ({amount_after_fee}) is below dust limit ({P2TR_DUST}). Amount: {amount}, Fee: {fee}")]
	AmountAfterFeeBelowDust {
		amount: Amount,
		fee: Amount,
		amount_after_fee: Amount,
	},
}

/// Validates fee amounts and calculates the resulting amount after fee.
///
/// This function ensures two critical conditions are met:
/// 1. Fee doesn't exceed the original amount (prevents overflow)
/// 2. Amount after fee is > zero
///
/// # Returns
/// * `Ok(Amount)` - The amount after subtracting the fee
/// * `Err(FeeValidationError)` - If any validation condition fails
///
/// # Example
/// ```
/// use ark::fees::{validate_and_subtract_fee, FeeValidationError};
/// use bitcoin::Amount;
///
/// let amount = Amount::from_sat(10_000);
/// let fee = Amount::from_sat(100);
/// let result = validate_and_subtract_fee(amount, fee);
/// assert_eq!(result.unwrap(), Amount::from_sat(9_900));
///
/// let amount = Amount::from_sat(10_000);
/// let fee = Amount::from_sat(10_000);
/// let result = validate_and_subtract_fee(amount, fee);
/// assert_eq!(result.unwrap_err(), FeeValidationError::FeeExceedsAmount { amount, fee });
///
/// let amount = Amount::from_sat(10_000);
/// let fee = Amount::from_sat(11_000);
/// let result = validate_and_subtract_fee(amount, fee);
/// assert_eq!(result.unwrap_err(), FeeValidationError::FeeExceedsAmount { amount, fee });
/// ```
pub fn validate_and_subtract_fee(
	amount: Amount,
	fee: Amount,
) -> Result<Amount, FeeValidationError> {
	let amount_after_fee = amount.checked_sub(fee)
		.ok_or(FeeValidationError::FeeExceedsAmount { amount, fee })?;

	if amount_after_fee == Amount::ZERO {
		Err(FeeValidationError::FeeExceedsAmount { amount, fee })
	} else {
		Ok(amount_after_fee)
	}
}

/// Validates fee amounts and calculates the resulting amount after fee.
///
/// This function ensures two critical conditions are met:
/// 1. Fee doesn't exceed the original amount (prevents overflow)
/// 2. Amount after fee is >= P2TR_DUST (ensures economically viable output)
///
/// # Returns
/// * `Ok(Amount)` - The amount after subtracting the fee
/// * `Err(FeeValidationError)` - If any validation condition fails
///
/// # Example
/// ```
/// use ark::fees::{validate_and_subtract_fee_min_dust, FeeValidationError};
/// use bitcoin::Amount;
/// use bitcoin_ext::P2TR_DUST;
///
/// let amount = Amount::from_sat(10_000);
/// let fee = Amount::from_sat(100);
/// let result = validate_and_subtract_fee_min_dust(amount, fee);
/// assert_eq!(result.unwrap(), Amount::from_sat(9_900));
///
/// let amount = Amount::from_sat(10_000);
/// let fee = Amount::from_sat(9_670);
/// let result = validate_and_subtract_fee_min_dust(amount, fee);
/// assert_eq!(result.unwrap(), P2TR_DUST);
///
/// let amount = Amount::from_sat(10_000);
/// let fee = Amount::from_sat(11_000);
/// let result = validate_and_subtract_fee_min_dust(amount, fee);
/// assert_eq!(result.unwrap_err(), FeeValidationError::FeeExceedsAmount { amount, fee });
///
/// let amount = Amount::from_sat(10_000);
/// let fee = Amount::from_sat(10_000);
/// let result = validate_and_subtract_fee_min_dust(amount, fee);
/// assert_eq!(result.unwrap_err(), FeeValidationError::AmountAfterFeeBelowDust {
/// 	amount,
/// 	fee,
/// 	amount_after_fee: amount - fee,
/// });
/// ```
pub fn validate_and_subtract_fee_min_dust(
	amount: Amount,
	fee: Amount,
) -> Result<Amount, FeeValidationError> {
	let amount_after_fee = amount.checked_sub(fee)
		.ok_or(FeeValidationError::FeeExceedsAmount { amount, fee })?;

	// amount - fee must be >= P2TR_DUST
	if amount_after_fee < P2TR_DUST {
		return Err(FeeValidationError::AmountAfterFeeBelowDust {
			amount,
			fee,
			amount_after_fee,
		});
	}

	Ok(amount_after_fee)
}

/// Calculates the total fee based on the provided fee-chargeable amount, a table of PPM
/// (Parts Per Million) expiry-based fee rates, and an iterable list of VTXO information.
///
/// # Parameters
///
/// * `fee_chargeable_amount` - An optional total amount from which the fee is chargeable. If
///   specified, this amount determines the maximum amount to be used for fee calculations across
///   all VTXOs. The value decreases as portions of it are consumed for each VTXOs fee calculation.
///   If `None`, each VTXOs full amount is considered chargeable.
///
/// * `ppm_expiry_table` - Each entry contains an expiry threshold and a corresponding PPM fee. This
///   table is assumed to be sorted in ascending order of `expiry_blocks_threshold` for correct
///   behavior.
///
/// * `vtxos` - An iterable input of `VtxoFeeInfo`, where each element contains the amount and
///   the number of blocks until the VTXO expires, which is relevant for fee calculation.
///
/// # Returns
///
/// Returns an `Amount` representing the total calculated fee based on the provided inputs. `None`
/// if an overflow occurs.
///
/// # Example Usage
///
/// ```rust
/// use ark::fees::{PpmExpiryFeeEntry, PpmFeeRate, VtxoFeeInfo, calc_ppm_expiry_fee};
/// use bitcoin::Amount;
///
/// let fee_chargeable_amount = Some(Amount::from_sat(15_000));
/// let ppm_expiry_table = vec![
///     PpmExpiryFeeEntry { expiry_blocks_threshold: 10, ppm: PpmFeeRate::ONE_PERCENT },
///     PpmExpiryFeeEntry { expiry_blocks_threshold: 20, ppm: PpmFeeRate(50_000) }, // 5%
/// ];
/// let vtxos = vec![
///     VtxoFeeInfo { amount: Amount::from_sat(5_000), expiry_blocks: 2 },
///     VtxoFeeInfo { amount: Amount::from_sat(3_000), expiry_blocks: 12 },
///     VtxoFeeInfo { amount: Amount::from_sat(7_000), expiry_blocks: 22 },
/// ];
///
/// let total_fee = calc_ppm_expiry_fee(fee_chargeable_amount, &ppm_expiry_table, vtxos);
/// assert_eq!(total_fee, Some(Amount::from_sat(380))); // 5,000 * 0% + 3,000 * 1% + 7,000 * 5% = 380
/// ```
pub fn calc_ppm_expiry_fee(
	fee_chargeable_amount: Option<Amount>,
	ppm_expiry_table: &Vec<PpmExpiryFeeEntry>,
	vtxos: impl IntoIterator<Item = VtxoFeeInfo>,
) -> Option<Amount> {
	let mut total_fee = Amount::ZERO;
	let mut remaining = fee_chargeable_amount;
	for v in vtxos {
		// If we were given a total amount, we should only account for that amount, else we should
		// assume every VTXO will be fully spent.
		let fee_chargeable_amount = if let Some(ref mut remaining) = remaining {
			let amount = v.amount.min(*remaining);
			*remaining -= amount;
			amount
		} else {
			v.amount
		};

		// We assume the table is sorted by expiry_blocks_threshold in ascending order
		let entry = ppm_expiry_table
			.iter()
			.rev()
			.find(|entry| v.expiry_blocks >= entry.expiry_blocks_threshold);

		// If we can't find an entry that is suitable, we assume no fee is necessary
		if let Some(entry) = entry {
			total_fee = total_fee.checked_add(entry.ppm.checked_mul(fee_chargeable_amount)?)?;
		}
	}
	Some(total_fee)
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_board_fees() {
		let mut fees = BoardFees {
			min_fee: Amount::ZERO,
			base_fee: Amount::from_sat(100),
			ppm: PpmFeeRate(1_000), // 0.1%
		};

		// Test with 10,000 sats
		let amount = Amount::from_sat(10_000);
		let fee = fees.calculate(amount).unwrap();
		// base (100) + (10,000 * 1,000) / 1,000,000 = 100 + 10 = 110
		assert_eq!(fee, Amount::from_sat(110));

		// Test with 10,000 sats and min fee
		fees.min_fee = Amount::from_sat(330);
		let amount = Amount::from_sat(10_000);
		let fee = fees.calculate(amount).unwrap();
		// base (100) + (10,000 * 1,000) / 1,000,000 = 100 + 10 = MAX(110, 330) = 330
		assert_eq!(fee, Amount::from_sat(330));
	}

	#[test]
	fn test_offboard_fees_with_single_vtxo() {
		let fees = OffboardFees {
			base_fee: Amount::from_sat(200),
			fixed_additional_vb: 100,
			ppm_expiry_table: vec![
				PpmExpiryFeeEntry { expiry_blocks_threshold: 100, ppm: PpmFeeRate(1_000) },
				PpmExpiryFeeEntry { expiry_blocks_threshold: 500, ppm: PpmFeeRate(2_000) },
				PpmExpiryFeeEntry { expiry_blocks_threshold: 1_000, ppm: PpmFeeRate(3_000) },
			],
		};

		let script_str = "6a0474657374"; // OP_RETURN, push 4 bytes with the string "test"
		let destination = ScriptBuf::from_hex(script_str)
			.expect("Failed to parse OP_RETURN script hex string");
		let fee_rate = FeeRate::from_sat_per_vb_unchecked(10);
		let amount = Amount::from_sat(100_000);

		// Test with expiry < 100 blocks (should use 0 ppm)
		let vtxo = VtxoFeeInfo { amount, expiry_blocks: 50 };
		let fee = fees.calculate(&destination, amount, fee_rate, vec![vtxo]).unwrap();
		// base (200) + ((100,000 * 0) / 1,000,000) + ((6 + 100) * 10) = 200 + 0 + 1,060 = 1,260
		assert_eq!(fee, Amount::from_sat(1_260));

		// Test with expiry = 150 blocks (should use 1,000 ppm)
		let vtxo = VtxoFeeInfo { amount, expiry_blocks: 150 };
		let fee = fees.calculate(&destination, amount, fee_rate, vec![vtxo]).unwrap();
		// base (200) + ((100,000 * 1,000) / 1,000,000) + ((6 + 100) * 10) = 200 + 100 + 1,060 = 1,360
		assert_eq!(fee, Amount::from_sat(1_360));

		// Test with expiry = 750 blocks (should use 2,000 ppm)
		let vtxo = VtxoFeeInfo { amount, expiry_blocks: 750 };
		let fee = fees.calculate(&destination, amount, fee_rate, vec![vtxo]).unwrap();
		// base (200) + ((100,000 * 2,000) / 1,000,000) + ((6 + 100) * 10) = 200 + 200 + 1,060 = 1,460
		assert_eq!(fee, Amount::from_sat(1_460));

		// Test with expiry = 2,000 blocks (should use 3,000 ppm)
		let vtxo = VtxoFeeInfo { amount, expiry_blocks: 2_000 };
		let fee = fees.calculate(&destination, amount, fee_rate, vec![vtxo]).unwrap();
		// base (200) + ((100,000 * 3,000) / 1,000,000) + ((6 + 100) * 10) = 200 + 300 + 1,060 = 1,560
		assert_eq!(fee, Amount::from_sat(1_560));
	}

	#[test]
	fn test_offboard_fees_with_multiple_vtxos() {
		let fees = OffboardFees {
			base_fee: Amount::from_sat(200),
			fixed_additional_vb: 100,
			ppm_expiry_table: vec![
				PpmExpiryFeeEntry { expiry_blocks_threshold: 100, ppm: PpmFeeRate(1_000) },
				PpmExpiryFeeEntry { expiry_blocks_threshold: 500, ppm: PpmFeeRate(2_000) },
			],
		};

		let script_str = "6a0474657374"; // OP_RETURN, push 4 bytes with the string "test"
		let destination = ScriptBuf::from_hex(script_str)
			.expect("Failed to parse OP_RETURN script hex string");
		let fee_rate = FeeRate::from_sat_per_vb_unchecked(10);
		// Test with multiple VTXOs where total VTXO value exceeds amount being sent
		// VTXOs total 120,000 but we're only sending 100,000
		let vtxos = vec![
			VtxoFeeInfo { amount: Amount::from_sat(30_000), expiry_blocks: 50 },  // 0 ppm (< 100)
			VtxoFeeInfo { amount: Amount::from_sat(50_000), expiry_blocks: 150 }, // 1,000 ppm
			VtxoFeeInfo { amount: Amount::from_sat(40_000), expiry_blocks: 600 }, // 2,000 ppm
		];

		let amount_to_send = Amount::from_sat(100_000);
		let fee = fees.calculate(&destination, amount_to_send, fee_rate, vtxos).unwrap();
		// We consume VTXOs in order until we have enough:
		// - First VTXO: 30,000 at 0 ppm -> fee = 30,000 * 0 / 1,000,000 = 0
		// - Second VTXO: 50,000 at 1,000 ppm -> fee = 50,000 * 1,000 / 1,000,000 = 50
		// - Third VTXO: Only need 20,000 at 2,000 ppm -> fee = 20,000 * 2,000 / 1,000,000 = 40
		// Total: base (200) + (0 + 50 + 40) + ((6 + 100) * 10) = 200 + 90 + 1,060 = 1,350
		assert_eq!(fee, Amount::from_sat(1_350));
	}

	#[test]
	fn test_offboard_fees_with_no_fee_rate() {
		let fees = OffboardFees {
			base_fee: Amount::from_sat(200),
			fixed_additional_vb: 100,
			ppm_expiry_table: vec![
				PpmExpiryFeeEntry { expiry_blocks_threshold: 1, ppm: PpmFeeRate(1_000) },
			],
		};

		let script_str = "6a0474657374"; // OP_RETURN, push 4 bytes with the string "test"
		let destination = ScriptBuf::from_hex(script_str)
			.expect("Failed to parse OP_RETURN script hex string");
		let fee_rate = FeeRate::from_sat_per_vb_unchecked(0);
		let vtxos = vec![
			VtxoFeeInfo { amount: Amount::from_sat(200_000), expiry_blocks: 50 },  // 1,000 ppm (> 1)
		];

		let amount_to_send = Amount::from_sat(100_000);
		let fee = fees.calculate(&destination, amount_to_send, fee_rate, vtxos).unwrap();
		// base (200) + ((100,000 * 1,000) / 1,000,000) + ((6 + 100) * 0) = 200 + 100 + 0 = 300
		assert_eq!(fee, Amount::from_sat(300));
	}

	#[test]
	fn test_offboard_fees_with_no_additional_vb() {
		let fees = OffboardFees {
			base_fee: Amount::from_sat(200),
			fixed_additional_vb: 0,
			ppm_expiry_table: vec![
				PpmExpiryFeeEntry { expiry_blocks_threshold: 1, ppm: PpmFeeRate(1_000) },
			],
		};

		let script_str = "6a0474657374"; // OP_RETURN, push 4 bytes with the string "test"
		let destination = ScriptBuf::from_hex(script_str)
			.expect("Failed to parse OP_RETURN script hex string");
		let fee_rate = FeeRate::from_sat_per_vb_unchecked(10);
		let vtxos = vec![
			VtxoFeeInfo { amount: Amount::from_sat(200_000), expiry_blocks: 50 },  // 1,000 ppm (> 1)
		];

		let amount_to_send = Amount::from_sat(100_000);
		let fee = fees.calculate(&destination, amount_to_send, fee_rate, vtxos).unwrap();
		// base (200) + ((100,000 * 1,000) / 1,000,000) + ((6 + 0) * 10) = 200 + 100 + 60 = 360
		assert_eq!(fee, Amount::from_sat(360));
	}

	#[test]
	fn test_refresh_fees_with_single_vtxo() {
		let fees = RefreshFees {
			base_fee: Amount::from_sat(150),
			ppm_expiry_table: vec![
				PpmExpiryFeeEntry { expiry_blocks_threshold: 200, ppm: PpmFeeRate(500) },
				PpmExpiryFeeEntry { expiry_blocks_threshold: 600, ppm: PpmFeeRate(1_500) },
			],
		};

		let amount = Amount::from_sat(200_000);

		// Test with expiry = 400 blocks (should use 500 ppm)
		let vtxo = VtxoFeeInfo { amount, expiry_blocks: 400 };
		let fee = fees.calculate(vec![vtxo]).unwrap();
		// base (150) + (200,000 * 500) / 1,000,000 = 150 + 100 = 250
		assert_eq!(fee, Amount::from_sat(250));

		// Test with expiry = 800 blocks (should use 1,500 ppm)
		let vtxo = VtxoFeeInfo { amount, expiry_blocks: 800 };
		let fee = fees.calculate(vec![vtxo]).unwrap();
		// base (150) + (200,000 * 1,500) / 1,000,000 = 150 + 300 = 450
		assert_eq!(fee, Amount::from_sat(450));
	}

	#[test]
	fn test_refresh_fees_with_multiple_vtxos() {
		let fees = RefreshFees {
			base_fee: Amount::from_sat(50),
			ppm_expiry_table: vec![
				PpmExpiryFeeEntry { expiry_blocks_threshold: 200, ppm: PpmFeeRate(500) },
				PpmExpiryFeeEntry { expiry_blocks_threshold: 600, ppm: PpmFeeRate(1_500) },
			],
		};

		// Test with multiple VTXOs
		let vtxos = vec![
			VtxoFeeInfo { amount: Amount::from_sat(70_000), expiry_blocks: 100 },  // 0 ppm (< 200)
			VtxoFeeInfo { amount: Amount::from_sat(100_000), expiry_blocks: 300 }, // 500 ppm
			VtxoFeeInfo { amount: Amount::from_sat(80_000), expiry_blocks: 700 },  // 1,500 ppm
		];

		let fee = fees.calculate(vtxos).unwrap();
		// We consume VTXOs in order until we have enough:
		// - First VTXO: 70,000 at 0 ppm -> fee = 70,000 * 0 / 1,000,000 = 0
		// - Second VTXO: 100,000 at 500 ppm -> fee = 100,000 * 500 / 1,000,000 = 50
		// - Third VTXO: 80,000 at 1,500 ppm -> fee = 80,000 * 1,500 / 1,000,000 = 120
		// Total: base (50) + 0 + 50 + 120 = 220
		assert_eq!(fee, Amount::from_sat(220));
	}

	#[test]
	fn test_lightning_receive_fees() {
		let fees = LightningReceiveFees {
			base_fee: Amount::from_sat(100),
			ppm: PpmFeeRate(2_000), // 0.2%
		};

		let amount = Amount::from_sat(10_000);
		let fee = fees.calculate(amount).unwrap();
		// base (100) + (10,000 * 2,000) / 1,000,000 = 100 + 20 = 120
		assert_eq!(fee, Amount::from_sat(120));
	}

	#[test]
	fn test_lightning_send_fees_with_single_vtxo() {
		let mut fees = LightningSendFees {
			min_fee: Amount::from_sat(10),
			base_fee: Amount::from_sat(75),
			ppm_expiry_table: vec![
				PpmExpiryFeeEntry { expiry_blocks_threshold: 50, ppm: PpmFeeRate(250) },
				PpmExpiryFeeEntry { expiry_blocks_threshold: 100, ppm: PpmFeeRate(750) },
			],
		};

		let amount = Amount::from_sat(1_000_000);

		// Test with expiry = 75 blocks (should use 250 ppm)
		let vtxo = VtxoFeeInfo { amount, expiry_blocks: 75 };
		let fee = fees.calculate(amount, vec![vtxo]).unwrap();
		// base (75) + (1,000,000 * 250) / 1,000,000 = 75 + 250 = 325
		assert_eq!(fee, Amount::from_sat(325));

		// Test with expiry = 150 blocks (should use 750 ppm)
		let vtxo = VtxoFeeInfo { amount, expiry_blocks: 150 };
		let fee = fees.calculate(amount, vec![vtxo]).unwrap();
		// base (75) + (1,000,000 * 750) / 1,000,000 = 75 + 750 = 825
		assert_eq!(fee, Amount::from_sat(825));

		// Test with 1,000 sats and min fee
		fees.min_fee = Amount::from_sat(330);
		let vtxo = VtxoFeeInfo { amount: Amount::from_sat(1_000), expiry_blocks: 150 };
		let fee = fees.calculate(amount, vec![vtxo]).unwrap();
		// base (75) + (1,000 * 750) / 1,000,000 = 75 + 0 = MAX(75, 330) = 330
		assert_eq!(fee, Amount::from_sat(330));
	}

	#[test]
	fn test_lightning_send_fees_with_multiple_vtxos() {
		let fees = LightningSendFees {
			min_fee: Amount::from_sat(10),
			base_fee: Amount::from_sat(25),
			ppm_expiry_table: vec![
				PpmExpiryFeeEntry { expiry_blocks_threshold: 50, ppm: PpmFeeRate(250) },
				PpmExpiryFeeEntry { expiry_blocks_threshold: 100, ppm: PpmFeeRate(750) },
				PpmExpiryFeeEntry { expiry_blocks_threshold: 200, ppm: PpmFeeRate(1_500) },
			],
		};

		// Test with multiple VTXOs where the total VTXO value exceeds the amount being paid.
		// The VTXOs total 1,500,000 sats but we're only sending 1,000,000.
		let vtxos = vec![
			VtxoFeeInfo { amount: Amount::from_sat(400_000), expiry_blocks: 75 },  // 250 ppm
			VtxoFeeInfo { amount: Amount::from_sat(500_000), expiry_blocks: 150 }, // 750 ppm
			VtxoFeeInfo { amount: Amount::from_sat(600_000), expiry_blocks: 250 }, // 1,500 ppm
		];

		let amount_to_send = Amount::from_sat(1_000_000);
		let fee = fees.calculate(amount_to_send, vtxos).unwrap();
		// We consume VTXOs in order until we have enough:
		// - First VTXO: 400,000 at 250 ppm -> fee = 400,000 * 250 / 1,000,000 = 100
		// - Second VTXO: 500,000 at 750 ppm -> fee = 500,000 * 750 / 1,000,000 = 375
		// - Third VTXO: only need 100,000 at 1,500 ppm -> fee = 100,000 * 1,500 / 1,000,000 = 150
		// Total: base (25) + 100 + 375 + 150 = 650
		assert_eq!(fee, Amount::from_sat(650));
	}
}

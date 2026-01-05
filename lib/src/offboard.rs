
use bitcoin::{Amount, FeeRate, Script, ScriptBuf, TxOut, Weight};

use bitcoin_ext::TxOutExt;


#[derive(Debug, Clone, PartialEq, Eq, Hash, thiserror::Error)]
#[error("invalid offboard request: {0}")]
pub struct InvalidOffboardRequestError(&'static str);

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
pub struct OffboardRequest {
	#[serde(with = "bitcoin_ext::serde::encodable")]
	pub script_pubkey: ScriptBuf,
	#[serde(rename = "amount_sat", with = "bitcoin::amount::serde::as_sat")]
	pub amount: Amount,
}

impl OffboardRequest {
	/// Calculate the fee we have to charge for adding an output
	/// with the given scriptPubkey to a transaction.
	///
	/// Returns `None` in the calculation overflows because of insane
	/// scriptPubkey or fee rate.
	pub fn calculate_fee(
		script_pubkey: &Script,
		fee_rate: FeeRate,
	) -> Option<Amount> {
		Some(fee_rate.checked_mul_by_weight(Weight::from_vb(script_pubkey.len() as u64)?)?)
	}

	/// Validate that the offboard has a valid script.
	pub fn validate(&self) -> Result<(), InvalidOffboardRequestError> {
		if self.to_txout().is_standard() {
			Ok(())
		} else {
			Err(InvalidOffboardRequestError("non-standard output"))
		}
	}

	/// Convert into a tx output.
	pub fn to_txout(&self) -> TxOut {
		TxOut {
			script_pubkey: self.script_pubkey.clone(),
			value: self.amount,
		}
	}

	/// Returns the fee charged for the user to make this offboard given the fee rate.
	///
	/// Returns `None` in the calculation overflows because of insane
	/// scriptPubkey or fee rate.
	pub fn fee(&self, fee_rate: FeeRate) -> Option<Amount> {
		Self::calculate_fee(&self.script_pubkey, fee_rate)
	}
}


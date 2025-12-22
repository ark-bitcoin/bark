
use bitcoin::{Amount, FeeRate, Script, ScriptBuf, TxOut, Weight};

use bitcoin_ext::{
	TxOutExt, P2PKH_DUST_VB, P2SH_DUST_VB, P2TR_DUST_VB, P2WPKH_DUST_VB, P2WSH_DUST_VB
};


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
	/// Returns an error if the output type is non-standard.
	pub fn calculate_fee(
		script_pubkey: &Script,
		fee_rate: FeeRate,
	) -> Result<Amount, InvalidOffboardRequestError> {
		// NB We calculate the required extra fee as the "dust" fee for the given feerate.
		// We take Bitcoin's dust amounts, which are calculated at 3 sat/vb, but then
		// calculated for the given feerate. For more on dust, see:
		// https://bitcoin.stackexchange.com/questions/10986/what-is-meant-by-bitcoin-dust

		let vb = if script_pubkey.is_p2pkh() {
			P2PKH_DUST_VB
		} else if script_pubkey.is_p2sh() {
			P2SH_DUST_VB
		} else if script_pubkey.is_p2wpkh() {
			P2WPKH_DUST_VB
		} else if script_pubkey.is_p2wsh() {
			P2WSH_DUST_VB
		} else if script_pubkey.is_p2tr() {
			P2TR_DUST_VB
		} else if script_pubkey.is_op_return() {
			if script_pubkey.len() > 83 {
				return Err(InvalidOffboardRequestError("OP_RETURN over 83 bytes"));
			} else {
				bitcoin::consensus::encode::VarInt(script_pubkey.len() as u64).size() as u64
					+ script_pubkey.len() as u64
					+ 8  // output amount
					// the input data (scriptSig and witness length fields included)
					+ 36 // input prevout
					+ 4  // sequence
					+ 1  // 0 length scriptsig
					+ 1  // 0 length witness
			}
		} else {
			return Err(InvalidOffboardRequestError("non-standard scriptPubkey"));
		};
		Ok(fee_rate * Weight::from_vb(vb).expect("no overflow"))
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
	pub fn fee(&self, fee_rate: FeeRate) -> Result<Amount, InvalidOffboardRequestError> {
		Ok(Self::calculate_fee(&self.script_pubkey, fee_rate)?)
	}
}


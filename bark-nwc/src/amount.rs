//! Conversions between NWC millisatoshis and bitcoin amounts.
//!
//! NIP-47 denominates every amount in millisatoshis, while bark works in whole
//! sats. Amounts that are not a whole number of sats are rounded the way the
//! lightning side rounds them, and for the same reason: up for what we pay, so
//! that we never underpay, and down for what we receive, so that we never ask
//! for more than the request named.

use bitcoin::Amount;
use bitcoin_ext::AmountExt;
use nostr::nips::nip47::{ErrorCode, NIP47Error};


#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AmountError {
	/// The amount rounds down to nothing, so there is no invoice to ask for.
	#[error("amount of {msat} msat is less than one sat")]
	BelowOneSat {
		msat: u64,
	},
}

/// The amount to pay a request denominated in `msat`.
///
/// Rounds up, like the lightning payment path, so that the sub-sat invoices
/// lightning allows are never underpaid.
pub fn pay_amount(msat: u64) -> Amount {
	Amount::from_msat_ceil(msat)
}

/// The amount to ask for in an invoice denominated in `msat`.
///
/// Rounds down, similar to what bark does on lightning side, so that we
/// never ask for more than the request named. An amount below one sat rounds
/// away entirely, which leaves nothing to ask for.
pub fn receive_amount(msat: u64) -> Result<Amount, AmountError> {
	let amount = Amount::from_msat_floor(msat);
	if amount == Amount::ZERO {
		return Err(AmountError::BelowOneSat { msat });
	}
	Ok(amount)
}

impl From<AmountError> for NIP47Error {
	fn from(e: AmountError) -> Self {
		// An amount too small for bark to represent is a standing limit, not a
		// transient failure, so it is reported like the other things we
		// structurally cannot do. No NIP-47 code says "amount too small", so
		// the message carries the detail.
		NIP47Error { code: ErrorCode::NotImplemented, message: e.to_string() }
	}
}


#[cfg(test)]
mod test {
	use super::*;

	#[test]
	fn whole_sats_are_unchanged_either_way() {
		for sat in [1, 21, 100_000, 2_100_000_000_000_000] {
			let msat = sat * 1000;
			assert_eq!(pay_amount(msat), Amount::from_sat(sat));
			assert_eq!(receive_amount(msat).unwrap(), Amount::from_sat(sat));
		}
	}

	/// Paying rounds up so that the 1 msat invoices lightning allows are paid
	/// in full rather than short.
	#[test]
	fn paying_rounds_up() {
		assert_eq!(pay_amount(1), Amount::from_sat(1));
		assert_eq!(pay_amount(1001), Amount::from_sat(2));
		assert_eq!(pay_amount(1999), Amount::from_sat(2));
	}

	#[test]
	fn receiving_rounds_down() {
		assert_eq!(receive_amount(1001).unwrap(), Amount::from_sat(1));
		assert_eq!(receive_amount(1999).unwrap(), Amount::from_sat(1));
	}

	/// The two directions round against us on the same amount, which is the
	/// point: neither underpay nor ask for more than was named.
	#[test]
	fn the_two_directions_round_opposite_ways() {
		assert_eq!(pay_amount(1500), Amount::from_sat(2));
		assert_eq!(receive_amount(1500).unwrap(), Amount::from_sat(1));
	}

	/// Rounding down leaves nothing to put in an invoice, and an invoice for
	/// zero is not something a payer can settle.
	#[test]
	fn an_amount_below_one_sat_cannot_be_received() {
		for msat in [0, 1, 999] {
			assert_eq!(receive_amount(msat), Err(AmountError::BelowOneSat { msat }));
		}
	}
}

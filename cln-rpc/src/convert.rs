
use crate::cln;

impl From<bitcoin::Amount> for cln::Amount {
	fn from(amount: bitcoin::Amount) -> cln::Amount {
		cln::Amount {
			msat: amount.to_sat() * 1000,
		}
	}
}


use ark::lightning::PaymentStatus;

use crate::cln;
use crate::listpays_pays::ListpaysPaysStatus;
use crate::listsendpays_payments::ListsendpaysPaymentsStatus;

impl From<ListpaysPaysStatus> for PaymentStatus {
	fn from(value: ListpaysPaysStatus) -> Self {
		match value {
			ListpaysPaysStatus::Complete => Self::Complete,
			ListpaysPaysStatus::Failed => Self::Failed,
			ListpaysPaysStatus::Pending => Self::Pending
		}
	}
}


impl From<ListsendpaysPaymentsStatus> for PaymentStatus {
	fn from(value: ListsendpaysPaymentsStatus) -> Self {
		match value {
			ListsendpaysPaymentsStatus::Complete => Self::Complete,
			ListsendpaysPaymentsStatus::Failed => Self::Failed,
			ListsendpaysPaymentsStatus::Pending => Self::Pending
		}
	}
}

impl From<bitcoin::Amount> for cln::Amount {
	fn from(amount: bitcoin::Amount) -> cln::Amount {
		cln::Amount {
			msat: amount.to_sat() * 1000,
		}
	}
}


use bitcoin::Amount;

use ark::lightning::PaymentStatus;

use crate::grpc;
use crate::grpc::listpays_pays::ListpaysPaysStatus;
use crate::grpc::listsendpays_payments::ListsendpaysPaymentsStatus;

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

impl From<Amount> for grpc::Amount {
	fn from(amount: Amount) -> grpc::Amount {
		grpc::Amount {
			msat: amount.to_sat() * 1000,
		}
	}
}

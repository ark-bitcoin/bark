use ark::lightning::PaymentStatus;

impl From<crate::PaymentStatus> for PaymentStatus {
	fn from(value: crate::PaymentStatus) -> Self {
		match value {
			crate::PaymentStatus::Pending => Self::Pending,
			crate::PaymentStatus::Complete => Self::Complete,
			crate::PaymentStatus::Failed => Self::Failed
		}
	}
}

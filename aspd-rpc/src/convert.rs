
impl From<ark::lightning::PaymentStatus> for crate::PaymentStatus {
	fn from(value: ark::lightning::PaymentStatus) -> Self {
		match value {
			ark::lightning::PaymentStatus::Complete => crate::PaymentStatus::Complete,
			ark::lightning::PaymentStatus::Pending => crate::PaymentStatus::Pending,
			ark::lightning::PaymentStatus::Failed => crate::PaymentStatus::Failed,
		}
	}
}

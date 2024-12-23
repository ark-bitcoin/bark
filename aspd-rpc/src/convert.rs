use crate::rpc;

impl From<ark::lightning::PaymentStatus> for rpc::PaymentStatus {
	fn from(value: ark::lightning::PaymentStatus) -> Self {
		match value {
			ark::lightning::PaymentStatus::Complete => rpc::PaymentStatus::Complete,
			ark::lightning::PaymentStatus::Pending => rpc::PaymentStatus::Pending,
			ark::lightning::PaymentStatus::Failed => rpc::PaymentStatus::Failed,
		}
	}
}
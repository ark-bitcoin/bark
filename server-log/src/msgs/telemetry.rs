use ark::rounds::RoundSeq;


/// Ark protocol fee recorded at the success boundary of an op.
/// `net_fee_sat` is what the server keeps (`user_fee - routing_fee`).
/// `routing_fee_sat` is `Some` only on ops with a lightning routing
/// component (`lightning_send`); other ops have no such split and leave it
/// `None`, in which case `net_fee_sat == user_fee_sat`. `round_seq` is set
/// for round-finalised ops.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArkFeeRecorded {
	pub op_type: String,
	pub net_fee_sat: u64,
	pub user_fee_sat: u64,
	pub routing_fee_sat: Option<u64>,
	pub round_seq: Option<RoundSeq>,
}
impl_slog!(ArkFeeRecorded, DEBUG, "ark protocol fee recorded");

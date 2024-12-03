
use ark::VtxoId;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoundStarted {
	pub round_id: u64,
}
impl_slog!(RoundStarted, Info, "Round started");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MissingForfeits {
	pub round_id: u64,
	pub input: VtxoId,
}
impl_slog!(MissingForfeits, Trace, "Missing forfeit sigs for input vtxo");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestartMissingForfeits {
	pub round_id: u64,
}
impl_slog!(RestartMissingForfeits, Debug, "Restarting round because of missing forfeits");

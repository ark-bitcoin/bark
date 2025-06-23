
use ark::VtxoId;


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArkoorInputAlreadyInFlux {
	pub vtxo: VtxoId,
}
impl_slog!(ArkoorInputAlreadyInFlux, Trace, "user attempted to arkoor spend vtxo already in flux");


use ark::VtxoId;


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArkoorInputAlreadyInFlux {
	pub vtxo: VtxoId,
}
impl_slog!(ArkoorInputAlreadyInFlux, TRACE, "user attempted to arkoor spend vtxo already in flux");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArkoorCosign {
	pub input_ids: Vec<VtxoId>,
	pub output_ids: Vec<VtxoId>,
}
impl_slog!(ArkoorCosign, TRACE, "server cosigned arkoor for inputs");

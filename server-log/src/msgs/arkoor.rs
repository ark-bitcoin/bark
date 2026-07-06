
use bitcoin::Amount;

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
	#[serde(with = "bitcoin::amount::serde::as_sat")]
	pub amount: Amount,
}
impl_slog!(ArkoorCosign, DEBUG, "server cosigned arkoor for inputs");

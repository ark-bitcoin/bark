
use ark::VtxoId;


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VtxosAddedToFlux {
	pub vtxos: Vec<VtxoId>,
}
impl_slog!(VtxosAddedToFlux, TRACE, "vtxos added to flux");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VtxosRemovedFromFlux {
	pub vtxos: Vec<VtxoId>,
}
impl_slog!(VtxosRemovedFromFlux, TRACE, "vtxos removed from flux");

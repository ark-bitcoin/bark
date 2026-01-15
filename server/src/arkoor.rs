use anyhow::Context;

use ark::arkoor::checkpoint::state::{ServerCanCosign, ServerSigned};
use ark::vtxo::{VtxoId, VtxoPolicy};
use ark::arkoor::checkpointed_package::{PackageCosignRequest, PackageCosignResponse, CheckpointedPackageBuilder};
use ark::arkoor::checkpoint::CosignRequest;

use crate::Server;

impl Server {
	pub async fn cosign_oor_with_builder(
		&self,
		builder: CheckpointedPackageBuilder<ServerCanCosign>,
	) -> anyhow::Result<CheckpointedPackageBuilder<ServerSigned>> {
		let vtxo_guard = self.vtxos_in_flux.try_lock(builder.input_ids()).map_err(|e| {
			slog!(ArkoorInputAlreadyInFlux, vtxo: e.id);
			badarg_err!("some VTXO is already locked by another process: {}", e.id)
		})?;

		// Check if the vtxo is not exited
		self.check_vtxos_not_exited(builder.input_ids()).await?;

		// We are going to compute all vtxos and spend-info
		// and mark it into the database
		let new_output_vtxos = builder.build_unsigned_vtxos();
		let new_internal_vtxos = builder.build_unsigned_internal_vtxos();
		let spend_info = builder.spend_info();

		// We are going to mark the update in the database
		self.db.upsert_vtxos_and_mark_spends(
			new_output_vtxos.chain(new_internal_vtxos),
			spend_info,
		).await?;
		drop(vtxo_guard);

		// Only now it's safe to sign
		let builder = builder.server_cosign(*self.server_key.leak_ref())
			.context("failed to sign arkoor")?;
		Ok(builder)
	}

	pub async fn cosign_oor(
		&self,
		request: PackageCosignRequest<VtxoId>
	) -> anyhow::Result<PackageCosignResponse> {
		let input_vtxo_ids = request.inputs().cloned().collect::<Vec<VtxoId>>();
		let input_vtxos = self.db.get_vtxos_by_id(&input_vtxo_ids).await?
			.into_iter().map(|v| v.vtxo).collect::<Vec<_>>();

		// Validate the inputs
		for vtxo in &input_vtxos {
			match vtxo.policy() {
				VtxoPolicy::Pubkey( ..) => {},
				VtxoPolicy::Checkpoint( ..) => bail!("checkpoint vtxo not supported"),
				VtxoPolicy::ServerHtlcSend( ..) => bail!("server htlc send vtxo not supported"),
				VtxoPolicy::ServerHtlcRecv( ..) => bail!("server htlc recv vtxo not supported"),
			}
		}

		// TODO: Check if the client actually owns the VTXO
		// We don't want users to be able to lock other
		// peoples VTXOs

		// We will maske the old value
		let request_parts = request.requests.into_iter().zip(input_vtxos)
			.map(|(request, vtxo)| CosignRequest {
				input: vtxo,
				user_pub_nonces: request.user_pub_nonces,
				outputs: request.outputs,
				isolated_outputs: request.isolated_outputs,
				use_checkpoint: request.use_checkpoint,
			})
			.collect::<Vec<_>>();
		let request = PackageCosignRequest { requests: request_parts };

		let builder = CheckpointedPackageBuilder::from_cosign_requests(request)
			.context("Invalid arkoor request")?;

		let builder = self.cosign_oor_with_builder(builder).await?;

		slog!(ArkoorCosign, input_ids: input_vtxo_ids,
			output_ids: builder.build_unsigned_vtxos().into_iter().map(|v| v.id()).collect(),
		);

		Ok(builder.cosign_response())
	}
}


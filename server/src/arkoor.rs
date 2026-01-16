use anyhow::Context;

use ark::vtxo::{VtxoId, VtxoPolicy};
use ark::arkoor::checkpointed_package::{PackageCosignRequest, PackageCosignResponse, CheckpointedPackageBuilder};
use ark::arkoor::checkpoint::CosignRequest;

use crate::Server;

impl Server {

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

		// Check if the vtxo is not exited
		self.check_vtxos_not_exited(&input_vtxo_ids).await?;

		// TODO: Check if the client actually owns the VTXO
		// We don't want users to be able to lock other
		// peoples VTXOs

		// Mark the vtxo as in-flux
		let guard = self.vtxos_in_flux.try_lock(&input_vtxo_ids)
			.context("some VTXO is already locked by another process")?;

		// Convert the PackageCosignRequest<VtxoId> into PackageCosignRequest<Vtxo>
		// We will maske the old value
		let request_parts = request.requests.into_iter().zip(input_vtxos)
			.map(|(request, vtxo)| CosignRequest {
				input: vtxo,
				user_pub_nonces: request.user_pub_nonces,
				outputs: request.outputs,
				dust_outputs: request.dust_outputs,
				use_checkpoint: request.use_checkpoint,
			})
			.collect::<Vec<_>>();
		let request = PackageCosignRequest { requests: request_parts };


		// Construct the builder and compute all transaction data
		let builder = CheckpointedPackageBuilder::from_cosign_requests(request)
			.context("invalid arkoor request")?;


		// We are going to compute all vtxos and spend-info
		// and mark it into the database
		let new_output_vtxos = builder.build_unsigned_vtxos();
		let new_checkpoint_vtxos = builder.build_unsigned_checkpoint_vtxos();
		let spend_info = builder.spend_info();

		// We are going to mark the update in the database
		self.db.upsert_vtxos_and_mark_spends(
			new_output_vtxos.chain(new_checkpoint_vtxos),
			spend_info
		).await?;


		// Only now it's safe to sign
		let builder = builder.server_cosign(*self.server_key.leak_ref())
			.context("Failed to sign")?;

		drop(guard);

		Ok(builder.cosign_response())
	}
}


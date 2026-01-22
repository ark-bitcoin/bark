use anyhow::Context;

use ark::util::IteratorExt;
use ark::{Vtxo, VtxoId, VtxoPolicy};
use ark::arkoor::state::{ServerCanCosign, ServerSigned};
use ark::arkoor::package::{
	ArkoorPackageCosignRequest, ArkoorPackageCosignResponse, ArkoorPackageBuilder,
};
use bitcoin_ext::P2TR_DUST;

use crate::database::VirtualTransaction;
use crate::error::ContextExt;
use crate::Server;

pub(crate) struct ArkoorCosignRequestValidationParams {
	/// whether checkpoints should be used
	pub use_checkpoints: bool,
	/// maximum number of outputs from a single input
	pub max_outputs_per_input: usize,
	/// Don't allow mixing dust and non-dust outputs when not necessary
	pub disallow_unnecessary_dust: bool,
}

impl Server {
	/// Validate the cosign request for the given validation params
	///
	/// Returns the arkoor builder that the server can then sign from.
	pub(crate) fn validate_cosign_request(
		&self,
		params: ArkoorCosignRequestValidationParams,
		cosign_req: ArkoorPackageCosignRequest<Vtxo>,
	) -> anyhow::Result<ArkoorPackageBuilder<ServerCanCosign>> {
		// this we can check before creating the builder

		if cosign_req.requests.is_empty() {
			bail!("empty request");
		}

		let use_checkpoint = cosign_req.requests.iter()
			.all_same(|r| r.use_checkpoint)
			.context("not all requests have the same use_checkpoints value")?;
		if params.use_checkpoints && !use_checkpoint {
			bail!("should use arkoor checkpoints");
		} else if !params.use_checkpoints && use_checkpoint {
			bail!("should not use arkoor checkpoints");
		}

		// then we create the builder
		let ret = ArkoorPackageBuilder::from_cosign_request(cosign_req)
			.context("error creating ArkoorPackageBuilder from ArkoorCosignRequest")?;
		for (idx, b) in ret.builders.iter().enumerate() {
			let nb_outputs = b.all_outputs().count();
			if nb_outputs > params.max_outputs_per_input {
				bail!("too many outputs for input {} (#{}) ({} > {})",
					b.input().id(), idx, nb_outputs, params.max_outputs_per_input,
				);
			}

			if params.disallow_unnecessary_dust {
				let non_dust_limit = P2TR_DUST * 2;
				if b.normal_outputs().iter().any(|o| o.total_amount < P2TR_DUST)
					&& b.normal_outputs().iter().any(|o| o.total_amount >= non_dust_limit)
				{
					bail!(
						"invalid mix of dust and non-dust outputs for input {} (#{})",
						b.input().id(), idx,
					);
				}

				if b.isolated_outputs().iter().any(|o| o.total_amount < P2TR_DUST)
					&& b.isolated_outputs().iter().any(|o| o.total_amount >= non_dust_limit)
				{
					bail!(
						"invalid mix of dust and non-dust isolated outputs for input {} (#{})",
						b.input().id(), idx,
					);
				}
			}
		}

		Ok(ret)
	}

	pub async fn cosign_oor_with_builder(
		&self,
		builder: ArkoorPackageBuilder<ServerCanCosign>,
	) -> anyhow::Result<ArkoorPackageBuilder<ServerSigned>> {
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

		// Create VirtualTransaction objects for virtual txs
		let virtual_txs = builder.virtual_transactions()
			.map(|txid| VirtualTransaction::new_unsigned(txid));

		// We are going to mark the update in the database
		self.db.update_virtual_transaction_tree(
			virtual_txs,
			new_output_vtxos.chain(new_internal_vtxos),
			spend_info,
		).await?;
		drop(vtxo_guard);

		// Only now it's safe to sign
		let builder = builder.server_cosign(self.server_key.leak_ref())
			.context("failed to sign arkoor")?;
		Ok(builder)
	}

	pub async fn cosign_oor(
		&self,
		request: ArkoorPackageCosignRequest<VtxoId>
	) -> anyhow::Result<ArkoorPackageCosignResponse> {
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

		let request = request.set_vtxos(input_vtxos)?;

		let validation = ArkoorCosignRequestValidationParams {
			use_checkpoints: true,
			max_outputs_per_input: self.config.max_arkoor_fanout,
			disallow_unnecessary_dust: true,
		};
		let builder = self.validate_cosign_request(validation, request)
			.badarg("invalid cosign request")?;

		let builder = self.cosign_oor_with_builder(builder).await?;

		slog!(ArkoorCosign, input_ids: input_vtxo_ids,
			output_ids: builder.build_unsigned_vtxos().into_iter().map(|v| v.id()).collect(),
		);

		Ok(builder.cosign_response())
	}
}


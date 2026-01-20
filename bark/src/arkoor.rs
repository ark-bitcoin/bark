use anyhow::Context;
use bitcoin::Amount;
use bitcoin::hex::DisplayHex;
use bitcoin::secp256k1::PublicKey;
use log::{info, error};

use ark::{VtxoPolicy, ProtocolEncoding};
use ark::arkoor::ArkoorDestination;
use ark::arkoor::package::{ArkoorPackageBuilder, ArkoorPackageCosignResponse};
use ark::vtxo::{Vtxo, VtxoId, VtxoPolicyKind};
use server_rpc::protos;

use crate::subsystem::Subsystem;
use crate::{ArkoorMovement, VtxoDelivery, MovementUpdate, Wallet};
use crate::movement::MovementDestination;
use crate::movement::manager::OnDropStatus;

/// The result of creating an arkoor transaction
pub struct ArkoorCreateResult {
	pub inputs: Vec<VtxoId>,
	pub created: Vec<Vtxo>,
	pub change: Vec<Vtxo>,
}

impl Wallet {
	/// Validate if we can send arkoor payments to the given [ark::Address], for example an error
	/// will be returned if the given [ark::Address] belongs to a different server (see
	/// [ark::address::ArkId]).
	pub async fn validate_arkoor_address(&self, address: &ark::Address) -> anyhow::Result<()> {
		let srv = self.require_server()?;

		if !address.ark_id().is_for_server(srv.ark_info().await?.server_pubkey) {
			bail!("Ark address is for different server");
		}

		// Not all policies are supported for sending arkoor
		match address.policy().policy_type() {
			VtxoPolicyKind::Pubkey => {},
			VtxoPolicyKind::Checkpoint | VtxoPolicyKind::ServerHtlcRecv | VtxoPolicyKind::ServerHtlcSend => {
				bail!("VTXO policy in address cannot be used for arkoor payment: {}",
					address.policy().policy_type(),
				);
			}
		}

		if address.delivery().is_empty() {
			bail!("No VTXO delivery mechanism provided in address");
		}
		// We first see if we know any of the deliveries, if not, we will log
		// the unknown onces.
		// We do this in two parts because we shouldn't log unknown ones if there is one known.
		if !address.delivery().iter().any(|d| !d.is_unknown()) {
			for d in address.delivery() {
				if let VtxoDelivery::Unknown { delivery_type, data } = d {
					info!("Unknown delivery in address: type={:#x}, data={}",
						delivery_type, data.as_hex(),
					);
				}
			}
		}

		Ok(())
	}

	pub(crate) async fn create_checkpointed_arkoor(
		&self,
		arkoor_dest: ArkoorDestination,
		change_pubkey: PublicKey,
	) -> anyhow::Result<ArkoorCreateResult> {
		if arkoor_dest.policy.user_pubkey() == change_pubkey {
			bail!("Cannot create arkoor to same address as change");
		}

		// Find vtxos to cover
		let mut srv = self.require_server()?;
		let inputs = self.select_vtxos_to_cover(arkoor_dest.total_amount).await?;
		let input_ids = inputs.iter().map(|v| v.id()).collect();

		let mut user_keypairs = vec![];
		for vtxo in &inputs {
			user_keypairs.push(self.get_vtxo_key(vtxo).await?);
		}

		let builder = ArkoorPackageBuilder::new_single_output_with_checkpoints(
			inputs.iter().map(|v| &v.vtxo).cloned(),
			arkoor_dest.clone(),
			VtxoPolicy::new_pubkey(change_pubkey),
		)
			.context("Failed to construct arkoor package")?
			.generate_user_nonces(&user_keypairs)
			.context("invalid nb of keypairs")?;

		let cosign_request = protos::ArkoorPackageCosignRequest::from(
			builder.cosign_request().convert_vtxo(|vtxo| vtxo.id()),
		);

		let response = srv.client.request_arkoor_cosign(cosign_request).await
			.context("server failed to cosign arkoor")?
			.into_inner();

		let cosign_responses = ArkoorPackageCosignResponse::try_from(response)
			.context("Failed to parse cosign response from server")?;

		let vtxos = builder
			.user_cosign(&user_keypairs, cosign_responses)
			.context("Failed to cosign vtxos")?
			.build_signed_vtxos();

		// divide between change and destination
		let (dest, change) = vtxos.into_iter()
			.partition::<Vec<_>, _>(|v| *v.policy() == arkoor_dest.policy);

		Ok(ArkoorCreateResult {
			inputs: input_ids,
			created: dest,
			change: change,
		})
	}

	/// Makes an out-of-round payment to the given [ark::Address]. This does not require waiting for
	/// a round, so it should be relatively instantaneous.
	///
	/// If the [Wallet] doesn't contain a VTXO larger than the given [Amount], multiple payments
	/// will be chained together, resulting in the recipient receiving multiple VTXOs.
	///
	/// Note that a change [Vtxo] may be created as a result of this call. With each payment these
	/// will become more uneconomical to unilaterally exit, so you should eventually refresh them
	/// with [Wallet::refresh_vtxos] or periodically call [Wallet::maintenance_refresh].
	pub async fn send_arkoor_payment(
		&self,
		destination: &ark::Address,
		amount: Amount,
	) -> anyhow::Result<Vec<Vtxo>> {
		let mut srv = self.require_server()?;

		self.validate_arkoor_address(&destination).await
			.context("address validation failed")?;

		let negative_amount = -amount.to_signed().context("Amount out-of-range")?;

		let change_pubkey = self.derive_store_next_keypair().await
			.context("Failed to create change keypair")?.0;

		let dest = ArkoorDestination { total_amount: amount, policy: destination.policy().clone() };
		let arkoor = self.create_checkpointed_arkoor(
			dest.clone(),
			change_pubkey.public_key(),
		).await.context("failed to create arkoor transaction")?;

		let mut movement = self.movements.new_guarded_movement_with_update(
			Subsystem::ARKOOR,
			ArkoorMovement::Send.to_string(),
			OnDropStatus::Failed,
			MovementUpdate::new()
				.intended_and_effective_balance(negative_amount)
				.consumed_vtxos(&arkoor.inputs)
				.sent_to([MovementDestination::ark(destination.clone(), amount)])
		).await?;

		let req = protos::ArkoorPackage {
			arkoors: arkoor.created.iter().map(|v| protos::ArkoorVtxo {
				pubkey: dest.policy.user_pubkey().serialize().to_vec(),
				vtxo: v.serialize().to_vec(),
			}).collect(),
		};

		#[allow(deprecated)]
		if let Err(e) = srv.client.post_arkoor_package_mailbox(req).await {
			error!("Failed to post the arkoor vtxo to the recipients mailbox: '{:#}'", e);
			//NB we will continue to at least not lose our own change
		}
		self.mark_vtxos_as_spent(&arkoor.inputs).await?;
		if !arkoor.change.is_empty() {
			self.store_spendable_vtxos(&arkoor.change).await?;
			movement.apply_update(MovementUpdate::new().produced_vtxos(arkoor.change)).await?;
		}
		movement.success().await?;
		Ok(arkoor.created)
	}
}

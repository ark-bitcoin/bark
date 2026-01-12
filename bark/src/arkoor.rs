use anyhow::Context;
use bitcoin::Amount;
use bitcoin::hex::DisplayHex;
use bitcoin::secp256k1::PublicKey;
use log::{info, error};

use ark::{VtxoRequest, ProtocolEncoding};
use ark::arkoor::checkpointed_package::{CheckpointedPackageBuilder, PackageCosignResponse};
use ark::vtxo::{Vtxo, VtxoId, VtxoPolicyKind};
use bitcoin_ext::P2TR_DUST;
use server_rpc::protos;

use crate::subsystem::Subsystem;
use crate::{ArkoorMovement, VtxoDelivery, MovementUpdate, Wallet};
use crate::movement::MovementDestination;
use crate::movement::manager::OnDropStatus;

/// The result of creating an arkoor transaction
pub struct ArkoorCreateResult {
	input: Vec<VtxoId>,
	created: Vec<Vtxo>,
	change: Option<Vtxo>,
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

	async fn create_checkpointed_arkoor(
		&self, vtxo_request: VtxoRequest, change_pubkey: PublicKey
	) -> anyhow::Result<ArkoorCreateResult> {
		if vtxo_request.policy.user_pubkey() == change_pubkey {
			bail!("Cannot create arkoor to same address as change");
		}

		// Find vtxos to cover
		let mut srv = self.require_server()?;
		let inputs: Vec<Vtxo> = self.select_vtxos_to_cover(vtxo_request.amount).await?;
		let input_ids: Vec<VtxoId> = inputs.iter().map(|v| v.id()).collect();

		let mut user_keypairs = vec![];
		for vtxo in inputs.iter() {
			user_keypairs.push(self.get_vtxo_key(&vtxo).await?);
		}

		let builder = CheckpointedPackageBuilder::new(inputs.clone(), vtxo_request, change_pubkey)
			.context("Failed to construct arkoor package")?
			.generate_user_nonces(&user_keypairs)
			.context("invalid nb of keypairs")?;

		let cosign_request = protos::CheckpointedPackageCosignRequest::from(
			builder.cosign_requests().convert_vtxo(|vtxo| vtxo.id()));

		let response = srv.client.checkpointed_cosign_oor(cosign_request).await
			.context("server failed to cosign arkoor")?
			.into_inner();

		let cosign_responses = PackageCosignResponse::try_from(response)
			.context("Failed to parse cosign response from server")?;

		let vtxos = builder
			.user_cosign(&user_keypairs, cosign_responses)
			.context("Failed to cosign vtxos")?
			.build_signed_vtxos();

		// See if their is a change vtxo
		if vtxos.last().expect("At least one vtxo").user_pubkey() == change_pubkey {
			let nb_vtxos = vtxos.len();
			let change = vtxos.last().cloned();
			Ok(ArkoorCreateResult {
				input: input_ids,
				// The last one is change
				created: vtxos.into_iter().take(nb_vtxos.saturating_sub(1)).collect::<Vec<_>>(),
				change: change,
			})
		} else {
			Ok(ArkoorCreateResult {
				input: input_ids,
				created: vtxos,
				change: None,
			})
		}
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
		if amount < P2TR_DUST {
			bail!("Sent amount must be at least {}", P2TR_DUST);
		}

		let change_pubkey = self.derive_store_next_keypair().await
			.context("Failed to create change keypair")?.0;

		let request = VtxoRequest { amount, policy: destination.policy().clone() };
		let arkoor = self.create_checkpointed_arkoor(request.clone(), change_pubkey.public_key())
			.await
			.context("Failed to create checkpointed transactions")?;

		let mut movement = self.movements.new_guarded_movement_with_update(
			Subsystem::ARKOOR,
			ArkoorMovement::Send.to_string(),
			OnDropStatus::Failed,
			MovementUpdate::new()
				.intended_and_effective_balance(negative_amount)
				.consumed_vtxos(&arkoor.input)
				.sent_to([MovementDestination::ark(destination.clone(), amount)])
		).await?;

		let req = protos::ArkoorPackage {
			arkoors: arkoor.created.iter().map(|v| protos::ArkoorVtxo {
				pubkey: request.policy.user_pubkey().serialize().to_vec(),
				vtxo: v.serialize().to_vec(),
			}).collect(),
		};

		#[allow(deprecated)]
		if let Err(e) = srv.client.post_arkoor_package_mailbox(req).await {
			error!("Failed to post the arkoor vtxo to the recipients mailbox: '{:#}'", e);
			//NB we will continue to at least not lose our own change
		}
		self.mark_vtxos_as_spent(&arkoor.input).await?;
		if let Some(change) = arkoor.change {
			self.store_spendable_vtxos([&change]).await?;
			movement.apply_update(MovementUpdate::new().produced_vtxo(change)).await?;
		}
		movement.success().await?;
		Ok(arkoor.created)
	}
}

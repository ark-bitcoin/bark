use anyhow::Context;
use bitcoin::{Amount, NetworkKind};
use bitcoin::hex::DisplayHex;
use bitcoin::secp256k1::Keypair;
use log::info;

use ark::VtxoPolicy;
use ark::arkoor::ArkoorDestination;
use ark::arkoor::package::{ArkoorPackageBuilder, ArkoorPackageCosignResponse};
use ark::vtxo::{Full, Vtxo, VtxoId};
use server_rpc::protos;

use crate::{VtxoDelivery, Wallet, WalletVtxo};
use crate::actions::DriveMode;
use crate::actions::arkoor_send::start_arkoor_send;

/// The result of creating an arkoor transaction
pub struct ArkoorCreateResult {
	pub inputs: Vec<VtxoId>,
	pub created: Vec<Vtxo<Full>>,
	pub change: Vec<Vtxo<Full>>,
}

/// Error returned by [`Wallet::create_checkpointed_arkoor_with_vtxos`].
///
/// The cosign RPC failure is kept as a typed [`tonic::Status`] rather
/// than flattened into `anyhow`, so a caller driving this as a wallet
/// action can route a genuine server rejection to its `on_rejection`
/// path (via `AdvanceError::is_server_rejection`) instead of retrying a
/// doomed request forever. Every other failure is opaque `Other`.
#[derive(Debug, thiserror::Error)]
pub enum ArkoorCreateError {
	/// The `request_arkoor_cosign` RPC failed. May be a rejection
	/// (`InvalidArgument`/`NotFound`) or a transient error; the caller
	/// classifies it via the status code.
	#[error("server failed to cosign arkoor: {0}")]
	Cosign(#[source] tonic::Status),
	#[error(transparent)]
	Other(#[from] anyhow::Error),
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ArkoorAddressError {
	#[error("Ark address is for different network")]
	NetworkMismatch,
	#[error("Ark address is for different server")]
	ServerMismatch,
	#[error("VTXO policy in address cannot be used for arkoor payment: {0:?}")]
	PolicyNotSupported(VtxoPolicy),
	#[error("No VTXO delivery mechanism provided in address")]
	NoDeliveryMechanism,
	#[error("Unknown delivery mechanism: {0}")]
	UnknownDeliveryMechanism(String),
	#[error("Other error: {0}")]
	Other(String),
}

impl Wallet {
	/// Validate if we can send arkoor payments to the given [ark::Address], for example an error
	/// will be returned if the given [ark::Address] belongs to a different server (see
	/// [ark::address::ArkId]).
	pub async fn validate_arkoor_address(&self, address: &ark::Address) -> Result<(), ArkoorAddressError> {
		let network = self.network().await
			.map_err(|e| ArkoorAddressError::Other(e.to_string()))?;
		let (_, ark_info) = self.require_server().await
			.map_err(|e| ArkoorAddressError::Other(e.to_string()))?;

		let network_kind = NetworkKind::from(network);
		if address.is_testnet() == network_kind.is_mainnet() {
			return Err(ArkoorAddressError::NetworkMismatch);
		}

		if !address.ark_id().is_for_server(ark_info.server_pubkey) {
			return Err(ArkoorAddressError::ServerMismatch);
		}

		// Not all policies are supported for sending arkoor
		match address.policy() {
			VtxoPolicy::Pubkey(_) => {},
			VtxoPolicy::ServerHtlcRecv(_) | VtxoPolicy::ServerHtlcSend(_) => {
				return Err(ArkoorAddressError::PolicyNotSupported(address.policy().clone()));
			}
		}

		if address.delivery().is_empty() {
			return Err(ArkoorAddressError::NoDeliveryMechanism);
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

	/// Build, cosign and split an arkoor package using a caller-provided
	/// change keypair.
	///
	/// Reusing the same change keypair on a retry keeps the implied
	/// `spending_txid` stable, so the server's `check_spendable_for_oor`
	/// idempotency check accepts the retry rather than rejecting it as a
	/// conflicting double-spend.
	pub(crate) async fn create_checkpointed_arkoor_with_vtxos(
		&self,
		arkoor_dest: ArkoorDestination,
		inputs: impl IntoIterator<Item = WalletVtxo>,
		change_keypair: Keypair,
	) -> Result<ArkoorCreateResult, ArkoorCreateError> {
		let (mut srv, _) = self.require_server().await?;
		let input_ids = inputs.into_iter().map(|v| v.id()).collect::<Vec<_>>();

		// Hydrate the inputs to their full form: the arkoor builder needs
		// the genesis chain and the server registration call sends the
		// full bytes over the wire.
		let inputs = self.inner.db.get_full_vtxos(&input_ids).await
			.context("failed to hydrate arkoor input vtxos")?;

		// Pre-register the input chains so the post-cosign register call
		// for the outputs finds a signed chain anchor:
		// register_vtxo_transactions validates a vtxo against its anchor's
		// signed_tx in the DB, and boarded inputs sit unsigned in
		// virtual_transaction (see register_board) until a
		// register_vtxo_transactions call backfills them.
		self.register_vtxo_transactions_with_server(&inputs).await
			.context("failed to register arkoor input vtxo transactions with server")?;

		let change_pubkey = change_keypair.public_key();
		if arkoor_dest.policy.user_pubkey() == change_pubkey {
			return Err(anyhow!("Cannot create arkoor to same address as change").into());
		}

		let mut user_keypairs = vec![];
		for vtxo in &inputs {
			user_keypairs.push(self.get_vtxo_key(vtxo).await?);
		}

		let builder = ArkoorPackageBuilder::new_single_output_with_checkpoints(
			inputs.into_iter(),
			arkoor_dest.clone(),
			VtxoPolicy::new_pubkey(change_pubkey),
		)
			.context("Failed to construct arkoor package")?
			.generate_user_nonces(&user_keypairs)
			.context("invalid nb of keypairs")?;

		let cosign_request = protos::ArkoorPackageCosignRequest::from(
			builder.cosign_request(),
		);

		let response = srv.client.request_arkoor_cosign(cosign_request).await
			.map_err(ArkoorCreateError::Cosign)?
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
			change,
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
	) -> anyhow::Result<()> {
		let action = start_arkoor_send(self, destination.clone(), amount).await?;

		// Persist the action together with the input locks so the executor has
		// something to drive on restart; otherwise a crash between this point and
		// `drive_action` leaves vtxos locked under an action id that has no
		// checkpoint row.
		self.inner.db.upsert_wallet_action_checkpoint(&action.id, &action.clone().into()).await?;

		self.drive_action(action, DriveMode::UntilDone).await
	}
}

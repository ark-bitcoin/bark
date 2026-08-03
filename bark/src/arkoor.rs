use anyhow::Context;
use bitcoin::{Amount, NetworkKind};
use bitcoin::hex::DisplayHex;
use bitcoin::secp256k1::Keypair;
use log::{error, info, warn};

use ark::{ProtocolEncoding, VtxoPolicy};
use ark::arkoor::ArkoorDestination;
use ark::arkoor::package::{ArkoorPackageBuilder, ArkoorPackageCosignResponse};
use ark::vtxo::{Full, Vtxo, VtxoId};
use server_rpc::{protos, ServerConnection};

use crate::{VtxoDelivery, Wallet, WalletVtxo};
use crate::actions::DriveMode;
use crate::actions::arkoor_send::{ArkoorSend, start_arkoor_send};

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

/// Split a change amount into the piece amounts of the change destinations.
///
/// Change exceeding the payment is split in `split_factor` pieces
/// (see [crate::Config::change_vtxo_split_factor]) so that repeated payments
/// build a tree of change VTXOs rather than a chain. Pieces below the dust
/// threshold are fine here: [ark::arkoor::ArkoorBuilder] isolates them.
///
/// Retries reuse the pieces stored on the action, so this policy can
/// change between versions.
pub(crate) fn split_change_amount(change: Amount, pay: Amount, split_factor: u8) -> Vec<Amount> {
	if change == Amount::ZERO {
		return Vec::new();
	}
	let pieces = if change > pay { u64::from(split_factor.max(1)) } else { 1 };
	let base = change / pieces;
	let mut ret = vec![base; pieces as usize];
	*ret.last_mut().unwrap() = change - base * (pieces - 1);
	ret
}

/// Resolve the change outputs of an arkoor package from the pieces stored
/// on the action. `None` means the action was persisted by a pre-split
/// bark, which built a single whole change output.
fn resolve_change_pieces(
	stored: Option<Vec<Amount>>,
	change: Amount,
) -> anyhow::Result<Vec<Amount>> {
	match stored {
		Some(pieces) => {
			let sum = pieces.iter().copied().sum::<Amount>();
			ensure!(sum == change, "stored change pieces sum to {}, expected {}", sum, change);
			Ok(pieces)
		},
		None if change == Amount::ZERO => Ok(Vec::new()),
		None => Ok(vec![change]),
	}
}

/// Outcome of one [`post_arkoor_to_mailboxes`] pass.
pub(crate) enum DeliveryOutcome {
	/// At least one mailbox accepted the post.
	AnySucceeded,
	/// No mailbox accepted the post. `summary` describes why and is meant to
	/// be captured in a caller's park error for observability.
	AllFailed { summary: String },
}

/// Posts `vtxos` to every [`VtxoDelivery::ServerMailbox`] method found in
/// `delivery`, in order, skipping any other delivery variant. Mailbox posts
/// are idempotent on the server.
///
/// Any-success semantics: one accepted post is enough, since the recipient
/// only needs the signed chain to arrive once.
pub(crate) async fn post_arkoor_to_mailboxes(
	srv: &mut ServerConnection,
	delivery: &[VtxoDelivery],
	vtxos: impl IntoIterator<Item = impl AsRef<Vtxo<Full>>>,
) -> DeliveryOutcome {
	let serialized = vtxos.into_iter()
		.map(|v| v.as_ref().serialize().to_vec())
		.collect::<Vec<_>>();

	let mut any_succeeded = false;
	let mut failures: Vec<String> = Vec::new();
	for method in delivery {
		let VtxoDelivery::ServerMailbox { blinded_id } = method else { continue };
		let req = protos::mailbox_server::PostArkoorMessageRequest {
			blinded_id: blinded_id.as_ref().to_vec(),
			vtxos: serialized.clone(),
		};
		match srv.mailbox_client.post_arkoor_message(req).await {
			Ok(_) => any_succeeded = true,
			Err(e) => {
				let reason = format!("{:#}", e);
				error!("failed to post arkoor vtxos to mailbox: {}", reason);
				failures.push(reason);
			},
		}
	}

	if any_succeeded {
		return DeliveryOutcome::AnySucceeded;
	}
	let summary = if failures.is_empty() {
		"no mailbox delivery mechanism configured on destination".to_string()
	} else {
		format!("no delivery mechanism accepted the arkoor vtxos: {}", failures.join("; "))
	};
	DeliveryOutcome::AllFailed { summary }
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
			VtxoPolicy::ServerHtlcRecv_v0(_) | VtxoPolicy::ServerHtlcSend_v0(_)
				| VtxoPolicy::ServerHtlcRecv(_) | VtxoPolicy::ServerHtlcSend(_) =>
			{
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
		change_pieces: Option<Vec<Amount>>,
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

		let total_input = inputs.iter().map(|v| v.amount()).sum::<Amount>();
		let change_amount = total_input.checked_sub(arkoor_dest.total_amount)
			.ok_or_else(|| anyhow!("arkoor inputs ({}) don't cover destination ({})",
				total_input, arkoor_dest.total_amount,
			))?;

		let change_policy = VtxoPolicy::new_pubkey(change_pubkey);
		let mut outputs = vec![arkoor_dest.clone()];
		for piece in resolve_change_pieces(change_pieces, change_amount)? {
			outputs.push(ArkoorDestination {
				total_amount: piece,
				policy: change_policy.clone(),
			});
		}

		let builder = ArkoorPackageBuilder::new_with_checkpoints(inputs, outputs)
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

	/// Returns every in-progress arkoor send checkpoint.
	pub async fn pending_arkoor_sends(&self) -> anyhow::Result<Vec<ArkoorSend>> {
		Ok(self.inner.db.get_all_wallet_action_checkpoints().await?
			.into_iter()
			.filter_map(|cp| cp.into_arkoor_send())
			.collect())
	}

	/// Drives every pending arkoor send forward by one step or to
	/// completion if it's ready.
	pub async fn sync_pending_arkoor_sends(&self) -> anyhow::Result<()> {
		let pending = self.pending_arkoor_sends().await?;
		if pending.is_empty() {
			return Ok(());
		}
		info!("Syncing {} pending arkoor sends", pending.len());
		for send in pending {
			let id = send.id.clone();
			if let Err(e) = self.drive_action(send, DriveMode::UntilParkOrDone).await {
				warn!("Failed to sync arkoor send {}: {:#}", id, e);
			}
		}
		Ok(())
	}
}

#[cfg(test)]
mod test {
	use super::*;

	#[test]
	fn resolve_change_pieces_fallback_and_validation() {
		let change = Amount::from_sat(30_000);
		let pieces = vec![Amount::from_sat(10_000), Amount::from_sat(20_000)];

		// stored pieces are used as-is when they sum to the change
		assert_eq!(resolve_change_pieces(Some(pieces.clone()), change).unwrap(), pieces);

		// a sum mismatch is an error, not a silently different package
		assert!(resolve_change_pieces(Some(pieces), Amount::from_sat(30_001)).is_err());

		// no stored pieces (pre-split checkpoint) rebuilds a single whole output
		assert_eq!(resolve_change_pieces(None, change).unwrap(), vec![change]);
		assert_eq!(resolve_change_pieces(None, Amount::ZERO).unwrap(), Vec::<Amount>::new());
	}

	#[test]
	fn split_change_amount_pieces() {
		let pay = Amount::from_sat(10_000);

		for factor in 1..=3u8 {
			// zero change yields no pieces
			assert_eq!(split_change_amount(Amount::ZERO, pay, factor), Vec::<Amount>::new());

			// change at or below the payment stays whole
			for sats in [1, 5_000, 10_000] {
				let change = Amount::from_sat(sats);
				assert_eq!(split_change_amount(change, pay, factor), vec![change]);
			}

			// change above the payment splits into factor pieces that add back up
			for sats in [10_001, 123_457, 100_000_000] {
				let change = Amount::from_sat(sats);
				let pieces = split_change_amount(change, pay, factor);
				assert_eq!(pieces.len(), factor as usize);
				assert_eq!(pieces.iter().copied().sum::<Amount>(), change);
			}
		}
	}
}

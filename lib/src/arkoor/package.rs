use std::collections::HashMap;
use std::borrow::Borrow;
use std::iter;

use bitcoin::{Amount, Transaction};
use bitcoin::secp256k1::{Keypair, PublicKey};
use bitcoin_ext::P2TR_DUST;

use crate::{Vtxo, VtxoRequest, VtxoId, VtxoPolicy, musig, error::IncorrectSigningKeyError};
use super::{ArkoorError, ArkoorBuilder, ArkoorCosignResponse};
use super::{build_arkoor_vtxos, unsigned_arkoor_tx};


/// This type helps both the client and server with building multiple arkoor transactions
/// in a synchronized way. It's purely a functional type, initialized with
/// the parameters that will make up the arkoor package: the input vtxos to be spent
/// and the desired payment request with optional change.
///
/// The flow works as follows:
/// - sender uses the constructor to check the payment request for validity
/// - server uses the constructor to check the payment request for validity
/// - server uses [ArkoorPackageBuilder::server_cosign] to construct a vector of
///   [ArkoorCosignResponse] to send back to the sender
/// - sender passes the responses into [ArkoorPackageBuilder::build_vtxos] to construct
///   the signed resulting VTXOs and optional change VTXO
///
/// The package can handle multiple input VTXOs to fulfill a single payment request,
/// automatically creating change outputs when necessary.
pub struct ArkoorPackageBuilder<'a, T: Clone> {
	/// Each transition from one input VTXO to one or two output VTXOs
	pub arkoors: Vec<ArkoorBuilder<'a, T>>,
	spending_tx_by_input: HashMap<VtxoId, Transaction>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ArkoorPackageError {
	#[error("Payment has non-null change amount but no change pubkey provided")]
	MissingChangePk,
	#[error("Invalid length of cosignature response")]
	InvalidLength,
	#[error("No vtxo created")]
	MissingVtxo,
	#[error("Invalid spk for revocation")]
	InvalidRevocationSpk,
	#[error("Invalid length of user nonces")]
	InvalidUserNoncesLength,
	#[error("Htlc amount does not match invoice amount")]
	InvalidHtlcAmount,
	#[error("An error occurred while building arkoor: {0}")]
	ArkoorError(ArkoorError),
	#[error("Too many outputs")]
	TooManyOutputs,
	#[error("incorrect signing key provided")]
	Signing(#[from] IncorrectSigningKeyError),
}

impl<'a> ArkoorPackageBuilder<'a, VtxoRequest> {
	pub fn new<V: AsRef<Vtxo> + 'a>(
		inputs: impl IntoIterator<Item = &'a V>,
		user_nonces: &'a [musig::PublicNonce],
		vtxo_request: VtxoRequest,
		change_pubkey: Option<PublicKey>,
	) -> Result<Self, ArkoorPackageError> {
		let mut remaining_amount = vtxo_request.amount;
		let mut arkoors = vec![];
		let mut spending_tx_by_input = HashMap::new();

		for (idx, input) in inputs.into_iter().enumerate() {
			let user_nonce = user_nonces.get(idx).ok_or(ArkoorPackageError::InvalidUserNoncesLength)?;

			let change_amount = input.as_ref().amount().checked_sub(remaining_amount);
			let (output_amount, change) = if let Some(change_amount) = change_amount {
				// NB: If change amount is less than the dust amount, we don't add any change output
				let change = if change_amount < P2TR_DUST {
					None
				} else {
					Some(VtxoRequest {
						amount: change_amount,
						policy: VtxoPolicy::new_pubkey(change_pubkey.ok_or(ArkoorPackageError::MissingChangePk)?),
					})
				};

				(remaining_amount, change)
			} else {
				(input.as_ref().amount(), None)
			};

			let output = VtxoRequest {
				amount: output_amount,
				policy: vtxo_request.policy.clone(),
			};

			let pay_reqs = iter::once(output.clone()).chain(change).collect::<Vec<_>>();

			let arkoor = ArkoorBuilder::new(input.as_ref(), user_nonce, pay_reqs)
				.map_err(ArkoorPackageError::ArkoorError)?;

			spending_tx_by_input.insert(input.as_ref().id(), arkoor.unsigned_transaction());
			arkoors.push(arkoor);

			remaining_amount = remaining_amount - output_amount;
			if remaining_amount == Amount::ZERO {
				break;
			}
		}

		Ok(Self {
			arkoors,
			spending_tx_by_input,
		})
	}

	pub fn inputs(&self) -> Vec<&'a Vtxo> {
		self.arkoors.iter().map(|a| a.input).collect::<Vec<_>>()
	}

	pub fn spending_tx(&self, input_id: VtxoId) -> Option<&Transaction> {
		self.spending_tx_by_input.get(&input_id)
	}

	pub fn build_vtxos<'b>(
		self,
		sigs: impl IntoIterator<Item = &'a ArkoorCosignResponse>,
		keypairs: impl IntoIterator<Item = &'a Keypair>,
		sec_nonces: impl IntoIterator<Item = musig::SecretNonce>,
	) -> Result<(Vec<Vtxo>, Option<Vtxo>), ArkoorPackageError> {
		let mut sent_vtxos = vec![];
		let mut change_vtxo = None;

		let expected_len = self.arkoors.len();

		let iter = self.arkoors.into_iter().zip(sigs).zip(keypairs).zip(sec_nonces);
		for (((arkoor, cosign), keypair), sec_nonce) in iter {
			let vtxos = arkoor.build_vtxos(sec_nonce, keypair, cosign)?;

			// The first one is of the recipient, we will post it to their mailbox.
			let mut vtxo_iter = vtxos.into_iter();
			let user_vtxo = vtxo_iter.next().ok_or(ArkoorPackageError::MissingVtxo)?;
			sent_vtxos.push(user_vtxo);

			if let Some(vtxo) = vtxo_iter.next() {
				assert!(change_vtxo.replace(vtxo).is_none(), "change vtxo already set");
			}
		}

		if sent_vtxos.len() != expected_len {
			return Err(ArkoorPackageError::InvalidLength);
		}

		Ok((sent_vtxos, change_vtxo))
	}

	pub fn new_vtxos(&self) -> Vec<Vec<Vtxo>> {
		self.arkoors.iter().map(|arkoor| {
			let txouts = arkoor.txouts();
			let tx = unsigned_arkoor_tx(&arkoor.input, &txouts);
			build_arkoor_vtxos(&arkoor.input, &arkoor.outputs, &txouts, tx.compute_txid(), None) //TODO(stevenroose) signaature
		}).collect::<Vec<Vec<_>>>()
	}

	/// Used by the Ark server to cosign the arkoor request.
	pub fn server_cosign(&self, keypair: &Keypair) -> Vec<ArkoorCosignResponse> {
		let mut cosign = vec![];

		for arkoor in self.arkoors.iter() {
			cosign.push(arkoor.server_cosign(keypair));
		}

		cosign
	}

	pub fn verify_cosign_response<T: Borrow<ArkoorCosignResponse>>(
		&self,
		server_cosign: &[T],
	) -> bool {
		for (idx, builder) in self.arkoors.iter().enumerate() {
			if let Some(cosign) = server_cosign.get(idx) {
				if !builder.verify_cosign_response(cosign.borrow()) {
					return false;
				}
			} else {
				return false;
			}
		}
		true
	}
}


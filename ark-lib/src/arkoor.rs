

use std::borrow::{Borrow, Cow};
use std::collections::HashMap;
use std::iter;

use bitcoin::hex::DisplayHex;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, Txid, Weight, Witness};
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{schnorr, Keypair, PublicKey};
use bitcoin::sighash::{self, SighashCache, TapSighash, TapSighashType};

use bitcoin_ext::{fee, P2TR_DUST, TAPROOT_KEYSPEND_WEIGHT};

use crate::error::IncorrectSigningKeyError;
use crate::lightning::revocation_payment_request;
use crate::vtxo::VtxoSpkSpec;
use crate::{musig, VtxoRequest, Vtxo, VtxoId, VtxoSpec};
use crate::util::{self, Encodable, SECP};


#[derive(Debug, Clone, PartialEq, Eq, Hash, thiserror::Error)]
pub enum ArkoorError {
	#[error("output amount of {input} exceeds input amount of {output}")]
	Unbalanced {
		input: Amount,
		output: Amount,
	},
	#[error("arkoor output amounts cannot be below the p2tr dust threshold")]
	Dust,
	#[error("arkoor cannot have more than 2 outputs")]
	TooManyOutputs,
}

pub fn arkoor_sighash(input_vtxo: &Vtxo, arkoor_tx: &Transaction) -> TapSighash {
	let prev = input_vtxo.txout();
	let mut shc = SighashCache::new(arkoor_tx);

	shc.taproot_key_spend_signature_hash(
		0, &sighash::Prevouts::All(&[prev]), TapSighashType::Default,
	).expect("sighash error")
}

pub fn unsigned_arkoor_tx(input: &Vtxo, outputs: &[VtxoSpec]) -> Transaction {
	Transaction {
		version: bitcoin::transaction::Version(3),
		lock_time: bitcoin::absolute::LockTime::ZERO,
		input: vec![TxIn {
			previous_output: input.point(),
			script_sig: ScriptBuf::new(),
			sequence: Sequence::ZERO,
			witness: Witness::new(),
		}],
		output: outputs
			.into_iter()
			.map(VtxoSpec::txout)
			.chain([fee::fee_anchor()])
			.collect(),
	}
}

/// Inner utility method to construct the arkoor vtxos.
fn build_arkoor_vtxos(
	input: &Vtxo,
	outputs: &[VtxoSpec],
	arkoor_txid: Txid,
) -> Vec<ArkoorVtxo> {
	outputs.iter().enumerate().map(|(idx, _output)| {
		ArkoorVtxo {
			input: input.clone().into(),
			signature: None,
			output_specs: outputs.to_owned(),
			point: OutPoint::new(arkoor_txid, idx as u32)
		}
	}).collect()
}

/// Build oor tx and signs it
///
/// ## Panic
///
/// Will panic if inputs and signatures don't have the same length,
/// or if some input witnesses are not empty
pub fn signed_arkoor_tx(
	input: &Vtxo,
	signature: schnorr::Signature,
	outputs: &[VtxoSpec]
) -> Transaction {
	let mut tx = unsigned_arkoor_tx(input, outputs);
	util::fill_taproot_sigs(&mut tx, &[signature]);
	tx
}

/// Build the oor tx with signatures and verify it
///
/// If a pubkey is provided, it'll check that vtxo's output user pubkey match
/// it (later want to check it's derived from it)
pub fn verify_oor(vtxo: &ArkoorVtxo, pubkey: Option<PublicKey>) -> Result<(), String> {
	// TODO: we also need to check that inputs are valid (round tx broadcasted, not spent yet, etc...)

	let sig = vtxo.signature.ok_or(format!("unsigned vtxo"))?;
	let tx = signed_arkoor_tx(&vtxo.input, sig, &vtxo.output_specs);
	let sighash = arkoor_sighash(&vtxo.input, &tx);
	SECP.verify_schnorr(
		&sig,
		&sighash.into(),
		&vtxo.input.spec().taproot_pubkey(),
	).map_err(|e| format!("schnorr signature verification error: {}", e))?;

	if let Some(pubkey) = pubkey {
		//TODO: handle derived keys here
		assert_eq!(pubkey, vtxo.output_specs[vtxo.point.vout as usize].user_pubkey)
	}

	Ok(())
}


/// The cosignature details received from the Ark server.
#[derive(Debug)]
pub struct ArkoorCosignResponse {
	pub pub_nonce: musig::MusigPubNonce,
	pub partial_signature: musig::MusigPartialSignature,
}

/// This types helps both the client and server with building arkoor txs in
/// a synchronized way. It's purely a functional type, initialized with
/// the parameters that will make up the arkoor: the input vtxo to be spent
/// and the desired outputs.
///
/// The flow works as follows:
/// - sender uses the constructor to check the request for validity
/// - server uses the contructor to check the request for validity
/// - server uses [ArkoorBuilder::server_cosign] to construct a
///   [ArkoorCosignResponse] to send back to the sender
/// - sender passes the response into [ArkoorBuilder::build_vtxos] to construct
///   the signed resulting VTXOs
pub struct ArkoorBuilder<'a, T: Clone> {
	pub input: &'a Vtxo,
	pub user_nonce: &'a musig::MusigPubNonce,
	pub outputs: Cow<'a, [T]>,
}

impl<'a, T: Borrow<VtxoRequest> + Clone> ArkoorBuilder<'a, T> {
	/// Construct a generic arkoor builder for the given input and outputs.
	pub fn new(
		input: &'a Vtxo,
		user_nonce: &'a musig::MusigPubNonce,
		outputs: impl Into<Cow<'a, [T]>>,
	) -> Result<Self, ArkoorError> {
		let outputs = outputs.into();
		if outputs.iter().any(|o| o.borrow().amount < P2TR_DUST) {
			return Err(ArkoorError::Dust);
		}
		let output_amount = outputs.as_ref().iter().map(|o| o.borrow().amount).sum::<Amount>();
		if output_amount > input.amount() {
			return Err(ArkoorError::Unbalanced {
				input: input.amount(),
				output: output_amount,
			});
		}

		if outputs.len() > 2 {
			return Err(ArkoorError::TooManyOutputs);
		}

		Ok(Self {
			input,
			user_nonce,
			outputs,
		})
	}

	pub fn output_specs(&self) -> Vec<VtxoSpec> {
		self.outputs.iter().map(|o| VtxoSpec {
			user_pubkey: o.borrow().pubkey,
			amount: o.borrow().amount,
			expiry_height: self.input.expiry_height(),
			asp_pubkey: self.input.asp_pubkey(),
			exit_delta: self.input.exit_delta(),
			spk: o.borrow().spk,
		}).collect::<Vec<_>>()
	}

	pub fn unsigned_transaction(&self) -> Transaction {
		unsigned_arkoor_tx(&self.input, &self.output_specs())
	}

	pub fn sighash(&self) -> TapSighash {
		arkoor_sighash(&self.input, &self.unsigned_transaction())
	}

	pub fn total_weight(&self) -> Weight {
		let spend_weight = Weight::from_wu(TAPROOT_KEYSPEND_WEIGHT as u64);
		self.unsigned_transaction().weight() + spend_weight
	}

	/// Used by the Ark server to cosign the arkoor request.
	pub fn server_cosign(&self, keypair: &Keypair) -> ArkoorCosignResponse {
		let (pub_nonce, partial_signature) = musig::deterministic_partial_sign(
			keypair,
			[self.input.spec().user_pubkey],
			&[&self.user_nonce],
			self.sighash().to_byte_array(),
			Some(self.input.spec().vtxo_taptweak().to_byte_array()),
		);
		ArkoorCosignResponse { pub_nonce, partial_signature }
	}

	/// Verify a partial signature from either of the two parties.
	fn verify_partial_sig(
		&self,
		is_user: bool,
		asp_nonce: musig::MusigPubNonce,
		user_nonce: musig::MusigPubNonce,
		partial_signature: musig::MusigPartialSignature,
	) -> bool {
		let sighash = self.sighash();
		let agg_nonce = musig::nonce_agg(&[&user_nonce, &asp_nonce]);
		let agg_pk = musig::tweaked_key_agg(
			[self.input.user_pubkey(), self.input.asp_pubkey()],
			self.input.spec().vtxo_taptweak().to_byte_array(),
		).0;

		let msg = musig::secpm::Message::from_digest(sighash.to_byte_array());
		let session = musig::MusigSession::new(&musig::SECP, &agg_pk, agg_nonce, msg);

		let (pubkey, nonce) = if is_user {
			(self.input.user_pubkey(), user_nonce)
		} else {
			(self.input.asp_pubkey(), asp_nonce)
		};
		session.partial_verify(
			&musig::SECP, &agg_pk, partial_signature, nonce, musig::pubkey_to(pubkey),
		)
	}

	/// Validate the server's partial signature.
	pub fn verify_cosign_response(
		&self,
		user_pub_nonce: musig::MusigPubNonce,
		server_cosign: &ArkoorCosignResponse,
	) -> bool {
		self.verify_partial_sig(
			false, server_cosign.pub_nonce, user_pub_nonce, server_cosign.partial_signature,
		)
	}

	/// Construct the vtxos of the outputs of this OOR tx.
	///
	/// These vtxos are not valid vtxos because they lack the signature.
	pub fn unsigned_output_vtxos(&self) -> Vec<ArkoorVtxo> {
		let outputs = self.output_specs();
		let tx = unsigned_arkoor_tx(&self.input, &outputs);
		build_arkoor_vtxos(&self.input, &outputs, tx.compute_txid())
	}

	/// Finish the arkoor process.
	///
	/// Returns the resulting vtxos and the signed arkoor tx.
	pub fn build_vtxos(
		&self,
		user_sec_nonce: musig::MusigSecNonce,
		user_pub_nonce: musig::MusigPubNonce,
		user_key: &Keypair,
		cosign_resp: &ArkoorCosignResponse,
	) -> Result<Vec<Vtxo>, IncorrectSigningKeyError> {
		if user_key.public_key() != self.input.user_pubkey() {
			return Err(IncorrectSigningKeyError {
				required: self.input.user_pubkey(),
				provided: user_key.public_key(),
			});
		}

		let outputs = self.output_specs();
		let tx = unsigned_arkoor_tx(&self.input, &outputs);
		let sighash = arkoor_sighash(&self.input, &tx);

		let agg_nonce = musig::nonce_agg(&[&user_pub_nonce, &cosign_resp.pub_nonce]);
		let (_part_sig, final_sig) = musig::partial_sign(
			[self.input.spec().user_pubkey, self.input.asp_pubkey()],
			agg_nonce,
			user_key,
			user_sec_nonce,
			sighash.to_byte_array(),
			Some(self.input.spec().vtxo_taptweak().to_byte_array()),
			Some(&[&cosign_resp.partial_signature]),
		);
		let final_sig = final_sig.expect("we provided the other sig");
		debug_assert!(
			SECP.verify_schnorr(
				&final_sig,
				&sighash.into(),
				&self.input.spec().taproot_pubkey(),
			).is_ok(),
			"invalid arkoor tx signature produced: input={}, outputs={:?}",
			self.input.serialize().as_hex(), &outputs,
		);

		Ok(build_arkoor_vtxos(&self.input, &outputs, tx.compute_txid()).into_iter()
			.map(|mut v| {
				v.signature = Some(final_sig.clone());
				v.into()
			}).collect())
	}
}


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
	pub fn new(
		inputs: &'a [Vtxo],
		user_nonces: &'a [musig::MusigPubNonce],
		pay_req: VtxoRequest,
		change: Option<PublicKey>,
	) -> Result<Self, ArkoorPackageError> {
		let mut remaining_amount = pay_req.amount;
		let mut arkoors = vec![];
		let mut spending_tx_by_input = HashMap::new();

		for (idx, input) in inputs.iter().enumerate() {
			let user_nonce = user_nonces.get(idx).ok_or(ArkoorPackageError::InvalidUserNoncesLength)?;

			let (output_amount, change) = if remaining_amount >= input.amount() {
				(input.amount(), None)
			} else {
				(remaining_amount, Some(VtxoRequest {
					pubkey: change.ok_or(ArkoorPackageError::MissingChangePk)?,
					amount: input.amount() - remaining_amount,
					spk: VtxoSpkSpec::Exit,
				}))
			};

			let output = VtxoRequest {
				amount: output_amount,
				pubkey: pay_req.pubkey,
				spk: pay_req.spk,
			};

			let pay_reqs = iter::once(output.clone()).chain(change).collect::<Vec<_>>();

			let arkoor = ArkoorBuilder::new(&input, user_nonce, pay_reqs)
				.map_err(ArkoorPackageError::ArkoorError)?;

			spending_tx_by_input.insert(input.id(), arkoor.unsigned_transaction());
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

	pub fn new_htlc_revocation(
		htlc_vtxos: &'a [Vtxo],
		user_nonces: &'a [musig::MusigPubNonce],
	) -> Result<Self, ArkoorPackageError> {
		let arkoors = htlc_vtxos.iter().zip(user_nonces).map(|(v, u)| {
			if !matches!(v.spec().spk, VtxoSpkSpec::HtlcOut { .. }) {
				return Err(ArkoorPackageError::InvalidRevocationSpk);
			}

			ArkoorBuilder::new(v, u, vec![revocation_payment_request(v)])
				.map_err(ArkoorPackageError::ArkoorError)
		}).collect::<Result<Vec<_>, ArkoorPackageError>>()?;

		Self::from_arkoors(arkoors)
	}

	pub fn from_arkoors(
		arkoors: Vec<ArkoorBuilder<'a, VtxoRequest>>,
	) -> Result<Self, ArkoorPackageError> {
		let mut spending_tx_by_input = HashMap::new();

		for arkoor in arkoors.iter() {
			spending_tx_by_input.insert(arkoor.input.id(), arkoor.unsigned_transaction());
		}


		Ok(Self {
			arkoors,
			spending_tx_by_input,
		})
	}

	pub fn inputs(&self) -> Vec<&'a Vtxo> {
		self.arkoors.iter().map(|a| a.input).collect::<Vec<_>>()
	}

	pub fn output_specs(&self) -> Vec<VtxoSpec> {
		self.arkoors.iter().flat_map(|a| {
			a.output_specs()
		}).collect()
	}

	pub fn spending_tx(&self, input_id: VtxoId) -> Option<&Transaction> {
		self.spending_tx_by_input.get(&input_id)
	}

	pub fn build_vtxos(
		self,
		sigs: &[ArkoorCosignResponse],
		keypairs: &[Keypair],
		sec_nonces: Vec<musig::MusigSecNonce>,
	) -> Result<(Vec<Vtxo>, Option<Vtxo>), ArkoorPackageError> {
		let mut sent_vtxos = vec![];
		let mut change_vtxo = None;

		for (idx, (arkoor, sec_nonce)) in self.arkoors
			.into_iter().zip(sec_nonces).enumerate()
		{
			let cosign = sigs.get(idx).ok_or(ArkoorPackageError::InvalidLength)?;

			let vtxos = arkoor.build_vtxos(
				sec_nonce,
				*arkoor.user_nonce,
				&keypairs[idx],
				&cosign,
			)?;

			// The first one is of the recipient, we will post it to their mailbox.
			let mut vtxo_iter = vtxos.into_iter();
			let user_vtxo = vtxo_iter.next().ok_or(ArkoorPackageError::MissingVtxo)?;
			sent_vtxos.push(user_vtxo);

			if let Some(vtxo) = vtxo_iter.next() {
				assert!(change_vtxo.replace(vtxo).is_none(), "change vtxo already set");
			}
		}

		Ok((sent_vtxos, change_vtxo))
	}

	pub fn new_vtxos(&self) -> Vec<Vec<ArkoorVtxo>> {
		self.arkoors.iter().map(|arkoor| {
			let outputs = arkoor.output_specs();
			let tx = arkoor.unsigned_transaction();
			build_arkoor_vtxos(&arkoor.input, &outputs, tx.compute_txid())
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
}
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ArkoorVtxo {
	pub input: Box<Vtxo>,
	pub signature: Option<schnorr::Signature>,
	pub output_specs:  Vec<VtxoSpec>,
	pub point: OutPoint,
}

impl ArkoorVtxo {
	pub fn id(&self) -> VtxoId {
		self.point.into()
	}

	pub fn spec(&self) -> &VtxoSpec {
		&self.output_specs[self.point.vout as usize]
	}

	pub fn amount(&self) -> Amount {
		self.spec().amount
	}

	pub fn asp_pubkey(&self) -> PublicKey {
		self.spec().asp_pubkey
	}

	pub fn input_vtxo_id(&self) -> VtxoId {
		self.input.id()
	}
}

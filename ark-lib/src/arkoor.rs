

use std::borrow::{Borrow, Cow};

use bitcoin::hex::DisplayHex;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, Txid, Weight, Witness};
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{schnorr, Keypair, PublicKey};
use bitcoin::sighash::{self, SighashCache, TapSighash, TapSighashType};

use bitcoin_ext::{fee, P2TR_DUST, TAPROOT_KEYSPEND_WEIGHT};
use lightning_invoice::Bolt11Invoice;

use crate::lightning::revocation_payment_request;
use crate::vtxo::VtxoSpkSpec;
use crate::{musig, PaymentRequest, Vtxo, VtxoId, VtxoSpec};
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
/// - user uses the constructor to check the request for validity
/// - server uses the contructor to check the request for validity
/// - server uses [ArkoorBuilder::server_cosign] to construct a
///   [ArkoorCosignResponse] to send back to the user
/// - user passes the response into [ArkoorBuilder::build_vtxos] to construct
///   the signed resulting VTXOs
pub struct ArkoorBuilder<'a, T: Clone> {
	pub input: &'a Vtxo,
	pub user_nonce: &'a musig::MusigPubNonce,
	pub outputs: Cow<'a, [T]>,
}

impl<'a, T: Borrow<PaymentRequest> + Clone> ArkoorBuilder<'a, T> {
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
		user_keypair: &Keypair,
		cosign_resp: &ArkoorCosignResponse,
	) -> Vec<Vtxo> {
		let outputs = self.output_specs();
		let tx = unsigned_arkoor_tx(&self.input, &outputs);
		let sighash = arkoor_sighash(&self.input, &tx);

		assert_eq!(user_keypair.public_key(), self.input.spec().user_pubkey);
		let agg_nonce = musig::nonce_agg(&[&user_pub_nonce, &cosign_resp.pub_nonce]);
		let (_part_sig, final_sig) = musig::partial_sign(
			[self.input.spec().user_pubkey, self.input.asp_pubkey()],
			agg_nonce,
			user_keypair,
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
			self.input.encode().as_hex(), &outputs,
		);

		build_arkoor_vtxos(&self.input, &outputs, tx.compute_txid()).into_iter()
			.map(|mut v| {
				v.signature = Some(final_sig.clone());
				v.into()
			}).collect()
	}
}

impl<'a> ArkoorBuilder<'a, PaymentRequest> {
	/// Construct a new builder for a lightning payment.
	pub fn new_lightning(
		invoice: &Bolt11Invoice,
		input: &'a Vtxo,
		user_pubkey: PublicKey,
		payment_amount: Amount,
		htlc_expiry: u32,
		user_nonce: &'a musig::MusigPubNonce,
	) -> Result<ArkoorBuilder<'a, PaymentRequest>, ArkoorError> {
		let (htlc_amount, change_amount) = {
			let required = payment_amount;
			let change = input.amount().checked_sub(required).ok_or_else(|| {
				ArkoorError::Unbalanced {
					input: input.amount(),
					output: required,
				}
			})?;
			if change > P2TR_DUST {
				(required, Some(change))
			} else {
				(required + change, None)
			}
		};

		let htlc_output = PaymentRequest {
			amount: htlc_amount,
			pubkey: user_pubkey,
			spk: VtxoSpkSpec::HtlcOut {
				payment_hash: *invoice.payment_hash(),
				htlc_expiry: htlc_expiry,
			},
		};

		let change_output = change_amount.map(|change| {
			PaymentRequest {
				amount: change,
				pubkey: user_pubkey,
				spk: VtxoSpkSpec::Exit,
			}
		});

		Ok(ArkoorBuilder::new(
			input,
			user_nonce,
			[htlc_output].into_iter().chain(change_output).collect::<Vec<_>>(),
		)?)
	}

	/// Construct a builder to start a lightning payment recovation.
	pub fn new_lightning_revocation(
		htlc_vtxo: &'a Vtxo,
		user_nonce: &'a musig::MusigPubNonce,
	) -> Result<ArkoorBuilder<'a, PaymentRequest>, ArkoorError> {
		ArkoorBuilder::new(htlc_vtxo, user_nonce, vec![revocation_payment_request(&htlc_vtxo)])
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

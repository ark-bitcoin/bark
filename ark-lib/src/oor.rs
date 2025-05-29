

use bitcoin::{
	Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, Txid, Weight, Witness
};
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{schnorr, Keypair, PublicKey};
use bitcoin::sighash::{self, SighashCache, TapSighash, TapSighashType};

use bitcoin_ext::{fee, TAPROOT_KEYSPEND_WEIGHT};

use crate::util::{Decodable, Encodable};
use crate::vtxo::VtxoSpkSpec;
use crate::{musig, util, PaymentRequest, Vtxo, VtxoId, VtxoSpec};

pub fn oor_sighash(input_vtxo: &Vtxo, oor_tx: &Transaction) -> TapSighash {
	let prev = input_vtxo.txout();
	let mut shc = SighashCache::new(oor_tx);

	shc.taproot_key_spend_signature_hash(
		0, &sighash::Prevouts::All(&[prev]), TapSighashType::Default,
	).expect("sighash error")
}

pub fn unsigned_oor_tx(input: &Vtxo, outputs: &[VtxoSpec]) -> Transaction {
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

/// Build oor tx and signs it
///
/// ## Panic
///
/// Will panic if inputs and signatures don't have the same length,
/// or if some input witnesses are not empty
pub fn signed_oor_tx(
	input: &Vtxo,
	signature: schnorr::Signature,
	outputs: &[VtxoSpec]
) -> Transaction {
	let mut tx = unsigned_oor_tx(input, outputs);
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
	let tx = signed_oor_tx(&vtxo.input, sig, &vtxo.output_specs);
	let sighash = oor_sighash(&vtxo.input, &tx);
	util::SECP.verify_schnorr(
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

#[derive(Debug, Deserialize, Serialize)]
pub struct OorPayment {
	pub asp_pubkey: PublicKey,
	pub exit_delta: u16,
	pub input: Vtxo,
	pub outputs: Vec<PaymentRequest>,
}

impl OorPayment {
	pub fn new(
		asp_pubkey: PublicKey,
		exit_delta: u16,
		input: Vtxo,
		outputs: Vec<PaymentRequest>,
	) -> OorPayment {
		OorPayment { asp_pubkey, exit_delta, input, outputs }
	}

	fn output_specs(&self) -> Vec<VtxoSpec> {
		let expiry_height = self.input.spec().expiry_height;
		self.outputs.iter().map(|o| VtxoSpec {
				user_pubkey: o.pubkey,
				amount: o.amount,
				expiry_height: expiry_height,
				exit_delta: self.exit_delta,
				asp_pubkey: self.asp_pubkey,
				spk: VtxoSpkSpec::Exit,
		}).collect::<Vec<_>>()
	}

	pub fn txid(&self) -> Txid {
		unsigned_oor_tx(&self.input, &self.output_specs()).compute_txid()
	}

	pub fn sighash(&self) -> TapSighash {
		oor_sighash(
			&self.input,
			&unsigned_oor_tx(&self.input, &self.output_specs())
		)
	}

	pub fn total_weight(&self) -> Weight {
		let tx = unsigned_oor_tx(&self.input, &self.output_specs());
		let spend_weight = Weight::from_wu(TAPROOT_KEYSPEND_WEIGHT as u64);
		tx.weight() + spend_weight
	}

	pub fn sign_asp(
		&self,
		keypair: &Keypair,
		user_nonce: musig::MusigPubNonce,
	) -> (musig::MusigPubNonce, musig::MusigPartialSignature) {
		let sighash = self.sighash();

		let (pub_nonce, part_sig) = musig::deterministic_partial_sign(
			keypair,
			[self.input.spec().user_pubkey],
			&[&user_nonce],
			sighash.to_byte_array(),
			Some(self.input.spec().vtxo_taptweak().to_byte_array()),
		);

		(pub_nonce, part_sig)
	}

	pub fn sign_finalize_user(
		self,
		user_sec_nonce: musig::MusigSecNonce,
		user_pub_nonce: musig::MusigPubNonce,
		user_keypair: &Keypair,
		asp_nonce: musig::MusigPubNonce,
		asp_part_sig: musig::MusigPartialSignature,
	) -> SignedOorPayment {
		let sighash = self.sighash();

		assert_eq!(user_keypair.public_key(), self.input.spec().user_pubkey);
		let agg_nonce = musig::nonce_agg(&[&user_pub_nonce, &asp_nonce]);
		let (_part_sig, final_sig) = musig::partial_sign(
			[self.input.spec().user_pubkey, self.input.asp_pubkey()],
			agg_nonce,
			user_keypair,
			user_sec_nonce,
			sighash.to_byte_array(),
			Some(self.input.spec().vtxo_taptweak().to_byte_array()),
			Some(&[&asp_part_sig]),
		);
		let final_sig = final_sig.expect("we provided the other sig");
		debug_assert!(util::SECP.verify_schnorr(
			&final_sig,
			&sighash.into(),
			&self.input.spec().taproot_pubkey(),
		).is_ok(), "invalid oor tx signature produced");

		SignedOorPayment {
			payment: self,
			signature: final_sig,
		}
	}

	/// Construct the vtxos of the outputs of this OOR tx.
	///
	/// These vtxos are not valid vtxos because they lack the signature.
	pub fn unsigned_output_vtxos(&self) -> Vec<ArkoorVtxo> {
		let outputs = self.output_specs();
		let tx = unsigned_oor_tx(&self.input, &outputs);

		self.outputs.iter().enumerate().map(|(idx, _output)| {
			ArkoorVtxo {
				input: self.input.clone().into(),
				signature: None,
				output_specs: outputs.clone(),
				point: OutPoint::new(tx.compute_txid(), idx as u32)
			}
		}).collect()
	}
}

impl Encodable for OorPayment {}
impl Decodable for OorPayment {}

#[derive(Debug, Deserialize, Serialize)]
pub struct SignedOorPayment {
	pub payment: OorPayment,
	pub signature: schnorr::Signature,
}

impl SignedOorPayment {
	pub fn signed_transaction(&self) -> Transaction {
		let tx = signed_oor_tx(&self.payment.input, self.signature, &self.payment.output_specs());

		//TODO(stevenroose) there seems to be a bug in the tx.weight method,
		// this +2 might be fixed later
		debug_assert_eq!(tx.weight(), self.payment.total_weight() + Weight::from_wu(2));

		tx
	}

	/// Construct the vtxos of the outputs of this OOR tx.
	pub fn output_vtxos(&self) -> Vec<ArkoorVtxo> {
		let mut ret = self.payment.unsigned_output_vtxos();
		for vtxo in ret.iter_mut() {
			vtxo.signature = Some(self.signature.clone());
		}
		ret
	}
}

#[derive(Debug)]
pub struct InsufficientFunds {
	pub required: Amount,
	pub missing: Amount,
	pub fee: Amount,
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
}

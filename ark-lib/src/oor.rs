

use std::borrow::Borrow;
use std::io;

use bitcoin::{
	Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, Txid, Weight, Witness
};
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{schnorr, Keypair, PublicKey};
use bitcoin::sighash::{self, SighashCache, TapSighash, TapSighashType};

use bitcoin_ext::{fee, P2TR_DUST, TAPROOT_KEYSPEND_WEIGHT};

use crate::util::SECP;
use crate::vtxo::VtxoSpkSpec;
use crate::{musig, util, PaymentRequest, Vtxo, VtxoId, VtxoSpec};


/// The minimum fee we consider for an oor transaction.
pub const OOR_MIN_FEE: Amount = P2TR_DUST;

pub fn oor_sighashes<T: Borrow<Vtxo>>(input_vtxos: &Vec<T>, oor_tx: &Transaction) -> Vec<TapSighash> {
	let prevs = input_vtxos.iter().map(|i| i.borrow().spec().txout()).collect::<Vec<_>>();
	let mut shc = SighashCache::new(oor_tx);

	(0..input_vtxos.len()).map(|idx| {
		shc.taproot_key_spend_signature_hash(
			idx, &sighash::Prevouts::All(&prevs), TapSighashType::Default,
		).expect("sighash error")
	}).collect()
}

pub fn unsigned_oor_tx<V: Borrow<Vtxo>>(inputs: &[V], outputs: &[VtxoSpec]) -> Transaction {
	Transaction {
		version: bitcoin::transaction::Version(3),
		lock_time: bitcoin::absolute::LockTime::ZERO,
		input: inputs.into_iter().map(|input| TxIn {
			previous_output: input.borrow().point(),
			script_sig: ScriptBuf::new(),
			sequence: Sequence::ZERO,
			witness: Witness::new(),
		}).collect(),
		output: outputs
			.into_iter()
			.map(VtxoSpec::txout)
			.chain([fee::dust_anchor()])
			.collect(),
	}
}

/// Build oor tx and signs it
///
/// ## Panic
///
/// Will panic if inputs and signatures don't have the same length,
/// or if some input witnesses are not empty
pub fn signed_oor_tx<V: Borrow<Vtxo>>(
	inputs: &[V],
	signatures: &[schnorr::Signature],
	outputs: &[VtxoSpec]
) -> Transaction {
	let mut tx = unsigned_oor_tx(inputs, outputs);
	util::fill_taproot_sigs(&mut tx, signatures);
	tx
}

/// Build the oor tx with signatures and verify it
///
/// If a pubkey is provided, it'll check that vtxo's output user pubkey match
/// it (later want to check it's derived from it)
pub fn verify_oor(vtxo: &ArkoorVtxo, pubkey: Option<PublicKey>) -> Result<(), String> {
	// TODO: we also need to check that inputs are valid (round tx broadcasted, not spent yet, etc...)

	if vtxo.inputs.len() != vtxo.signatures.len() {
		return Err(format!("number of signatures doesn't match number of inputs"));
	}

	let tx = signed_oor_tx(&vtxo.inputs, &vtxo.signatures, &vtxo.output_specs);
	let sighashes = oor_sighashes(&vtxo.inputs, &tx);
	for (idx, input) in vtxo.inputs.iter().enumerate() {
		SECP.verify_schnorr(
			&vtxo.signatures[idx],
			&sighashes[idx].into(),
			&input.spec().taproot_pubkey(),
		).map_err(|e| format!("schnorr signature verification error: {}", e))?;
	}

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
	pub inputs: Vec<Vtxo>,
	pub outputs: Vec<PaymentRequest>,
}

impl OorPayment {
	pub fn new(
		asp_pubkey: PublicKey,
		exit_delta: u16,
		inputs: Vec<Vtxo>,
		outputs: Vec<PaymentRequest>,
	) -> OorPayment {
		OorPayment { asp_pubkey, exit_delta, inputs, outputs }
	}

	fn expiry_height(&self) -> u32 {
		self.inputs.iter().map(|i| i.spec().expiry_height).min().unwrap()
	}

	fn output_specs(&self) -> Vec<VtxoSpec> {
		let expiry_height = self.expiry_height();
		self.outputs.iter().map(|o| VtxoSpec {
				user_pubkey: o.pubkey,
				amount: o.amount,
				expiry_height: expiry_height,
				asp_pubkey: self.asp_pubkey,
				spk: VtxoSpkSpec::Exit { exit_delta: self.exit_delta },
		}).collect::<Vec<_>>()
	}

	pub fn txid(&self) -> Txid {
		unsigned_oor_tx(&self.inputs, &self.output_specs()).compute_txid()
	}

	pub fn sighashes(&self) -> Vec<TapSighash> {
		oor_sighashes(
			&self.inputs,
			&unsigned_oor_tx(&self.inputs, &self.output_specs())
		)
	}

	pub fn total_weight(&self) -> Weight {
		let tx = unsigned_oor_tx(&self.inputs, &self.output_specs());
		let spend_weight = Weight::from_wu(TAPROOT_KEYSPEND_WEIGHT as u64);
		let nb_inputs = self.inputs.len() as u64;
		tx.weight() + nb_inputs * spend_weight
	}

	pub fn sign_asp(
		&self,
		keypair: &Keypair,
		user_nonces: &[musig::MusigPubNonce],
	) -> (Vec<musig::MusigPubNonce>, Vec<musig::MusigPartialSignature>) {
		assert_eq!(self.inputs.len(), user_nonces.len());
		let sighashes = self.sighashes();

		let mut pub_nonces = Vec::with_capacity(self.inputs.len());
		let mut part_sigs = Vec::with_capacity(self.inputs.len());
		for (idx, input) in self.inputs.iter().enumerate() {
			assert_eq!(keypair.public_key(), input.spec().asp_pubkey);
			let (pub_nonce, part_sig) = musig::deterministic_partial_sign(
				keypair,
				[input.spec().user_pubkey],
				&[&user_nonces[idx]],
				sighashes[idx].to_byte_array(),
				Some(input.spec().vtxo_taptweak().to_byte_array()),
			);
			pub_nonces.push(pub_nonce);
			part_sigs.push(part_sig);
		}

		(pub_nonces, part_sigs)
	}

	pub fn sign_finalize_user(
		self,
		user_sec_nonces: Vec<musig::MusigSecNonce>,
		user_pub_nonces: &[musig::MusigPubNonce],
		user_keypairs: &[Keypair],
		asp_nonces: &[musig::MusigPubNonce],
		asp_part_sigs: &[musig::MusigPartialSignature],
	) -> SignedOorPayment {
		assert_eq!(self.inputs.len(), user_sec_nonces.len());
		assert_eq!(self.inputs.len(), user_pub_nonces.len());
		assert_eq!(self.inputs.len(), user_keypairs.len());
		assert_eq!(self.inputs.len(), asp_nonces.len());
		assert_eq!(self.inputs.len(), asp_part_sigs.len());
		let sighashes = self.sighashes();

		let mut sigs = Vec::with_capacity(self.inputs.len());
		for (idx, (input, sec_nonce)) in self.inputs.iter().zip(user_sec_nonces.into_iter()).enumerate() {
			let keypair = &user_keypairs[idx];
			assert_eq!(keypair.public_key(), input.spec().user_pubkey);
			let agg_nonce = musig::nonce_agg(&[&user_pub_nonces[idx], &asp_nonces[idx]]);
			let (_part_sig, final_sig) = musig::partial_sign(
				[input.spec().user_pubkey, input.spec().asp_pubkey],
				agg_nonce,
				keypair,
				sec_nonce,
				sighashes[idx].to_byte_array(),
				Some(input.spec().vtxo_taptweak().to_byte_array()),
				Some(&[&asp_part_sigs[idx]]),
			);
			let final_sig = final_sig.expect("we provided the other sig");
			debug_assert!(util::SECP.verify_schnorr(
				&final_sig,
				&sighashes[idx].into(),
				&input.spec().taproot_pubkey(),
			).is_ok(), "invalid oor tx signature produced");
			sigs.push(final_sig);
		}

		SignedOorPayment {
			payment: self,
			signatures: sigs,
		}
	}

	/// Construct the vtxos of the outputs of this OOR tx.
	///
	/// These vtxos are not valid vtxos because they lack the signature.
	pub fn unsigned_output_vtxos(&self) -> Vec<ArkoorVtxo> {
		let outputs = self.output_specs();
		let inputs = self.inputs.clone();
		let tx = unsigned_oor_tx(&inputs, &outputs);

		self.outputs.iter().enumerate().map(|(idx, _output)| {
			ArkoorVtxo {
				inputs: self.inputs.clone(),
				signatures: vec![],
				output_specs: outputs.clone(),
				point: OutPoint::new(tx.compute_txid(), idx as u32)
			}
		}).collect()
	}

	pub fn encode(&self) -> Vec<u8> {
		let mut buf = Vec::new();
		ciborium::into_writer(self, &mut buf).unwrap();
		buf
	}

	pub fn decode(bytes: &[u8]) -> Result<Self, ciborium::de::Error<io::Error>> {
		ciborium::from_reader(bytes)
	}
}


#[derive(Debug, Deserialize, Serialize)]
pub struct SignedOorPayment {
	pub payment: OorPayment,
	pub signatures: Vec<schnorr::Signature>,
}

impl SignedOorPayment {
	pub fn signed_transaction(&self) -> Transaction {
		let tx = signed_oor_tx(&self.payment.inputs, &self.signatures, &self.payment.output_specs());

		//TODO(stevenroose) there seems to be a bug in the tx.weight method,
		// this +2 might be fixed later
		debug_assert_eq!(tx.weight(), self.payment.total_weight() + Weight::from_wu(2));

		tx
	}

	/// Construct the vtxos of the outputs of this OOR tx.
	pub fn output_vtxos(&self) -> Vec<ArkoorVtxo> {
		let mut ret = self.payment.unsigned_output_vtxos();
		for vtxo in ret.iter_mut() {
			vtxo.signatures = self.signatures.clone();
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
	pub inputs: Vec<Vtxo>,
	pub signatures: Vec<schnorr::Signature>,
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
}

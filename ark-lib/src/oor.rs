

use std::borrow::Borrow;
use std::io;

use bitcoin::key::Keypair;
use bitcoin::{
	Amount, FeeRate, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Weight, Witness
};
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{Error, schnorr, PublicKey};
use bitcoin::sighash::{self, SighashCache, TapSighash, TapSighashType};

use crate::{fee, musig, util, PaymentRequest, Vtxo, VtxoSpec};


/// The minimum fee we consider for an oor transaction.
pub const OOR_MIN_FEE: Amount = crate::P2TR_DUST;

fn oor_sighashes<T: Borrow<Vtxo>>(input_vtxos: &Vec<T>, oor_tx: &Transaction) -> Vec<TapSighash> {
	let prevs = input_vtxos.iter().map(|i| i.borrow().txout()).collect::<Vec<_>>();
	let mut shc = SighashCache::new(oor_tx);

	(0..input_vtxos.len()).map(|idx| {
		shc.taproot_key_spend_signature_hash(
			idx, &sighash::Prevouts::All(&prevs), TapSighashType::Default,
		).expect("sighash error")
	}).collect()
}

pub fn unsigned_oor_transaction<V: Borrow<Vtxo>>(inputs: &[V], outputs: &[VtxoSpec]) -> Transaction {
	Transaction {
		version: bitcoin::transaction::Version(3),
		lock_time: bitcoin::absolute::LockTime::ZERO,
		input: inputs.into_iter().map(|input| {
			TxIn {
				previous_output: input.borrow().point(),
				script_sig: ScriptBuf::new(),
				sequence: Sequence::ZERO,
				witness: Witness::new(),
			}
		}).collect(),
		output: outputs.into_iter().map(|output| {
			let spk = crate::exit_spk(output.user_pubkey, output.asp_pubkey, output.exit_delta);
			TxOut {
				value: output.amount,
				script_pubkey: spk,
			}
		}).chain([fee::dust_anchor()]).collect(),
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
	// build the oor_tx
	let mut tx = unsigned_oor_transaction(inputs, outputs);

	util::fill_taproot_sigs(&mut tx, signatures);

	tx
}

/// Build the oor tx with signatures and verify it
///
/// If a pubkey is provided, it'll check that vtxo's output user pubkey match it (later want to check it's derived from it)
pub fn verify_oor(vtxo: Vtxo, pubkey: Option<PublicKey>) -> Result<(), Error> {
	match vtxo {
		Vtxo::Oor { inputs, signatures, output_specs, point } => {
			// TODO: we also need to check that inputs are valid (round tx broadcasted, not spent yet, etc...)

			let tx = signed_oor_tx(&inputs, &signatures, &output_specs);

			let sighashes = oor_sighashes(&inputs, &tx);
			for (idx, input) in inputs.iter().enumerate() {
				util::SECP.verify_schnorr(
					&schnorr::Signature::from_slice(&tx.input[idx].witness.to_vec()[0][..]).unwrap(),
					&sighashes[idx].into(),
					&input.spec().exit_taproot().output_key().to_inner(),
				)?;
			}

			if let Some(pubkey) = pubkey {
				//TODO: handle derived keys here
				assert_eq!(pubkey, output_specs[point.vout as usize].user_pubkey)
			}
		},
		_ => {}
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
				exit_delta: self.exit_delta,
		}).collect::<Vec<_>>()
	}

	pub fn txid(&self) -> Txid {
		unsigned_oor_transaction(&self.inputs, &self.output_specs()).compute_txid()
	}

	pub fn sighashes(&self) -> Vec<TapSighash> {
		oor_sighashes(
			&self.inputs,
			&unsigned_oor_transaction(&self.inputs, &self.output_specs())
		)
	}

	pub fn total_weight(&self) -> Weight {
		let tx = unsigned_oor_transaction(&self.inputs, &self.output_specs());
		let spend_weight = Weight::from_wu(crate::TAPROOT_KEYSPEND_WEIGHT as u64);
		let nb_inputs = self.inputs.len() as u64;
		tx.weight() + nb_inputs * spend_weight
	}

	/// Check if there is sufficient fee provided for the given feerate.
	pub fn check_fee(&self, fee_rate: FeeRate) -> Result<(), InsufficientFunds> {
		let total_input = self.inputs.iter().map(|i| i.amount()).sum::<Amount>();
		let total_output = self.outputs.iter().map(|o| o.amount).sum::<Amount>();

		let weight = self.total_weight();
		let fee = fee_rate * weight;

		let required = total_output + fee;
		if required > total_input {
			Err(InsufficientFunds {
				required, fee, missing: required - total_input,
			})
		} else {
			Ok(())
		}
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
				Some(input.spec().exit_taptweak().to_byte_array()),
			);
			pub_nonces.push(pub_nonce);
			part_sigs.push(part_sig);
		}

		(pub_nonces, part_sigs)
	}

	pub fn sign_finalize_user(
		self,
		keypair: &Keypair,
		our_sec_nonces: Vec<musig::MusigSecNonce>,
		our_pub_nonces: &[musig::MusigPubNonce],
		asp_nonces: &[musig::MusigPubNonce],
		asp_part_sigs: &[musig::MusigPartialSignature],
	) -> SignedOorPayment {
		assert_eq!(self.inputs.len(), our_sec_nonces.len());
		assert_eq!(self.inputs.len(), our_pub_nonces.len());
		assert_eq!(self.inputs.len(), asp_nonces.len());
		assert_eq!(self.inputs.len(), asp_part_sigs.len());
		let sighashes = self.sighashes();

		let mut sigs = Vec::with_capacity(self.inputs.len());
		for (idx, (input, sec_nonce)) in self.inputs.iter().zip(our_sec_nonces.into_iter()).enumerate() {
			assert_eq!(keypair.public_key(), input.spec().user_pubkey);
			let agg_nonce = musig::nonce_agg(&[&our_pub_nonces[idx], &asp_nonces[idx]]);
			let (_part_sig, final_sig) = musig::partial_sign(
				[input.spec().user_pubkey, input.spec().asp_pubkey],
				agg_nonce,
				keypair,
				sec_nonce,
				sighashes[idx].to_byte_array(),
				Some(input.spec().exit_taptweak().to_byte_array()),
				Some(&[&asp_part_sigs[idx]]),
			);
			let final_sig = final_sig.expect("we provided the other sig");
			debug_assert!(util::SECP.verify_schnorr(
				&final_sig,
				&sighashes[idx].into(),
				&input.spec().exit_taproot().output_key().to_inner(),
			).is_ok(), "invalid oor tx signature produced");
			sigs.push(final_sig);
		}

		SignedOorPayment {
			payment: self,
			signatures: sigs,
		}
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

	pub fn output_vtxos(&self) -> Vec<Vtxo> {
		let outputs = self.payment.output_specs();
		let inputs = self.payment.inputs.clone();

		let tx = unsigned_oor_transaction(&inputs, &outputs);

		self.payment.outputs.iter().enumerate().map(|(idx, _output)| {
			Vtxo::Oor {
				inputs: self.payment.inputs.clone(),
				signatures: self.signatures.clone(),
				output_specs: outputs.clone(),
				point: OutPoint::new(tx.compute_txid(), idx as u32)
			}
		}).collect()
	}
}

#[derive(Debug)]
pub struct InsufficientFunds {
	pub required: Amount,
	pub missing: Amount,
	pub fee: Amount,
}

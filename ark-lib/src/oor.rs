

use std::io;

use bitcoin::{
	Amount, FeeRate, OutPoint, ScriptBuf, Sequence, Transaction, Txid, TxIn, TxOut, Weight,
	Witness,
};
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{schnorr, Keypair, PublicKey};
use bitcoin::sighash::{self, SighashCache, TapSighash, TapSighashType};

use crate::{fee, musig, util, Vtxo, VtxoRequest, VtxoSpec};


pub const OOR_MIN_FEE: Amount = crate::P2TR_DUST;

#[derive(Debug, Deserialize, Serialize)]
pub struct OorPayment {
	pub asp_pubkey: PublicKey,
	pub exit_delta: u16,
	pub inputs: Vec<Vtxo>,
	pub outputs: Vec<VtxoRequest>,
}

impl OorPayment {
	pub fn new(
		asp_pubkey: PublicKey,
		exit_delta: u16,
		inputs: Vec<Vtxo>,
		outputs: Vec<VtxoRequest>,
	) -> OorPayment {
		OorPayment { asp_pubkey, exit_delta, inputs, outputs }
	}

	pub fn unsigned_transaction(&self) -> Transaction {
		Transaction {
			version: bitcoin::transaction::Version::TWO,
			lock_time: bitcoin::absolute::LockTime::ZERO,
			input: self.inputs.iter().map(|input| {
				TxIn {
					previous_output: input.point(),
					script_sig: ScriptBuf::new(),
					sequence: Sequence::ZERO,
					witness: Witness::new(),
				}
			}).collect(),
			output: self.outputs.iter().map(|output| {
				let spk = crate::exit_spk(output.pubkey, self.asp_pubkey, self.exit_delta);
				TxOut {
					value: output.amount,
					script_pubkey: spk,
				}
			}).chain([fee::dust_anchor()]).collect(),
		}
	}

	pub fn txid(&self) -> Txid {
		self.unsigned_transaction().compute_txid()
	}

	pub fn sighashes(&self) -> Vec<TapSighash> {
		let tx = self.unsigned_transaction();
		let prevs = self.inputs.iter().map(|i| i.txout()).collect::<Vec<_>>();
		let mut shc = SighashCache::new(&tx);

		(0..self.inputs.len()).map(|idx| {
			shc.taproot_key_spend_signature_hash(
				idx, &sighash::Prevouts::All(&prevs), TapSighashType::Default,
			).expect("sighash error")
		}).collect()
	}

	pub fn total_weight(&self) -> Weight {
		let tx = self.unsigned_transaction();
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
				[user_nonces[idx]],
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
	) -> OorTransaction {
		assert_eq!(self.inputs.len(), our_sec_nonces.len());
		assert_eq!(self.inputs.len(), our_pub_nonces.len());
		assert_eq!(self.inputs.len(), asp_nonces.len());
		assert_eq!(self.inputs.len(), asp_part_sigs.len());
		let sighashes = self.sighashes();

		let mut sigs = Vec::with_capacity(self.inputs.len());
		for (idx, (input, sec_nonce)) in self.inputs.iter().zip(our_sec_nonces.into_iter()).enumerate() {
			assert_eq!(keypair.public_key(), input.spec().user_pubkey);
			let agg_nonce = musig::nonce_agg([our_pub_nonces[idx], asp_nonces[idx]]);
			let (_part_sig, final_sig) = musig::partial_sign(
				[input.spec().user_pubkey, input.spec().asp_pubkey],
				agg_nonce,
				keypair,
				sec_nonce,
				sighashes[idx].to_byte_array(),
				Some(input.spec().exit_taptweak().to_byte_array()),
				Some(&[asp_part_sigs[idx]]),
			);
			let final_sig = final_sig.expect("we provided the other sig");
			debug_assert!(util::SECP.verify_schnorr(
				&final_sig,
				&sighashes[idx].into(),
				&input.spec().exit_taproot().output_key().to_inner(),
			).is_ok(), "invalid oor tx signature produced");
			sigs.push(final_sig);
		}

		OorTransaction {
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
pub struct OorTransaction {
	pub payment: OorPayment,
	pub signatures: Vec<schnorr::Signature>,
}

impl OorTransaction {
	pub fn signed_transaction(&self) -> Transaction {
		let mut tx = self.payment.unsigned_transaction();
		for (input, sig) in tx.input.iter_mut().zip(self.signatures.iter()) {
			assert!(input.witness.is_empty());
			input.witness.push(&sig[..]);
			debug_assert_eq!(crate::TAPROOT_KEYSPEND_WEIGHT, input.witness.size());
		}
		//TODO(stevenroose) there seems to be a bug in the tx.weight method,
		// this +2 might be fixed later
		debug_assert_eq!(tx.weight(), self.payment.total_weight() + Weight::from_wu(2));
		tx
	}

	pub fn output_vtxos(&self, asp_pubkey: PublicKey, exit_delta: u16) -> Vec<Vtxo> {
		let inputs = self.payment.inputs.iter()
			.map(|input| Box::new(input.clone()))
			.collect::<Vec<_>>();

		let expiry_height = self.payment.inputs.iter().map(|i| i.spec().expiry_height).min().unwrap();
		let oor_tx = self.signed_transaction();
		let oor_txid = oor_tx.compute_txid();
		self.payment.outputs.iter().enumerate().map(|(idx, output)| {
			Vtxo::Oor {
				inputs: inputs.clone(),
				pseudo_spec: VtxoSpec {
					amount: output.amount,
					exit_delta,
					expiry_height,
					asp_pubkey,
					user_pubkey: output.pubkey,
				},
				oor_tx: oor_tx.clone(),
				final_point: OutPoint::new(oor_txid, idx as u32),
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


use std::{fmt, iter};

use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Weight, Witness};
use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::{self, schnorr, Keypair, PublicKey, XOnlyPublicKey};
use bitcoin::taproot::TaprootSpendInfo;
use lightning_invoice::Bolt11Invoice;

use bitcoin_ext::{fee, AmountExt, P2TR_DUST, TAPROOT_KEYSPEND_WEIGHT};

use crate::oor::OorPayment;
use crate::util::{Decodable, Encodable};
use crate::vtxo::{exit_spk, VtxoSpkSpec};
use crate::{musig, util, ArkoorVtxo, PaymentRequest, Vtxo, VtxoSpec};

const HTLC_VOUT: u32 = 0;
const CHANGE_VOUT: u32 = 1;


/// The minimum fee we consider for an HTLC transaction.
pub const HTLC_MIN_FEE: Amount = P2TR_DUST;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bolt11Payment {
	pub invoice: Bolt11Invoice,
	pub inputs: Vec<Vtxo>,
	pub asp_pubkey: PublicKey,
	pub user_pubkey: PublicKey,
	pub payment_amount: Amount,
	pub forwarding_fee: Amount,
	/// Set the HTLC
	pub htlc_delta: u16,
	/// Relative time-lock enforced on claiming the HTLC expiry
	pub htlc_expiry_delta: u16,
	/// The expiration-height of the HTLC granted from client to ASP
	pub htlc_expiry: u32,
	pub exit_delta: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, thiserror::Error)]
#[error("{0}")]
pub struct CheckAmountsError(String);

pub fn htlc_taproot(
	payment_hash: sha256::Hash,
	asp_pubkey: PublicKey,
	user_pubkey: PublicKey,
	htlc_expiry_delta: u16,
	htlc_expiry: u32) -> TaprootSpendInfo
{
	let asp_branch = util::hash_and_sign(payment_hash, asp_pubkey.x_only_public_key().0);
	let user_branch = util::delay_timelock_sign(htlc_expiry_delta, htlc_expiry, user_pubkey.x_only_public_key().0);

	let combined_pk = musig::combine_keys([user_pubkey, asp_pubkey]);
	bitcoin::taproot::TaprootBuilder::new()
		.add_leaf(1, asp_branch).unwrap()
		.add_leaf(1, user_branch).unwrap()
		.finalize(&util::SECP, combined_pk).unwrap()
}

impl Bolt11Payment {
	pub fn check_amounts(&self) -> Result<(), CheckAmountsError> {
		if let Some(invoice_msat) = self.invoice.amount_milli_satoshis() {
			let invoice_amount = Amount::from_msat_ceil(invoice_msat);
			if invoice_amount != self.payment_amount {
				return Err(CheckAmountsError(format!(
					"payment amount ({}) is not equal to invoice amount ({})",
					self.payment_amount, invoice_amount,
				)));
			}
		}

		let inputs = self.inputs.iter().map(|v| v.amount()).sum::<Amount>();
		let total_amount = self.payment_amount + self.forwarding_fee;
		if inputs < total_amount {
			return Err(CheckAmountsError(format!(
				"inputs sum is too low. provided: {}, required: {}",
				inputs, total_amount)
			));
		}

		if self.change_amount() < P2TR_DUST {
			return Err(CheckAmountsError(
				format!("change amount must be at least {}", P2TR_DUST)));
		}

		if self.payment_amount < P2TR_DUST {
			return Err(CheckAmountsError(
				format!("payment amount must be at least {}", P2TR_DUST)));
		}

		Ok(())
	}

	fn htlc_spk(&self) -> ScriptBuf {
		let taproot = htlc_taproot(
			*self.invoice.payment_hash(),
			self.asp_pubkey,
			self.user_pubkey,
			self.htlc_expiry_delta,
			self.htlc_expiry);

		ScriptBuf::new_p2tr_tweaked(taproot.output_key())
	}

	fn change_txout(&self) -> Option<TxOut> {
		let amount = self.change_amount();
		if amount > Amount::ZERO {
			Some(TxOut {
				value: amount,
				script_pubkey: exit_spk(self.user_pubkey, self.asp_pubkey, self.exit_delta)
			})
		} else {
			None
		}
	}

	pub fn htlc_amount(&self) -> Amount {
		// This is the fee collected by the ASP for forwarding the payment
		// We will calculate this later as base_fee + ppm * payment_amount
		//
		// The ASP uses this to pay for it's operation and pay for all routing-fees.
		let forwarding_fee = self.forwarding_fee;

		self.payment_amount + forwarding_fee
	}

	fn htlc_txout(&self) -> TxOut {
		TxOut {
			value: self.htlc_amount(),
			script_pubkey: self.htlc_spk()
		}
	}

	pub fn change_amount(&self) -> Amount {
		let input_amount = self.inputs.iter().map(|vtxo| vtxo.amount()).sum::<Amount>();
		let payment_amount = self.payment_amount;
		let forwarding_fee = self.forwarding_fee;
		input_amount - payment_amount - forwarding_fee
	}

	pub fn unsigned_transaction(&self) -> Transaction {
		let input_amount = self.inputs.iter().map(|vtxo| vtxo.amount()).sum::<Amount>();

		// Let's draft the output transactions
		let htlc_output = self.htlc_txout();
		let htlc_amount = htlc_output.value;

		// Just checking the computed fees work
		// Our input's should equal our outputs + onchain fees
		let change_output = self.change_txout();
		let change_amount = change_output.as_ref().map(|o| o.value).unwrap_or_default();

		assert_eq!(input_amount, htlc_amount + change_amount,
			"htlc={htlc_amount}, change={change_amount}",
		);

		Transaction {
			version: bitcoin::blockdata::transaction::Version(3),
			lock_time: bitcoin::absolute::LockTime::ZERO,
			input: self.inputs.iter().map(|vtxo| {
				TxIn {
					previous_output: vtxo.point(),
					script_sig: ScriptBuf::new(),
					sequence: Sequence::ZERO,
					witness: Witness::new()
				}
			}).collect(),
			output: iter::once(htlc_output)
				.chain(change_output)
				.chain(Some(fee::fee_anchor()))
				.collect(),
		}
	}

	pub fn total_weight(&self) -> Weight {
		let tx = self.unsigned_transaction();
		let spend_weight = Weight::from_wu(TAPROOT_KEYSPEND_WEIGHT as u64);
		let nb_inputs = self.inputs.len() as u64;
		tx.weight() + nb_inputs * spend_weight
	}

	pub fn htlc_sighashes(&self) -> Vec<bitcoin::TapSighash> {
		let prevouts = self.inputs.iter().map(|v| v.spec().txout()).collect::<Vec<_>>();

		let tx = self.unsigned_transaction();
		let mut shc = bitcoin::sighash::SighashCache::new(tx);
		(0..self.inputs.len()).map(|idx| {
			shc.taproot_key_spend_signature_hash(
				idx, &bitcoin::sighash::Prevouts::All(&prevouts), bitcoin::TapSighashType::Default,
			).expect("sighash error")
		}).collect()
	}

	fn outputs(&self) -> Vec<VtxoSpec> {
		let expiry_height = self.inputs.iter().map(|i| i.spec().expiry_height).min().unwrap();

		let htlc_output = VtxoSpec {
			amount: self.htlc_amount(),
			expiry_height: expiry_height,
			asp_pubkey: self.asp_pubkey,
			user_pubkey: self.user_pubkey,
			spk: VtxoSpkSpec::Htlc {
				payment_hash: *self.invoice.payment_hash(),
				htlc_expiry: self.htlc_expiry,
				htlc_expiry_delta: self.htlc_expiry_delta
			}
		};

		if let Some(txout) = self.change_txout() {
			let change_output = VtxoSpec {
				amount: txout.value,
				expiry_height: expiry_height,
				asp_pubkey: self.asp_pubkey,
				user_pubkey: self.user_pubkey,
				spk: VtxoSpkSpec::Exit { exit_delta: self.exit_delta },
			};

			return vec![htlc_output, change_output]
		}

		vec![htlc_output]
	}

	pub fn unsigned_change_vtxo(&self) -> Option<ArkoorVtxo> {
		let tx = self.unsigned_transaction();
		let outputs = self.outputs();

		outputs.get(CHANGE_VOUT as usize).map(|_txout| ArkoorVtxo {
			inputs: self.inputs.clone(),
			output_specs: self.outputs(),
			point: OutPoint::new(tx.compute_txid(), CHANGE_VOUT),
			signatures: vec![]
		})
	}

	pub fn unsigned_htlc_vtxo(&self) -> ArkoorVtxo {
		let tx = self.unsigned_transaction();

		ArkoorVtxo {
			inputs: self.inputs.clone(),
			output_specs: self.outputs(),
			point: OutPoint::new(tx.compute_txid(), HTLC_VOUT),
			signatures: vec![]
		}
	}

	pub fn sign_asp(
		&self,
		keypair: &Keypair,
		user_nonces: &[musig::MusigPubNonce],
	) -> (Vec<musig::MusigPubNonce>, Vec<musig::MusigPartialSignature>) {
		let sighashes = self.htlc_sighashes();
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
		our_sec_nonces: Vec<musig::MusigSecNonce>,
		our_pub_nonces: &[musig::MusigPubNonce],
		our_keypairs: &[Keypair],
		asp_nonces: &[musig::MusigPubNonce],
		asp_part_sigs: &[musig::MusigPartialSignature],
	) -> SignedBolt11Payment {
		assert_eq!(self.inputs.len(), our_sec_nonces.len());
		assert_eq!(self.inputs.len(), our_pub_nonces.len());
		assert_eq!(self.inputs.len(), our_keypairs.len());
		assert_eq!(self.inputs.len(), asp_nonces.len());
		assert_eq!(self.inputs.len(), asp_part_sigs.len());
		let sighashes = self.htlc_sighashes();

		let mut sigs = Vec::with_capacity(self.inputs.len());
		for (idx, (input, sec_nonce)) in self.inputs.iter().zip(our_sec_nonces.into_iter()).enumerate() {
			let keypair = &our_keypairs[idx];
			assert_eq!(keypair.public_key(), input.spec().user_pubkey);
			let agg_nonce = musig::nonce_agg(&[&our_pub_nonces[idx], &asp_nonces[idx]]);
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
			).is_ok(), "invalid htlc tx signature produced");
			sigs.push(final_sig);
		}

		SignedBolt11Payment {
			payment: self,
			signatures: sigs,
		}
	}
}

impl Encodable for Bolt11Payment {}
impl Decodable for Bolt11Payment {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedBolt11Payment {
	pub payment: Bolt11Payment,
	pub signatures: Vec<schnorr::Signature>,
}

impl SignedBolt11Payment {
	pub fn validate_signatures(
		&self,
		secp: &secp256k1::Secp256k1<impl secp256k1::Verification>,
	) -> Result<(), InvalidSignatureError> {
		for (idx, sighash) in self.payment.htlc_sighashes().into_iter().enumerate() {
			let sig = self.signatures.get(idx).ok_or(InvalidSignatureError::Missing { idx })?;
			let pubkey = self.payment.inputs[idx].spec().taproot_pubkey();
			let msg = secp256k1::Message::from_digest(*sighash.as_byte_array());
			if secp.verify_schnorr(sig, &msg, &pubkey).is_err() {
				return Err(InvalidSignatureError::Invalid { idx, pubkey });
			}
		}
		Ok(())
	}

	pub fn change_vtxo(&self) -> Option<ArkoorVtxo> {
		self.payment.unsigned_change_vtxo().map(|mut vtxo| {
			vtxo.signatures = self.signatures.clone();
			vtxo
		})
	}

	pub fn htlc_vtxo(&self) -> ArkoorVtxo {
		let mut vtxo = self.payment.unsigned_htlc_vtxo();
		vtxo.signatures = self.signatures.clone();
		vtxo
	}

	pub fn revocation_payment(&self) -> OorPayment {
		let htlc_vtxo = Vtxo::from(self.htlc_vtxo());

		let pay_req = PaymentRequest {
			pubkey: htlc_vtxo.spec().user_pubkey,
			amount: htlc_vtxo.amount(),
			spk: VtxoSpkSpec::Exit { exit_delta: self.payment.exit_delta },
		};

		OorPayment {
			asp_pubkey: htlc_vtxo.spec().asp_pubkey,
			exit_delta: self.payment.exit_delta,
			inputs: vec![htlc_vtxo],
			outputs: vec![pay_req],
		}
	}
}

impl Encodable for SignedBolt11Payment {}
impl Decodable for SignedBolt11Payment {}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum InvalidSignatureError {
	#[error("signature missing at idx {idx}")]
	Missing {
		idx: usize,
	},
	#[error("invalid signature at idx {idx} for public key {pubkey}")]
	Invalid {
		idx: usize,
		pubkey: XOnlyPublicKey,
	},
}

#[derive(Debug)]
pub struct InsufficientFunds {
	pub required: Amount,
	pub missing: Amount,
	pub fee: Amount,
}

#[derive(Debug, Clone)]
pub enum PaymentStatus {
	Pending,
	Complete,
	Failed
}

impl fmt::Display for PaymentStatus {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		fmt::Debug::fmt(self, f)
	}
}

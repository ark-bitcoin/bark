use std::{fmt, iter};

use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Weight, Witness};
use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::{self, schnorr, Keypair, PublicKey, XOnlyPublicKey};
use bitcoin::taproot::TaprootSpendInfo;
use lightning_invoice::Bolt11Invoice;

use bitcoin_ext::{fee, AmountExt, P2TR_DUST, TAPROOT_KEYSPEND_WEIGHT};

use crate::oor::OorPayment;
use crate::util::{Decodable, Encodable, SECP};
use crate::vtxo::{exit_spk, VtxoSpkSpec};
use crate::{musig, util, ArkoorVtxo, PaymentRequest, Vtxo, VtxoSpec};

const HTLC_VOUT: u32 = 0;
const CHANGE_VOUT: u32 = 1;


/// The minimum fee we consider for an HTLC transaction.
pub const HTLC_MIN_FEE: Amount = P2TR_DUST;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bolt11Payment {
	pub invoice: Bolt11Invoice,
	pub input: Vtxo,
	pub asp_pubkey: PublicKey,
	pub user_pubkey: PublicKey,
	pub payment_amount: Amount,
	pub forwarding_fee: Amount,
	/// The expiration-height of the HTLC granted from client to ASP
	pub htlc_expiry: u32,
	pub exit_delta: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, thiserror::Error)]
#[error("{0}")]
pub struct CheckAmountsError(String);

/// Build taproot spend info to build a VTXO to enable lightning send
///
/// This build a taproot with 3 clauses:
/// 1. The keyspend path allows Alice and Server to collaborate to spend
/// the HTLC. The Server can use this path to revoke the HTLC if payment
/// failed
///
/// 2. One leaf of the tree allows Server to spend the HTLC after the
/// expiry, if it knows the preimage. Server can use this path if Alice
/// tries to spend using 3rd path.
///
/// 3. The other leaf allows Alice to spend the HTLC after its expiry
/// and with a delay. Alice must use this path if the server fails to
/// provide the preimage and refuse to revoke the HTLC. It will either
/// force the Server to reveal the preimage (by spending using 2nd path)
/// or give Alice her money back.
pub fn htlc_out_taproot(
	payment_hash: sha256::Hash,
	asp_pubkey: PublicKey,
	user_pubkey: PublicKey,
	exit_delta: u16,
	htlc_expiry: u32) -> TaprootSpendInfo
{
	let asp_branch = util::hash_delay_sign(
		payment_hash, exit_delta, asp_pubkey.x_only_public_key().0,
	);
	let user_branch = util::delay_timelock_sign(
		2 * exit_delta, htlc_expiry, user_pubkey.x_only_public_key().0,
	);

	let combined_pk = musig::combine_keys([user_pubkey, asp_pubkey]);
	bitcoin::taproot::TaprootBuilder::new()
		.add_leaf(1, asp_branch).unwrap()
		.add_leaf(1, user_branch).unwrap()
		.finalize(&SECP, combined_pk).unwrap()
}

/// Build taproot spend info to build a VTXO for Alice lightning onboard
///
/// This build a taproot with 3 clauses:
/// 1. The keyspend path allows Alice and Server to collaborate to spend
/// the HTLC. This is the expected path to be used. Server should only
/// accept to collaborate if Alice reveals the preimage.
///
/// 2. One leaf of the tree allows Server to spend the HTLC after the
/// expiry, with an exit delta delay. Server can use this path if Alice
/// tries to spend the HTLC using the 3rd path after the HTLC expiry
///
/// 3. The other leaf of the tree allows Alice to spend the HTLC if she
/// knows the preimage, but with a greater exit delta delay than Server.
/// Alice must use this path if she revealed the preimage but Server
/// refused to collaborate using the 1rst path.
pub fn htlc_in_taproot(
	payment_hash: sha256::Hash,
	asp_pubkey: PublicKey,
	user_pubkey: PublicKey,
	exit_delta: u16,
	htlc_expiry: u32,
) -> TaprootSpendInfo {
	let asp_branch =
		util::delay_timelock_sign(exit_delta, htlc_expiry, asp_pubkey.x_only_public_key().0);
	let user_branch = util::hash_delay_sign(
		payment_hash,
		2 * exit_delta,
		user_pubkey.x_only_public_key().0,
	);

	let combined_pk = musig::combine_keys([user_pubkey, asp_pubkey]);
	bitcoin::taproot::TaprootBuilder::new()
		.add_leaf(1, asp_branch).unwrap()
		.add_leaf(1, user_branch).unwrap()
		.finalize(&SECP, combined_pk).unwrap()
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

		let total_amount = self.payment_amount + self.forwarding_fee;
		if self.input.amount() < total_amount {
			return Err(CheckAmountsError(format!(
				"inputs sum is too low. provided: {}, required: {}",
				self.input.amount(), total_amount)
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
		let taproot = htlc_out_taproot(
			*self.invoice.payment_hash(),
			self.asp_pubkey,
			self.user_pubkey,
			self.exit_delta,
			self.htlc_expiry,
		);

		ScriptBuf::new_p2tr_tweaked(taproot.output_key())
	}

	fn change_txout(&self) -> Option<TxOut> {
		let amount = self.change_amount();
		if amount > Amount::ZERO {
			Some(TxOut {
				value: amount,
				script_pubkey: exit_spk(self.user_pubkey, self.asp_pubkey, self.exit_delta),
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
			script_pubkey: self.htlc_spk(),
		}
	}

	pub fn change_amount(&self) -> Amount {
		let payment_amount = self.payment_amount;
		let forwarding_fee = self.forwarding_fee;
		self.input.amount() - payment_amount - forwarding_fee
	}

	pub fn unsigned_transaction(&self) -> Transaction {
		// Let's draft the output transactions
		let htlc_output = self.htlc_txout();
		let htlc_amount = htlc_output.value;

		// Just checking the computed fees work
		// Our input's should equal our outputs + onchain fees
		let change_output = self.change_txout();
		let change_amount = change_output.as_ref().map(|o| o.value).unwrap_or_default();

		assert_eq!(self.input.amount(), htlc_amount + change_amount,
			"htlc={htlc_amount}, change={change_amount}",
		);

		Transaction {
			version: bitcoin::blockdata::transaction::Version(3),
			lock_time: bitcoin::absolute::LockTime::ZERO,
			input: vec![TxIn {
				previous_output: self.input.point(),
				script_sig: ScriptBuf::new(),
				sequence: Sequence::ZERO,
				witness: Witness::new()
			}],
			output: iter::once(htlc_output)
				.chain(change_output)
				.chain(Some(fee::fee_anchor()))
				.collect(),
		}
	}

	pub fn total_weight(&self) -> Weight {
		let tx = self.unsigned_transaction();
		let spend_weight = Weight::from_wu(TAPROOT_KEYSPEND_WEIGHT as u64);
		tx.weight() + spend_weight
	}

	pub fn htlc_sighash(&self) -> bitcoin::TapSighash {
		let prevout = self.input.txout();

		let tx = self.unsigned_transaction();
		let mut shc = bitcoin::sighash::SighashCache::new(tx);
		shc.taproot_key_spend_signature_hash(
			0, &bitcoin::sighash::Prevouts::All(&[prevout]), bitcoin::TapSighashType::Default,
		).expect("sighash error")
	}

	fn outputs(&self) -> Vec<VtxoSpec> {
		let expiry_height = self.input.expiry_height();

		let htlc_output = VtxoSpec {
			amount: self.htlc_amount(),
			expiry_height: expiry_height,
			asp_pubkey: self.asp_pubkey,
			exit_delta: self.exit_delta,
			user_pubkey: self.user_pubkey,
			spk: VtxoSpkSpec::HtlcOut {
				payment_hash: *self.invoice.payment_hash(),
				htlc_expiry: self.htlc_expiry,
			},
		};

		if let Some(txout) = self.change_txout() {
			let change_output = VtxoSpec {
				amount: txout.value,
				expiry_height: expiry_height,
				asp_pubkey: self.asp_pubkey,
				exit_delta: self.exit_delta,
				user_pubkey: self.user_pubkey,
				spk: VtxoSpkSpec::Exit,
			};

			return vec![htlc_output, change_output];
		}

		vec![htlc_output]
	}

	pub fn unsigned_change_vtxo(&self) -> Option<ArkoorVtxo> {
		let tx = self.unsigned_transaction();
		let outputs = self.outputs();

		outputs.get(CHANGE_VOUT as usize).map(|_txout| ArkoorVtxo {
			input: self.input.clone().into(),
			output_specs: self.outputs(),
			point: OutPoint::new(tx.compute_txid(), CHANGE_VOUT),
			signature: None,
		})
	}

	pub fn unsigned_htlc_vtxo(&self) -> ArkoorVtxo {
		let tx = self.unsigned_transaction();

		ArkoorVtxo {
			input: self.input.clone().into(),
			output_specs: self.outputs(),
			point: OutPoint::new(tx.compute_txid(), HTLC_VOUT),
			signature: None,
		}
	}

	pub fn output_vtxos(&self) -> Vec<ArkoorVtxo> {
		iter::once(self.unsigned_htlc_vtxo())
			.chain(self.unsigned_change_vtxo().into_iter())
			.collect()
	}

	pub fn sign_asp(
		&self,
		keypair: &Keypair,
		user_nonce: musig::MusigPubNonce,
	) -> (musig::MusigPubNonce, musig::MusigPartialSignature) {
		let sighash = self.htlc_sighash();
		assert_eq!(keypair.public_key(), self.input.asp_pubkey());
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
	) -> SignedBolt11Payment {
		let sighash = self.htlc_sighash();

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
		debug_assert!(SECP.verify_schnorr(
			&final_sig,
			&sighash.into(),
			&self.input.spec().taproot_pubkey(),
		).is_ok(), "invalid htlc tx signature produced");

		SignedBolt11Payment {
			payment: self,
			signature: final_sig,
		}
	}
}

impl Encodable for Bolt11Payment {}
impl Decodable for Bolt11Payment {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedBolt11Payment {
	pub payment: Bolt11Payment,
	pub signature: schnorr::Signature,
}

impl SignedBolt11Payment {
	pub fn validate_signature(
		&self,
		secp: &secp256k1::Secp256k1<impl secp256k1::Verification>,
	) -> Result<(), InvalidSignatureError> {
		let sighash = self.payment.htlc_sighash();
		let pubkey = self.payment.input.spec().taproot_pubkey();
		let msg = secp256k1::Message::from_digest(*sighash.as_byte_array());
		if secp.verify_schnorr(&self.signature, &msg, &pubkey).is_err() {
			return Err(InvalidSignatureError { pubkey });
		}
		Ok(())
	}

	pub fn change_vtxo(&self) -> Option<ArkoorVtxo> {
		self.payment.unsigned_change_vtxo().map(|mut vtxo| {
			vtxo.signature = Some(self.signature);
			vtxo
		})
	}

	pub fn htlc_vtxo(&self) -> ArkoorVtxo {
		let mut vtxo = self.payment.unsigned_htlc_vtxo();
		vtxo.signature = Some(self.signature);
		vtxo
	}

	pub fn revocation_payment(&self) -> OorPayment {
		let htlc_vtxo = Vtxo::from(self.htlc_vtxo());

		let pay_req = PaymentRequest {
			pubkey: htlc_vtxo.spec().user_pubkey,
			amount: htlc_vtxo.amount(),
			spk: VtxoSpkSpec::Exit,
		};

		OorPayment {
			asp_pubkey: htlc_vtxo.asp_pubkey(),
			exit_delta: self.payment.exit_delta,
			input: htlc_vtxo,
			outputs: vec![pay_req],
		}
	}
}

impl Encodable for SignedBolt11Payment {}
impl Decodable for SignedBolt11Payment {}

#[derive(Debug, thiserror::Error)]
#[error("invalid signature for pubkey {pubkey}")]
pub struct InvalidSignatureError {
	pub pubkey: XOnlyPublicKey,
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
	Failed,
}

impl fmt::Display for PaymentStatus {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		fmt::Debug::fmt(self, f)
	}
}

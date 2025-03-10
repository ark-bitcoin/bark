
use std::{fmt, io, iter};

use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Weight, Witness};
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{self, schnorr, Keypair, PublicKey, XOnlyPublicKey};
use bitcoin::taproot::TaprootSpendInfo;
use lightning_invoice::Bolt11Invoice;

use bitcoin_ext::{fee, P2TR_DUST, P2TR_DUST_SAT, P2WSH_DUST, TAPROOT_KEYSPEND_WEIGHT};

use crate::{musig, util, Vtxo, VtxoId, VtxoSpec};

const HTLC_VOUT: u32 = 0;
const CHANGE_VOUT: u32 = 1;

/// The minimum fee we consider for an HTLC transaction.
pub const HTLC_MIN_FEE: Amount = P2TR_DUST;

#[derive(Debug, Serialize, Deserialize)]
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

impl Bolt11Payment {
	pub fn check_amounts(&self) -> bool {
		let inputs = self.inputs.iter().map(|v| v.amount()).sum::<Amount>();
		//TODO(stevenroose) account for relay fee
		inputs >= (self.payment_amount + self.forwarding_fee + P2WSH_DUST)
	}

	pub fn htlc_taproot(&self) -> TaprootSpendInfo {
		let payment_hash = self.invoice.payment_hash();

		let asp_branch = util::hash_and_sign(*payment_hash, self.asp_pubkey.x_only_public_key().0);
		let client_branch = util::delay_timelock_sign(self.htlc_expiry_delta, self.htlc_expiry, self.user_pubkey.x_only_public_key().0);

		let combined_pk = musig::combine_keys([self.user_pubkey, self.asp_pubkey]);
		bitcoin::taproot::TaprootBuilder::new()
			.add_leaf(1, asp_branch).unwrap()
			.add_leaf(1, client_branch).unwrap()
			.finalize(&util::SECP, combined_pk).unwrap()
	}

	pub fn htlc_spk(&self) -> ScriptBuf {
		let taproot = self.htlc_taproot();
		ScriptBuf::new_p2tr_tweaked(taproot.output_key())
	}

	fn change_txout(&self) -> Option<TxOut> {
		let amount = self.change_amount();
		if  amount > Amount::ZERO {
			let spk = crate::vtxo::exit_spk(self.user_pubkey, self.asp_pubkey, self.exit_delta);
			Some(TxOut {
				value: amount,
				script_pubkey: spk,
			})
		} else {
			None
		}
	}

	fn htlc_output(&self, amount: Amount) -> TxOut {
		TxOut {
			value: amount,
			script_pubkey: self.htlc_spk()
		}
	}

	pub fn change_amount(&self) -> Amount {
		let input_amount = self.inputs.iter().map(|vtxo| vtxo.amount()).fold(Amount::ZERO, |a,b| a+b);
		let payment_amount = self.payment_amount;
		let forwarding_fee = self.forwarding_fee;
		let dust_amount = Amount::from_sat(P2TR_DUST_SAT);
		input_amount - payment_amount - forwarding_fee - dust_amount
	}

	pub fn unsigned_transaction(&self) -> Transaction {
		let input_amount = self.inputs.iter().map(|vtxo| vtxo.amount()).sum::<Amount>();
		let payment_amount = self.payment_amount;

		// This is the fee collected by the ASP for forwarding the payment
		// We will calculate this later as base_fee + ppm * payment_amount
		//
		// The ASP uses this to pay for it's operation and pay for all routing-fees.
		// The ASP can set this number similarly to how an LSP using trampoline payments would do it.
		let forwarding_fee = self.forwarding_fee;

		let dust_amount = Amount::from_sat(P2TR_DUST_SAT);
		let htlc_amount = payment_amount + forwarding_fee;

		// Just checking the computed fees work
		// Our input's should equal our outputs + onchain fees
		let change_output = self.change_txout();
		let change_amount = change_output.as_ref().map(|o| o.value).unwrap_or_default();

		assert_eq!(input_amount, htlc_amount + dust_amount + change_amount,
			"htlc = {htlc_amount}, dust={dust_amount}, change={change_amount}",
		);

		// Let's draft the output transactions
		let htlc_output = self.htlc_output(htlc_amount);
		let dust_anchor_output = fee::dust_anchor();

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
				.chain(Some(dust_anchor_output))
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
		let tx = self.unsigned_transaction();

		let prevouts = self.inputs.iter().map(|v| v.spec().txout()).collect::<Vec<_>>();
		let prevouts = bitcoin::sighash::Prevouts::All(&prevouts);

		let mut shc = bitcoin::sighash::SighashCache::new(tx);
		(0..self.inputs.len()).map(|idx| {
			shc.taproot_key_spend_signature_hash(
				idx, &prevouts, bitcoin::TapSighashType::Default,
			).expect("sighash error")
		}).collect()
	}

	pub fn unsigned_change_vtxo(&self) -> Option<Bolt11ChangeVtxo> {
		let tx = self.unsigned_transaction();
		let expiry_height = self.inputs.iter().map(|i| i.spec().expiry_height).min().unwrap();

		self.change_txout().map(|txout| {
			Bolt11ChangeVtxo {
				inputs: self.inputs.clone(),
				pseudo_spec: VtxoSpec {
					amount: txout.value,
					exit_delta: self.exit_delta,
					expiry_height: expiry_height,
					asp_pubkey: self.asp_pubkey,
					user_pubkey: self.user_pubkey,
				},
				final_point: OutPoint::new(tx.compute_txid(), CHANGE_VOUT),
				htlc_tx: tx,
			}
		})
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

	pub fn encode(&self) -> Vec<u8> {
		let mut buf = Vec::new();
		ciborium::into_writer(self, &mut buf).unwrap();
		buf
	}

	pub fn decode(bytes: &[u8]) -> Result<Self, ciborium::de::Error<io::Error>> {
		ciborium::from_reader(bytes)
	}
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignedBolt11Payment {
	pub payment: Bolt11Payment,
	pub signatures: Vec<schnorr::Signature>,
}

impl SignedBolt11Payment {
	pub fn validate_signatures(
		&self,
		secp: &secp256k1::Secp256k1<impl secp256k1::Verification>,
	) -> Result<(), InvalidSignature> {
		for (idx, sighash) in self.payment.htlc_sighashes().into_iter().enumerate() {
			let sig = self.signatures.get(idx).ok_or(InvalidSignature::Missing { idx })?;
			let pubkey = self.payment.inputs[idx].spec().taproot_pubkey();
			let msg = secp256k1::Message::from_digest(*sighash.as_byte_array());
			if secp.verify_schnorr(sig, &msg, &pubkey).is_err() {
				return Err(InvalidSignature::Invalid { idx, pubkey });
			}
		}
		Ok(())
	}

	pub fn change_vtxo(&self) -> Option<Bolt11ChangeVtxo> {
		self.payment.unsigned_change_vtxo().map(|mut vtxo| {
			util::fill_taproot_sigs(&mut vtxo.htlc_tx, &self.signatures);
			//TODO(stevenroose) there seems to be a bug in the vtxo.htlc_tx.weight method,
			// this +2 might be fixed later
			debug_assert_eq!(vtxo.htlc_tx.weight(), self.payment.total_weight() + Weight::from_wu(2));
			vtxo
		})
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

#[derive(Debug)]
pub enum InvalidSignature {
	Missing {
		idx: usize,
	},
	Invalid {
		idx: usize,
		pubkey: XOnlyPublicKey,
	},
}

impl fmt::Display for InvalidSignature {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		fmt::Debug::fmt(self, f)
	}
}
impl std::error::Error for InvalidSignature {}

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

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Bolt11ChangeVtxo {
	pub inputs: Vec<Vtxo>,
	/// This has the fields for the spec, but were not necessarily
	/// actually being used for the generation of the vtxos.
	/// Primarily, the expiry height is the first of all the parents
	/// expiry heights.
	pub pseudo_spec: VtxoSpec,
	pub htlc_tx: Transaction,
	pub final_point: OutPoint,
}

impl Bolt11ChangeVtxo {
	pub fn id(&self) -> VtxoId {
		self.final_point.into()
	}
}
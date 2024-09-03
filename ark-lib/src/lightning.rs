use crate::{fee::{dust_anchor, DUST_ANCHOR_SIZE}, util, Vtxo, P2TR_DUST_SAT};
use bitcoin::{taproot::TaprootSpendInfo, Amount, Sequence, ScriptBuf, Transaction, TxIn, TxOut, Witness};
use bitcoin::secp256k1::PublicKey;
use lightning_invoice::Bolt11Invoice;

use crate::musig;

pub struct Bolt11PaymentDetails {
	bolt11_invoice: Bolt11Invoice,
	inputs: Vec<Vtxo>,
	asp_pubkey: PublicKey,
	user_pubkey: PublicKey,
	payment_amount: Amount,
	forwarding_fee: Amount,
	/// Set the HTLC
	htlc_delta: u16,
	/// Relative time-lock enforced on claiming the HTLC expiry
	htlc_expiry_delta: u16,
	/// The expiration-height of the HTLC granted from client to ASP
	htlc_expiry: u32,
	exit_delta: u16,
}

impl Bolt11PaymentDetails {

	pub fn htlc_taproot(&self) -> TaprootSpendInfo {
		let payment_hash = self.bolt11_invoice.payment_hash();

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

	fn change_output(&self, amount: Amount) -> TxOut {
		let spk = crate::exit_spk(self.user_pubkey, self.asp_pubkey, self.exit_delta);
		TxOut {
			value: amount,
			script_pubkey: spk,
		}
	}

	fn htlc_output(&self, amount: Amount) -> TxOut {
		TxOut {
			value: amount,
			script_pubkey: self.htlc_spk()
		}
	}

	pub fn unsigned_transaction(&self) -> Transaction {
		let input_amount = self.inputs.iter().map(|vtxo| vtxo.amount()).fold(Amount::ZERO, |a,b| a+b);

		let payment_amount =self.payment_amount;

		// To ensure this transaction can be relayed we need to put in a
		// transaction fee. We currently set it to a few hundred sats
		// TODO: Provide a proper value
		// TODO: Can we delete this once tx-relay 1c1p is merged?
		let onchain_fee = Amount::from_sat(500);

		// This is the fee collected by the ASP for forwarding the payment
		// We will calculate this later as base_fee + ppm * payment_amount
		//
		// The ASP uses this to pay for it's operation and pay for all routing-fees.
		// The ASP can set this number similarly to how an LSP using trampoline payments would do it.
		let forwarding_fee = self.forwarding_fee;


		let dust_amount = Amount::from_sat(P2TR_DUST_SAT);
		let change_amount = input_amount - payment_amount - forwarding_fee - onchain_fee - dust_amount;
		let htlc_amount = payment_amount + forwarding_fee;

		// Just checking the computed fees work
		// Our input's should equal our outputs + onchain fees
		assert_eq!(input_amount, payment_amount + htlc_amount + onchain_fee + dust_amount);

		// Let's draft the output transactions
		let change_output = self.change_output(change_amount);
		let htlc_output = self.htlc_output(htlc_amount);
		let dust_anchor_output = dust_anchor();

		Transaction {
			version: bitcoin::blockdata::transaction::Version::TWO,
			lock_time: bitcoin::absolute::LockTime::ZERO,
			input: self.inputs.iter().map(|vtxo| {
				TxIn {
					previous_output: vtxo.point(),
					script_sig: ScriptBuf::new(),
					sequence: Sequence::from_height(self.htlc_delta),
					witness: Witness::new()
				}
			}).collect(),
			output: vec![
				htlc_output, change_output, dust_anchor_output
				]
		}
	}
}

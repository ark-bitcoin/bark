//! The payout script of an expiry payout.

use bitcoin::secp256k1::PublicKey;
use bitcoin::ScriptBuf;

use crate::SECP;

/// The output that a server in expiry payout mode pays the expired VTXOs
/// of owner mailbox `M` to: the BIP-86 Taproot key-path output `tr(M)`.
pub fn payout_script(mailbox: PublicKey) -> ScriptBuf {
	ScriptBuf::new_p2tr(&SECP, mailbox.x_only_public_key().0, None)
}

#[cfg(test)]
mod test {
	use bitcoin::{Amount, OutPoint, Sequence, Transaction, TxIn, TxOut, Txid, Witness};
	use bitcoin::absolute::LockTime;
	use bitcoin::hashes::Hash;
	use bitcoin::secp256k1::{schnorr, Keypair, Message};
	use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
	use bitcoin::transaction::Version;
	use bitcoin_ext::KeypairExt;

	use crate::ProtocolEncoding;
	use crate::mailbox::MailboxAuthorization;

	use super::*;

	/// The mailbox key `M` signs mailbox authorizations and the payout
	/// output. One kind of signature cannot replace the other.
	#[test]
	fn mailbox_authorization_cannot_spend_the_payout() {
		let mailbox = Keypair::from_seckey_slice(&SECP, &[6; 32]).unwrap();
		let authorization = MailboxAuthorization::new(&mailbox, chrono::Local::now() + chrono::Duration::hours(1));
		let encoded = authorization.serialize();
		// The signature is the last field of the encoding.
		let sig_at = encoded.len() - 64;
		let auth_sig = schnorr::Signature::from_slice(&encoded[sig_at..]).unwrap();

		let prevout = TxOut { value: Amount::from_sat(10_000), script_pubkey: payout_script(mailbox.public_key()) };
		let spend = Transaction {
			version: Version::TWO,
			lock_time: LockTime::ZERO,
			input: vec![TxIn {
				previous_output: OutPoint::new(Txid::from_byte_array([1; 32]), 0),
				script_sig: ScriptBuf::new(),
				sequence: Sequence::MAX,
				witness: Witness::new(),
			}],
			output: vec![prevout.clone()],
		};
		let sighash: Message = SighashCache::new(&spend)
			.taproot_key_spend_signature_hash(0, &Prevouts::All(&[prevout]), TapSighashType::Default)
			.unwrap().into();
		let output_key = mailbox.for_keyspend_only(&SECP);
		let spend_sig = SECP.sign_schnorr_no_aux_rand(&sighash, &output_key);

		assert!(SECP.verify_schnorr(&auth_sig, &sighash, &output_key.x_only_public_key().0).is_err());

		let mut with_spend_sig = encoded.clone();
		with_spend_sig[sig_at..].copy_from_slice(spend_sig.as_ref());
		assert!(!MailboxAuthorization::deserialize(&with_spend_sig).unwrap().verify());
	}
}

pub mod checkpoint;
pub mod checkpointed_package;

use bitcoin::{Transaction, TxOut};
use bitcoin::sighash::{self, SighashCache, TapSighash, TapSighashType};


pub fn arkoor_sighash(prevout: &TxOut, arkoor_tx: &Transaction) -> TapSighash {
	let mut shc = SighashCache::new(arkoor_tx);

	shc.taproot_key_spend_signature_hash(
		0, &sighash::Prevouts::All(&[prevout]), TapSighashType::Default,
	).expect("sighash error")
}

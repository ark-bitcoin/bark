

use bitcoin::{OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Weight, Witness};
use bitcoin::sighash::{self, SighashCache, TapSighash, TapSighashType};

use crate::{fee, util, Vtxo};
use crate::connectors::ConnectorChain;


//TODO(stevenroose) fix
pub const SIGNED_FORFEIT_TX_WEIGHT: Weight = Weight::from_vb_unchecked(0);

pub fn create_forfeit_tx(vtxo: &Vtxo, connector: OutPoint) -> Transaction {
	Transaction {
		version: bitcoin::transaction::Version::TWO,
		lock_time: bitcoin::absolute::LockTime::ZERO,
		input: vec![
			TxIn {
				previous_output: vtxo.point(),
				sequence: Sequence::MAX,
				script_sig: ScriptBuf::new(),
				witness: Witness::new(),
			},
			TxIn {
				previous_output: connector,
				sequence: Sequence::MAX,
				script_sig: ScriptBuf::new(),
				witness: Witness::new(),
			},
		],
		output: vec![
			TxOut {
				// we gain the dust amount from the connector output
				value: vtxo.amount() + fee::DUST,
				script_pubkey: ScriptBuf::new_p2tr(&util::SECP, vtxo.spec().combined_pubkey(), None),
			},
			fee::dust_anchor(),
		],
	}
}

pub fn forfeit_sighash(vtxo: &Vtxo, connector: OutPoint) -> (TapSighash, Transaction) {
	let spec = vtxo.spec();
	let exit_spk = spec.exit_spk();
	let exit_prevout = TxOut {
		script_pubkey: exit_spk,
		value: vtxo.amount(),
	};
	let connector_prevout = TxOut {
		script_pubkey: ConnectorChain::output_script(spec.asp_pubkey),
		value: fee::DUST,
	};
	let tx = create_forfeit_tx(vtxo, connector);
	let sighash = SighashCache::new(&tx).taproot_key_spend_signature_hash(
		0,
		&sighash::Prevouts::All(&[exit_prevout, connector_prevout]),
		TapSighashType::Default,
	).expect("sighash error");
	(sighash, tx)
}

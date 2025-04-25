

use bitcoin::secp256k1::schnorr;
use bitcoin::{OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Weight, Witness};
use bitcoin::secp256k1::PublicKey;
use bitcoin::sighash::{self, SighashCache, TapSighash, TapSighashType};

use bitcoin_ext::{fee, P2WSH_DUST};

use crate::Vtxo;
use crate::connectors::ConnectorChain;
use crate::util::SECP;


//TODO(stevenroose) fix
pub const SIGNED_FORFEIT_TX_WEIGHT: Weight = Weight::from_vb_unchecked(0);

pub fn create_forfeit_tx(
	vtxo: &Vtxo,
	connector: OutPoint,
	forfeit_sig: Option<&schnorr::Signature>,
	connector_sig: Option<&schnorr::Signature>,
) -> Transaction {
	Transaction {
		version: bitcoin::transaction::Version(3),
		lock_time: bitcoin::absolute::LockTime::ZERO,
		input: vec![
			TxIn {
				previous_output: vtxo.point(),
				sequence: Sequence::MAX,
				script_sig: ScriptBuf::new(),
				witness: forfeit_sig.map(|s| Witness::from_slice(&[&s[..]])).unwrap_or_default(),
			},
			TxIn {
				previous_output: connector,
				sequence: Sequence::MAX,
				script_sig: ScriptBuf::new(),
				witness: connector_sig.map(|s| Witness::from_slice(&[&s[..]])).unwrap_or_default(),
			},
		],
		output: vec![
			TxOut {
				value: vtxo.amount(),
				script_pubkey: ScriptBuf::new_p2tr(&SECP, vtxo.spec().asp_pubkey.into(), None),
			},
			fee::fee_anchor(),
		],
	}
}

fn forfeit_input_sighash(
	vtxo: &Vtxo,
	connector: OutPoint,
	connector_pk: PublicKey,
	input_idx: usize,
) -> (TapSighash, Transaction) {
	let spec = vtxo.spec();
	let exit_prevout = TxOut {
		script_pubkey: spec.vtxo_spk(),
		value: vtxo.amount(),
	};
	let connector_prevout = TxOut {
		script_pubkey: ConnectorChain::output_script(connector_pk),
		value: P2WSH_DUST,
	};
	let tx = create_forfeit_tx(vtxo, connector, None, None);
	let sighash = SighashCache::new(&tx).taproot_key_spend_signature_hash(
		input_idx,
		&sighash::Prevouts::All(&[exit_prevout, connector_prevout]),
		TapSighashType::Default,
	).expect("sighash error");
	(sighash, tx)
}

/// The sighash of the exit tx input of a forfeit tx.
pub fn forfeit_sighash_exit(
	vtxo: &Vtxo,
	connector: OutPoint,
	connector_pk: PublicKey,
) -> (TapSighash, Transaction) {
	forfeit_input_sighash(vtxo, connector, connector_pk, 0)
}

/// The sighash of the connector input of a forfeit tx.
pub fn forfeit_sighash_connector(
	vtxo: &Vtxo,
	connector: OutPoint,
	connector_pk: PublicKey,
) -> (TapSighash, Transaction) {
	forfeit_input_sighash(vtxo, connector, connector_pk, 1)
}

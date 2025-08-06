

use std::borrow::BorrowMut;

use anyhow::Context;
use bitcoin::secp256k1::{Keypair, SecretKey};
use bitcoin::{psbt, sighash, taproot, Psbt, Witness};
use bitcoin_ext::KeypairExt;
use log::trace;

use crate::SECP;


#[derive(Debug, Clone, Deserialize, Serialize)]
pub enum SweepMeta {
	Board,
	Connector(SecretKey),
	Vtxo,
}

const PROP_KEY_PREFIX: &'static [u8] = "bark-server".as_bytes();

enum PropKey {
	SweepMeta = 1,
}

lazy_static::lazy_static! {
	static ref PROP_KEY_SWEEP_META: psbt::raw::ProprietaryKey = psbt::raw::ProprietaryKey {
		prefix: PROP_KEY_PREFIX.to_vec(),
		subtype: PropKey::SweepMeta as u8,
		key: Vec::new(),
	};
}

pub trait PsbtInputExt: BorrowMut<psbt::Input> {
	fn set_sweep_meta(&mut self, meta: SweepMeta) {
		let encoded = rmp_serde::to_vec_named(&meta).expect("serde serialization");
		self.borrow_mut().proprietary.insert(PROP_KEY_SWEEP_META.clone(), encoded);
	}

	fn get_sweep_meta(&self) -> anyhow::Result<Option<SweepMeta>> {
		for (key, val) in &self.borrow().proprietary {
			if *key == *PROP_KEY_SWEEP_META {
				let meta = rmp_serde::from_slice(&val[..]).context("corrupt psbt: SweepMeta")?;
				return Ok(Some(meta));
			}
		}
		Ok(None)
	}
}
impl PsbtInputExt for psbt::Input {}


pub trait PsbtExt: BorrowMut<Psbt> {
	fn try_sign_sweeps(&mut self, server_key: &Keypair) -> anyhow::Result<()> {
		let psbt = self.borrow_mut();

		let mut shc = sighash::SighashCache::new(&psbt.unsigned_tx);
		let prevouts = psbt.inputs.iter()
			.map(|i| i.witness_utxo.clone().unwrap())
			.collect::<Vec<_>>();

		for (idx, input) in psbt.inputs.iter_mut().enumerate() {
			if let Some(meta) = input.get_sweep_meta().context("corrupt psbt")? {
				match meta {
					// board and vtxo happen to be exactly the same signing logic
					SweepMeta::Vtxo | SweepMeta::Board => {
						let (control, (script, lv)) = input.tap_scripts.iter().next()
							.context("corrupt psbt: missing tap_scripts")?;
						let leaf_hash = taproot::TapLeafHash::from_script(script, *lv);
						let sighash = shc.taproot_script_spend_signature_hash(
							idx,
							&sighash::Prevouts::All(&prevouts),
							leaf_hash,
							sighash::TapSighashType::Default,
						).expect("all prevouts provided");
						trace!("Signing expired VTXO input for sighash {}", sighash);
						let sig = SECP.sign_schnorr(&sighash.into(), &server_key);
						let wit = Witness::from_slice(
							&[&sig[..], script.as_bytes(), &control.serialize()],
						);
						debug_assert!(
							wit.size() <= ark::tree::signed::NODE_SPEND_WEIGHT.to_wu() as usize,
							"weight: {}, NODE_SPEND_WEIGHT: {}",
							wit.size(), ark::tree::signed::NODE_SPEND_WEIGHT.to_wu(),
						);
						input.final_script_witness = Some(wit);
					},
					SweepMeta::Connector(key) => {
						let sighash = shc.taproot_key_spend_signature_hash(
							idx,
							&sighash::Prevouts::All(&prevouts),
							sighash::TapSighashType::Default,
						).expect("all prevouts provided");
						trace!("Signing expired connector input for sighash {}", sighash);
						let keypair = Keypair::from_secret_key(&*SECP, &key).for_keyspend(&*SECP);
						let sig = SECP.sign_schnorr(&sighash.into(), &keypair);
						input.final_script_witness = Some(Witness::from_slice(&[&sig[..]]));
					},
				}
			}
		}
		Ok(())
	}
}
impl PsbtExt for Psbt {}

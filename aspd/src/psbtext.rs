

use std::borrow::BorrowMut;

use anyhow::Context;
use bitcoin::key::Keypair;
use bitcoin::{psbt, sighash, taproot, Psbt, Witness};
use bitcoin_ext::KeypairExt;

use crate::SECP;


#[derive(Debug, Clone, Deserialize, Serialize)]
pub enum SweepMeta {
	Onboard,
	Connector,
	Vtxo,
}

const PROP_KEY_PREFIX: &'static [u8] = "aspd".as_bytes();

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
		let mut buf = Vec::new();
		ciborium::into_writer(&meta, &mut buf).expect("can't fail");
		self.borrow_mut().proprietary.insert(PROP_KEY_SWEEP_META.clone(), buf);
	}

	fn get_sweep_meta(&self) -> anyhow::Result<Option<SweepMeta>> {
		for (key, val) in &self.borrow().proprietary {
			if *key == *PROP_KEY_SWEEP_META {
				let meta = ciborium::from_reader(&val[..]).context("corrupt psbt: SweepMeta")?;
				return Ok(Some(meta));
			}
		}
		Ok(None)
	}
}
impl PsbtInputExt for psbt::Input {}


pub trait PsbtExt: BorrowMut<Psbt> {
	fn try_sign_sweeps(&mut self, asp_key: &Keypair) -> anyhow::Result<()> {
		let psbt = self.borrow_mut();

		let mut shc = sighash::SighashCache::new(&psbt.unsigned_tx);
		let prevouts = psbt.inputs.iter()
			.map(|i| i.witness_utxo.clone().unwrap())
			.collect::<Vec<_>>();

		let connector_key = asp_key.for_keyspend(&*SECP);
		for (idx, input) in psbt.inputs.iter_mut().enumerate() {
			if let Some(meta) = input.get_sweep_meta().context("corrupt psbt")? {
				match meta {
					// onboard and vtxo happen to be exactly the same signing logic
					SweepMeta::Vtxo | SweepMeta::Onboard => {
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
						let sig = SECP.sign_schnorr(&sighash.into(), &asp_key);
						let wit = Witness::from_slice(
							&[&sig[..], script.as_bytes(), &control.serialize()],
						);
						debug_assert_eq!(wit.size(), ark::tree::signed::NODE_SPEND_WEIGHT.to_wu() as usize);
						input.final_script_witness = Some(wit);
					},
					SweepMeta::Connector => {
						let sighash = shc.taproot_key_spend_signature_hash(
							idx,
							&sighash::Prevouts::All(&prevouts),
							sighash::TapSighashType::Default,
						).expect("all prevouts provided");
						trace!("Signing expired connector input for sighash {}", sighash);
						let sig = SECP.sign_schnorr(&sighash.into(), &connector_key);
						input.final_script_witness = Some(Witness::from_slice(&[sig[..].to_vec()]));
					},
				}
			}
		}
		Ok(())
	}
}
impl PsbtExt for Psbt {}

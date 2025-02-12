

use std::borrow::BorrowMut;

use anyhow::Context;
use bitcoin::psbt;


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



use std::borrow::BorrowMut;

use anyhow::Context;
use bitcoin::psbt;


#[derive(Debug, Clone, Deserialize, Serialize)]
pub enum RoundMeta {
	Connector,
	Vtxo,
}

const PROP_KEY_PREFIX: &'static [u8] = "aspd".as_bytes();

lazy_static::lazy_static! {
	static ref PROP_KEY_ROUND_META: psbt::raw::ProprietaryKey = psbt::raw::ProprietaryKey {
		prefix: PROP_KEY_PREFIX.to_vec(),
		subtype: PropKey::RoundMeta as u8,
		key: Vec::new(),
	};
}

enum PropKey {
	RoundMeta = 1,
}

pub trait PsbtInputExt: BorrowMut<psbt::Input> {
	fn set_round_meta(&mut self, meta: RoundMeta) {
		let mut buf = Vec::new();
		ciborium::into_writer(&meta, &mut buf).expect("can't fail");
		self.borrow_mut().proprietary.insert(PROP_KEY_ROUND_META.clone(), buf);
	}

	fn get_round_meta(&self) -> anyhow::Result<Option<RoundMeta>> {
		for (key, val) in &self.borrow().proprietary {
			if *key == *PROP_KEY_ROUND_META {
				let meta = ciborium::from_reader(&val[..]).context("corrupt psbt: RoundMeta")?;
				return Ok(Some(meta));
			}
		}
		Ok(None)
	}
}

impl PsbtInputExt for psbt::Input {}

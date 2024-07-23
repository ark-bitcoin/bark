

use std::borrow::BorrowMut;

use anyhow::Context;
use bitcoin::{psbt, Txid};
use bitcoin::hashes::Hash;


#[derive(Debug, Clone, Deserialize, Serialize)]
pub enum RoundMeta {
	Connector,
	Vtxo,
}

const PROP_KEY_PREFIX: &'static [u8] = "aspd".as_bytes();

enum PropKey {
	RoundMeta = 1,
}

fn prop_key_round_meta(id: Txid) -> psbt::raw::ProprietaryKey {
	psbt::raw::ProprietaryKey {
		prefix: PROP_KEY_PREFIX.to_vec(),
		subtype: PropKey::RoundMeta as u8,
		key: id[..].to_vec(),
	}
}

pub trait PsbtInputExt: BorrowMut<psbt::Input> {
	fn set_round_meta(&mut self, round_id: Txid, meta: RoundMeta) {
		let mut buf = Vec::new();
		ciborium::into_writer(&meta, &mut buf).expect("can't fail");
		self.borrow_mut().proprietary.insert(prop_key_round_meta(round_id), buf);
	}

	fn get_round_meta(&self) -> anyhow::Result<Option<(Txid, RoundMeta)>> {
		for (key, val) in &self.borrow().proprietary {
			if key.prefix == PROP_KEY_PREFIX && key.subtype == PropKey::RoundMeta as u8 {
				let txid = Txid::from_slice(&key.key).context("corrupt psbt: Txid")?;
				let meta = ciborium::from_reader(&val[..]).context("corrupt psbt: RoundMeta")?;
				return Ok(Some((txid, meta)));
			}
		}
		Ok(None)
	}
}

impl PsbtInputExt for psbt::Input {}

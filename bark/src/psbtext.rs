

use std::borrow::BorrowMut;

use bitcoin::psbt;

use crate::exit;


const PROP_KEY_PREFIX: &'static [u8] = "bark".as_bytes();

enum PropKey {
	ClaimInput = 1,
}

lazy_static::lazy_static! {
	static ref PROP_KEY_CLAIM_INPUT: psbt::raw::ProprietaryKey = psbt::raw::ProprietaryKey {
		prefix: PROP_KEY_PREFIX.to_vec(),
		subtype: PropKey::ClaimInput as u8,
		key: Vec::new(),
	};
}

//TODO(stevenroose) the "corrupt psbt" expects are only safe if all psbts stay
// within internal use, if we ever share them for communication or in a db,
// they need to return errors
pub trait PsbtInputExt: BorrowMut<psbt::Input> {
	fn set_claim_input(&mut self, input: &exit::ClaimInput) {
		self.borrow_mut().proprietary.insert(PROP_KEY_CLAIM_INPUT.clone(), input.encode());
	}

	fn get_claim_input(&self) -> Option<exit::ClaimInput> {
		self.borrow().proprietary.get(&*PROP_KEY_CLAIM_INPUT)
			.map(|e| exit::ClaimInput::decode(&e).expect("corrupt psbt"))
	}
}

impl PsbtInputExt for psbt::Input {}

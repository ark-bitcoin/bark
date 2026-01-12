
use std::borrow::Borrow;

use anyhow::Context;
use bitcoin::{Amount, Script, Weight};

use ark::ArkInfo;
use ark::offboard::OffboardRequest;


/// Extension trait for [ArkInfo] used in the bark crate
pub trait ArkInfoExt: Borrow<ArkInfo> {
	fn calculate_offboard_fee(&self, destination: &Script) -> anyhow::Result<Amount> {
		Ok(OffboardRequest::calculate_fee(
			&destination,
			self.borrow().offboard_feerate,
			Weight::from_vb(self.borrow().offboard_fixed_fee_vb as u64)
				.context("invalid offboard_fixed_fee_vb from server")?,
		).context("offboard fee calculation overflow")?)
	}
}

impl ArkInfoExt for ArkInfo {}

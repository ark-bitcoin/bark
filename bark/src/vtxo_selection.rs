
use std::collections::HashSet;

use anyhow::Context;
use bitcoin_ext::BlockHeight;

use ark::{Vtxo, VtxoId};

use crate::Wallet;
use crate::persist::BarkPersister;

/// Trait needed to be implemented to filter wallet VTXOs.
///
/// See [`Wallet::vtxos_with`]. For easy filtering, see [VtxoFilter].
///
/// This trait is also implemented for `Fn(&Vtxo) -> anyhow::Result<bool>`.
/// ```
/// use bitcoin::Amount;
/// use bark::ark::Vtxo;
/// use bark::vtxo_selection::FilterVtxos;
///
/// let vtxos = vec![];
///
/// fn very_large(vtxo: &Vtxo) -> anyhow::Result<bool> {
///		Ok(vtxo.amount() > Amount::from_sat(1000))
/// }
/// let result = FilterVtxos::filter(&very_large, vtxos);
/// ```
pub trait FilterVtxos {
	fn filter(&self, vtxos: Vec<Vtxo>) -> anyhow::Result<Vec<Vtxo>>;
}

impl<F> FilterVtxos for F
where
	F: Fn(&Vtxo) -> anyhow::Result<bool>,
{
	fn filter(&self, mut vtxos: Vec<Vtxo>) -> anyhow::Result<Vec<Vtxo>> {
		for i in (0..vtxos.len()).rev() {
			let vtxo = &vtxos[i];
			if !self(&vtxo)? {
				vtxos.swap_remove(i);
			}
		}
		Ok(vtxos)
	}
}

/// Filter vtxos based on criteria.
///
/// Builder pattern is used.
pub struct VtxoFilter<'a, P: BarkPersister> {
	/// Include vtxos that expire before the given height.
	pub expires_before: Option<BlockHeight>,
	/// If true, include vtxos that have counterparty risk.
	pub counterparty: bool,
	/// Exclude certain vtxos.
	pub exclude: HashSet<VtxoId>,
	/// Force include certain vtxos.
	pub include: HashSet<VtxoId>,

	wallet: &'a Wallet<P>,
}

impl<'a, P: BarkPersister> VtxoFilter<'a, P> {
	pub fn new(wallet: &'a Wallet<P>) -> VtxoFilter<'a, P> {
		VtxoFilter {
			expires_before: None,
			counterparty: false,
			exclude: HashSet::new(),
			include: HashSet::new(),
			wallet: wallet,
		}
	}

	fn matches(&self, vtxo: &Vtxo) -> anyhow::Result<bool> {
		let id = vtxo.id();

		// First do explicit includes and excludes.
		if self.include.contains(&id) {
			return Ok(true);
		}
		if self.exclude.contains(&id) {
			return Ok(false);
		}

		if let Some(height) = self.expires_before {
			if (vtxo.spec().expiry_height) < height {
				return Ok(true);
			}
		}

		if self.counterparty {
			if self.wallet.has_counterparty_risk(vtxo).context("db error")? {
				return Ok(true);
			}
		}

		Ok(false)
	}

	/// Include vtxos that expire before the given height.
	pub fn expires_before(mut self, expires_before: BlockHeight) -> Self {
		self.expires_before = Some(expires_before);
		self
	}

	/// Include vtxos that have counterparty risk.
	pub fn counterparty(mut self) -> Self {
		self.counterparty = true;
		self
	}

	/// Exclude the given vtxo.
	pub fn exclude(mut self, exclude: VtxoId) -> Self {
		self.exclude.insert(exclude);
		self
	}

	/// Exclude the given vtxos.
	pub fn exclude_many(mut self, exclude: impl IntoIterator<Item = VtxoId>) -> Self {
		self.exclude.extend(exclude);
		self
	}

	/// Include the given vtxo.
	pub fn include(mut self, include: VtxoId) -> Self {
		self.include.insert(include);
		self
	}

	/// Include the given vtxos.
	pub fn include_many(mut self, include: impl IntoIterator<Item = VtxoId>) -> Self {
		self.include.extend(include);
		self
	}
}

impl<P: BarkPersister> FilterVtxos for VtxoFilter<'_, P> {
	fn filter(&self, mut vtxos: Vec<Vtxo>) -> anyhow::Result<Vec<Vtxo>> {
		for i in (0..vtxos.len()).rev() {
			let vtxo = &vtxos[i];
			if !self.matches(&vtxo)? {
				vtxos.swap_remove(i);
			}
		}
		Ok(vtxos)
	}
}

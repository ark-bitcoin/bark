
use std::collections::HashSet;

use anyhow::Context;
use bitcoin_ext::BlockHeight;

use ark::{Vtxo, VtxoId};
use log::warn;

use crate::{exit::progress::util::estimate_exit_cost, Wallet};


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
pub struct VtxoFilter<'a> {
	/// Include vtxos that expire before the given height.
	pub expires_before: Option<BlockHeight>,
	/// If true, include vtxos that have counterparty risk.
	pub counterparty: bool,
	/// Exclude certain vtxos.
	pub exclude: HashSet<VtxoId>,
	/// Force include certain vtxos.
	pub include: HashSet<VtxoId>,

	wallet: &'a Wallet,
}

impl<'a> VtxoFilter<'a> {
	pub fn new(wallet: &'a Wallet) -> VtxoFilter<'a> {
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
			if (vtxo.expiry_height()) < height {
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

impl FilterVtxos for VtxoFilter<'_> {
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

enum InnerRefreshStrategy {
	MustRefresh,
	ShouldRefresh,
}

pub struct RefreshStrategy<'a> {
	inner: InnerRefreshStrategy,
	tip: BlockHeight,
	wallet: &'a Wallet,
}

impl<'a> RefreshStrategy<'a> {
	pub fn must_refresh(wallet: &'a Wallet, tip: BlockHeight) -> Self {
		Self {
			inner: InnerRefreshStrategy::MustRefresh,
			tip,
			wallet,
		}
	}

	pub fn should_refresh(wallet: &'a Wallet, tip: BlockHeight) -> Self {
		Self {
			inner: InnerRefreshStrategy::ShouldRefresh,
			tip,
			wallet,
		}
	}
}

impl FilterVtxos for RefreshStrategy<'_> {
	fn filter(&self, vtxos: Vec<Vtxo>) -> anyhow::Result<Vec<Vtxo>> {
		match self.inner {
			InnerRefreshStrategy::MustRefresh => {
				Ok(vtxos.into_iter().filter(|vtxo| {
					if let Some(max_arkoor_depth) = self.wallet.ark_info().map(|i| i.max_arkoor_depth) {
						if vtxo.arkoor_depth() >= max_arkoor_depth {
							warn!("VTXO {} reached max OOR depth {}, must be refreshed", vtxo.id(), max_arkoor_depth);
							return true;
						}
					}

					if self.tip > vtxo.spec().expiry_height.saturating_sub(self.wallet.config().vtxo_refresh_threshold) {
						warn!("VTXO {} is about to expire soon, must be refreshed", vtxo.id());
						return true;
					}

					false
				}).collect::<Vec<_>>())
			},
			InnerRefreshStrategy::ShouldRefresh => {
				Ok(vtxos.into_iter().filter(|vtxo| {
					let soft_depth_threshold = self.wallet.ark_info().map(|i| i.max_arkoor_depth - 1);
					if let Some(max_oor_depth) = soft_depth_threshold {
						if vtxo.arkoor_depth() >= max_oor_depth {
							warn!("VTXO {} is about to become too deep, should be refreshed on next opportunity", vtxo.id());
							return true;
						}
					}

					let soft_threshold = self.wallet.config().vtxo_refresh_threshold + 28;
					if self.tip > vtxo.spec().expiry_height.saturating_sub(soft_threshold) {
						warn!("VTXO {} is about to expire, should be refreshed on next opportunity", vtxo.id());
						return true;
					}

					let fr = self.wallet.onchain.chain.urgent_feerate();
					if vtxo.amount() < estimate_exit_cost(&[vtxo.clone()], fr) {
						warn!("VTXO {} is uneconomical to exit, should be refreshed on next opportunity", vtxo.id());
						return true;
					}

					false
				}).collect::<Vec<_>>())
			},
		}
	}
}
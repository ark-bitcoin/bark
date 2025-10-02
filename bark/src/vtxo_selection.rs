//! VTXO selection and filtering utilities.
//!
//! This module provides reusable filters to select subsets of wallet VTXOs for various workflows.
//! The primary interface to facilitate this is the [FilterVtxos] trait, which is accepted by
//! methods such as [Wallet::vtxos_with] and [Wallet::inround_vtxos_with] to filter VTXOs based on
//! custom logic or ready-made builders.
//!
//! Provided filters:
//! - [VtxoFilter]: A builder to match VTXOs by criteria such as expiry height, counterparty risk,
//!   and explicit include/exclude lists.
//! - [RefreshStrategy]: Selects VTXOs that must or should be refreshed preemptively based on
//!   depth, expiry proximity, and economic viability.
//!
//! Usage examples
//!
//! Custom predicate via [FilterVtxos]:
//! ```rust
//! use anyhow::Result;
//! use bitcoin::Amount;
//! use bark::WalletVtxo;
//! use bark::vtxo_selection::FilterVtxos;
//!
//! fn is_large(v: &WalletVtxo) -> Result<bool> {
//!     Ok(v.amount() >= Amount::from_sat(50_000))
//! }
//!
//! # fn demo(mut vtxos: Vec<WalletVtxo>) -> Result<Vec<WalletVtxo>> {
//! let selected = FilterVtxos::filter(&is_large, vtxos)?;
//! # Ok(selected) }
//! ```
//!
//! Builder style with [VtxoFilter]:
//! ```rust
//! use bitcoin_ext::BlockHeight;
//! use bark::vtxo_selection::{FilterVtxos, VtxoFilter};
//!
//! # fn example(wallet: &bark::Wallet, vtxos: Vec<bark::WalletVtxo>) -> anyhow::Result<Vec<bark::WalletVtxo>> {
//! let tip: BlockHeight = 1_000;
//! let filter = VtxoFilter::new(wallet)
//!     .expires_before(tip + 144) // expiring within ~1 day
//!     .counterparty();           // and/or with counterparty risk
//! let expiring_or_risky = filter.filter(vtxos)?;
//! # Ok(expiring_or_risky) }
//! ```
//!
//! Notes on semantics
//! - Include/exclude precedence: an ID in `include` always matches; an ID in `exclude` never
//!   matches. These take precedence over other criteria.
//! - Criteria are OR'ed together: a [WalletVtxo] matches if any enabled criterion matches (after applying
//!   include/exclude).
//! - “Counterparty risk” is wallet-defined and indicates a [WalletVtxo] may be invalidated by another
//!   party; see [VtxoFilter::counterparty].
//!
//! See also:
//! - [Wallet::vtxos_with]
//! - [Wallet::inround_vtxos_with]
//!
//! The intent is to allow users to filter VTXOs based on different parameters.

use std::collections::HashSet;

use anyhow::Context;
use bitcoin::FeeRate;
use bitcoin_ext::BlockHeight;

use ark::VtxoId;
use log::warn;

use crate::{exit::progress::util::estimate_exit_cost, Wallet, WalletVtxo};

/// Trait needed to be implemented to filter wallet VTXOs.
///
/// See [`Wallet::vtxos_with`]. For easy filtering, see [VtxoFilter].
///
/// This trait is also implemented for `Fn(&WalletVtxo) -> anyhow::Result<bool>`.
pub trait FilterVtxos {
	fn filter(&self, vtxos: Vec<WalletVtxo>) -> anyhow::Result<Vec<WalletVtxo>>;
}

impl<F> FilterVtxos for F
where
	F: Fn(&WalletVtxo) -> anyhow::Result<bool>,
{
	fn filter(&self, mut vtxos: Vec<WalletVtxo>) -> anyhow::Result<Vec<WalletVtxo>> {
		for i in (0..vtxos.len()).rev() {
			if !self(&vtxos[i])? {
				vtxos.swap_remove(i);
			}
		}
		Ok(vtxos)
	}
}

/// Filter vtxos based on criteria.
///
/// Builder pattern is used.
///
/// Matching semantics:
/// - Explicit `include` and `exclude` lists have the highest priority.
/// - Remaining criteria (expiry, counterparty risk) are combined with OR: if any matches, the VTXO
///   is kept.
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
	/// Create a new [VtxoFilter] bound to a wallet context.
	///
	/// The wallet is used to evaluate properties such as counterparty risk.
	/// By default, the filter matches nothing until criteria are added.
	///
	/// Examples
	/// ```
	/// # fn demo(wallet: &bark::Wallet) -> anyhow::Result<Vec<bark::WalletVtxo>> {
	/// use bark::vtxo_selection::{VtxoFilter, FilterVtxos};
	/// use bitcoin_ext::BlockHeight;
	///
	/// let tip: BlockHeight = 1_000;
	/// let filter = VtxoFilter::new(wallet)
	///     .expires_before(tip + 144) // expiring within ~1 day
	///     .counterparty();           // or with counterparty risk
	/// let filtered = wallet.vtxos_with(&filter)?;
	/// # Ok(filtered) }
	/// ```
	pub fn new(wallet: &'a Wallet) -> VtxoFilter<'a> {
		VtxoFilter {
			expires_before: None,
			counterparty: false,
			exclude: HashSet::new(),
			include: HashSet::new(),
			wallet,
		}
	}

	fn matches(&self, vtxo: &WalletVtxo) -> anyhow::Result<bool> {
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
	///
	/// Examples
	/// ```
	/// # fn demo(wallet: &bark::Wallet) -> anyhow::Result<Vec<bark::WalletVtxo>> {
	/// use bark::vtxo_selection::{VtxoFilter, FilterVtxos};
	/// use bitcoin_ext::BlockHeight;
	///
	/// let h: BlockHeight = 10_000;
	/// let filter = VtxoFilter::new(wallet)
	///     .expires_before(h);
	/// let filtered = wallet.vtxos_with(&filter)?;
	/// # Ok(filtered) }
	/// ```
	pub fn expires_before(mut self, expires_before: BlockHeight) -> Self {
		self.expires_before = Some(expires_before);
		self
	}

	/// Include vtxos that have counterparty risk.
	///
	/// An arkoor vtxo is considered to have some counterparty risk if it's (directly or not) based
	/// on round VTXOs that aren't owned by the wallet.
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
	fn filter(&self, mut vtxos: Vec<WalletVtxo>) -> anyhow::Result<Vec<WalletVtxo>> {
		for i in (0..vtxos.len()).rev() {
			if !self.matches(&vtxos[i])? {
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

/// Strategy to select VTXOs that need proactive refreshing.
///
/// Refreshing is recommended when a VTXO is nearing its expiry, has reached a soft/hard
/// out-of-round depth threshold, or is uneconomical to exit onchain at the current fee rate.
///
/// Variants:
/// - [RefreshStrategy::must_refresh]: strict selection intended for mandatory refresh actions
///   (e.g., at or beyond maximum depth or near-hard expiry threshold).
/// - [RefreshStrategy::should_refresh]: softer selection for opportunistic refreshes
///   (e.g., approaching soft thresholds or uneconomical unilateral exit).
///
/// This type implements [FilterVtxos], so it can be passed directly to
/// [`Wallet::vtxos_with`] or [`Wallet::inround_vtxos_with`].
pub struct RefreshStrategy<'a> {
	inner: InnerRefreshStrategy,
	tip: BlockHeight,
	wallet: &'a Wallet,
	fee_rate: FeeRate,
}

impl<'a> RefreshStrategy<'a> {
	/// Builds a strategy that matches VTXOs that must be refreshed immediately.
	///
	/// A [WalletVtxo] is selected when at least one of the following strict conditions holds:
	/// - It reached or exceeded the maximum allowed out-of-round (OOR) depth (if configured by the
	///   Ark server info in the wallet).
	/// - It is within `vtxo_refresh_expiry_threshold` blocks of expiry at `tip`.
	///
	/// Parameters:
	/// - `wallet`: [Wallet] context used to read configuration and Ark parameters.
	/// - `tip`: Current chain tip height used to evaluate expiry proximity.
	/// - `fee_rate`: [FeeRate] to use for any economic checks (kept for parity with the
	///   "should" strategy; not all checks require it in the strict mode).
	///
	/// Returns:
	/// - A [RefreshStrategy] implementing [FilterVtxos]. Pass it to [Wallet::vtxos_with] or call
	///   [FilterVtxos::filter] directly.
	///
	/// Examples
	/// ```
	/// # fn demo(wallet: &bark::Wallet, vtxos: Vec<bark::WalletVtxo>) -> anyhow::Result<Vec<bark::WalletVtxo>> {
	/// use bark::vtxo_selection::{FilterVtxos, RefreshStrategy};
	/// use bitcoin::FeeRate;
	/// use bitcoin_ext::BlockHeight;
	///
	/// let tip: BlockHeight = 200_000;
	/// let fr = FeeRate::from_sat_per_vb(5).unwrap();
	/// let must = RefreshStrategy::must_refresh(wallet, tip, fr);
	/// let to_refresh_now = must.filter(vtxos)?;
	/// # Ok(to_refresh_now) }
	/// ```
	pub fn must_refresh(wallet: &'a Wallet, tip: BlockHeight, fee_rate: FeeRate) -> Self {
		Self {
			inner: InnerRefreshStrategy::MustRefresh,
			tip,
			wallet,
			fee_rate,
		}
	}

	/// Builds a strategy that matches VTXOs that should be refreshed soon (opportunistic).
	///
	/// A [WalletVtxo] is selected when at least one of the following softer conditions holds:
	/// - It is at or beyond a soft OOR depth threshold (typically one less than the maximum, if
	///   configured by the Ark server info in the wallet).
	/// - It is within a softer expiry window (e.g., `vtxo_refresh_expiry_threshold + 28` blocks)
	///   relative to `tip`.
	/// - It is uneconomical to unilaterally exit at the provided `fee_rate` (e.g., its amount is
	///   lower than the estimated exit cost).
	///
	/// Parameters:
	/// - `wallet`: [Wallet] context used to read configuration and Ark parameters.
	/// - `tip`: Current chain tip height used to evaluate expiry proximity.
	/// - `fee_rate`: [FeeRate] used for economic feasibility checks.
	///
	/// Returns:
	/// - A [RefreshStrategy] implementing [FilterVtxos]. Pass it to [Wallet::vtxos_with] or call
	///   [FilterVtxos::filter] directly.
	///
	/// Examples
	/// ```
	/// # fn demo(wallet: &bark::Wallet, vtxos: Vec<bark::WalletVtxo>) -> anyhow::Result<Vec<bark::WalletVtxo>> {
	/// use bark::vtxo_selection::{FilterVtxos, RefreshStrategy};
	/// use bitcoin::FeeRate;
	/// use bitcoin_ext::BlockHeight;
	///
	/// let tip: BlockHeight = 200_000;
	/// let fr = FeeRate::from_sat_per_vb(8).unwrap();
	/// let should = RefreshStrategy::should_refresh(wallet, tip, fr);
	/// let to_refresh_soon = should.filter(vtxos)?;
	/// # Ok(to_refresh_soon) }
	/// ```
	pub fn should_refresh(wallet: &'a Wallet, tip: BlockHeight, fee_rate: FeeRate) -> Self {
		Self {
			inner: InnerRefreshStrategy::ShouldRefresh,
			tip,
			wallet,
			fee_rate,
		}
	}
}

impl FilterVtxos for RefreshStrategy<'_> {
	fn filter(&self, vtxos: Vec<WalletVtxo>) -> anyhow::Result<Vec<WalletVtxo>> {
		match self.inner {
			InnerRefreshStrategy::MustRefresh => {
				Ok(vtxos.into_iter().filter(|vtxo| {
					if let Some(max_arkoor_depth) = self.wallet.ark_info().map(|i| i.max_arkoor_depth) {
						if vtxo.arkoor_depth() >= max_arkoor_depth {
							warn!("VTXO {} reached max OOR depth {}, must be refreshed", vtxo.id(), max_arkoor_depth);
							return true;
						}
					}

					if self.tip > vtxo.spec().expiry_height.saturating_sub(self.wallet.config().vtxo_refresh_expiry_threshold) {
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

					let soft_threshold = self.wallet.config().vtxo_refresh_expiry_threshold + 28;
					if self.tip > vtxo.spec().expiry_height.saturating_sub(soft_threshold) {
						warn!("VTXO {} is about to expire, should be refreshed on next opportunity", vtxo.id());
						return true;
					}

					let fr = self.fee_rate;
					if vtxo.amount() < estimate_exit_cost(&[vtxo.vtxo.clone()], fr) {
						warn!("VTXO {} is uneconomical to exit, should be refreshed on next opportunity", vtxo.id());
						return true;
					}

					false
				}).collect::<Vec<_>>())
			},
		}
	}
}

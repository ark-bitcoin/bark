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
//! use bark::vtxo::FilterVtxos;
//!
//! fn is_large(v: &WalletVtxo) -> Result<bool> {
//!     Ok(v.amount() >= Amount::from_sat(50_000))
//! }
//!
//! # async fn demo(mut vtxos: Vec<WalletVtxo>) -> Result<Vec<WalletVtxo>> {
//! FilterVtxos::filter_vtxos(&is_large, &mut vtxos).await?;
//! # Ok(vtxos) }
//! ```
//!
//! Builder style with [VtxoFilter]:
//! ```rust
//! use bitcoin_ext::BlockHeight;
//! use bark::vtxo::{FilterVtxos, VtxoFilter};
//!
//! # async fn example(wallet: &bark::Wallet, mut vtxos: Vec<bark::WalletVtxo>) -> anyhow::Result<Vec<bark::WalletVtxo>> {
//! let tip: BlockHeight = 1_000;
//! let filter = VtxoFilter::new(wallet)
//!     .expires_before(tip + 144) // expiring within ~1 day
//!     .counterparty();           // and/or with counterparty risk
//! filter.filter_vtxos(&mut vtxos).await?;
//! # Ok(vtxos) }
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

use std::borrow::Borrow;
use std::collections::HashSet;

use anyhow::Context;
use bitcoin::FeeRate;
use log::{debug, warn};

use ark::VtxoId;
use bitcoin_ext::{BlockDelta, BlockHeight, P2TR_DUST};

use crate::Wallet;
use crate::exit::progress::util::estimate_exit_cost;
use crate::vtxo::state::{VtxoStateKind, WalletVtxo};

const SOFT_REFRESH_EXPIRY_THRESHOLD: BlockDelta = 28;

/// Trait needed to be implemented to filter wallet VTXOs.
///
/// See [`Wallet::vtxos_with`]. For easy filtering, see [VtxoFilter].
///
/// This trait is also implemented for `Fn(&WalletVtxo) -> anyhow::Result<bool>`.
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait FilterVtxos: Send + Sync {
	/// Check whether the VTXO mathes this filter
	async fn matches(&self, vtxo: &WalletVtxo) -> anyhow::Result<bool>;

	/// Eliminate from the vector all non-matching VTXOs
	async fn filter_vtxos<V: Borrow<WalletVtxo> + Send>(&self, vtxos: &mut Vec<V>) -> anyhow::Result<()> {
		for i in (0..vtxos.len()).rev() {
			if !self.matches(vtxos[i].borrow()).await? {
				vtxos.swap_remove(i);
			}
		}
		Ok(())
	}
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl<F> FilterVtxos for F
where
	F: Fn(&WalletVtxo) -> anyhow::Result<bool> + Send + Sync,
{
	async fn matches(&self, vtxo: &WalletVtxo) -> anyhow::Result<bool> {
	    self(vtxo)
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
	/// # async fn demo(wallet: &bark::Wallet) -> anyhow::Result<Vec<bark::WalletVtxo>> {
	/// use bark::vtxo::{VtxoFilter, FilterVtxos};
	/// use bitcoin_ext::BlockHeight;
	///
	/// let tip: BlockHeight = 1_000;
	/// let filter = VtxoFilter::new(wallet)
	///     .expires_before(tip + 144) // expiring within ~1 day
	///     .counterparty();           // or with counterparty risk
	/// let filtered = wallet.spendable_vtxos_with(&filter).await?;
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

	/// Include vtxos that expire before the given height.
	///
	/// Examples
	/// ```
	/// # async fn demo(wallet: &bark::Wallet) -> anyhow::Result<Vec<bark::WalletVtxo>> {
	/// use bark::vtxo::{VtxoFilter, FilterVtxos};
	/// use bitcoin_ext::BlockHeight;
	///
	/// let h: BlockHeight = 10_000;
	/// let filter = VtxoFilter::new(wallet)
	///     .expires_before(h);
	/// let filtered = wallet.spendable_vtxos_with(&filter).await?;
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

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl FilterVtxos for VtxoFilter<'_> {
	async fn matches(&self, vtxo: &WalletVtxo) -> anyhow::Result<bool> {
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
			if self.wallet.has_counterparty_risk(vtxo).await.context("db error")? {
				return Ok(true);
			}
		}

		Ok(false)
	}
}

/// Determines how VTXOs get filtered when deciding whether to refresh them.
enum InnerRefreshStrategy {
	/// Includes a VTXO absolutely must be refreshed, for example, if it is about to expire.
	MustRefresh,
	/// Includes a VTXO that should be refreshed soon, for example, if it's approaching expiry, is
	/// uneconomical to exit, or is dust. This will also include VTXOs that meet the
	/// [InnerRefreshStrategy::MustRefresh] criteria.
	ShouldRefreshInclusive,
	/// Same as [InnerRefreshStrategy::ShouldRefreshInclusive], but it excludes VTXOs that meet the
	/// [InnerRefreshStrategy::MustRefresh] criteria.
	ShouldRefreshExclusive,
	/// If any VTXOs _MUST_ be refreshed, then both _MUST_ and _SHOULD_ VTXOs will be included.
	ShouldRefreshIfMustRefresh,
}

/// Strategy to select VTXOs that need proactive refreshing.
///
/// Refreshing is recommended when a VTXO is nearing its expiry, has reached a soft/hard
/// out-of-round depth threshold, or is uneconomical to exit onchain at the current fee rate.
///
/// Variants:
/// - [RefreshStrategy::must_refresh]: strict selection intended for mandatory refresh actions
///   (e.g., at near expiry threshold).
/// - [RefreshStrategy::should_refresh]: softer selection for opportunistic refreshes
///   (e.g., approaching expiry thresholds or uneconomical unilateral exit).
/// - [RefreshStrategy::should_refresh_exclusive]: same as [RefreshStrategy::should_refresh], but
///   excludes VTXOs that meet the [RefreshStrategy::must_refresh] criteria.
/// - [RefreshStrategy::should_refresh_if_must]: same as [RefreshStrategy::should_refresh], but
///   only keeps the _SHOULD_ VTXOs if at least one VTXO meets the _MUST_ criteria.
///
/// Notes:
/// - This type implements [FilterVtxos], so it can be passed directly to [`Wallet::vtxos_with`].
/// - Calling [FilterVtxos::matches] on [RefreshStategy::should_result_if_must] is invalid.
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
	/// - It is within `vtxo_refresh_expiry_threshold` blocks of expiry at `tip`.
	/// - Its exit depth has reached `max_vtxo_exit_depth` as advertised by the server, meaning the
	///   server will refuse to cosign any further OOR payments spending it.
	///
	/// Parameters:
	/// - `wallet`: [Wallet] context used to read configuration and Ark parameters.
	/// - `tip`: Current chain tip height used to evaluate expiry proximity.
	/// - `fee_rate`: [FeeRate] to use for any economic checks (kept for parity with the
	///   "should" strategy; not all checks require it in the strict mode).
	///
	/// Returns:
	/// - A [RefreshStrategy] implementing [FilterVtxos]. Pass it to [Wallet::vtxos_with] or call
	///   [FilterVtxos::filter_vtxos] directly.
	///
	/// Examples
	/// ```
	/// # async fn demo(wallet: &bark::Wallet, mut vtxos: Vec<bark::WalletVtxo>) -> anyhow::Result<Vec<bark::WalletVtxo>> {
	/// use bark::vtxo::{FilterVtxos, RefreshStrategy};
	/// use bitcoin::FeeRate;
	/// use bitcoin_ext::BlockHeight;
	///
	/// let tip: BlockHeight = 200_000;
	/// let fr = FeeRate::from_sat_per_vb(5).unwrap();
	/// let must = RefreshStrategy::must_refresh(wallet, tip, fr);
	/// must.filter_vtxos(&mut vtxos).await?;
	/// # Ok(vtxos) }
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
	/// - It is within a softer expiry window (e.g., `vtxo_refresh_expiry_threshold + 28` blocks)
	///   relative to `tip`.
	/// - It is uneconomical to unilaterally exit at the provided `fee_rate` (e.g., its amount is
	///   lower than the estimated exit cost).
	/// - Its exit depth has reached half of the server's `max_vtxo_exit_depth` limit
	///   (ensuring proactive refresh well before hitting the hard ceiling).
	///
	/// Parameters:
	/// - `wallet`: [Wallet] context used to read configuration and Ark parameters.
	/// - `tip`: Current chain tip height used to evaluate expiry proximity.
	/// - `fee_rate`: [FeeRate] used for economic feasibility checks.
	///
	/// Returns:
	/// - A [RefreshStrategy] implementing [FilterVtxos]. Pass it to [Wallet::vtxos_with] or call
	///   [FilterVtxos::filter_vtxos] directly.
	///
	/// Examples
	/// ```
	/// # async fn demo(wallet: &bark::Wallet, mut vtxos: Vec<bark::WalletVtxo>) -> anyhow::Result<Vec<bark::WalletVtxo>> {
	/// use bark::vtxo::{FilterVtxos, RefreshStrategy};
	/// use bitcoin::FeeRate;
	/// use bitcoin_ext::BlockHeight;
	///
	/// let tip: BlockHeight = 200_000;
	/// let fr = FeeRate::from_sat_per_vb(8).unwrap();
	/// let should = RefreshStrategy::should_refresh(wallet, tip, fr);
	/// should.filter_vtxos(&mut vtxos).await?;
	/// # Ok(vtxos) }
	/// ```
	pub fn should_refresh(wallet: &'a Wallet, tip: BlockHeight, fee_rate: FeeRate) -> Self {
		Self {
			inner: InnerRefreshStrategy::ShouldRefreshInclusive,
			tip,
			wallet,
			fee_rate,
		}
	}

	/// Same as [RefreshStrategy::should_refresh] but it filters out VTXOs which meet the
	/// [RefreshStrategy::must_refresh] criteria.
	pub fn should_refresh_exclusive(
		wallet: &'a Wallet,
		tip: BlockHeight,
		fee_rate: FeeRate,
	) -> Self {
		Self {
			inner: InnerRefreshStrategy::ShouldRefreshExclusive,
			tip,
			wallet,
			fee_rate,
		}
	}

	/// Similar to calling [RefreshStrategy::must_refresh] and then
	/// [RefreshStrategy::should_refresh_exclusive], but it only keeps the _SHOULD_ VTXOs if at
	/// least one VTXO meets the _MUST_ criteria.
	pub fn should_refresh_if_must(wallet: &'a Wallet, tip: BlockHeight, fee_rate: FeeRate) -> Self {
		Self {
			inner: InnerRefreshStrategy::ShouldRefreshIfMustRefresh,
			tip,
			wallet,
			fee_rate,
		}
	}

	/// Returns the `max_vtxo_exit_depth` advertised by the server, or `None` if the wallet
	/// has no active server connection.
	async fn server_max_arkoor_depth(&self) -> anyhow::Result<Option<u16>> {
		Ok(self.wallet.ark_info().await?.map(|i| i.max_vtxo_exit_depth))
	}

	/// Checks if a VTXO must be refreshed based on its exit depth and expiry height.
	async fn check_must_refresh(&self, vtxo: &WalletVtxo) -> anyhow::Result<bool> {
		// Check if the VTXO's exit depth has reached the server maximum.
		if let Some(max_depth) = self.server_max_arkoor_depth().await? {
			if vtxo.exit_depth() >= max_depth {
				warn!(
					"VTXO {} exit depth {} has reached the server maximum of {}; \
					 must be refreshed before further OOR payments are possible",
					vtxo.id(), vtxo.exit_depth(), max_depth,
				);
				return Ok(true);
			}
		}

		// Check if the VTXO's expiry height is within the refresh threshold.
		let threshold = self.wallet.config().vtxo_refresh_expiry_threshold;
		if self.tip > vtxo.expiry_height() {
			warn!("VTXO {} is expired, must be refreshed", vtxo.id());
			return Ok(true)
		} else if self.tip > vtxo.expiry_height().saturating_sub(threshold) {
			debug!("VTXO {} is about to expire soon, must be refreshed", vtxo.id());
			return Ok(true);
		}

		Ok(false)
	}

	/// Checks if a VTXO should be refreshed based on its exit depth, expiry height
	/// whether it is uneconomical to exit, or whether it is dust.
	async fn check_should_refresh_depth(&self, vtxo: &WalletVtxo) -> anyhow::Result<bool> {
		// Check if the VTXO's exit depth has reached the server maximum.
		if let Some(max_depth) = self.server_max_arkoor_depth().await? {
			// Trigger refresh when exit depth reaches half the server limit.
			// This ensures the wallet stays well below the hard ceiling and
			// avoids hitting it unexpectedly during normal usage.
			let soft_depth_threshold = max_depth / 2;
			if vtxo.exit_depth() >= soft_depth_threshold {
				warn!(
					"VTXO {} exit depth {} is approaching the server maximum of {}; \
					 should be refreshed on next opportunity",
					vtxo.id(), vtxo.exit_depth(), max_depth,
				);
				return Ok(true);
			}
		}

		// Check if the VTXO's expiry height is within the refresh threshold.
		let soft_threshold = self.wallet.config().vtxo_refresh_expiry_threshold
			+ SOFT_REFRESH_EXPIRY_THRESHOLD as u32;
		if self.tip > vtxo.expiry_height().saturating_sub(soft_threshold) {
			warn!("VTXO {} is about to expire, should be refreshed on next opportunity",
				vtxo.id(),
			);
			return Ok(true);
		}

		// Check if the VTXO's amount is uneconomical to exit.
		let fr = self.fee_rate;
		if vtxo.amount() < estimate_exit_cost(&[vtxo.vtxo.clone()], fr) {
			warn!("VTXO {} is uneconomical to exit, should be refreshed on \
				next opportunity", vtxo.id(),
			);
			return Ok(true);
		}

		// Check if the VTXO's amount is below the dust threshold.
		if vtxo.amount() < P2TR_DUST {
			warn!("VTXO {} is dust, should be refreshed on next opportunity", vtxo.id());
			return Ok(true);
		}

		Ok(false)
	}
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl FilterVtxos for RefreshStrategy<'_> {
	async fn matches(&self, vtxo: &WalletVtxo) -> anyhow::Result<bool> {
		match self.inner {
			InnerRefreshStrategy::MustRefresh => Ok(self.check_must_refresh(vtxo).await?),
			InnerRefreshStrategy::ShouldRefreshInclusive => Ok(
				self.check_must_refresh(vtxo).await? ||
				self.check_should_refresh_depth(vtxo).await?
			),
			InnerRefreshStrategy::ShouldRefreshExclusive => Ok(
				!self.check_must_refresh(vtxo).await? &&
				self.check_should_refresh_depth(vtxo).await?
			),
			InnerRefreshStrategy::ShouldRefreshIfMustRefresh =>
				bail!("FilterVtxos::matches called on RefreshStrategy::should_refresh_if_must"),
		}
	}

	async fn filter_vtxos<V: Borrow<WalletVtxo> + Send>(
		&self,
		vtxos: &mut Vec<V>,
	) -> anyhow::Result<()> {
		match self.inner {
			InnerRefreshStrategy::ShouldRefreshIfMustRefresh => {
				let mut must_refresh = false;
				for i in (0..vtxos.len()).rev() {
					let keep = {
						let vtxo = vtxos[i].borrow();
						let is_must = self.check_must_refresh(vtxo).await?;
						if is_must {
							must_refresh = true;
							true
						} else {
							self.check_should_refresh_depth(vtxo).await?
						}
					};
					if !keep {
						vtxos.swap_remove(i);
					}
				}
				// We can safely clear the container since we should only keep the should-refresh
				// vtxos if we found at least one must-refresh vtxo.
				if !must_refresh {
					vtxos.clear();
				}
			},
			_ => {
				for i in (0..vtxos.len()).rev() {
					let vtxo = vtxos[i].borrow();
					if !self.matches(vtxo).await? {
						vtxos.swap_remove(i);
					}
				}
			},
		}
		Ok(())
	}
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl FilterVtxos for VtxoStateKind {
	async fn matches(&self, vtxo: &WalletVtxo) -> anyhow::Result<bool> {
	    Ok(vtxo.state.kind() == *self)
	}
}

//! Selection of wallet VTXOs to use as inputs to a payment.

use std::collections::HashSet;
use std::{cmp, fmt, mem, slice};

use anyhow::Context;
use bitcoin::Amount;
use log::trace;

use ark::VtxoId;
use ark::fees::VtxoFeeInfo;
use bitcoin_ext::BlockHeight;

use crate::WalletVtxo;

/// A simple way to identify the purpose of an amount is to represent a fee.
pub type FeeAmount = Amount;

/// Maximum number of iterations in the fee-scheme variant of [InputSelection::select]
/// before we give up on the fee converging.
const MAX_FEE_ITERATIONS: usize = 100;

/// Parameters controlling which VTXOs may be selected as inputs for a payment.
///
/// Builder pattern is used. By default there is no limit on the number of inputs and no
/// VTXOs are excluded.
///
/// ```
/// use bitcoin::Amount;
/// use bark::vtxo::selection::InputSelection;
///
/// # fn demo(poisoned: ark::VtxoId, vtxos: Vec<bark::WalletVtxo>) -> anyhow::Result<()> {
/// let selected = InputSelection::new()
///     .max_inputs(10)       // use at most 10 VTXOs
///     .exclude(poisoned)    // never select this one
///     .select(vtxos, Amount::from_sat(100_000))?;
/// # Ok(()) }
/// ```
///
/// Adding a fee scheme with [InputSelection::fee_scheme] makes [InputSelection::select]
/// also cover the fee charged on top of the amount and return it alongside the VTXOs.
#[derive(Debug, Clone, Default)]
pub struct InputSelection<F = ()> {
	/// Cap on the total number of inputs that may be selected.
	pub max_inputs: Option<usize>,
	/// Never select these vtxos.
	pub exclude: HashSet<VtxoId>,

	fee_scheme: F,
}

impl<F> InputSelection<F> {
	/// Cap the total number of inputs that may be selected.
	pub fn max_inputs(mut self, max_inputs: usize) -> Self {
		self.max_inputs = Some(max_inputs);
		self
	}

	/// Exclude the given vtxo from selection.
	pub fn exclude(mut self, exclude: VtxoId) -> Self {
		self.exclude.insert(exclude);
		self
	}

	/// Exclude the given vtxos from selection.
	pub fn exclude_many(mut self, exclude: impl IntoIterator<Item = VtxoId>) -> Self {
		self.exclude.extend(exclude);
		self
	}
}

impl InputSelection {
	/// Create a new [InputSelection] with no input limit, no exclusions, and no fee scheme.
	pub fn new() -> InputSelection {
		Default::default()
	}

	/// Make the selection also cover the fee charged on top of the amount, where the fee
	/// itself depends on the selected VTXOs. E.g., a lightning payment, a send-onchain
	/// payment.
	///
	/// `calc_fee` receives the target amount and the [VtxoFeeInfo] of each selected VTXO
	/// (derived from the `tip` block height). [InputSelection::select] then returns the
	/// calculated fee alongside the selected VTXOs.
	pub fn fee_scheme<F>(self, tip: BlockHeight, calc_fee: F) -> InputSelection<FeeScheme<F>>
	where
		F: for<'a> Fn(Amount, SelectedFeeInfos<'a>) -> anyhow::Result<FeeAmount>,
	{
		InputSelection {
			max_inputs: self.max_inputs,
			exclude: self.exclude,
			fee_scheme: FeeScheme { tip, calc_fee },
		}
	}

	/// Select VTXOs from the given candidates to cover the provided amount.
	///
	/// Candidates are selected soonest-expiring-first; see [InputScanner::cover_amount] for
	/// how the input limit affects this. The selection is returned
	/// soonest-expiring-first.
	///
	/// Returns an error if the amount cannot be reached.
	pub fn select(
		&self,
		vtxos: Vec<WalletVtxo>,
		amount: Amount,
	) -> anyhow::Result<Vec<WalletVtxo>> {
		let mut scanner = InputScanner::new(self, vtxos);
		scanner.cover_amount(amount)?;
		Ok(scanner.into_selected())
	}
}

impl<F> InputSelection<FeeScheme<F>>
where
	F: for<'a> Fn(Amount, SelectedFeeInfos<'a>) -> anyhow::Result<FeeAmount>,
{
	/// Select VTXOs from the given candidates to cover the provided amount plus the fee
	/// computed by the configured [InputSelection::fee_scheme].
	///
	/// Candidates are selected soonest-expiring-first; see [InputScanner::cover_amount]
	/// for how the input limit affects this. The selection is returned
	/// soonest-expiring-first.
	///
	/// Returns a collection of VTXOs capable of covering the desired amount as well as the
	/// calculated fee.
	pub fn select(
		&self,
		vtxos: Vec<WalletVtxo>,
		amount: Amount,
	) -> anyhow::Result<(Vec<WalletVtxo>, FeeAmount)> {
		let mut scanner = InputScanner::new(self, vtxos);

		// We need to loop to find suitable inputs due to the VTXOs having a direct impact
		// on how much we must pay in fees. The required amount never shrinks between
		// iterations, so the scan can be resumed instead of restarted (see
		// [InputScanner::cover_amount]).
		let mut fee = Amount::ZERO;
		for _ in 0..MAX_FEE_ITERATIONS {
			let required = amount.checked_add(fee)
				.context("Amount + fee overflow")?;

			scanner.cover_amount(required)
				.context("Could not find enough suitable VTXOs to cover payment + fees")?;
			fee = (self.fee_scheme.calc_fee)(
				amount, scanner.selected_fee_infos(self.fee_scheme.tip),
			)?;

			let new_required = amount.checked_add(fee)
				.context("Amount + fee overflow")?;
			if new_required <= scanner.total() {
				trace!("Selected vtxos to cover amount + fee: amount = {}, fee = {}, total inputs = {}",
					amount, fee, scanner.total(),
				);
				return Ok((scanner.into_selected(), fee));
			}
			trace!("VTXO sum of {} did not exceed amount {} and fee {}, iterating again",
				scanner.total(), amount, fee,
			);
		}
		bail!("Fee calculation did not converge after maximum iterations")
	}
}

/// The fee configuration of an [InputSelection], set via [InputSelection::fee_scheme].
#[derive(Clone)]
pub struct FeeScheme<F> {
	tip: BlockHeight,
	calc_fee: F,
}

impl<F> fmt::Debug for FeeScheme<F> {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("FeeScheme")
			.field("tip", &self.tip)
			.finish_non_exhaustive()
	}
}

/// A resumable scan over selection candidates.
///
/// Construction applies the [InputSelection] exclusions and sorts the candidates
/// soonest-expiring-first. [InputScanner::cover_amount] then advances the scan; it may be
/// called repeatedly as long as the requested amounts never shrink, which lets the
/// fee-convergence loop grow an earlier selection instead of restarting it.
struct InputScanner {
	/// Eligible candidates, sorted soonest-expiring-first.
	candidates: Vec<WalletVtxo>,
	/// Index into `candidates` of the next candidate to consider.
	cursor: usize,
	/// Indices into `candidates` of the currently selected VTXOs.
	selected: Vec<usize>,
	/// Sum of the selected VTXO amounts.
	total: Amount,
	/// Cap on the size of `selected`.
	max_inputs: usize,
}

impl InputScanner {
	/// Takes ownership of the given candidates vector and sorts it soonest-expiring-first, ready
	/// for [InputScanner::cover_amount].
	fn new<F>(selection: &InputSelection<F>, mut candidates: Vec<WalletVtxo>) -> InputScanner {
		candidates.retain(|v| !selection.exclude.contains(&v.id()));
		candidates.sort_by_key(|v| v.expiry_height());

		let max_inputs = selection.max_inputs.unwrap_or(usize::MAX);
		let capacity = max_inputs.min(candidates.len());
		InputScanner {
			candidates,
			cursor: 0,
			selected: Vec::with_capacity(capacity),
			total: Amount::ZERO,
			max_inputs,
		}
	}

	/// Advances the scan until the selection covers `amount`, at which point the
	/// selection totals at least `amount` using at most `max_inputs` VTXOs.
	///
	/// Candidates are accepted soonest-expiring-first. Once the input limit is reached, a
	/// candidate can only enter the selection by replacing the smallest selected VTXO
	/// (the latest-expiring one on equal amounts, so that soon-expiring VTXOs stay
	/// selected). A replaced or skipped candidate can never become useful again — the
	/// selection always holds the largest VTXOs seen so far — so later calls with larger
	/// amounts can safely resume where the scan left off.
	///
	/// Returns an error if the candidates are exhausted before the amount is covered.
	fn cover_amount(&mut self, amount: Amount) -> anyhow::Result<()> {
		while self.total < amount {
			let Some(vtxo) = self.candidates.get(self.cursor) else {
				if self.candidates.len() > self.max_inputs {
					bail!("Insufficient money available. Needed {} but the best {} inputs \
						only amount to {}", amount, self.max_inputs, self.total,
					);
				}
				bail!("Insufficient money available. Needed {} but {} is available",
					amount, self.total,
				);
			};

			// We can safely add the input since we have room.
			if self.selected.len() < self.max_inputs {
				self.total = self.total.checked_add(vtxo.amount()).context("total overflow")?;
				self.selected.push(self.cursor);
			} else {
				// We should only accept the input if it's beneficial to do so
				if let Some(pos) = self.position_to_replace(vtxo.amount()) {
					let evicted = mem::replace(&mut self.selected[pos], self.cursor);
					self.total = self.total.checked_sub(self.candidates[evicted].amount())
						.context("total deduction overflow")?;
					self.total = self.total.checked_add(vtxo.amount())
						.context("total addition overflow")?;
				}
			}
			self.cursor += 1;
		}
		Ok(())
	}

	/// Returns the position in `selected` of the VTXO that a new candidate of the given
	/// amount should replace: the smallest selected VTXO, preferring the latest-expiring
	/// one on equal amounts. Returns `None` if the candidate doesn't improve the
	/// selection, i.e. it is no larger than the current minimum.
	fn position_to_replace(&self, candidate_amount: Amount) -> Option<usize> {
		// Candidates are sorted by expiry, so on equal amounts the highest index
		// expires last and is the preferred one to replace.
		let (pos, &idx) = self.selected.iter().enumerate()
			.min_by_key(|&(_, &idx)| (self.candidates[idx].amount(), cmp::Reverse(idx)))?;

		if candidate_amount > self.candidates[idx].amount() {
			Some(pos)
		} else {
			None
		}
	}

	fn total(&self) -> Amount {
		self.total
	}

	/// The [VtxoFeeInfo] of each currently selected VTXO, derived from the given chain tip.
	fn selected_fee_infos(&self, tip: BlockHeight) -> SelectedFeeInfos<'_> {
		SelectedFeeInfos {
			selected: self.selected.iter(),
			candidates: &self.candidates,
			tip,
		}
	}

	/// Consumes the scan, returning the selected VTXOs soonest-expiring-first.
	fn into_selected(self) -> Vec<WalletVtxo> {
		let InputScanner { candidates, mut selected, .. } = self;
		selected.sort();
		let mut selected = selected.into_iter().peekable();
		candidates.into_iter().enumerate()
			.filter(|(idx, _)| selected.next_if_eq(idx).is_some())
			.map(|(_, vtxo)| vtxo)
			.collect()
	}
}

/// Iterator yielding the [VtxoFeeInfo] of each selected VTXO, computed on the fly so fee
/// calculation doesn't require an allocation per fee-convergence iteration.
///
/// Passed to the `calc_fee` callback of [InputSelection::fee_scheme].
pub struct SelectedFeeInfos<'a> {
	selected: slice::Iter<'a, usize>,
	candidates: &'a [WalletVtxo],
	tip: BlockHeight,
}

impl Iterator for SelectedFeeInfos<'_> {
	type Item = VtxoFeeInfo;

	fn next(&mut self) -> Option<VtxoFeeInfo> {
		let vtxo = &self.candidates[*self.selected.next()?];
		Some(VtxoFeeInfo::from_vtxo_and_tip(vtxo, self.tip))
	}

	fn size_hint(&self) -> (usize, Option<usize>) {
		self.selected.size_hint()
	}
}

#[cfg(test)]
mod test {
	use super::*;

	use bitcoin::Weight;

	use ark::test_util::dummy::DummyTestVtxoSpec;

	use crate::vtxo::state::VtxoState;

	/// Builds a spendable [WalletVtxo] with the given amount and expiry height.
	///
	/// Use distinct amount/expiry combinations within a test: identical specs produce
	/// identical VTXO ids.
	fn dummy_wallet_vtxo(sats: u64, expiry_height: BlockHeight) -> WalletVtxo {
		let amount = Amount::from_sat(sats);
		let fee = Amount::from_sat(330);
		let (_, vtxo) = DummyTestVtxoSpec {
			amount: amount + fee,
			fee,
			expiry_height,
			..Default::default()
		}.build();
		assert_eq!(vtxo.amount(), amount);
		WalletVtxo {
			vtxo: vtxo.into_bare(),
			state: VtxoState::Spendable,
			exit_depth: 0,
			exit_tx_weight: Weight::ZERO,
		}
	}

	fn amounts(vtxos: &[WalletVtxo]) -> Vec<u64> {
		vtxos.iter().map(|v| v.amount().to_sat()).collect()
	}

	#[test]
	fn covers_soonest_expiring_first() {
		// Deliberately not in expiry order.
		let vtxos = vec![
			dummy_wallet_vtxo(30_000, 300),
			dummy_wallet_vtxo(10_000, 100),
			dummy_wallet_vtxo(20_000, 200),
		];
		let selection = InputSelection::new();

		let selected = selection.select(vtxos.clone(), Amount::from_sat(25_000)).unwrap();
		assert_eq!(amounts(&selected), [10_000, 20_000]);

		let selected = selection.select(vtxos.clone(), Amount::from_sat(60_000)).unwrap();
		assert_eq!(amounts(&selected), [10_000, 20_000, 30_000]);

		let err = selection.select(vtxos, Amount::from_sat(60_001)).unwrap_err();
		assert!(err.to_string().contains("Insufficient money"), "{}", err);
		assert!(!err.to_string().contains("inputs"), "{}", err);
	}

	#[test]
	fn max_inputs_replaces_smallest_selected() {
		let vtxos = vec![
			dummy_wallet_vtxo(10_000, 100),
			dummy_wallet_vtxo(20_000, 200),
			dummy_wallet_vtxo(30_000, 300),
		];
		let selection = InputSelection::new()
			.max_inputs(2);

		// No replacement needed: the two soonest-expiring VTXOs cover the amount.
		let selected = selection.select(vtxos.clone(), Amount::from_sat(25_000)).unwrap();
		assert_eq!(amounts(&selected), [10_000, 20_000]);

		// The soonest-expiring pair doesn't cover the amount, so the smallest selected
		// VTXO makes way for a bigger one.
		let selected = selection.select(vtxos.clone(), Amount::from_sat(40_000)).unwrap();
		assert_eq!(amounts(&selected), [20_000, 30_000]);

		// Not coverable with any two inputs.
		let err = selection.select(vtxos, Amount::from_sat(50_001)).unwrap_err();
		assert!(err.to_string().contains("best 2 inputs"), "{}", err);
	}

	#[test]
	fn max_inputs_evicts_latest_expiring_on_equal_amounts() {
		let soonest = dummy_wallet_vtxo(10_000, 100);
		let soonest_id = soonest.id();
		let vtxos = vec![
			soonest,
			dummy_wallet_vtxo(10_000, 200),
			dummy_wallet_vtxo(30_000, 300),
		];

		let selected = InputSelection::new()
			.max_inputs(2)
			.select(vtxos, Amount::from_sat(40_000)).unwrap();

		// Of the two equal-amount VTXOs, the soonest-expiring one stays selected.
		assert_eq!(amounts(&selected), [10_000, 30_000]);
		assert_eq!(selected[0].id(), soonest_id);
	}

	#[test]
	fn exclusions_are_never_selected() {
		let vtxos = vec![
			dummy_wallet_vtxo(10_000, 100),
			dummy_wallet_vtxo(20_000, 200),
			dummy_wallet_vtxo(30_000, 300),
		];
		let excluded = vtxos[1].id();

		let selected = InputSelection::new()
			.exclude(excluded)
			.select(vtxos, Amount::from_sat(20_000)).unwrap();

		assert_eq!(amounts(&selected), [10_000, 30_000]);
		assert!(selected.iter().all(|v| v.id() != excluded));
	}

	#[test]
	fn with_fee_resumes_the_scan_as_the_fee_grows() {
		let vtxos = vec![
			dummy_wallet_vtxo(10_000, 100),
			dummy_wallet_vtxo(20_000, 200),
		];

		// A flat fee: the first iteration selects 10k sats for the amount alone, the
		// second extends the selection to also cover the fee.
		let (selected, fee) = InputSelection::new()
			.fee_scheme(0, |_, _| Ok(Amount::from_sat(500)))
			.select(vtxos, Amount::from_sat(9_800)).unwrap();

		assert_eq!(amounts(&selected), [10_000, 20_000]);
		assert_eq!(fee, Amount::from_sat(500));
	}

	#[test]
	fn with_fee_respects_max_inputs() {
		let vtxos = vec![
			dummy_wallet_vtxo(10_000, 100),
			dummy_wallet_vtxo(20_000, 200),
		];

		// Amount plus fee doesn't fit in the soonest-expiring VTXO, and the input limit
		// forbids adding the second one, so the selection replaces the first.
		let (selected, fee) = InputSelection::new()
			.max_inputs(1)
			.fee_scheme(0, |_, _| Ok(Amount::from_sat(500)))
			.select(vtxos, Amount::from_sat(9_800)).unwrap();

		assert_eq!(amounts(&selected), [20_000]);
		assert_eq!(fee, Amount::from_sat(500));
	}
}

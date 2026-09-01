
//! In-memory HTLC ledger for a single payment hash.
//!
//! The ledger tracks granted, fulfilled, and revoked HTLCs and enforces two
//! invariants:
//!
//! 1. **Fulfillment invariant**: the total value of fulfilled incoming HTLCs
//!    must be at least the total value of fulfilled outgoing HTLCs.
//!
//! 2. **Coverage invariant**: for every block height `H`,
//!    `incoming_coverage(H) >= outgoing_coverage(H)`.
//!
//!    A fulfilled HTLC contributes at every height.
//!    Incoming htlcs contribute if `H + expiry_delta <= expiry`;
//!    Outgoing htlcs contribute if `H <= expiry`.
//!
//! All operations are idempotent: granting the same HTLC again, fulfilling a
//! fulfilled HTLC, or revoking an absent HTLC all succeed without effect.
//!
//! Actions that can only make the ledger safer — granting or fulfilling an
//! incoming HTLC, revoking an outgoing one — skip the invariant checks and
//! always succeed.

use std::collections::HashMap;
use std::fmt;
use std::hash::Hash;

use bitcoin::Amount;
use bitcoin_ext::{BlockDelta, BlockHeight};

/// Direction of an HTLC from the servers perspective
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
	Incoming,
	Outgoing,
}

/// An HTLC tracked by the ledger.
#[derive(Debug, Clone)]
pub struct Htlc<I> {
	pub id: I,
	pub direction: Direction,
	pub amount: Amount,
	pub expiry: BlockHeight,
	/// Whether the HTLC has been fulfilled/claimed.
	pub fulfilled: bool,
}

/// Errors that can occur when operating on a [`Ledger`].
#[derive(Debug, thiserror::Error)]
pub enum Error<I: fmt::Debug> {
	/// An HTLC with this id was already present with different parameters.
	#[error("HTLC with id {0:?} already exists with different parameters")]
	DuplicateHtlcId(I),

	/// The requested HTLC id was not found.
	#[error("HTLC with id {0:?} not found")]
	HtlcNotFound(I),

	/// The fulfillment invariant was violated.
	#[error("fulfillment invariant violated: incoming {incoming} < outgoing {outgoing}")]
	FulfillmentInvariant { incoming: Amount, outgoing: Amount },

	/// The coverage invariant was violated at a specific block height.
	#[error("coverage invariant violated at height {height}: incoming {incoming} < outgoing {outgoing}")]
	CoverageInvariant { height: BlockHeight, incoming: Amount, outgoing: Amount },
}

/// In-memory HTLC ledger that enforces fulfillment and coverage invariants.
#[derive(Debug, Clone)]
pub struct Ledger<I> {
	expiry_delta: BlockDelta,
	htlcs: HashMap<I, Htlc<I>>,
}

impl<I: Copy + Eq + Hash + fmt::Debug> Ledger<I> {
	/// Create a new empty ledger with the given HTLC expiry delta.
	pub fn new(expiry_delta: BlockDelta) -> Self {
		Self {
			expiry_delta,
			htlcs: HashMap::new(),
		}
	}

	/// The expiry delta used by this ledger.
	pub fn expiry_delta(&self) -> BlockDelta {
		self.expiry_delta
	}

	/// Reconstruct an HTLC from persisted state.
	///
	/// This does **not** check invariants.
	pub fn force_htlc(
		&mut self,
		id: I,
		amount: Amount,
		expiry: BlockHeight,
		claimed: bool,
		direction: Direction,
	) -> Result<(), Error<I>> {
		self.htlcs.insert(id, Htlc {
			id,
			direction,
			amount,
			expiry,
			fulfilled: claimed,
		});
		Ok(())
	}

	/// Add a new granted incoming HTLC and check invariants.
	///
	/// Idempotent: re-adding an existing HTLC with the same parameters is a
	/// no-op; with different parameters it fails.
	pub fn add_incoming(
		&mut self,
		id: I,
		amount: Amount,
		expiry: BlockHeight,
	) -> Result<(), Error<I>> {
		self.add(id, Direction::Incoming, amount, expiry)
	}

	/// Add a new granted outgoing HTLC and check invariants.
	///
	/// Idempotent: re-adding an existing HTLC with the same parameters is a
	/// no-op; with different parameters it fails.
	pub fn add_outgoing(
		&mut self,
		id: I,
		amount: Amount,
		expiry: BlockHeight,
	) -> Result<(), Error<I>> {
		self.add(id, Direction::Outgoing, amount, expiry)
	}

	fn add(
		&mut self,
		id: I,
		direction: Direction,
		amount: Amount,
		expiry: BlockHeight,
	) -> Result<(), Error<I>> {
		if let Some(existing) = self.htlcs.get(&id) {
			// If a fullfilled htlc exists this a no-op
			let same = existing.direction == direction
				&& existing.amount == amount
				&& existing.expiry == expiry;
			return if same { Ok(()) } else { Err(Error::DuplicateHtlcId(id)) };
		}
		self.htlcs.insert(id, Htlc {
			id,
			direction,
			amount,
			expiry,
			fulfilled: false,
		});
		// A new incoming HTLC only adds coverage, so nothing to check.
		if direction == Direction::Outgoing {
			if let Err(e) = self.check_invariants() {
				self.htlcs.remove(&id);
				return Err(e);
			}
		}
		Ok(())
	}

	/// Mark an HTLC as fulfilled (claimed).
	///
	/// Idempotent: fulfilling an already fulfilled HTLC is a no-op.
	pub fn fulfill(&mut self, id: I) -> Result<(), Error<I>> {
		let htlc = self.htlcs.get(&id).ok_or(Error::HtlcNotFound(id))?;
		if htlc.fulfilled {
			return Ok(());
		}
		let direction = htlc.direction;
		let mut htlc = htlc.clone();
		htlc.fulfilled = true;
		self.htlcs.insert(id, htlc);
		// Fulfilling an incoming HTLC only adds fulfilled value and coverage.
		if direction == Direction::Outgoing {
			if let Err(e) = self.check_invariants() {
				self.htlcs.get_mut(&id).expect("just inserted").fulfilled = false;
				return Err(e);
			}
		}
		Ok(())
	}

	/// Revoke an HTLC, removing it from the ledger.
	///
	/// Idempotent: revoking an absent HTLC is a no-op.
	pub fn revoke(&mut self, id: I) -> Result<(), Error<I>> {
		let Some(htlc) = self.htlcs.remove(&id) else {
			return Ok(());
		};
		// Revoking an outgoing HTLC only removes liability.
		if htlc.direction == Direction::Incoming {
			if let Err(e) = self.check_invariants() {
				self.htlcs.insert(id, htlc);
				return Err(e);
			}
		}
		Ok(())
	}

	/// Check that the fulfillment and coverage invariants hold.
	pub fn check_invariants(&self) -> Result<(), Error<I>> {
		let (incoming_fulfilled, outgoing_fulfilled) = self.fulfilled_totals();
		if incoming_fulfilled < outgoing_fulfilled {
			return Err(Error::FulfillmentInvariant {
				incoming: incoming_fulfilled,
				outgoing: outgoing_fulfilled,
			});
		}

		// Each HTLC contributes coverage from height 0 until its coverage
		// ends, so both sides are non-increasing step functions of the
		// height. Starting from the full totals and dropping each HTLC at the
		// first height past its coverage checks every height in one pass.
		let mut incoming = Amount::ZERO;
		let mut outgoing = Amount::ZERO;
		let mut drops: Vec<(BlockHeight, Direction, Amount)> = Vec::new();
		for htlc in self.htlcs.values() {
			match htlc.direction {
				Direction::Incoming => incoming += htlc.amount,
				Direction::Outgoing => outgoing += htlc.amount,
			}
			if let Some(end) = htlc.coverage_end(self.expiry_delta) {
				drops.push((end + BlockDelta::new(1), htlc.direction, htlc.amount));
			}
		}
		if incoming < outgoing {
			return Err(Error::CoverageInvariant { height: BlockHeight::ZERO, incoming, outgoing });
		}

		drops.sort_unstable_by_key(|&(height, ..)| height);
		let mut drops = drops.into_iter().peekable();
		while let Some((height, direction, amount)) = drops.next() {
			match direction {
				Direction::Incoming => incoming -= amount,
				Direction::Outgoing => outgoing -= amount,
			}
			// Only check once all coverage ending at this height is dropped.
			if drops.peek().is_some_and(|&(next, ..)| next == height) {
				continue;
			}
			if incoming < outgoing {
				return Err(Error::CoverageInvariant {
					height,
					incoming,
					outgoing,
				});
			}
		}

		Ok(())
	}

	/// Return the HTLC with the given id, if present.
	pub fn get(&self, id: I) -> Option<&Htlc<I>> {
		self.htlcs.get(&id)
	}

	/// Iterate over all HTLCs in the ledger.
	pub fn htlcs(&self) -> impl Iterator<Item = &Htlc<I>> {
		self.htlcs.values()
	}

	/// Total value of fulfilled incoming HTLCs.
	pub fn incoming_fulfilled(&self) -> Amount {
		self.fulfilled_totals().0
	}

	/// Total value of fulfilled outgoing HTLCs.
	pub fn outgoing_fulfilled(&self) -> Amount {
		self.fulfilled_totals().1
	}

	/// Returns the fulfilled totals as (incoming, outgoing)
	fn fulfilled_totals(&self) -> (Amount, Amount) {
		let mut incoming = Amount::ZERO;
		let mut outgoing = Amount::ZERO;
		for htlc in self.htlcs.values() {
			if !htlc.fulfilled {
				continue;
			}
			match htlc.direction {
				Direction::Incoming => incoming += htlc.amount,
				Direction::Outgoing => outgoing += htlc.amount,
			}
		}
		(incoming, outgoing)
	}

}

impl<I> Htlc<I> {
	/// The last height at which this HTLC contributes to coverage, or `None`
	/// if it contributes at every height.
	fn coverage_end(&self, expiry_delta: BlockDelta) -> Option<BlockHeight> {
		if self.fulfilled {
			return None;
		}
		match self.direction {
			Direction::Incoming => {
				Some(self.expiry.saturating_sub(expiry_delta))
			},
			Direction::Outgoing => Some(self.expiry),
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	const DELTA: BlockDelta = BlockDelta::new(10);

	#[test]
	fn empty_ledger_is_valid() {
		let ledger = Ledger::<&'static str>::new(DELTA);
		ledger.check_invariants().unwrap();
	}

	#[test]
	fn incoming_covers_outgoing() {
		let mut ledger = Ledger::new(DELTA);
		ledger.add_incoming("in", Amount::from_sat(1000), BlockHeight::new(100)).unwrap();
		ledger.add_outgoing("out", Amount::from_sat(500), BlockHeight::new(90)).unwrap();
		ledger.check_invariants().unwrap();
	}

	#[test]
	fn outgoing_without_coverage_fails() {
		let mut ledger = Ledger::new(DELTA);
		ledger.add_incoming("in", Amount::from_sat(1000), BlockHeight::new(100)).unwrap();
		let err = ledger
			.add_outgoing("out", Amount::from_sat(1500), BlockHeight::new(90))
			.expect_err("should violate coverage");
		assert!(matches!(err, Error::CoverageInvariant { .. }));
	}

	#[test]
	fn outgoing_expiring_exactly_delta_before_incoming_is_allowed() {
		let mut ledger = Ledger::new(DELTA);
		ledger.add_incoming("in", Amount::from_sat(1000), BlockHeight::new(100)).unwrap();
		// Gap of exactly DELTA blocks (100 - 90 = 10) is allowed.
		ledger.add_outgoing("out", Amount::from_sat(500), BlockHeight::new(90)).unwrap();
		ledger.check_invariants().unwrap();
	}

	#[test]
	fn outgoing_expiring_less_than_delta_before_incoming_fails() {
		let mut ledger = Ledger::new(DELTA);
		ledger.add_incoming("in", Amount::from_sat(1000), BlockHeight::new(100)).unwrap();
		// Gap of only 9 blocks (100 - 91 < 10) leaves too little time to
		// claim the incoming HTLC after an on-chain claim of the outgoing.
		let err = ledger
			.add_outgoing("out", Amount::from_sat(500), BlockHeight::new(91))
			.expect_err("gap below expiry delta should fail");
		assert!(matches!(err, Error::CoverageInvariant { .. }));
	}

	#[test]
	fn fulfillment_invariant_requires_claimed_incoming() {
		let mut ledger = Ledger::new(DELTA);
		ledger.add_incoming("in", Amount::from_sat(1000), BlockHeight::new(100)).unwrap();
		ledger.add_outgoing("out", Amount::from_sat(500), BlockHeight::new(90)).unwrap();
		// Coverage OK, but fulfillment fails because outgoing would be claimed
		// before incoming.
		let err = ledger.fulfill("out").expect_err("should violate fulfillment");
		assert!(matches!(err, Error::FulfillmentInvariant { .. }));

		ledger.fulfill("in").unwrap();
		ledger.fulfill("out").unwrap();
		ledger.check_invariants().unwrap();
	}

	#[test]
	fn fulfill_outgoing_can_break_coverage_while_fulfillment_holds() {
		let mut ledger = Ledger::new(DELTA);
		// A fulfilled incoming of 1000 covers every height.
		ledger.add_incoming("in-a", Amount::from_sat(1000), BlockHeight::new(200)).unwrap();
		ledger.fulfill("in-a").unwrap();
		// An outgoing at expiry 150 leans on that fulfilled incoming.
		ledger.add_outgoing("out-e", Amount::from_sat(1000), BlockHeight::new(150)).unwrap();
		// A second pair: unclaimed incoming covering up to height 90,
		// outgoing at expiry 90.
		ledger.add_incoming("in-b", Amount::from_sat(1000), BlockHeight::new(100)).unwrap();
		ledger.add_outgoing("out-c", Amount::from_sat(1000), BlockHeight::new(90)).unwrap();

		// Fulfilling out-c keeps the fulfillment invariant (1000 vs 1000) but
		// extends its demand past height 90, where only in-a's 1000 remains
		// against out-c plus out-e. First uncovered height is 91.
		let err = ledger.fulfill("out-c").expect_err("should violate coverage");
		match err {
			Error::CoverageInvariant { height, .. } => assert_eq!(height, BlockHeight::new(91)),
			_ => panic!("expected coverage invariant at height 91, got {err:?}"),
		}

		// The failed fulfill is rolled back, leaving a valid ledger.
		ledger.check_invariants().unwrap();
		assert!(!ledger.get("out-c").unwrap().fulfilled);
	}

	#[test]
	fn revoke_removes_htlc() {
		let mut ledger = Ledger::new(DELTA);
		ledger.add_incoming("in", Amount::from_sat(1000), BlockHeight::new(100)).unwrap();
		ledger.revoke("in").unwrap();
		assert!(ledger.get("in").is_none());
		ledger.check_invariants().unwrap();
	}

	#[test]
	fn revoke_incoming_that_covers_outgoing_fails() {
		let mut ledger = Ledger::new(DELTA);
		ledger.add_incoming("in", Amount::from_sat(1000), BlockHeight::new(100)).unwrap();
		ledger.add_outgoing("out", Amount::from_sat(500), BlockHeight::new(90)).unwrap();
		ledger.revoke("in").expect_err("should violate coverage");
	}

	#[test]
	fn add_rejects_same_id_with_different_parameters() {
		let mut ledger = Ledger::new(DELTA);
		ledger.add_incoming("in", Amount::from_sat(1000), BlockHeight::new(100)).unwrap();
		let err = ledger
			.add_incoming("in", Amount::from_sat(500), BlockHeight::new(100))
			.expect_err("different parameters should fail");
		assert!(matches!(err, Error::DuplicateHtlcId("in")));
	}

	#[test]
	fn add_twice_with_same_parameters_is_noop() {
		let mut ledger = Ledger::new(DELTA);
		ledger.add_incoming("in", Amount::from_sat(1000), BlockHeight::new(100)).unwrap();
		ledger.add_incoming("in", Amount::from_sat(1000), BlockHeight::new(100)).unwrap();
		assert_eq!(ledger.htlcs().count(), 1);
	}

	#[test]
	fn fulfill_twice_is_noop() {
		let mut ledger = Ledger::new(DELTA);
		ledger.add_incoming("in", Amount::from_sat(1000), BlockHeight::new(100)).unwrap();
		ledger.fulfill("in").unwrap();
		ledger.fulfill("in").unwrap();
		assert_eq!(ledger.incoming_fulfilled(), Amount::from_sat(1000));
	}

	#[test]
	fn revoke_twice_is_noop() {
		let mut ledger = Ledger::new(DELTA);
		ledger.add_incoming("in", Amount::from_sat(1000), BlockHeight::new(100)).unwrap();
		ledger.revoke("in").unwrap();
		ledger.revoke("in").unwrap();
		assert!(ledger.get("in").is_none());
	}

	#[test]
	fn force_htlc_allows_inconsistent_state() {
		let mut ledger = Ledger::new(DELTA);
		ledger
			.force_htlc("in", Amount::from_sat(100), BlockHeight::new(100), false, Direction::Incoming)
			.unwrap();
		ledger
			.force_htlc("out", Amount::from_sat(200), BlockHeight::new(90), false, Direction::Outgoing)
			.unwrap();
		let err = ledger.check_invariants().expect_err("should be inconsistent");
		assert!(matches!(err, Error::CoverageInvariant { .. }));
	}

	#[test]
	fn force_htlc_preserves_id_uniqueness() {
		let mut ledger = Ledger::new(DELTA);
		ledger
			.force_htlc("in", Amount::from_sat(100), BlockHeight::new(100), false, Direction::Incoming)
			.unwrap();
		ledger
			.force_htlc("in", Amount::from_sat(100), BlockHeight::new(100), false, Direction::Incoming)
			.expect("Force overrides the existing value")

	}

	#[test]
	fn safe_actions_succeed_on_inconsistent_ledger() {
		let mut ledger = Ledger::new(DELTA);
		ledger
			.force_htlc("bad-out", Amount::from_sat(200), BlockHeight::new(90), true, Direction::Outgoing)
			.unwrap();
		ledger.check_invariants().expect_err("should be inconsistent");
		// Safe actions never check invariants, so they succeed regardless.
		ledger.add_incoming("in", Amount::from_sat(50), BlockHeight::new(100)).unwrap();
		ledger.fulfill("in").unwrap();
		ledger.revoke("bad-out").unwrap();
	}

	#[test]
	fn coverage_violation_reports_first_uncovered_height() {
		let mut ledger = Ledger::new(DELTA);
		// Incoming at expiry 100 covers up to height 90, so an outgoing
		// expiring at 91 is uncovered from height 91 onward.
		ledger.add_incoming("in", Amount::from_sat(1000), BlockHeight::new(100)).unwrap();
		let err = ledger
			.add_outgoing("out", Amount::from_sat(500), BlockHeight::new(91))
			.expect_err("should violate coverage past the incoming window");
		match err {
			Error::CoverageInvariant { height, .. } => assert_eq!(height, BlockHeight::new(91)),
			_ => panic!("expected coverage invariant at height 91, got {err:?}"),
		}
	}
}

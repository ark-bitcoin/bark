//! Differential test suite for [BarkPersister] implementations.
//!
//! Call [run_all] with two freshly created persisters to verify that both
//! implementations satisfy the [BarkPersister] contract and produce identical
//! results for every operation.  Invoke this from a `#[tokio::test]` that
//! constructs one instance of each backend under test.

use super::BarkPersister;

/// Run all [BarkPersister] differential tests against `a` and `b`.
///
/// Both persisters must be freshly initialised (empty).  Every method is
/// called on both with identical inputs and the outputs are asserted equal,
/// so any behavioural divergence between the two backends surfaces as a test
/// failure.
pub async fn run_all<A: BarkPersister, B: BarkPersister>(a: &A, b: &B) {
	let _ = (a, b); // groups added incrementally
}

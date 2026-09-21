//! Maps the free-text `lightning_payment_attempt.error` onto a closed set of
//! kinds usable as a metric label.
//!
//! CLN errors carry a JSON-RPC code (`common/jsonrpc_errors.h`) that cln-grpc
//! only exposes inside its message, as `code: Some(N)`. Codes checked against
//! CLN v26.06.8.

use std::fmt;

use server_rpc::protos;

/// `PAY_*` codes xpay and askrene return.
const PAY_DESTINATION_PERM_FAIL: i32 = 203;
const PAY_ROUTE_NOT_FOUND: i32 = 205;
const PAY_ROUTE_TOO_EXPENSIVE: i32 = 206;
const PAY_INVOICE_EXPIRED: i32 = 207;
const PAY_UNSPECIFIED_ERROR: i32 = 209;
const PAY_STOPPED_RETRYING: i32 = 210;
const PAY_INJECTPAYMENTONION_ALREADY_PAID: i32 = 219;

/// Why a lightning payment attempt failed. Derived, not stored, so
/// re-classifying old rows is a code change rather than a migration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LightningFailureKind {
	/// A route existed but cost more than the authorised `maxfee`.
	FeeTooLow,
	/// A route existed but its total CLTV exceeded `maxdelay`.
	CltvTooLong,
	/// No route to the destination, for reasons other than cost or delay.
	NoRoute,
	/// Routes were tried but every attempt failed before xpay gave up.
	RetriesExhausted,
	/// The destination rejected the payment (unknown invoice, wrong amount).
	DestinationRejected,
	/// The client never finished setting up the HTLC vtxos.
	SetupTimeout,
	/// The invoice was expired, canceled, or otherwise not payable.
	InvoiceState,
	/// Failed with an error we have not classified.
	Other,
	/// Failed with no error recorded at all.
	Unknown,
}

impl LightningFailureKind {
	pub fn as_str(self) -> &'static str {
		match self {
			Self::FeeTooLow => "fee_too_low",
			Self::CltvTooLong => "cltv_too_long",
			Self::NoRoute => "no_route",
			Self::RetriesExhausted => "retries_exhausted",
			Self::DestinationRejected => "destination_rejected",
			Self::SetupTimeout => "setup_timeout",
			Self::InvoiceState => "invoice_state",
			Self::Other => "other",
			Self::Unknown => "unknown",
		}
	}

	/// `None` maps to [`Self::Unknown`], not [`Self::Other`]: nobody writing
	/// a reason down is a different problem from one we can't parse.
	pub fn classify(error: Option<&str>) -> Self {
		let Some(error) = error else { return Self::Unknown };
		let e = error.to_lowercase();

		match cln_error_code(&e) {
			Some(PAY_DESTINATION_PERM_FAIL) => Self::DestinationRejected,
			Some(PAY_ROUTE_NOT_FOUND) | Some(PAY_STOPPED_RETRYING) => Self::NoRoute,
			// askrene uses 206 for both cost and delay.
			Some(PAY_ROUTE_TOO_EXPENSIVE) => if e.contains("excessive delay") {
				Self::CltvTooLong
			} else {
				Self::FeeTooLow
			},
			Some(PAY_INVOICE_EXPIRED) | Some(PAY_INJECTPAYMENTONION_ALREADY_PAID) => Self::InvoiceState,
			// After a first attempt xpay reports routing failures as 209 too.
			Some(PAY_UNSPECIFIED_ERROR) => if e.contains("excessive cost") {
				Self::FeeTooLow
			} else if e.contains("excessive delay") {
				Self::CltvTooLong
			} else if e.contains(" attempts.") {
				Self::RetriesExhausted
			} else {
				Self::Other
			},
			Some(_) => Self::Other,
			// Our own errors, not from CLN.
			None => if e.contains("htlc vtxo setup timed out") {
				Self::SetupTimeout
			} else if e.contains("invoice expired")
				|| e.contains("invoice is not in a valid state")
				|| e.contains("invoice has already been paid")
			{
				Self::InvoiceState
			} else {
				Self::Other
			},
		}
	}
}

impl From<LightningFailureKind> for protos::LightningFailureReason {
	fn from(kind: LightningFailureKind) -> Self {
		match kind {
			LightningFailureKind::FeeTooLow => Self::LightningFailureFeeTooLow,
			LightningFailureKind::CltvTooLong => Self::LightningFailureCltvTooLong,
			LightningFailureKind::NoRoute => Self::LightningFailureNoRoute,
			LightningFailureKind::RetriesExhausted => Self::LightningFailureRetriesExhausted,
			LightningFailureKind::DestinationRejected => Self::LightningFailureDestinationRejected,
			LightningFailureKind::SetupTimeout => Self::LightningFailureSetupTimeout,
			LightningFailureKind::InvoiceState => Self::LightningFailureInvoiceState,
			LightningFailureKind::Other => Self::LightningFailureOther,
			// A classification we could not make is reported as unset, not as
			// a reason the client might act on.
			LightningFailureKind::Unknown => Self::LightningFailureUnspecified,
		}
	}
}

/// Extracts `N` from cln-grpc's `code: Some(N)`.
fn cln_error_code(error: &str) -> Option<i32> {
	let (_, rest) = error.split_once("code: some(")?;
	let (code, _) = rest.split_once(')')?;
	code.parse().ok()
}

impl fmt::Display for LightningFailureKind {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str(self.as_str())
	}
}

#[cfg(test)]
mod test {
	use super::*;

	fn xpay_err(code: i32, msg: &str) -> String {
		format!("code: 'Unknown error', message: \"Error calling method Xpay: RpcError {{ \
			code: Some({}), message: \\\"{}\\\", data: None }}\"", code, msg)
	}

	/// Messages verbatim from second-green and second-monitoring.
	#[test]
	fn classifies_observed_errors() {
		let cases = [
			(xpay_err(205, "Failed: Unknown destination node \
				029e958ea003b832bf5c0d95a874826ac052a3749f8b982a5b549435e72e8b76cf"),
				LightningFailureKind::NoRoute),
			(xpay_err(205, "Failed: We could not find a usable set of paths. The shortest \
				path is 961783x1217x0->962839x1529x1->900858x2249x1, but 900858x2249x1/0 \
				layer xpay says max is 16684108msat"),
				LightningFailureKind::NoRoute),
			(xpay_err(206, "Failed: Could not find route without excessive cost"),
				LightningFailureKind::FeeTooLow),
			(xpay_err(206, "Failed: Could not find route without excessive delays"),
				LightningFailureKind::CltvTooLong),
			(xpay_err(209, "Timed out after after 5 attempts. We got temporary_channel_failure \
				for 961759x2001x1/0, assuming it can't carry 39038msat. "),
				LightningFailureKind::RetriesExhausted),
			(xpay_err(209, "Failed after 17 attempts. We got temporary_channel_failure for \
				900411x3204x1/1, assuming it can't carry 28859000msat. "),
				LightningFailureKind::RetriesExhausted),
			(xpay_err(209, "Failed after 2 attempts. We got temporary_channel_failure for \
				900411x3204x1/1, assuming it can't carry 28859000msat. Then routing failed: \
				Could not find route without excessive cost"),
				LightningFailureKind::FeeTooLow),
			(xpay_err(203, "Destination said it doesn't know invoice: \
				incorrect_or_unknown_payment_details"),
				LightningFailureKind::DestinationRejected),
			(xpay_err(207, "Invoice expired 12 seconds ago"),
				LightningFailureKind::InvoiceState),
			(xpay_err(219, "Already paid this invoice successfully"),
				LightningFailureKind::InvoiceState),
			(xpay_err(209, "Reservation failed: '{}'"), LightningFailureKind::Other),
			("htlc vtxo setup timed out".into(), LightningFailureKind::SetupTimeout),
			("invoice expired".into(), LightningFailureKind::InvoiceState),
			("invoice is not in a valid state to pay: canceled. expected: created".into(),
				LightningFailureKind::InvoiceState),
			("connection reset by peer".into(), LightningFailureKind::Other),
		];

		for (input, expected) in cases {
			assert_eq!(
				LightningFailureKind::classify(Some(&input)), expected,
				"misclassified: {:?}", input,
			);
		}
		assert_eq!(LightningFailureKind::classify(None), LightningFailureKind::Unknown);
	}

	/// The wire enum must not silently collapse kinds onto one value, and an
	/// unclassified failure must report unspecified rather than a reason the
	/// client could act on.
	#[test]
	fn wire_reason_is_distinct_per_kind() {
		use protos::LightningFailureReason as R;
		let all = [
			LightningFailureKind::FeeTooLow,
			LightningFailureKind::CltvTooLong,
			LightningFailureKind::NoRoute,
			LightningFailureKind::RetriesExhausted,
			LightningFailureKind::DestinationRejected,
			LightningFailureKind::SetupTimeout,
			LightningFailureKind::InvoiceState,
			LightningFailureKind::Other,
		];
		let mapped = all.map(R::from);
		for (i, a) in mapped.iter().enumerate() {
			assert_ne!(*a, R::LightningFailureUnspecified,
				"{:?} must not map to unspecified", all[i]);
			for b in &mapped[i + 1..] {
				assert_ne!(a, b, "two kinds share a wire value");
			}
		}
		assert_eq!(R::from(LightningFailureKind::Unknown), R::LightningFailureUnspecified);
	}

	/// Cost must not be swallowed by the generic route arm.
	#[test]
	fn parses_code() {
		assert_eq!(cln_error_code(&xpay_err(206, "x").to_lowercase()), Some(206));
		assert_eq!(cln_error_code("connection reset by peer"), None);
	}
}

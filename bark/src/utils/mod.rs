pub(crate) mod json_patch;
pub mod time;

use std::time::Duration;

use log::trace;

use ark::VtxoId;
use server_rpc::StatusExt;

/// Base delay for the first reconnect of a dropped subscription stream.
const RECONNECT_BACKOFF_BASE: Duration = Duration::from_secs(1);
/// Cap on the reconnect delay so we keep probing a long-down server.
const RECONNECT_BACKOFF_MAX: Duration = Duration::from_secs(30);

/// Exponential backoff for reconnecting a dropped server subscription stream.
///
/// The always-on subscriptions (round events, mailbox) reconnect whenever their
/// stream ends or is reset. Without a delay, a server that closes the stream
/// quickly — or that is actively rate-limiting us — turns the client into a
/// tight resubscribe loop that opens and resets HTTP/2 streams as fast as it
/// can. That is exactly the "rapid reset" pattern the server's h2 layer flags
/// (and defends against by resetting our streams, which [`is_h2_stream_error`]
/// would otherwise treat as a cue to reconnect *faster*).
///
/// Callers sleep via [`ReconnectBackoff::wait`] before every resubscribe and
/// call [`ReconnectBackoff::reset`] once a stream has proven healthy, so the
/// delay only grows while reconnects keep failing and healthy reconnects stay
/// prompt.
pub struct ReconnectBackoff {
	attempts: u32,
}

impl ReconnectBackoff {
	pub fn new() -> ReconnectBackoff {
		ReconnectBackoff { attempts: 0 }
	}

	/// Reset after a healthy stream so the next disconnect reconnects promptly.
	pub fn reset(&mut self) {
		self.attempts = 0;
	}

	fn next_delay(&mut self) -> Duration {
		// exponential: base * 2^attempts, saturating at the cap.
		let factor = 1u32.checked_shl(self.attempts).unwrap_or(u32::MAX);
		let delay = RECONNECT_BACKOFF_BASE
			.checked_mul(factor)
			.unwrap_or(RECONNECT_BACKOFF_MAX)
			.min(RECONNECT_BACKOFF_MAX);
		self.attempts = self.attempts.saturating_add(1);

		// Equal jitter: sleep in [delay/2, delay]. The floor guarantees we
		// never tight-loop (a bad RNG draw can't drive the delay to zero),
		// while the random component keeps many clients from reconnecting in
		// lockstep after a shared event like a server restart.
		let half = delay / 2;
		half + half.mul_f64(rand::random::<f64>())
	}

	/// Sleep for the next backoff interval before resubscribing.
	///
	/// This is not cancellation-aware on its own; callers that need to abort on
	/// shutdown race it in their own `select!`.
	pub async fn wait(&mut self) {
		let delay = self.next_delay();
		trace!("Reconnecting subscription stream in {:?}", delay);
		crate::utils::time::sleep(delay).await;
	}
}

/// Returns `true` if the error chain contains a tonic h2 protocol error,
/// which typically indicates a server- or proxy-side issue (e.g. an idle
/// timeout that reset the underlying stream) rather than a genuine
/// server failure.
pub(crate) fn is_h2_stream_error(e: &anyhow::Error) -> bool {
	e.chain().any(|cause| {
		cause.downcast_ref::<tonic::Status>().is_some_and(|s| {
			s.code() == tonic::Code::Internal
				&& s.message().starts_with("h2 protocol error")
		})
	})
}

/// Ensure a URL carries an explicit scheme, defaulting to `https`.
///
/// Users commonly configure a bare host like `esplora.signet.2nd.dev` or
/// `ark.signet.2nd.dev`. A scheme-less URL is treated as relative and breaks
/// the HTTP/gRPC clients downstream, so we prepend `https://` when no scheme
/// is present.
pub(crate) fn url_with_default_https_scheme(url: &str) -> String {
	let trimmed = url.trim();
	if trimmed.contains("://") {
		trimmed.to_owned()
	} else {
		format!("https://{}", trimmed)
	}
}

#[cfg(not(feature = "wasm-web"))]
pub fn spawn<F>(fut: F) -> tokio::task::JoinHandle<F::Output>
where
	F: Future<Output = ()> + Send + 'static,
{
	tokio::spawn(fut)
}

#[cfg(feature = "wasm-web")]
pub fn spawn<F>(fut: F)
where
	F: Future<Output = ()> + 'static,
{
	wasm_bindgen_futures::spawn_local(fut)
}

/// Extract the input VTXO ids the server flagged as the reason it rejected a
/// refresh round, by reading the `identifiers` metadata of a [tonic::Status] in
/// the error chain.
///
/// Both maintenance paths submit synchronously (interactive via `start_attempt`,
/// delegated via `join_next_round_delegated`), so the [tonic::Status] survives in
/// the error chain untouched rather than being stringified by the round state
/// machine.
pub(crate) fn rejected_vtxos_from_error(err: &anyhow::Error) -> Vec<VtxoId> {
	for cause in err.chain() {
		if let Some(status) = cause.downcast_ref::<tonic::Status>() {
			return status.rejected_vtxos();
		}
	}
	Vec::new()
}

#[cfg(test)]
mod test {
	use super::*;

	use std::str::FromStr;

	const VTXO_A: &str = "0000000000000000000000000000000000000000000000000000000000000001:0";
	const VTXO_B: &str = "0000000000000000000000000000000000000000000000000000000000000002:1";

	#[test]
	fn url_defaults_to_https() {
		assert_eq!(url_with_default_https_scheme("esplora.signet.2nd.dev"), "https://esplora.signet.2nd.dev");
		assert_eq!(url_with_default_https_scheme("ark.signet.2nd.dev"), "https://ark.signet.2nd.dev");
		assert_eq!(url_with_default_https_scheme("  esplora.signet.2nd.dev  "), "https://esplora.signet.2nd.dev");
	}

	#[test]
	fn url_keeps_explicit_scheme() {
		assert_eq!(url_with_default_https_scheme("https://esplora.signet.2nd.dev"), "https://esplora.signet.2nd.dev");
		assert_eq!(url_with_default_https_scheme("http://127.0.0.1:3000"), "http://127.0.0.1:3000");
	}

	#[test]
	fn rejected_vtxos_from_tonic_status_metadata() {
		let a = VtxoId::from_str(VTXO_A).unwrap();
		let b = VtxoId::from_str(VTXO_B).unwrap();
		let mut status = tonic::Status::invalid_argument("input vtxo(s) not spendable");
		status.metadata_mut().insert(
			"identifiers", format!("{},{}", a, b).parse().unwrap(),
		);
		// Wrapped with context, mirroring how the client tags the submit error.
		let err = anyhow::Error::new(status).context("Ark server refused our payment submission");
		assert_eq!(rejected_vtxos_from_error(&err), vec![a, b]);
	}

	#[test]
	fn rejected_vtxos_from_not_found_status() {
		// An unknown input comes back as NotFound (not UnusableInputs), but the
		// refresh loop must treat it the same way: drop the named id and retry.
		// This is what makes maintenance handle NotFound, not just spent/exited.
		let a = VtxoId::from_str(VTXO_A).unwrap();
		let mut status = tonic::Status::not_found("input vtxo does not exist");
		status.metadata_mut().insert("identifiers", a.to_string().parse().unwrap());
		let err = anyhow::Error::new(status).context("Ark server refused our payment submission");
		assert_eq!(rejected_vtxos_from_error(&err), vec![a]);
	}

	#[test]
	fn reconnect_backoff_bounds_and_reset() {
		let mut b = ReconnectBackoff::new();

		// First delays sit within the equal-jitter window [base/2, base] and
		// never reach zero, so we can't tight-loop even on unlucky RNG draws.
		for _ in 0..50 {
			let mut fresh = ReconnectBackoff::new();
			let d = fresh.next_delay();
			assert!(d >= RECONNECT_BACKOFF_BASE / 2, "delay {d:?} below floor");
			assert!(d <= RECONNECT_BACKOFF_BASE, "delay {d:?} above base");
		}

		// The delay grows and then saturates at the cap; it never exceeds it.
		for _ in 0..40 {
			let d = b.next_delay();
			assert!(d <= RECONNECT_BACKOFF_MAX, "delay {d:?} above cap");
		}
		// Deep into the backoff we're pinned near the cap.
		let capped = b.next_delay();
		assert!(capped >= RECONNECT_BACKOFF_MAX / 2, "delay {capped:?} not near cap");

		// Resetting returns us to the base window for a prompt reconnect.
		b.reset();
		let after_reset = b.next_delay();
		assert!(after_reset <= RECONNECT_BACKOFF_BASE, "reset didn't shrink delay");
	}

	#[test]
	fn rejected_vtxos_empty_for_unrelated_error() {
		// A plain error carries no rejected vtxos.
		assert!(rejected_vtxos_from_error(&anyhow::anyhow!("boom")).is_empty());
		// Neither does a non-rejection status (e.g. a transient internal error),
		// even if it somehow carried identifiers.
		let mut status = tonic::Status::internal("h2 protocol error");
		status.metadata_mut().insert(
			"identifiers", VtxoId::from_str(VTXO_A).unwrap().to_string().parse().unwrap(),
		);
		let err = anyhow::Error::new(status);
		assert!(rejected_vtxos_from_error(&err).is_empty());
	}
}

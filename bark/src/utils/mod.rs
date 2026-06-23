pub(crate) mod json_patch;
pub mod time;

use ark::VtxoId;
use server_rpc::StatusExt;

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

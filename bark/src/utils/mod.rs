pub(crate) mod json_patch;
pub mod time;

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

#[cfg(test)]
mod test {
	use super::*;

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
}

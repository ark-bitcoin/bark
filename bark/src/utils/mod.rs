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

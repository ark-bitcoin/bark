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
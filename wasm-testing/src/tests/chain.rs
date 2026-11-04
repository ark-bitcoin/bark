
use wasm_bindgen_test::*;

use bark::chain::{ChainSource, ChainSourceSpec};

wasm_bindgen_test_configure!(run_in_browser);

/// A chain source backed by the control server's esplora stub, which answers
/// `status` to every request after the genesis lookup.
async fn chain_source_answering(status: u16) -> ChainSource {
	let spec = ChainSourceSpec::Esplora {
		url: format!("{}/esplora_status/{}", env!("ARK_CONTROL_URL"), status),
	};
	ChainSource::new(spec, bitcoin::Network::Regtest, None).await
		.expect("creating the chain source only needs the genesis lookup")
}

/// The esplora client retries 429, 500 and 503 with a backoff sleep between
/// attempts. In the browser that sleep has to come from the web timers: a
/// tokio sleep traps with `RuntimeError: unreachable` and the call never
/// returns, so the wallet hangs instead of reporting the failed request.
#[wasm_bindgen_test]
async fn esplora_retryable_status_returns_an_error() {
	let _ = console_log::init_with_level(log::Level::Debug);

	for status in [429u16, 500, 503] {
		let chain = chain_source_answering(status).await;
		let err = chain.tip().await
			.unwrap_err();
		let msg = format!("{:?}", err);
		assert!(msg.contains(&status.to_string()), "status {}: {}", status, msg);
	}
}

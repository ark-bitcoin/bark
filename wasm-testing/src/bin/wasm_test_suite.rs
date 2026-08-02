#![cfg(not(test))]

use std::process::Command;
use std::sync::Arc;

use ark_testing::{btc, control_server, TestContext};

fn run_wasm_tests(server_url: &str, control_url: &str, esplora_url: &str) {
	let mut args = vec!["test",
		"--headless", "--firefox", "bark",
		"--package", "wasm-testing",
		"--no-default-features", "--features=wasm",
		"--lib"];

	// Optional test name filter, forwarded to the wasm test harness.
	let filter = std::env::args().nth(1).filter(|f| !f.is_empty());
	if let Some(ref filter) = filter {
		args.push("--");
		args.push(filter);
	}

	// wasm-bindgen-test's default per-test timeout is 20 seconds, which is
	// tight for tests that board, confirm and settle payments against a
	// real server. Respect an explicit override from the environment.
	let timeout = std::env::var("WASM_BINDGEN_TEST_TIMEOUT")
		.unwrap_or_else(|_| "120".into());

	let status = Command::new("wasm-pack")
		.args(&args)
		.env("ARK_SERVER_URL", server_url)
		.env("ARK_CONTROL_URL", control_url)
		.env("ARK_ESPLORA_URL", esplora_url)
		.env("WASM_BINDGEN_TEST_TIMEOUT", timeout)
		.status()
		.expect("failed to run cargo test");

	if !status.success() {
		std::process::exit(status.code().unwrap_or(1));
	}
}

#[tokio::main]
async fn main() {
	let ctx = Arc::new(TestContext::new("wasm-testing").await);
	let srv = ctx.captaind("server").funded(btc(10)).create().await;

	let server_url = srv.ark_url().replace("0.0.0.0", "127.0.0.1");

	let control = control_server::ControlServer::new(ctx.clone(), srv);
	let control_url = control.url();
	let esplora_url = format!("{}/esplora", control_url);
	control.spawn();

	println!("Test context ready — server at {}, esplora at {}",
		server_url, esplora_url);

	run_wasm_tests(&server_url, &control_url, &esplora_url);
}

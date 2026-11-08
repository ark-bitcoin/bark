//! Tests for the thin `bark-cli` REST client: driving wallet commands over a
//! running barkd and the lock-based barkd lifecycle commands. Wallet
//! behavior itself is covered by the barkd suite — these tests exercise
//! the client's plumbing.

use std::time::Instant;

use bark_json::cli::DebugInfo;
use bark_rest_client::apis::wallet_api;

use ark_testing::{BarkClient, TestContext};
use ark_testing::util::{poll_interval, wait_timeout};

/// The client drives wallet commands over a running barkd, and `status`
/// reports the pid stamped in the datadir lock.
#[tokio::test]
async fn drives_running_barkd() {
	let ctx = TestContext::new("bark_client/drives_running_barkd").await;

	let srv = ctx.captaind("server").create().await;
	let barkd = ctx.barkd("barkd1", &srv).create().await;
	let bark = BarkClient::new("bark", barkd.datadir(), Some(barkd.base_url()));

	let balance = bark.run(["balance"]).await;
	assert!(balance.contains("spendable_sat"), "unexpected balance output: {}", balance);

	let debug_info = serde_json::from_str::<DebugInfo>(&bark.run(["debug-info"]).await)
		.expect("debug-info should print the DebugInfo JSON");
	let expected = wallet_api::debug_info(&barkd.client_config()).await
		.expect("failed to get barkd debug info");
	assert_eq!(debug_info, expected);

	let pid = bark.barkd_pid().expect("the datadir lock should carry the barkd pid");
	let status = bark.run(["status"]).await;
	assert!(status.contains(&format!("barkd running (pid {})", pid)),
		"unexpected status output: {}", status);
}

/// After barkd is killed hard, the OS releases the datadir lock:
/// `status` reads as down and wallet commands refuse to run.
#[tokio::test]
async fn killed_daemon_reads_as_down() {
	let ctx = TestContext::new("bark_client/killed_daemon_reads_as_down").await;

	let srv = ctx.captaind("server").create().await;
	let barkd = ctx.barkd("barkd1", &srv).create().await;
	let bark = BarkClient::new("bark", barkd.datadir(), Some(barkd.base_url()));

	let pid = bark.barkd_pid().expect("the datadir lock should carry the barkd pid");
	nix::sys::signal::kill(
		nix::unistd::Pid::from_raw(pid as i32),
		nix::sys::signal::Signal::SIGKILL,
	).expect("failed to kill barkd");

	// SIGKILL termination is asynchronous; poll until the OS releases the lock.
	let deadline = Instant::now() + wait_timeout();
	let status = loop {
		let out = bark.run(["status"]).await;
		if !out.contains("barkd running") {
			break out;
		}
		assert!(Instant::now() < deadline, "barkd (pid {}) did not die: {}", pid, out);
		tokio::time::sleep(poll_interval()).await;
	};
	assert!(status.contains("no barkd is running"), "unexpected status output: {}", status);

	// Wallet commands on the datadir refuse to run without a barkd.
	let no_url = BarkClient::new("bark2", barkd.datadir(), None);
	let err = no_url.try_run(["balance"]).await
		.expect_err("wallet commands must fail without a barkd");
	assert!(err.to_string().contains("no barkd is running"), "unexpected error: {}", err);
}

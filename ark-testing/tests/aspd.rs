#[macro_use] extern crate log;

use ark_testing::aspd;
use ark_testing::TestContext;

#[test]
fn test_arkd_version() {
	let mut cmd = aspd::get_base_cmd().unwrap().get_cmd();
	cmd.arg("--version");

	trace!("Executing {:?}", cmd);
	let output = cmd.output().unwrap();
	let stdout_str = std::str::from_utf8(&output.stdout).unwrap();
	let stderr_str = std::str::from_utf8(&output.stderr).unwrap();

	println!("{}", stderr_str);
  assert!(stdout_str.starts_with("bark-aspd"));
}

#[test]
fn fund_aspd() {
	let mut ctx = TestContext::generate();
	log::info!("Initialized TestContext");
	let bitcoind = ctx.bitcoind();
	let aspd = ctx.aspd(&bitcoind);

	// We should wait until aspd is ready
	// TODO: Ensure ctx.aspd(&bitcoind) only returns once the `aspd` is useable
	std::thread::sleep(std::time::Duration::from_secs(2));

	let adm_addr = format!("http://localhost:{}", aspd.admin_rpc_port().expect("The port is available"));
  let balance = aspd.run_cmd_with_args(&["rpc", "--addr", &adm_addr, "balance"]).expect("Can retrieve balance");
  assert_eq!(balance,  "0 BTC\n");
}

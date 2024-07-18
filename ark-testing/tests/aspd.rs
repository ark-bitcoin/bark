
#[macro_use] extern crate log;

use ark_testing::aspd;

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

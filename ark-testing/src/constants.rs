
pub const BOARD_CONFIRMATIONS: u32 = 12;

pub mod env {
	pub const TEST_DIRECTORY: &str = "TEST_DIRECTORY";
	pub const BITCOIND_EXEC: &str = "BITCOIND_EXEC";
	/// The time-out used by the bitcoincore_rpc-client in seconds
	/// If the time-out is exceeded a SocketError(Os { code: 35: WouldBlock, ...})
	/// is returned
	pub const BITCOINRPC_TIMEOUT_SECS: &str = "BITCOINRPC_TIMEOUT_SECS";
	pub const ELECTRS_EXEC: &str = "ELECTRS_EXEC";
	pub const BARK_EXEC: &str = "BARK_EXEC";
	pub const ASPD_EXEC: &str = "ASPD_EXEC";
	pub const LIGHTNINGD_DOCKER_IMAGE: &str = "LIGHTNINGD_DOCKER_IMAGE";
	pub const LIGHTNINGD_EXEC: &str = "LIGHTNINGD_EXEC";
	pub const LIGHTNINGD_PLUGIN_DIR: &str = "LIGHTNINGD_PLUGIN_DIR";
	pub const CHAIN_SOURCE: &str = "CHAIN_SOURCE";
	// If a daemon isn't initialized in DAEMON_INIT_TIMEOUT_MILLIS
	// the test will fail
	pub const DAEMON_INIT_TIMEOUT_MILLIS: &str = "DAEMON_INIT_TIMEOUT";
	/// The env var to reach postgres binaries folder
	pub const POSTGRES_BINS: &str = "POSTGRES_BINS";
	/// Remove the directory once a test is successful
	pub const CLEAN_SUCCESSFUL_TESTS: &str = "CLEAN_SUCCESSFUL_TESTS";
}

pub mod bitcoind {
	pub const BITCOINRPC_TEST_AUTH: &str = "test:7859aeb9ce7176a4f5c53de996bd5d5b$af59d74cb4b2973fe92f421b3345a3c985d111a28cefa694ffa498bcc4212fdc";
	pub const BITCOINRPC_TEST_USER: &str = "test";
	pub const BITCOINRPC_TEST_PASSWORD: &str = "test";
}

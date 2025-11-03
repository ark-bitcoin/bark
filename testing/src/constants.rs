use std::time::Duration;

pub const BOARD_CONFIRMATIONS: u32 = 3;
pub const ROUND_CONFIRMATIONS: u32 = 6;
pub const TX_PROPAGATION_SLEEP_TIME: Duration = Duration::from_millis(1000);

pub mod env {
	pub const TEST_DIRECTORY: &str = "TEST_DIRECTORY";
	pub const BITCOIND_EXEC: &str = "BITCOIND_EXEC";
	/// The time-out used by the bitcoincore_rpc-client in seconds
	/// If the time-out is exceeded a SocketError(Os { code: 35: WouldBlock, ...})
	/// is returned
	pub const BITCOINRPC_TIMEOUT_SECS: &str = "BITCOINRPC_TIMEOUT_SECS";
	pub const ESPLORA_ELECTRS_EXEC: &str = "ESPLORA_ELECTRS_EXEC";
	pub const MEMPOOL_ELECTRS_EXEC: &str = "MEMPOOL_ELECTRS_EXEC";
	pub const BARK_EXEC: &str = "BARK_EXEC";
	pub const CAPTAIND_EXEC: &str = "CAPTAIND_EXEC";
	pub const LIGHTNINGD_DOCKER_IMAGE: &str = "LIGHTNINGD_DOCKER_IMAGE";
	pub const LIGHTNINGD_EXEC: &str = "LIGHTNINGD_EXEC";
	pub const LIGHTNINGD_PLUGIN_DIR: &str = "LIGHTNINGD_PLUGIN_DIR";
	pub const CHAIN_SOURCE: &str = "CHAIN_SOURCE";
	// If a daemon isn't initialized in DAEMON_INIT_TIMEOUT_MILLIS
	// the test will fail
	pub const DAEMON_INIT_TIMEOUT_MILLIS: &str = "DAEMON_INIT_TIMEOUT_MILLIS";
	// If a bark command doesn't return in BARK_COMMAND_TIMEOUT_MILLIS
	// the test will fail
	pub const BARK_COMMAND_TIMEOUT_MILLIS: &str = "BARK_COMMAND_TIMEOUT_MILLIS";
	// The maximum time to wait for a transaction to be propagated to a node, in milliseconds.
	pub const TX_PROPAGATION_TIMEOUT_MILLIS: &str = "TX_PROPAGATION_TIMEOUT_MILLIS";
	/// The env var to reach postgres binaries folder
	pub const POSTGRES_BINS: &str = "POSTGRES_BINS";
	/// By default, all artifacts of a tests are deleted after a succesful run.
	/// We only keep the data for failed tests
	/// When KEEP_ALL_TEST_DATA is set all test data is kept by default
	pub const KEEP_ALL_TEST_DATA: &str = "KEEP_ALL_TEST_DATA";
	/// Use an external database to run the tests
	pub const TEST_POSTGRES_HOST: &str = "TEST_POSTGRES_HOST";
}

pub mod bitcoind {
	pub const BITCOINRPC_TEST_AUTH: &str = "test:7859aeb9ce7176a4f5c53de996bd5d5b$af59d74cb4b2973fe92f421b3345a3c985d111a28cefa694ffa498bcc4212fdc";
	pub const BITCOINRPC_TEST_USER: &str = "test";
	pub const BITCOINRPC_TEST_PASSWORD: &str = "test";
}

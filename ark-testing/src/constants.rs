pub mod env {
	pub const TEST_DIRECTORY: &str = "TEST_DIRECTORY";
	pub const BITCOIND_EXEC: &str = "BITCOIND_EXEC";
	/// The time-out used by the bitcoincore_rpc-client in seconds
	/// If the time-out is exceeded a SocketError(Os { code: 35: WouldBlock, ...})
	/// is returned
	pub const BITCOINRPC_TIMEOUT_SECS: &str = "BITCOINRPC_TIMEOUT_SECS";
	pub const BARK_EXEC: &str = "BARK_EXEC";
	pub const ASPD_EXEC: &str = "ASPD_EXEC";
	pub const LIGHTNINGD_EXEC: &str = "LIGHTNINGD_EXEC";
	pub const LIGHTNINGD_PLUGINS: &str = "LIGHTNINGD_PLUGINS";
}

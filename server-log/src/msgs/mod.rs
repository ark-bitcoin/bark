
mod arkoor;
pub use self::arkoor::*;
mod board;
pub use self::board::*;
mod lightning;
pub use self::lightning::*;
mod fee_estimator;
pub use self::fee_estimator::*;
mod offboards;
pub use self::offboards::*;
mod rounds;
pub use self::rounds::*;
mod txindex;
pub use self::txindex::*;
mod system;
pub use self::system::*;
mod vtxopool;
pub use self::vtxopool::*;
mod wallet;
pub use self::wallet::*;
mod watchman;
pub use self::watchman::*;


use ark::VtxoId;
use bitcoin::secp256k1::PublicKey;
use bitcoin::BlockHash;
use bitcoin::OutPoint;
use bitcoin::Txid;
use bitcoin_ext::BlockHeight;
use chrono::DateTime;
use chrono::Local;


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostgresConnectionPoolConnectionFailure {
	pub err: String,
	pub backtrace: String,
	/// How long pool.get() took before failing (ms).
	pub elapsed_ms: u64,
	/// Pool state when get_conn() was called.
	pub before_connections: u32,
	pub before_idle: u32,
	pub before_get_started: u64,
	pub before_get_direct: u64,
	pub before_get_waited: u64,
	pub before_get_timed_out: u64,
	pub before_pending_gets: u64,
	pub before_connections_created: u64,
	pub before_connections_closed_broken: u64,
	pub before_connections_closed_invalid: u64,
	pub before_connections_closed_idle_timeout: u64,
	pub before_connections_closed_max_lifetime: u64,
	/// Pool state after pool.get() returned the error.
	pub after_connections: u32,
	pub after_idle: u32,
	pub after_get_started: u64,
	pub after_get_direct: u64,
	pub after_get_waited: u64,
	pub after_get_timed_out: u64,
	pub after_pending_gets: u64,
	pub after_connections_created: u64,
	pub after_connections_closed_broken: u64,
	pub after_connections_closed_invalid: u64,
	pub after_connections_closed_idle_timeout: u64,
	pub after_connections_closed_max_lifetime: u64,
}
impl_slog!(PostgresConnectionPoolConnectionFailure, ERROR, "postgres connection pool failed to provide a connection");


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TipUpdated {
	pub height: BlockHeight,
	pub hash: BlockHash,
}
impl_slog!(TipUpdated, DEBUG, "the chain tip has been updated");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncedToHeight {
	pub height: BlockHeight,
	pub hash: BlockHash,
}
impl_slog!(SyncedToHeight, DEBUG, "synced to height");


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredEphemeralTweak {
	pub pubkey: PublicKey,
	pub expires_at: DateTime<Local>,
}
impl_slog!(StoredEphemeralTweak, DEBUG, "stored new ephemeral tweak");


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FetchedEphemeralTweak {
	pub pubkey: PublicKey,
}
impl_slog!(FetchedEphemeralTweak, DEBUG, "fetched ephemeral tweak");


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DroppedEphemeralTweak {
	pub pubkey: PublicKey,
}
impl_slog!(DroppedEphemeralTweak, INFO, "dropped ephemeral tweak");


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CleanedEphemeralTweaks {
	pub nb_tweaks: usize,
}
impl_slog!(CleanedEphemeralTweaks, INFO, "cleaned expired ephemeral tweaks");


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OffboardSessionTimeout {
	pub offboard_txid: Txid,
	pub utxos: Vec<OutPoint>,
	pub vtxos: Vec<VtxoId>,
}
impl_slog!(OffboardSessionTimeout, DEBUG, "offboard session timed out and dropped");


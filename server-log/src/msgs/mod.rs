
mod arkoor;
pub use self::arkoor::*;
mod board;
pub use self::board::*;
mod forfeits;
pub use self::forfeits::*;
mod rounds;
pub use self::rounds::*;
mod sweeps;
pub use self::sweeps::*;
mod txindex;
pub use self::txindex::*;
mod system;
pub use self::system::*;
mod vtxopool;
pub use self::vtxopool::*;
mod wallet;
pub use self::wallet::*;


use bitcoin::secp256k1::PublicKey;
use bitcoin::BlockHash;
use bitcoin_ext::BlockHeight;
use chrono::DateTime;
use chrono::Local;


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostgresConnectionPoolConnectionFailure {
	pub err: String,
	pub backtrace: String,
}
impl_slog!(PostgresConnectionPoolConnectionFailure, Error, "postgres connection pool failed to provide a connection");


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TipUpdated {
	pub height: BlockHeight,
	pub hash: BlockHash,
}
impl_slog!(TipUpdated, Debug, "the chain tip has been updated");


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredEphemeralTweak {
	pub pubkey: PublicKey,
	pub expires_at: DateTime<Local>,
}
impl_slog!(StoredEphemeralTweak, Debug, "stored new ephemeral tweak");


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FetchedEphemeralTweak {
	pub pubkey: PublicKey,
}
impl_slog!(FetchedEphemeralTweak, Debug, "fetched ephemeral tweak");


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DroppedEphemeralTweak {
	pub pubkey: PublicKey,
}
impl_slog!(DroppedEphemeralTweak, Info, "dropped ephemeral tweak");


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CleanedEphemeralTweaks {
	pub nb_tweaks: usize,
}
impl_slog!(CleanedEphemeralTweaks, Info, "cleaned expired ephemeral tweaks");




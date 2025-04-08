
mod board;
pub use self::board::*;
mod rounds;
pub use self::rounds::*;
mod sweeps;
pub use self::sweeps::*;
mod txindex;
pub use self::txindex::*;
mod wallet;
pub use self::wallet::*;
mod system;
pub use self::system::*;


use bitcoin::BlockHash;
use bitcoin_ext::BlockHeight;


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TipUpdated {
	pub height: BlockHeight,
	pub hash: BlockHash,
}
impl_slog!(TipUpdated, Debug, "the chain tip has been updated");


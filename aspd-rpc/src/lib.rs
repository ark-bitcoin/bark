pub extern crate tonic;

mod aspd; // generated
mod convert;
pub use convert::{ConvertError, TryFromBytes};

pub mod protos {
	pub use crate::aspd::*;
}
pub use crate::aspd::ark_service_client::ArkServiceClient;
pub use crate::aspd::admin_service_client::AdminServiceClient;

#[cfg(feature = "server")]
pub mod server {
	pub use crate::aspd::ark_service_server::{ArkService, ArkServiceServer};
	pub use crate::aspd::admin_service_server::{AdminService, AdminServiceServer};
}

use bitcoin::{Address, Amount, OutPoint};
use bitcoin::address::NetworkUnchecked;

/// The maximum number of pubkeys that should be provided to the
/// `empty_arkoor_mailbox` endpoint.
pub const MAX_NB_MAILBOX_PUBKEYS: usize = 100;

#[derive(Debug, Clone)]
pub struct WalletStatus {
	pub address: Address<NetworkUnchecked>,
	pub total_balance: Amount,
	pub trusted_pending_balance: Amount,
	pub untrusted_pending_balance: Amount,
	pub confirmed_balance: Amount,
	pub confirmed_utxos: Vec<OutPoint>,
	pub unconfirmed_utxos: Vec<OutPoint>,
}

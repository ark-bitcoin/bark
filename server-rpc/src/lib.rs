//!
//!
//! # Note on protocol version
//!
//! Whenever anything changes related to the interactions between client and
//! server, including protocol encoding versions, gRPC data fields, expected
//! behavior etc, that is not automatically backwards compatible, the protocol
//! version is bumped.
//!
//! Both the server and the client can be implemented so as to support multiple
//! different protocol versions. This gives maximum flexibility to implement
//! compatibility for both sides.
//!
//! The server advertises the protocol versions it supports and the client picks
//! one and sets it in the header of each subsequent request.
//!
//! However, the server will only check the protocol version in cases where
//! behavior can be different for different versions. This gives outdated or
//! exotic clients an extra level of flexibility, as calls that have not
//! changed since the latest supported protocol version might still work.
//!
//! This makes the server maximally flexible and puts all the responsibility
//! on the client. Our own client implementation bails out if it cannot speak
//! any of the supported protocol versions the server supports.
//!
//! ## Protocol version changelog
//!
//! * `1`: initial version

pub extern crate tonic;

// Generated gRPC method lookup from proto files (server-only)
#[cfg(feature = "server")]
include!(concat!(env!("OUT_DIR"), "/grpc_methods.rs"));

mod convert;
use std::borrow::BorrowMut;

pub use convert::{ConvertError, TryFromBytes};

pub mod client;
pub mod protos {
	pub mod core {
		tonic::include_proto!("core");
	}
	pub use core::*;
	pub mod bark_server {
		tonic::include_proto!("bark_server");
	}
	pub use bark_server::*;
	pub mod intman {
		tonic::include_proto!("intman");
	}
	pub mod mailbox_server {
		tonic::include_proto!("mailbox_server");
	}
}

pub use client::ServerConnection;
pub use crate::protos::bark_server::ark_service_client::ArkServiceClient;

pub mod admin {
	pub use crate::protos::bark_server::wallet_admin_service_client::WalletAdminServiceClient;
	pub use crate::protos::bark_server::round_admin_service_client::RoundAdminServiceClient;
	pub use crate::protos::bark_server::lightning_admin_service_client::LightningAdminServiceClient;
	pub use crate::protos::bark_server::sweep_admin_service_client::SweepAdminServiceClient;
}

#[cfg(feature = "intman")]
pub mod intman {
	pub use crate::protos::intman::integration_service_client::IntegrationServiceClient;
}

#[cfg(feature = "server")]
pub mod server {
	pub use crate::protos::bark_server::ark_service_server::{ArkService, ArkServiceServer};
	pub use crate::protos::bark_server::wallet_admin_service_server::{WalletAdminService, WalletAdminServiceServer};
	pub use crate::protos::bark_server::round_admin_service_server::{RoundAdminService, RoundAdminServiceServer};
	pub use crate::protos::bark_server::lightning_admin_service_server::{LightningAdminService, LightningAdminServiceServer};
	pub use crate::protos::bark_server::sweep_admin_service_server::{SweepAdminService, SweepAdminServiceServer};
	pub use crate::protos::intman::integration_service_server::{IntegrationService, IntegrationServiceServer};
	pub use crate::protos::mailbox_server::mailbox_service_server::{MailboxService, MailboxServiceServer};
}

pub mod mailbox {
	pub use crate::protos::mailbox_server::mailbox_service_client::MailboxServiceClient;
}


use std::str::FromStr;

use bitcoin::{Address, Amount, OutPoint};
use bitcoin::address::NetworkUnchecked;

/// The maximum number of pubkeys that should be provided to the
/// `empty_arkoor_mailbox` endpoint.
pub const MAX_NB_MAILBOX_PUBKEYS: usize = 100;

/// The string used in the gRPC HTTP header for the protocol version.
pub const PROTOCOL_VERSION_HEADER: &str = "pver";

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

/// Extension trait on [tonic::Request].
pub trait RequestExt<T>: BorrowMut<tonic::Request<T>> {
	/// Check for the protocol version header.
	///
	/// Returns None in case of missing header.
	fn try_pver(&self) -> Result<Option<u64>, tonic::Status> {
		self.borrow().metadata().get(PROTOCOL_VERSION_HEADER).map(|v| {
			v.to_str().ok().and_then(|s| u64::from_str(s).ok())
				.ok_or_else(|| tonic::Status::invalid_argument("invalid protocol version header"))
		}).transpose()
	}

	/// Check for the protocol version header.
	///
	/// Returns error in case of missing header.
	fn pver(&self) -> Result<u64, tonic::Status> {
		self.try_pver()?.ok_or_else(|| tonic::Status::invalid_argument("missing pver header"))
	}

	/// Set the protocol version header.
	fn set_pver(&mut self, pver: u64) {
		self.borrow_mut().metadata_mut().insert(PROTOCOL_VERSION_HEADER, pver.into());
	}
}
impl<T> RequestExt<T> for tonic::Request<T> {}

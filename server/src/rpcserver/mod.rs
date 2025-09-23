
pub mod admin;
pub mod ark;
pub mod intman;
mod middleware;
mod convert;


use std::fmt;
use std::sync::atomic::{self, AtomicBool};
use log::trace;
use opentelemetry::KeyValue;
use opentelemetry::trace::get_active_span;
use tokio::sync::oneshot;
use tonic::async_trait;

use server_rpc::RequestExt;
use crate::error::{AnyhowErrorExt, BadArgument, NotFound};


/// The minimum protocol version supported by the server.
///
/// For info on protocol versions, see [server_rpc] module documentation.
pub const MIN_PROTOCOL_VERSION: u64 = 1;

/// The maximum protocol version supported by the server.
///
/// For info on protocol versions, see [server_rpc] module documentation.
pub const MAX_PROTOCOL_VERSION: u64 = 1;

/// Whether to provide rich internal errors to RPC users.
///
/// We keep this static because it's hard to propagate the config
/// into all error conversions.
pub(crate) static RPC_RICH_ERRORS: AtomicBool = AtomicBool::new(false);

/// A trait to easily convert some errors to [tonic::Status].
trait ToStatus {
	fn to_status(self) -> tonic::Status;
}

impl ToStatus for anyhow::Error {
	fn to_status(self) -> tonic::Status {
		// NB tonic seems to have an undocumented limit on the body size
		// of error messages. We don't return the full stack trace, which
		// is included when we format the error with Debug.

		// NB it's important that not found goes first as a bad argument could
		// have been added afterward
		trace!("RPC ERROR: {}", self.full_msg());
		if let Some(nf) = self.downcast_ref::<NotFound>() {
			let mut metadata = tonic::metadata::MetadataMap::new();
			let ids = nf.identifiers().join(",").parse().expect("non-ascii identifier");
			metadata.insert("identifiers", ids);
			tonic::Status::with_metadata(tonic::Code::NotFound, self.full_msg(), metadata)
		} else if let Some(_) = self.downcast_ref::<BadArgument>() {
			tonic::Status::invalid_argument(self.full_msg())
		} else {
			if RPC_RICH_ERRORS.load(atomic::Ordering::Relaxed) {
				tonic::Status::internal(self.full_msg())
			} else {
				tonic::Status::internal("internal error")
			}
		}
	}
}

/// A trait to easily convert some generic [Result]s into [tonic] [Result].
pub trait ToStatusResult<T> {
	/// Convert the error into a tonic error.
	fn to_status(self) -> Result<T, tonic::Status>;
}

impl<T, E: ToStatus> ToStatusResult<T> for Result<T, E> {
	fn to_status(self) -> Result<T, tonic::Status> {
		self.map_err(ToStatus::to_status)
	}
}

/// A trait to add context to errors that return tonic [tonic::Status] errors.
trait StatusContext<T, E> {
	/// Shortcut for `.context(..).to_status()`.
	fn context<C>(self, context: C) -> Result<T, tonic::Status>
	where
		C: fmt::Display + Send + Sync + 'static;

	/// Shortcut for `.badarg(..).to_status()`.
	fn badarg<C>(self, context: C) -> Result<T, tonic::Status>
	where
		C: fmt::Display + Send + Sync + 'static;

	/// Shortcut for `.not_found(..).to_status()`.
	fn not_found<I, V, C>(self, ids: V, context: C) -> Result<T, tonic::Status>
	where
		V: IntoIterator<Item = I>,
		I: fmt::Display,
		C: fmt::Display + Send + Sync + 'static;
}

impl<R, T, E> StatusContext<T, E> for R
where
	R: crate::error::ContextExt<T, E>,
{
	fn context<C>(self, context: C) -> Result<T, tonic::Status>
	where
		C: fmt::Display + Send + Sync + 'static
	{
		anyhow::Context::context(self, context).to_status()
	}

	fn badarg<C>(self, context: C) -> Result<T, tonic::Status>
	where
		C: fmt::Display + Send + Sync + 'static
	{
		crate::error::ContextExt::badarg(self, context).to_status()
	}

	fn not_found<I, V, C>(self, ids: V, context: C) -> Result<T, tonic::Status>
	where
		V: IntoIterator<Item = I>,
		I: fmt::Display,
		C: fmt::Display + Send + Sync + 'static,
	{
		crate::error::ContextExt::not_found(self, ids, context).to_status()
	}
}


#[async_trait]
trait ReceiverExt {
	async fn wait_for_status(self) -> Result<(), tonic::Status>;
}

#[async_trait]
impl ReceiverExt for oneshot::Receiver<anyhow::Error> {
	/// Wait for an explicit Error sent in the channel
	///
	/// If the channel gets closed without any explicit error,
	/// success is assumed
	async fn wait_for_status(self) -> Result<(), tonic::Status> {
		if let Ok(e) = self.await {
			Err(e).to_status()?;
		}

		Ok(())
	}
}

fn add_tracing_attributes(attributes: Vec<KeyValue>) -> () {
	get_active_span(|span| {
		span.add_event("attach-attributes", attributes);
	})
}

/// Get the protocol version sent by the user and check if it's supported.
#[allow(unused)]
fn validate_pver<T>(req: &tonic::Request<T>) -> Result<u64, tonic::Status> {
	let pver = req.pver()?;

	if !(MIN_PROTOCOL_VERSION..=MAX_PROTOCOL_VERSION).contains(&pver) {
		return Err(tonic::Status::invalid_argument("unsupported protocol version"));
	}

	Ok(pver)
}

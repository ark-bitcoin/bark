//! Reporting failures to a NWC client.
//!
//! A host answering requests works in its own error type, usually [anyhow],
//! while NIP-47 wants a code and a message. These extension traits do that
//! conversion at the point of failure, so a call site says which code it means
//! and nothing else.
//!
//! Note that [NIP47Error] cannot implement `From<anyhow::Error>`: both types
//! are foreign to this crate, so the orphan rule rules it out and the
//! conversion has to be named rather than happening under `?`.

use std::fmt;

use log::warn;
use nostr::nips::nip47::{ErrorCode, NIP47Error};


/// Extension trait turning a failure into the error a NWC client receives.
///
/// Implemented for both [Result] and [Option], since a missing value and a
/// failed call are reported to a client the same way.
pub trait ContextExt<T> {
	/// Report an internal failure that was being attempted as `context`.
	///
	/// The client is told only `context` while the failure itself goes to the
	/// log, because the client is a third-party app and the detail describes
	/// wallet internals.
	fn internal(self, context: &str) -> Result<T, NIP47Error>;

	/// Report something this wallet structurally cannot do.
	///
	/// A standing limit rather than a failure, so the client learns not to ask
	/// again rather than retrying.
	fn not_implemented(self, message: impl Into<String>) -> Result<T, NIP47Error>;

	/// Report a failure that no other NIP-47 code describes.
	fn other(self, message: impl Into<String>) -> Result<T, NIP47Error>;
}

impl<T, E: fmt::Display> ContextExt<T> for Result<T, E> {
	fn internal(self, context: &str) -> Result<T, NIP47Error> {
		self.map_err(|e| {
			warn!("NWC {context} failed: {e:#}");
			NIP47Error { code: ErrorCode::Internal, message: context.to_string() }
		})
	}

	fn not_implemented(self, message: impl Into<String>) -> Result<T, NIP47Error> {
		self.map_err(|_| NIP47Error::not_implemented(message))
	}

	fn other(self, message: impl Into<String>) -> Result<T, NIP47Error> {
		self.map_err(|_| NIP47Error::other(message))
	}
}

impl<T> ContextExt<T> for Option<T> {
	fn internal(self, context: &str) -> Result<T, NIP47Error> {
		self.ok_or_else(|| {
			warn!("NWC {context} failed: nothing to report");
			NIP47Error { code: ErrorCode::Internal, message: context.to_string() }
		})
	}

	fn not_implemented(self, message: impl Into<String>) -> Result<T, NIP47Error> {
		self.ok_or_else(|| NIP47Error::not_implemented(message))
	}

	fn other(self, message: impl Into<String>) -> Result<T, NIP47Error> {
		self.ok_or_else(|| NIP47Error::other(message))
	}
}

/// Constructors for the failures that are not something else going wrong, and
/// so have nothing to convert from.
pub trait NIP47ErrorExt {
	/// See [ContextExt::not_implemented].
	fn not_implemented(message: impl Into<String>) -> NIP47Error;

	/// See [ContextExt::other].
	fn other(message: impl Into<String>) -> NIP47Error;
}

impl NIP47ErrorExt for NIP47Error {
	fn not_implemented(message: impl Into<String>) -> NIP47Error {
		NIP47Error { code: ErrorCode::NotImplemented, message: message.into() }
	}

	fn other(message: impl Into<String>) -> NIP47Error {
		NIP47Error { code: ErrorCode::Other, message: message.into() }
	}
}


#[cfg(test)]
mod test {
	use anyhow::Context;

	use super::*;

	fn failing() -> anyhow::Result<u8> {
		Err(anyhow::anyhow!("the database is on fire")).context("while reading")
	}

	/// The client is a third-party app, so it learns what was attempted and
	/// nothing about why it failed.
	#[test]
	fn an_internal_failure_tells_the_client_only_the_context() {
		let err = failing().internal("balance lookup").unwrap_err();

		assert_eq!(err.code, ErrorCode::Internal);
		assert_eq!(err.message, "balance lookup");
		assert!(!err.message.contains("on fire"), "{}", err.message);
	}

	#[test]
	fn a_coded_failure_carries_its_message() {
		let err = failing().not_implemented("bark cannot set an invoice expiry").unwrap_err();
		assert_eq!(err.code, ErrorCode::NotImplemented);
		assert_eq!(err.message, "bark cannot set an invoice expiry");

		let err = failing().other("payment_hash is not valid hex").unwrap_err();
		assert_eq!(err.code, ErrorCode::Other);
		assert_eq!(err.message, "payment_hash is not valid hex");
	}

	/// A missing value is reported the same way as a failed call, so a caller
	/// does not have to turn one into the other first.
	#[test]
	fn a_missing_value_is_reported_like_a_failure() {
		let err = None::<u8>.not_implemented("invoice has no amount").unwrap_err();
		assert_eq!(err.code, ErrorCode::NotImplemented);
		assert_eq!(err.message, "invoice has no amount");

		let err = None::<u8>.internal("chain tip lookup").unwrap_err();
		assert_eq!(err.code, ErrorCode::Internal);
		assert_eq!(err.message, "chain tip lookup");
	}

	#[test]
	fn a_success_passes_through() {
		assert_eq!(Ok::<_, anyhow::Error>(21).internal("balance lookup").unwrap(), 21);
		assert_eq!(Some(21).other("unused").unwrap(), 21);
	}

	#[test]
	fn errors_can_be_built_without_anything_to_convert() {
		let err = NIP47Error::other("either payment_hash or a parseable invoice is required");
		assert_eq!(err.code, ErrorCode::Other);

		let err = NIP47Error::not_implemented("bark cannot bind a description hash");
		assert_eq!(err.code, ErrorCode::NotImplemented);
	}
}

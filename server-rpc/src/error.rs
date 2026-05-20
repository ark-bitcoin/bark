
use std::borrow::Borrow;

use bitcoin::hex::FromHex;
use log::debug;


/// Extension trait for [tonic::Status]
pub trait StatusExt: Borrow<tonic::Status> {
	/// Whether the server rejected the request and no state has changed
	fn is_rejection(&self) -> bool;

	/// Get any not-found identifiers
	fn not_found<T: FromHex>(&self) -> Option<Vec<T>>;
}

impl StatusExt for tonic::Status {
	fn is_rejection(&self) -> bool {
	    match self.code() {
			tonic::Code::InvalidArgument | tonic::Code::NotFound => true,
			_ => false,
		}
	}

	fn not_found<T: FromHex>(&self) -> Option<Vec<T>> {
		if self.code() != tonic::Code::NotFound {
			return None;
		}

		let ids = match self.metadata().get("identifiers") {
			Some(v) => v,
			None => {
				debug!("Server sent NOT_FOUND error without identifiers");
				return Some(vec![]);
			},
		};
		let mut ret = Vec::new();
		let ids_str = match ids.to_str() {
			Ok(v) => v,
			Err(e) => {
				debug!("Invalid (non-ASCII) value in NOT_FOUND identifiers metadata: {:#}", e);
				return Some(vec![]);
			},
		};
		for value in ids_str.split(',') {
			match T::from_hex(value) {
				Ok(v) => ret.push(v),
				Err(e) => {
					debug!("Server NOT_FOUND identifier could not be parsed: {:#}", e);
				},
			}
		}
		Some(ret)
	}
}

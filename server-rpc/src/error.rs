
use std::borrow::Borrow;
use std::str::FromStr;

use bitcoin::hex::FromHex;
use log::debug;

use ark::VtxoId;

/// Extension trait for [tonic::Status]
pub trait StatusExt: Borrow<tonic::Status> {
	/// Whether the server rejected the request and no state has changed
	fn is_rejection(&self) -> bool;

	/// Get any not-found identifiers
	fn not_found<T: FromHex>(&self) -> Option<Vec<T>>;

	/// The VTXO ids the server flagged as the reason it rejected the request.
	///
	/// Returns an empty vec when the status is not a rejection, carries no
	/// identifiers (e.g. an older server), or none of them parse as a vtxo id.
	fn rejected_vtxos(&self) -> Vec<VtxoId>;
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

	fn rejected_vtxos(&self) -> Vec<VtxoId> {
		if !self.is_rejection() {
			return vec![];
		}

		let ids = match self.metadata().get("identifiers") {
			Some(v) => v,
			None => return vec![],
		};
		let ids_str = match ids.to_str() {
			Ok(v) => v,
			Err(e) => {
				debug!("Invalid (non-ASCII) value in identifiers metadata: {:#}", e);
				return vec![];
			},
		};

		ids_str.split(',')
			.filter(|s| !s.is_empty())
			.filter_map(|s| match VtxoId::from_str(s) {
				Ok(id) => Some(id),
				Err(e) => {
					debug!("Server identifier could not be parsed as a vtxo id: {:#}", e);
					None
				},
			})
			.collect()
	}
}

#[cfg(test)]
mod test {
	use super::*;

	const VTXO_A: &str = "0000000000000000000000000000000000000000000000000000000000000001:0";
	const VTXO_B: &str = "0000000000000000000000000000000000000000000000000000000000000002:1";

	#[test]
	fn rejected_vtxos_parses_identifiers_metadata() {
		let a = VtxoId::from_str(VTXO_A).unwrap();
		let b = VtxoId::from_str(VTXO_B).unwrap();
		let mut status = tonic::Status::invalid_argument("input vtxo(s) not spendable");
		status.metadata_mut().insert("identifiers", format!("{},{}", a, b).parse().unwrap());
		assert_eq!(status.rejected_vtxos(), vec![a, b]);
	}

	#[test]
	fn rejected_vtxos_empty_without_metadata() {
		assert!(tonic::Status::invalid_argument("nope").rejected_vtxos().is_empty());
	}

	#[test]
	fn rejected_vtxos_ignores_non_rejection_codes() {
		let a = VtxoId::from_str(VTXO_A).unwrap();
		let mut status = tonic::Status::internal("boom");
		status.metadata_mut().insert("identifiers", a.to_string().parse().unwrap());
		assert!(status.rejected_vtxos().is_empty());
	}

	#[test]
	fn rejected_vtxos_skips_unparseable_entries() {
		let a = VtxoId::from_str(VTXO_A).unwrap();
		let mut status = tonic::Status::invalid_argument("nope");
		status.metadata_mut().insert("identifiers", format!("garbage,{}", a).parse().unwrap());
		assert_eq!(status.rejected_vtxos(), vec![a]);
	}
}

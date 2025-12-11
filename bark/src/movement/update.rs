use std::collections::HashMap;
use std::hash::Hash;

use bdk_esplora::esplora_client::Amount;
use bitcoin::SignedAmount;
use chrono::DateTime;

use ark::vtxo::VtxoRef;
use ark::VtxoId;

use crate::movement::{Movement, MovementDestination};

/// Informs [Movement::apply_update] how to apply a [MovementUpdate].
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
enum UpdateMethod<T> {
	/// Combines the given values with any existing values, ensuring no duplicates are present.
	Merge(T),
	/// Replaces any existing values with the given value.
	Replace(T),
}

/// A struct to allow easy updating of a [Movement]. Each field can be set individually; however,
/// methods are available to allow construction of an update in a more expressive/declarative way.
///
/// Each [Option] field that is set to `None` will be ignored. The default behavior of each field is
/// to merge existing values with the new ones unless a field is explicitly set to
/// [UpdateMethod::Replace] or a method indicates otherwise. Duplicate [VtxoId] values will be
/// ignored.
///
/// See [UpdateMethod] to understand how to control how the [MovementUpdate] is applied.
#[derive(Debug, Clone)]
pub struct MovementUpdate {
	intended_balance: Option<SignedAmount>,
	effective_balance: Option<SignedAmount>,
	offchain_fee: Option<Amount>,
	sent_to: Option<UpdateMethod<Vec<MovementDestination>>>,
	received_on: Option<UpdateMethod<Vec<MovementDestination>>>,
	consumed_vtxos: Option<UpdateMethod<Vec<VtxoId>>>,
	produced_vtxos: Option<UpdateMethod<Vec<VtxoId>>>,
	exited_vtxos: Option<UpdateMethod<Vec<VtxoId>>>,
	metadata: Option<UpdateMethod<HashMap<String, serde_json::Value>>>,
}

impl MovementUpdate {
	pub fn new() -> Self {
		Self {
			intended_balance: None,
			effective_balance: None,
			offchain_fee: None,
			sent_to: None,
			received_on: None,
			consumed_vtxos: None,
			produced_vtxos: None,
			exited_vtxos: None,
			metadata: None,
		}
	}

	pub fn consumed_vtxo(self, vtxo: impl VtxoRef) -> Self {
		self.consumed_vtxos([vtxo.vtxo_id()])
	}

	pub fn consumed_vtxo_if_some(self, vtxo: Option<impl VtxoRef>) -> Self {
		if let Some(vtxo) = vtxo {
			self.consumed_vtxo(vtxo)
		} else {
			self
		}
	}

	pub fn consumed_vtxos(mut self, vtxos: impl IntoIterator<Item = impl VtxoRef>) -> Self {
		let vtxos = vtxos.into_iter().map(|vtxo| vtxo.vtxo_id());
		match &mut self.consumed_vtxos {
			None => self.consumed_vtxos = Some(UpdateMethod::Merge(vtxos.collect())),
			Some(vec) => vec.merge(vtxos),
		}
		self
	}

	pub fn effective_balance(mut self, effective: SignedAmount) -> Self {
		self.effective_balance = Some(effective);
		self
	}

	pub fn exited_vtxo(self, vtxo: impl VtxoRef) -> Self {
		self.exited_vtxos([vtxo.vtxo_id()])
	}

	pub fn exited_vtxo_if_some(self, vtxo: Option<impl VtxoRef>) -> Self {
		if let Some(vtxo) = vtxo {
			self.exited_vtxo(vtxo)
		} else {
			self
		}
	}

	pub fn exited_vtxos(mut self, vtxos: impl IntoIterator<Item = impl VtxoRef>) -> Self {
		let vtxos = vtxos.into_iter().map(|vtxo| vtxo.vtxo_id());
		match &mut self.exited_vtxos {
			None => self.exited_vtxos = Some(UpdateMethod::Merge(vtxos.collect())),
			Some(vec) => vec.merge(vtxos),
		}
		self
	}

	pub fn fee(mut self, offchain_fee: Amount) -> Self {
		self.offchain_fee = Some(offchain_fee);
		self
	}

	pub fn intended_balance(mut self, intended: SignedAmount) -> Self {
		self.intended_balance = Some(intended);
		self
	}

	pub fn intended_and_effective_balance(mut self, balance: SignedAmount) -> Self {
		self.intended_balance = Some(balance);
		self.effective_balance = Some(balance);
		self
	}

	pub fn metadata(
		mut self,
		metadata: impl IntoIterator<Item = (String, serde_json::Value)>,
	) -> Self {
		match &mut self.metadata {
			None => self.metadata = Some(UpdateMethod::Merge(metadata.into_iter().collect())),
			Some(map) => map.insert(metadata),
		}
		self
	}

	pub fn produced_vtxo(self, vtxo: impl VtxoRef) -> Self {
		self.produced_vtxos([vtxo])
	}

	pub fn produced_vtxo_if_some(self, vtxo: Option<impl VtxoRef>) -> Self {
		if let Some(vtxo) = vtxo {
			self.produced_vtxo(vtxo)
		} else {
			self
		}
	}

	pub fn produced_vtxos(mut self, vtxos: impl IntoIterator<Item = impl VtxoRef>) -> Self {
		let vtxos = vtxos.into_iter().map(|v| v.vtxo_id());
		match &mut self.produced_vtxos {
			None => self.produced_vtxos = Some(UpdateMethod::Merge(vtxos.collect())),
			Some(vec) => vec.merge(vtxos),
		}
		self
	}

	pub fn received_on(mut self, received: impl IntoIterator<Item = MovementDestination>) -> Self {
		match &mut self.received_on {
			None => self.received_on = Some(UpdateMethod::Merge(received.into_iter().collect())),
			Some(vec) => vec.merge(received),
		}
		self
	}

	pub fn sent_to(mut self, destinations: impl IntoIterator<Item = MovementDestination>) -> Self {
		match &mut self.sent_to {
			None => self.sent_to = Some(UpdateMethod::Merge(destinations.into_iter().collect())),
			Some(vec) => vec.merge(destinations),
		}
		self
	}

	pub fn replace_consumed_vtxos(mut self, vtxos: impl IntoIterator<Item = impl VtxoRef>) -> Self {
		self.consumed_vtxos = Some(UpdateMethod::Replace(
			vtxos.into_iter().map(|v| v.vtxo_id()).collect(),
		));
		self
	}

	pub fn replace_exited_vtxos(mut self, vtxos: impl IntoIterator<Item = impl VtxoRef>) -> Self {
		self.exited_vtxos = Some(UpdateMethod::Replace(
			vtxos.into_iter().map(|v| v.vtxo_id()).collect(),
		));
		self
	}

	pub fn replace_metadata(
		mut self,
		metadata: impl IntoIterator<Item = (String, serde_json::Value)>,
	) -> Self {
		self.metadata = Some(UpdateMethod::Replace(metadata.into_iter().collect()));
		self
	}

	pub fn replace_produced_vtxos(mut self, vtxos: impl IntoIterator<Item = impl VtxoRef>) -> Self {
		self.produced_vtxos = Some(UpdateMethod::Replace(
			vtxos.into_iter().map(|v| v.vtxo_id()).collect(),
		));
		self
	}

	pub fn replace_received_on(
		mut self,
		received: impl IntoIterator<Item = MovementDestination>,
	) -> Self {
		self.received_on = Some(UpdateMethod::Replace(
			received.into_iter().collect(),
		));
		self
	}

	pub fn replace_sent_on(
		mut self,
		destinations: impl IntoIterator<Item = MovementDestination>,
	) -> Self {
		self.sent_to = Some(UpdateMethod::Replace(
			destinations.into_iter().collect(),
		));
		self
	}

	pub fn apply_to(self, movement: &mut Movement, at: DateTime<chrono::Local>) {
		movement.time.updated_at = at;
		if let Some(metadata) = self.metadata {
			metadata.apply_to(&mut movement.metadata);
		}
		if let Some(intended) = self.intended_balance {
			movement.intended_balance = intended;
		}
		if let Some(effective) = self.effective_balance {
			movement.effective_balance = effective;
		}
		if let Some(offchain_fee) = self.offchain_fee {
			movement.offchain_fee = offchain_fee;
		}
		if let Some(sent_to) = self.sent_to {
			sent_to.apply_to(&mut movement.sent_to);
		}
		if let Some(received_on) = self.received_on {
			received_on.apply_to(&mut movement.received_on);
		}
		if let Some(input_vtxos) = self.consumed_vtxos {
			input_vtxos.apply_unique_to(&mut movement.input_vtxos);
		}
		if let Some(output_vtxos) = self.produced_vtxos {
			output_vtxos.apply_unique_to(&mut movement.output_vtxos);
		}
		if let Some(exited_vtxos) = self.exited_vtxos {
			exited_vtxos.apply_unique_to(&mut movement.exited_vtxos);
		}
	}
}

impl<T: PartialEq + Eq> UpdateMethod<Vec<T>> {
	pub fn apply_to(self, target: &mut Vec<T>) {
		match self {
			UpdateMethod::Merge(vec) => target.extend(vec),
			UpdateMethod::Replace(vec) => *target = vec,
		}
	}

	pub fn apply_unique_to(self, target: &mut Vec<T>) {
		match self {
			UpdateMethod::Merge(vec) => {
				for value in vec {
					if !target.contains(&value) {
						target.push(value);
					}
				}
			},
			UpdateMethod::Replace(vec) => {
				target.clear();
				target.reserve(vec.len());
				for value in vec {
					if !target.contains(&value) {
						target.push(value);
					}
				}
			},
		}
	}

	pub fn merge(&mut self, values: impl IntoIterator<Item = T>) {
		let vec = match self {
			UpdateMethod::Merge(vec) => vec,
			UpdateMethod::Replace(vec) => vec,
		};
		values.into_iter().for_each(|value| vec.push(value));
	}
}

impl<K: Eq + Hash, V> UpdateMethod<HashMap<K, V>> {
	pub fn apply_to(self, target: &mut HashMap<K, V>) {
		match self {
			UpdateMethod::Merge(map) => target.extend(map),
			UpdateMethod::Replace(map) => *target = map,
		}
	}

	pub fn insert(&mut self, key_pairs: impl IntoIterator<Item = (K, V)>) {
		let map = match self {
			UpdateMethod::Merge(map) => map,
			UpdateMethod::Replace(map) => map,
		};
		for (key, value) in key_pairs {
			map.insert(key, value);
		}
	}
}

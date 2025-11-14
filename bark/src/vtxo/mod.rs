pub mod selection;
pub mod state;

use log::{debug, error, trace};
use ark::{ProtocolEncoding, Vtxo};
use ark::vtxo::VtxoRef;

use crate::Wallet;
use crate::movement::MovementId;
use crate::vtxo::state::{VtxoState, VtxoStateKind, UNSPENT_STATES};

impl Wallet {
	/// Attempts to lock VTXOs with the given [VtxoId] values. This will only work if the current
	/// [VtxoState] is contained by [UNSPENT_STATES].
	///
	/// # Errors
	/// - If the VTXO is not in a lockable [VtxoState].
	/// - If the VTXO doesn't exist.
	/// - If a database error occurs.
	pub fn lock_vtxos(
		&self,
		vtxos: impl IntoIterator<Item = impl VtxoRef>,
		movement_id: Option<MovementId>,
	) -> anyhow::Result<()> {
		self.set_vtxo_states(vtxos, &VtxoState::Locked { movement_id }, &UNSPENT_STATES, None)
	}

	/// Attempts to mark VTXOs as [VtxoState::Spent], given that each [VtxoId] is currently a state
	/// contained by [UNSPENT_STATES].
	///
	/// # Errors
	/// - If the VTXO is not currently spent.
	/// - If the VTXO doesn't exist.
	/// - If a database error occurs.
	pub fn mark_vtxos_as_spent(
		&self,
		vtxos: impl IntoIterator<Item = impl VtxoRef>,
		movement_id: Option<MovementId>,
	) -> anyhow::Result<()> {
		self.set_vtxo_states(vtxos, &VtxoState::Spent, &UNSPENT_STATES, movement_id)
	}

	/// Updates the state set the [VtxoState] of VTXOs corresponding to each given [VtxoId]while
	/// validating if the transition is allowed based on the current state and allowed transitions.
	///
	/// # Parameters
	/// - `vtxos`: The [VtxoId] of each [Vtxo] to update.
	/// - `state`: A reference to the new [VtxoState] that the VTXOs should be transitioned to.
	/// - `allowed_states`: A slice of [VtxoStateKind] representing the permissible current states
	///   from which the VTXOs are allowed to transition to the given `state`.
	/// - `movement_id`: A [MovementId] used to track certain state transitions, e.g. from
	///   unspent -> spent.
	///
	/// # Errors
	/// - The database operation to update the states fails.
	/// - The state transition is invalid or does not match the allowed transitions.
	pub fn set_vtxo_states(
		&self,
		vtxos: impl IntoIterator<Item = impl VtxoRef>,
		state: &VtxoState,
		allowed_states: &[VtxoStateKind],
		movement_id: Option<MovementId>,
	) -> anyhow::Result<()> {
		let mut problematic_vtxos = Vec::new();
		for vtxo in vtxos {
			let id = vtxo.vtxo_id();
			if let Err(e) = self.db.update_vtxo_state_checked(
				id,
				state.clone(),
				allowed_states,
			) {
				error!(
					"Failed to set {} state with allowed states {:?} for VTXO {}: {:#}",
					state.kind(), allowed_states, id, e,
				);
				problematic_vtxos.push(id);
			}
			match (state.kind(), movement_id) {
				(VtxoStateKind::Spent, Some(movement_id)) => {
					if let Err(e) = self.db.link_spent_vtxo_to_movement(id, movement_id) {
						error!("Failed to link VTXO {} to movement {}: {:#}", id, movement_id, e);
					}
				},
				_ => {}
			}
		}
		if problematic_vtxos.is_empty() {
			Ok(())
		} else {
			Err(anyhow!(
				"Failed to set {} state for {} VTXOs: {:?}",
				state.kind(),
				problematic_vtxos.len(),
				problematic_vtxos
			))
		}
	}

	/// Stores the given collection of VTXOs in the wallet with an initial state of
	/// [VtxoState::Locked].
	///
	/// # Parameters
	/// - `vtxos`: The VTXOs to store in the wallet.
	/// - `movement_id`: The ID of the [Movement] to indicate how the [Vtxo] was received initially.
	pub fn store_locked_vtxos<'a>(
		&self,
		vtxos: impl IntoIterator<Item = &'a Vtxo>,
		movement_id: Option<MovementId>,
	) -> anyhow::Result<()> {
		self.store_vtxos(vtxos, &VtxoState::Locked { movement_id }, movement_id)
	}

	/// Stores the given collection of VTXOs in the wallet with an initial state of
	/// [VtxoState::Spendable].
	///
	/// # Parameters
	/// - `vtxos`: The VTXOs to store in the wallet.
	/// - `movement_id`: The ID of the [Movement] to indicate how the [Vtxo] was received initially.
	pub fn store_spendable_vtxos<'a>(
		&self,
		vtxos: impl IntoIterator<Item = &'a Vtxo>,
		movement_id: Option<MovementId>,
	) -> anyhow::Result<()> {
		self.store_vtxos(vtxos, &VtxoState::Spendable, movement_id)
	}

	/// Stores the given collection of VTXOs in the wallet with an initial state of
	/// [VtxoState::Spent].
	///
	/// # Parameters
	/// - `vtxos`: The VTXOs to store in the wallet.
	/// - `movement_id`: The ID of the [Movement] to indicate how the [Vtxo] was received initially.
	pub fn store_spent_vtxos<'a>(
		&self,
		vtxos: impl IntoIterator<Item = &'a Vtxo>,
		movement_id: Option<MovementId>,
	) -> anyhow::Result<()> {
		self.store_vtxos(vtxos, &VtxoState::Spent, movement_id)
	}

	/// Stores the given collection of VTXOs in the wallet with the given initial state.
	///
	/// # Parameters
	/// - `vtxos`: The VTXOs to store in the wallet.
	/// - `state`: The initial state of the VTXOs.
	/// - `movement_id`: The ID of the [Movement] to indicate how the [Vtxo] was received initially.
	pub fn store_vtxos<'a>(
		&self,
		vtxos: impl IntoIterator<Item = &'a Vtxo>,
		state: &VtxoState,
		movement_id: Option<MovementId>,
	) -> anyhow::Result<()> {
		let vtxos = vtxos.into_iter().map(|v| (v, state)).collect::<Vec<_>>();
		if let Err(e) = self.db.store_vtxos(&vtxos, movement_id) {
			error!("An error occurred while storing {} VTXOs: {:#}", vtxos.len(), e);
			error!("Raw VTXOs for debugging:");
			for (vtxo, _) in vtxos {
				error!(" - {}", vtxo.serialize_hex());
			}
			Err(e)
		} else {
			debug!("Stored {} VTXOs", vtxos.len());
			trace!("New VTXO IDs: {:?}", vtxos.into_iter().map(|(v, _)| v.id()));
			Ok(())
		}
	}

	/// Attempts to unlock VTXOs with the given [VtxoId] values. This will only work if the current
	/// [VtxoState] is [VtxoStateKind::Locked].
	///
	/// # Errors
	/// - If the VTXO is not currently locked.
	/// - If the VTXO doesn't exist.
	/// - If a database error occurs.
	pub fn unlock_vtxos(
		&self,
		vtxos: impl IntoIterator<Item = impl VtxoRef>,
	) -> anyhow::Result<()> {
		self.set_vtxo_states(vtxos, &VtxoState::Spendable, &[VtxoStateKind::Locked], None)
	}
}

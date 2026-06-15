
mod selection;
mod signing;
mod state;

pub use self::selection::{FilterVtxos, RefreshStrategy, VtxoFilter};
pub use self::state::{VtxoLockHolder, VtxoState, VtxoStateKind, WalletVtxo};

use log::{debug, error, trace};
use ark::{ProtocolEncoding, Vtxo};
use ark::vtxo::{Full, VtxoRef};

use crate::Wallet;

impl Wallet {
	/// Attempts to lock VTXOs with the given [VtxoId](ark::VtxoId) values.
	///
	/// Only [VtxoStateKind::Spendable] vtxos can be locked; re-locking a
	/// vtxo that is already in the exact target state (same holder) is a
	/// no-op success, but any other prior state — including a Locked vtxo
	/// owned by a different holder — fails. The whole batch is atomic:
	/// if any vtxo fails the check, no vtxo's state changes.
	///
	/// `holder` records which operation is reserving the vtxos so
	/// "who holds this vtxo?" is a typed lookup. Pass `None` only for
	/// the narrow window before the operation's holder identity is
	/// known (e.g. offboard's preparatory arkoor).
	///
	/// # Errors
	/// - If any VTXO is not Spendable (and not already locked by the same holder).
	/// - If a VTXO doesn't exist.
	/// - If a database error occurs.
	pub async fn lock_vtxos(
		&self,
		vtxos: impl IntoIterator<Item = impl VtxoRef>,
		holder: Option<VtxoLockHolder>,
	) -> anyhow::Result<()> {
		self.set_vtxo_states(
			vtxos, &VtxoState::Locked { holder }, &[VtxoStateKind::Spendable],
		).await
	}

	/// Marks VTXOs as [VtxoState::Spent].
	///
	/// This operation is idempotent: VTXOs already in [VtxoState::Spent] will
	/// remain spent without inserting a redundant state entry.
	///
	/// # Errors
	/// - If the VTXO doesn't exist.
	/// - If a database error occurs.
	pub async fn mark_vtxos_as_spent(
		&self,
		vtxos: impl IntoIterator<Item = impl VtxoRef>,
	) -> anyhow::Result<()> {
		const ALLOWED: &[VtxoStateKind] = &[
			VtxoStateKind::Spendable,
			VtxoStateKind::Locked,
			VtxoStateKind::Spent,
		];
		self.set_vtxo_states(vtxos, &VtxoState::Spent, ALLOWED).await
	}

	/// Marks VTXOs as [VtxoState::Exited]. Called from the unilateral exit progression once
	/// every exit transaction has been broadcast — at that point the VTXO is effectively gone
	/// from the protocol's view, but it shouldn't be confused with a forfeited VTXO.
	///
	/// This operation is idempotent: VTXOs already in [VtxoState::Exited] will remain exited
	/// without inserting a redundant state entry.
	///
	/// # Errors
	/// - If the VTXO is in a state other than `Spendable`, `Locked`, or `Exited`.
	/// - If the VTXO doesn't exist.
	/// - If a database error occurs.
	pub async fn mark_vtxos_as_exited(
		&self,
		vtxos: impl IntoIterator<Item = impl VtxoRef>,
	) -> anyhow::Result<()> {
		const ALLOWED: &[VtxoStateKind] = &[
			VtxoStateKind::Spendable,
			VtxoStateKind::Locked,
			VtxoStateKind::Exited,
		];
		self.set_vtxo_states(vtxos, &VtxoState::Exited, ALLOWED).await
	}

	/// Updates the state set the [VtxoState] of VTXOs corresponding to each given
	/// [VtxoId](ark::VtxoId) while validating if the transition is allowed based
	/// on the current state and allowed transitions.
	///
	/// # Parameters
	/// - `vtxos`: The [VtxoId](ark::VtxoId) of each [Vtxo] to update.
	/// - `state`: A reference to the new [VtxoState] that the VTXOs should be transitioned to.
	/// - `allowed_states`: A slice of [VtxoStateKind] representing the permissible current states
	///   from which the VTXOs are allowed to transition to the given `state`. If an empty
	///   slice is passed, all states are allowed.
	///
	/// # Errors
	/// - The database operation to update the states fails.
	/// - The state transition is invalid or does not match the allowed transitions.
	pub async fn set_vtxo_states(
		&self,
		vtxos: impl IntoIterator<Item = impl VtxoRef>,
		state: &VtxoState,
		mut allowed_states: &[VtxoStateKind],
	) -> anyhow::Result<()> {
		if allowed_states.is_empty() {
			allowed_states = VtxoStateKind::ALL;
		}

		let ids: Vec<_> = vtxos.into_iter().map(|v| v.vtxo_id()).collect();
		self.inner.db.update_vtxo_states_checked(&ids, state.clone(), allowed_states).await
	}

	/// Stores the given collection of VTXOs in the wallet with an initial state of
	/// [VtxoState::Locked].
	///
	/// It does nothing if the VTXOs already exist.
	///
	/// # Parameters
	/// - `vtxos`: The VTXOs to store in the wallet.
	pub async fn store_locked_vtxos<'a>(
		&self,
		vtxos: impl IntoIterator<Item = &'a Vtxo<Full>>,
		holder: Option<VtxoLockHolder>,
	) -> anyhow::Result<()> {
		self.store_vtxos(vtxos, &VtxoState::Locked { holder }).await
	}

	/// Stores the given collection of VTXOs in the wallet with an initial state of
	/// [VtxoState::Spendable].
	///
	/// It does nothing if the VTXOs already exist.
	///
	/// Also posts the vtxo IDs to the server's recovery mailbox (non-critical, errors are logged).
	///
	/// # Parameters
	/// - `vtxos`: The VTXOs to store in the wallet.
	pub async fn store_spendable_vtxos<'a>(
		&self,
		vtxos: impl IntoIterator<Item = &'a Vtxo<Full>> + Clone,
	) -> anyhow::Result<()> {
		self.store_vtxos(vtxos.clone(), &VtxoState::Spendable).await?;

		// Post vtxo IDs to server for recovery (non-critical, just log errors)
		if let Err(e) = self.post_recovery_vtxo_ids(vtxos.into_iter().map(|v| v.id())).await {
			error!("Failed to post recovery vtxo IDs to server: {:#}", e);
		}

		Ok(())
	}

	/// Stores the given collection of VTXOs in the wallet with an initial state of
	/// [VtxoState::Spent].
	///
	/// It does nothing if the VTXOs already exist.
	///
	/// # Parameters
	/// - `vtxos`: The VTXOs to store in the wallet.
	pub async fn store_spent_vtxos<'a>(
		&self,
		vtxos: impl IntoIterator<Item = &'a Vtxo<Full>>,
	) -> anyhow::Result<()> {
		self.store_vtxos(vtxos, &VtxoState::Spent).await
	}

	/// Stores the given collection of VTXOs in the wallet with the given initial state.
	///
	/// It does nothing if the VTXOs already exist.
	///
	/// # Parameters
	/// - `vtxos`: The VTXOs to store in the wallet.
	/// - `state`: The initial state of the VTXOs.
	pub async fn store_vtxos<'a>(
		&self,
		vtxos: impl IntoIterator<Item = &'a Vtxo<Full>>,
		state: &VtxoState,
	) -> anyhow::Result<()> {
		let vtxos = vtxos.into_iter().map(|v| (v, state)).collect::<Vec<_>>();
		if let Err(e) = self.inner.db.store_vtxos(&vtxos).await {
			error!("An error occurred while storing {} VTXOs: {:#}", vtxos.len(), e);
			error!("Raw VTXOs for debugging:");
			for (vtxo, _) in vtxos {
				error!(" - {}", vtxo.serialize_hex());
			}
			Err(e)
		} else {
			debug!("Stored {} VTXOs", vtxos.len());
			trace!("New VTXO IDs: {:?}", vtxos.into_iter().map(|(v, _)| v.id()).collect::<Vec<_>>());
			Ok(())
		}
	}

	/// Attempts to unlock VTXOs with the given [VtxoId](ark::VtxoId) values. This will only work if the current
	/// [VtxoState] is [VtxoStateKind::Locked] or [VtxoStateKind::Spendable].
	///
	/// This operation is idempotent: VTXOs already in [VtxoState::Spendable] will
	/// remain spendable without inserting a redundant state entry.
	///
	/// # Errors
	/// - If the VTXO is not currently locked or spendable.
	/// - If the VTXO doesn't exist.
	/// - If a database error occurs.
	pub async fn unlock_vtxos(
		&self,
		vtxos: impl IntoIterator<Item = impl VtxoRef>,
	) -> anyhow::Result<()> {
		self.set_vtxo_states(
			vtxos, &VtxoState::Spendable, &[VtxoStateKind::Locked, VtxoStateKind::Spendable],
		).await
	}
}

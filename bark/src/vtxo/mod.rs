
pub mod selection;
mod signing;
mod state;

pub use self::selection::{FilterVtxos, RefreshStrategy, VtxoFilter};
pub use self::state::{VtxoLockHolder, VtxoState, VtxoStateKind, WalletVtxo};

use bitcoin::secp256k1::PublicKey;
use log::{debug, error, trace};
use ark::{ProtocolEncoding, Vtxo};
use ark::vtxo::{Full, VtxoRef};
use bitcoin_ext::{BlockDelta, BlockHeight};

use crate::Wallet;

/// Validate the tree-level security parameters the server chose for the VTXOs
/// we're about to accept in a round.
///
/// Checks that server pubkey and exit delta match.
/// Checks that expiry height is above minimum threshold.
pub(crate) fn validate_vtxo_tree_params(
	server_pubkey: PublicKey,
	exit_delta: BlockDelta,
	expiry_height: BlockHeight,
	expected_server_pubkey: PublicKey,
	expected_exit_delta: BlockDelta,
	min_expiry_height: BlockHeight,
) -> anyhow::Result<()> {
	ensure!(server_pubkey == expected_server_pubkey,
		"round VTXO tree uses an unexpected server pubkey: got {}, expected {}",
		server_pubkey, expected_server_pubkey,
	);

	ensure!(exit_delta == expected_exit_delta,
		"round VTXO tree uses an unexpected exit delta: got {}, expected {}",
		exit_delta, expected_exit_delta,
	);

	ensure!(expiry_height >= min_expiry_height,
		"round VTXO tree expiry height {} is below the required minimum {}; \
		server may be trying to sweep before we can exit",
		expiry_height, min_expiry_height,
	);

	Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum VtxoValidationError {
	#[error("chain error: {0}")]
	Chain(anyhow::Error),
	#[error("anchor not found")]
	AnchorNotFound,
	#[error("invalid: {0}")]
	Invalid(#[from] ark::vtxo::VtxoValidationError),
}

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
	/// Also posts the vtxo IDs to the server's recovery mailbox (non-critical, errors are logged).
	///
	/// # Parameters
	/// - `vtxos`: The VTXOs to store in the wallet.
	pub async fn store_locked_vtxos<'a>(
		&self,
		vtxos: impl IntoIterator<Item = &'a Vtxo<Full>> + Clone,
		holder: Option<VtxoLockHolder>,
	) -> anyhow::Result<()> {
		self.store_vtxos(vtxos.clone(), &VtxoState::Locked { holder }).await?;

		// Post vtxo IDs to server for recovery (non-critical, just log errors)
		if let Err(e) = self.post_recovery_vtxo_ids(vtxos.into_iter().map(|v| v.id())).await {
			error!("Failed to post recovery vtxo IDs to server: {:#}", e);
		}

		Ok(())
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

	/// Release `holder`'s lock on the given VTXOs, transitioning each one
	/// to [VtxoState::Spendable]. `holder` must match the value passed to
	/// [Self::lock_vtxos] when the lock was taken; a mismatch (including
	/// `None` vs `Some`) leaves the vtxo untouched. VTXOs not currently
	/// locked by `holder` are silently skipped, so calling this
	/// repeatedly is equivalent to calling it once and can safely be
	/// retried after a crash mid-batch.
	pub async fn unlock_vtxos(
		&self,
		vtxos: impl IntoIterator<Item = impl VtxoRef>,
		holder: Option<VtxoLockHolder>,
	) -> anyhow::Result<()> {
		for v in vtxos {
			self.inner.db.release_vtxo_lock(v.vtxo_id(), holder.as_ref()).await?;
		}
		Ok(())
	}
}

#[cfg(test)]
mod test {
	use super::*;

	use bip39::rand;
	use bitcoin::key::Keypair;
	use bitcoin::secp256k1::Secp256k1;

	use ark::vtxo::policy::MAX_BLOCK_DELTA;

	#[test]
	fn vtxo_tree_params_accepts_honest_and_rejects_hostile() {
		let secp = Secp256k1::new();
		let mut rng = rand::thread_rng();
		let server = Keypair::new(&secp, &mut rng).public_key();
		let other = Keypair::new(&secp, &mut rng).public_key();

		let exit_delta: BlockDelta = 144;
		let min_expiry: BlockHeight = 100_000;

		// Expiry at or above the minimum, with matching pubkey and delta, passes.
		validate_vtxo_tree_params(server, exit_delta, min_expiry, server, exit_delta, min_expiry)
			.expect("expiry exactly at the minimum should validate");
		validate_vtxo_tree_params(
			server, exit_delta, min_expiry + 5_000, server, exit_delta, min_expiry,
		).expect("expiry above the minimum should validate");

		// A wrong server pubkey is rejected.
		assert!(validate_vtxo_tree_params(
			other, exit_delta, min_expiry, server, exit_delta, min_expiry,
		).is_err(), "wrong server pubkey must be rejected");

		// An inflated exit delta (hostage) is rejected.
		assert!(validate_vtxo_tree_params(
			server, MAX_BLOCK_DELTA, min_expiry, server, exit_delta, min_expiry,
		).is_err(), "inflated exit delta must be rejected");

		// An expiry below the minimum (e.g. the short-expiry sweep attack) is
		// rejected, right down to a single block short.
		assert!(validate_vtxo_tree_params(
			server, exit_delta, min_expiry - 1, server, exit_delta, min_expiry,
		).is_err(), "expiry one block below the minimum must be rejected");
	}
}

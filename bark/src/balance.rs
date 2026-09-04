//! The wallet balance: which sats can be spent right now and which are held
//! by an operation in progress.
//!
//! [Wallet::balance] sums the spendable VTXOs, setting aside the ones that
//! have to be refreshed before they can be sent again, and then asks every
//! operation in progress which VTXOs it holds, so a VTXO is counted once, in
//! the field of the operation that holds it.

use std::collections::{HashMap, HashSet};

use bitcoin::Amount;
use bitcoin_ext::BlockHeight;
use log::{debug, warn};

use ark::VtxoId;

use crate::{Wallet, WalletVtxo};
use crate::actions::{WalletAction, WalletActionCheckpoint};
use crate::exit::ExitStateKind;
use crate::vtxo::{VtxoState, VtxoStateKind};

/// The different balances of a Bark wallet.
///
/// Each field counts different VTXOs, so the fields never overlap. See
/// [Wallet::balance] for how the fields are computed.
#[derive(Debug, Clone)]
pub struct Balance {
	/// Sats in VTXOs that can be spent right now, in an arkoor or lightning
	/// payment, an offboard or a round.
	pub spendable: Amount,
	/// Sats in VTXOs that can no longer be sent in an arkoor payment because
	/// they have expired or their exit depth has reached the server's limit.
	/// Nothing holds them, and they can still be offboarded, exited or
	/// refreshed, but they are kept out of [Balance::spendable] until
	/// maintenance has refreshed them. See [crate::WalletVtxo::needs_refresh].
	pub needs_refresh: Amount,
	/// Sats locked in an outgoing lightning payment that has not settled yet.
	/// They come back as spendable VTXOs if the payment fails and leave the
	/// wallet once the payment succeeds.
	pub pending_lightning_send: Amount,
	/// Sats in HTLC VTXOs of an incoming lightning payment whose preimage has
	/// been revealed but which have not been swapped for spendable VTXOs yet.
	/// An incoming payment that can still be cancelled is not counted.
	pub claimable_lightning_receive: Amount,
	/// Sats locked in VTXOs used as inputs to a round that has not completed
	/// yet. A participation still awaiting its round holds no lock, so its
	/// inputs stay in [Balance::spendable]: an interactive participation locks
	/// them when a round attempt starts, a delegated one once the server has
	/// issued the round and its funding transaction has been seen.
	pub pending_in_round: Amount,
	/// Sats in VTXOs whose unilateral exit has committed on-chain but which
	/// have not been claimed to the on-chain wallet yet. These VTXOs are
	/// [`crate::vtxo::VtxoStateKind::Exited`] and unusable in the Ark protocol.
	/// An exit that can still be canceled isn't counted here.
	pub pending_exit: Amount,
	/// Sats in board VTXOs that are waiting for enough on-chain confirmations
	/// to be registered with the Ark server. A board whose funding transaction
	/// has not reached the network is not counted anywhere yet.
	pub pending_board: Amount,
	/// Sats locked in an outgoing arkoor payment that has not completed yet:
	/// the whole input amount, until the send finalizes and the change comes
	/// back as spendable.
	pub pending_arkoor_send: Amount,
	/// Sats locked in an offboard whose transaction has not been broadcast
	/// yet, including any change that comes back. Once the transaction is on
	/// the network the sats belong to the on-chain wallet.
	pub pending_offboard: Amount,
}

impl Wallet {
	/// Return the [Balance] of the wallet.
	///
	/// When not running the daemon, make sure you sync before calling this method.
	pub async fn balance(&self) -> anyhow::Result<Balance> {
		let tip = match self.inner.chain.tip().await {
			Ok(tip) => Some(tip),
			Err(e) => {
				debug!("Chain tip unavailable for the balance, using the last one seen: {:#}", e);
				self.inner.chain.last_observed_tip().await
			},
		};
		let max_exit_depth = match self.ark_info().await {
			Ok(info) => info.map(|i| i.max_vtxo_exit_depth),
			Err(e) => {
				// TODO(pc): Cache this value in the wallet to solve the case where the server is
				//   unreachable and the users balance is miscategorized as a result.
				debug!("Server info unavailable for the balance, judging expiry only: {:#}", e);
				None
			},
		};

		// Every VTXO the balance can count, read once.
		let vtxos = self.inner.db.get_vtxos_by_state(
			&[VtxoStateKind::Spendable, VtxoStateKind::Locked, VtxoStateKind::Exited],
		).await?.into_iter().map(|v| (v.id(), v)).collect::<HashMap<_, _>>();

		let mut balance = Balance {
			spendable: Amount::ZERO,
			needs_refresh: Amount::ZERO,
			pending_in_round: Amount::ZERO,
			pending_lightning_send: Amount::ZERO,
			claimable_lightning_receive: Amount::ZERO,
			pending_exit: Amount::ZERO,
			pending_board: Amount::ZERO,
			pending_arkoor_send: Amount::ZERO,
			pending_offboard: Amount::ZERO,
		};

		for vtxo in vtxos.values().filter(|v| v.state == VtxoState::Spendable) {
			// Without a tip only the depth can be judged; a tip of zero
			// expires nothing.
			if vtxo.needs_refresh(tip.unwrap_or(BlockHeight::ZERO), max_exit_depth) {
				balance.needs_refresh += vtxo.amount();
			} else {
				balance.spendable += vtxo.amount();
			}
		}

		let mut counted = HashSet::with_capacity(vtxos.len());
		for round in self.pending_round_states().await? {
			let holder = round.state().lock_holder();
			for input in round.state().locked_pending_inputs() {
				let Some(vtxo) = vtxos.get(&input.id()) else { continue };
				let held = matches!(&vtxo.state, VtxoState::Locked { holder: h } if *h == holder);
				if held && counted.insert(vtxo.id()) {
					balance.pending_in_round += vtxo.amount();
				}
			}
		}

		for action in self.inner.db.get_all_wallet_action_checkpoints().await? {
			match &action {
				WalletActionCheckpoint::LightningSend(a) => {
					balance.pending_lightning_send += held_by(a, &vtxos, &mut counted);
				},
				WalletActionCheckpoint::LightningReceive(a) => {
					balance.claimable_lightning_receive += held_by(a, &vtxos, &mut counted);
				},
				WalletActionCheckpoint::ArkoorSend(a) => {
					balance.pending_arkoor_send += held_by(a, &vtxos, &mut counted);
				},
				WalletActionCheckpoint::Board(a) => {
					balance.pending_board += held_by(a, &vtxos, &mut counted);
				},
				WalletActionCheckpoint::Offboard(a) => {
					balance.pending_offboard += held_by(a, &vtxos, &mut counted);
				},
			}
		}

		// Read the exits from the database rather than the exit manager, whose
		// lock may be held for a while by an exit in progress.
		let exits = self.inner.db
			.get_exit_vtxo_entries_with_states(ExitStateKind::LIVE_STATES).await?;
		for exit in exits {
			if !exit.state.warrants_exited_vtxo() {
				continue;
			}
			match vtxos.get(&exit.vtxo_id) {
				Some(v) if v.state == VtxoState::Exited => balance.pending_exit += v.amount(),
				Some(v) => warn!("Exit of VTXO {} has committed but the VTXO is {:?}",
					exit.vtxo_id, v.state,
				),
				None => warn!("Exit of VTXO {} has committed but the VTXO is spent or unknown",
					exit.vtxo_id,
				),
			}
		}

		Ok(balance)
	}
}

/// The sats `action` holds: the locked VTXOs among the ones it reports,
/// leaving out any already `counted` by another operation.
fn held_by<A: WalletAction>(
	action: &A,
	vtxos: &HashMap<VtxoId, WalletVtxo>,
	counted: &mut HashSet<VtxoId>,
) -> Amount {
	let mut amount = Amount::ZERO;
	for id in action.pending_balance_vtxo_ids() {
		if !counted.insert(id) {
			warn!("VTXO {} is held by action {} but was already counted", id, action.id());
			continue;
		}
		// A spent VTXO is not in the map: the action is done with it.
		let Some(vtxo) = vtxos.get(&id) else { continue };
		match vtxo.state {
			VtxoState::Locked { .. } => amount += vtxo.amount(),
			// An exit took it from the action; it counts in pending_exit.
			VtxoState::Exited => {},
			// Released by the action, or not locked by it yet.
			VtxoState::Spendable => {},
			VtxoState::Spent => {},
		}
	}
	amount
}

//! Consistency checks for the [bark::Balance] of an in-process SDK wallet.

use bitcoin::Amount;

use ark::VtxoId;
use bark::actions::WalletAction;
use bark::vtxo::VtxoState;

/// Fetch the balance, syncing first when `sync` is set, and assert that it
/// agrees with the wallet's VTXOs and operations: the spendable sats are the
/// spendable VTXOs that need no refresh, every pending field is the locked
/// VTXOs its operations report, no locked VTXO is counted twice and the
/// totals add up. Returns the balance so callers can assert the individual
/// amounts.
pub async fn assert_balance_consistent(wallet: &bark::Wallet, sync: bool) -> bark::Balance {
	if sync {
		wallet.sync().await;
	}
	let balance = wallet.balance().await.expect("balance");
	let vtxos = wallet.vtxos().await.expect("vtxos");

	let locked_amount_of = |ids: &[VtxoId]| -> Amount {
		vtxos.iter()
			.filter(|v| ids.contains(&v.id()) && matches!(v.state, VtxoState::Locked { .. }))
			.map(|v| v.amount())
			.sum()
	};

	let tip = wallet.chain().tip().await.expect("chain tip");
	let max_exit_depth = wallet.ark_info().await.expect("ark info").map(|i| i.max_vtxo_exit_depth);
	let mut spendable = Amount::ZERO;
	let mut needs_refresh = Amount::ZERO;
	let mut locked = Amount::ZERO;
	for vtxo in &vtxos {
		match vtxo.state {
			VtxoState::Spendable if vtxo.needs_refresh(tip, max_exit_depth) => {
				needs_refresh += vtxo.amount()
			},
			VtxoState::Spendable => spendable += vtxo.amount(),
			VtxoState::Locked { .. } => locked += vtxo.amount(),
			VtxoState::Spent | VtxoState::Exited => panic!("vtxos() returned a spent VTXO"),
		}
	}
	assert_eq!(balance.spendable, spendable,
		"spendable must equal the spendable VTXOs that need no refresh: {balance:?}",
	);
	assert_eq!(balance.needs_refresh, needs_refresh,
		"needs_refresh must equal the expired or depth-limited spendable VTXOs: {balance:?}",
	);

	let round_ids = wallet.pending_round_input_vtxos().await.expect("round inputs")
		.iter().map(|v| v.id()).collect::<Vec<_>>();
	assert_eq!(balance.pending_in_round, locked_amount_of(&round_ids),
		"pending_in_round must equal the locked round inputs: {balance:?}",
	);

	let board_ids = wallet.pending_board_vtxos().await.expect("pending board vtxos")
		.iter().map(|v| v.id()).collect::<Vec<_>>();
	assert_eq!(balance.pending_board, locked_amount_of(&board_ids),
		"pending_board must equal the confirming board VTXOs: {balance:?}",
	);

	let ln_send_ids = wallet.pending_lightning_sends().await.expect("ln sends").iter()
		.flat_map(|s| s.pending_balance_vtxo_ids())
		.collect::<Vec<_>>();
	assert_eq!(balance.pending_lightning_send, locked_amount_of(&ln_send_ids),
		"pending_lightning_send must equal the VTXOs held by lightning sends: {balance:?}",
	);

	let ln_recv_ids = wallet.pending_lightning_receives().await.expect("ln receives").iter()
		.flat_map(|r| r.pending_balance_vtxo_ids())
		.collect::<Vec<_>>();
	assert_eq!(balance.claimable_lightning_receive, locked_amount_of(&ln_recv_ids),
		"claimable_lightning_receive must equal the revealed HTLC VTXOs: {balance:?}",
	);

	let send_ids = wallet.pending_arkoor_sends().await.expect("arkoor sends").iter()
		.flat_map(|s| s.pending_balance_vtxo_ids())
		.collect::<Vec<_>>();
	assert_eq!(balance.pending_arkoor_send, locked_amount_of(&send_ids),
		"pending_arkoor_send must equal the VTXOs held by arkoor sends: {balance:?}",
	);

	let offboard_ids = wallet.pending_offboards().await.expect("offboards").iter()
		.flat_map(|o| o.pending_balance_vtxo_ids())
		.collect::<Vec<_>>();
	assert_eq!(balance.pending_offboard, locked_amount_of(&offboard_ids),
		"pending_offboard must equal the VTXOs held by offboards: {balance:?}",
	);

	let pending_locked = balance.pending_in_round
		+ balance.pending_board
		+ balance.pending_arkoor_send
		+ balance.pending_lightning_send
		+ balance.claimable_lightning_receive
		+ balance.pending_offboard;
	assert!(pending_locked <= locked,
		"pending fields count more than the locked VTXOs ({locked}): {balance:?}",
	);
	assert_eq!(balance.pending(), pending_locked + balance.pending_exit, "{balance:?}");
	assert_eq!(balance.total(), spendable + needs_refresh + pending_locked + balance.pending_exit,
		"total must be the sum of every field: {balance:?}",
	);
	assert_eq!(balance.has_pending(), balance.pending() > Amount::ZERO, "{balance:?}");
	let summary = balance.summary();
	assert_eq!(
		(summary.spendable, summary.needs_refresh, summary.pending, summary.total),
		(balance.spendable, balance.needs_refresh, balance.pending(), balance.total()),
		"{balance:?}",
	);
	balance
}

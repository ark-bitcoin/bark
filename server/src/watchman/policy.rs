
use bitcoin::Txid;

use ark::{ServerVtxo, ServerVtxoPolicy, VtxoId, VtxoPolicy};
use ark::lightning::PaymentHash;
use bitcoin_ext::{BlockDelta, BlockHeight};
use server_log::slog;
use tracing::warn;

use crate::database::Db;
use super::{Action, Config};

struct ActionParams<T = ()> {
	vtxo_id: VtxoId,
	chain_tip_height: BlockHeight,
	//TODO(stevenroose) why option
	progress_grace_period: Option<BlockDelta>,
	expiry_height: BlockHeight,
	exit_delta: BlockDelta,
	confirmed_at: BlockHeight,
	/// Policy-specific extra database
	///
	/// Defaults to nothing (`()`).
	policy_extras: T,
}

impl ActionParams<()> {
	/// Add policy extras to the params
	fn with_policy_extras<U>(self, policy_extras: U) -> ActionParams<U> {
		ActionParams {
			vtxo_id: self.vtxo_id,
			chain_tip_height: self.chain_tip_height,
			progress_grace_period: self.progress_grace_period,
			expiry_height: self.expiry_height,
			exit_delta: self.exit_delta,
			confirmed_at: self.confirmed_at,
			policy_extras,
		}
	}
}

struct PubkeyExtra {
	/// The next transaction, if any. The bool indicates whether the signature is known.
	next_tx: Option<(Txid, bool)>,
	/// Whether the server may own an ancestor of this VTXO.
	server_may_own_ancestor: bool,
}

struct HtlcSendExtra {
	/// The next transaction, if any. The bool indicates whether the signature is known.
	next_tx: Option<(Txid, bool)>,
	htlc_expiry: BlockHeight,
	has_preimage: bool,
}

struct HtlcRecvExtra {
	/// The next transaction, if any. The bool indicates whether the signature is known.
	next_tx: Option<(Txid, bool)>,
	htlc_expiry: BlockHeight,
	htlc_expiry_delta: BlockDelta,
}

/// Check if we can continue to the next tx in the chain from these params
///
/// If possible, it returns a `Wait` action until the grace period passed
/// and then a `Progress` action
fn try_progress<T>(
	params: &ActionParams<T>,
	next_tx: Option<(Txid, bool)>,
	deadline: BlockHeight,
) -> Option<Action> {
	let txid = match next_tx {
		Some((txid, true)) => txid,
		Some((txid, false)) => {
			slog!(ProgressMissingSignature, vtxo_id: params.vtxo_id, txid);
			return None;
		},
		None => return None,
	};

	if let Some(wait_blocks) = params.progress_grace_period {
		if params.chain_tip_height.saturating_sub(params.confirmed_at) < wait_blocks.into() {
			return Some(Action::Wait);
		}
	}

	Some(Action::Progress { txid, deadline: Some(deadline) })
}

/// Determine the action for an Expiry policy
///
/// Claim if expired, otherwise wait
fn decide_action_expiry(params: &ActionParams) -> Action {
	if params.chain_tip_height >= params.expiry_height {
		Action::Claim { deadline: None }
	} else {
		Action::Wait
	}
}

/// Determine action for Pubkey policy
///
/// We should continue with checkpoint tx if we own an ancestor, otherwise
/// do nothing, the VTXO is exit by the user and owned by him.
fn decide_action_pubkey(params: &ActionParams<PubkeyExtra>) -> Action {
	if !params.policy_extras.server_may_own_ancestor {
		return Action::Wait;
	}
	let deadline = params.confirmed_at + BlockHeight::from(params.exit_delta);
	try_progress(params, params.policy_extras.next_tx, deadline).unwrap_or(Action::Wait)
}

/// Determine action for ServerHtlcSend (outgoing Lightning payment).
///
/// The server can claim with preimage after `exit_delta` from confirmation.
/// The user can reclaim after `htlc_expiry` AND `2*exit_delta` from confirmation.
///
/// Deadline is `min(htlc_expiry, confirmed_at + 2*exit_delta)`.
fn decide_action_server_htlc_send(params: &ActionParams<HtlcSendExtra>) -> Action {
	let deadline = std::cmp::min(
		params.policy_extras.htlc_expiry,
		params.confirmed_at + BlockHeight::from(2 * params.exit_delta),
	);

	if let Some(action) = try_progress(params, params.policy_extras.next_tx, deadline) {
		return action;
	}

	if params.policy_extras.has_preimage {
		let claim_height = params.confirmed_at + BlockHeight::from(params.exit_delta);
		if params.chain_tip_height >= claim_height {
			return Action::Claim { deadline: Some(deadline) };
		}
	}

	Action::Wait
}

/// Determine action for ServerHtlcRecv (incoming Lightning payment).
///
/// The server can claim after `htlc_expiry` AND `exit_delta` from confirmation.
/// The user can claim with preimage after `htlc_expiry_delta + exit_delta` from confirmation.
///
/// Deadline is `confirmed_at + htlc_expiry_delta + exit_delta`.
fn decide_action_server_htlc_recv(params: &ActionParams<HtlcRecvExtra>) -> Action {
	let deadline = (params.confirmed_at + BlockHeight::from(params.exit_delta))
		// htlc expiry delta comes from user input
		.saturating_add(BlockHeight::from(params.policy_extras.htlc_expiry_delta));

	if let Some(action) = try_progress(params, params.policy_extras.next_tx, deadline) {
		return action;
	}

	let claim_height = std::cmp::max(
		params.policy_extras.htlc_expiry,
		params.confirmed_at + BlockHeight::from(params.exit_delta),
	);
	if params.chain_tip_height >= claim_height {
		return Action::Claim { deadline: Some(deadline) };
	}

	Action::Wait
}

pub struct ActionContextFetcher<'a> {
	pub config: &'a Config,
	pub db: &'a Db,
	pub chain_tip_height: BlockHeight,
}

impl ActionContextFetcher<'_> {
	pub async fn get_action(
		&self,
		vtxo: &ServerVtxo,
		confirmed_at: Option<BlockHeight>,
	) -> Action {
		let Some(confirmed_at) = confirmed_at else {
			return Action::Wait;
		};

		let params = self.build_params(vtxo, confirmed_at).await;

		let action = match vtxo.policy() {
			ServerVtxoPolicy::Expiry(_)
				| ServerVtxoPolicy::Checkpoint(_)
				| ServerVtxoPolicy::HarkLeaf(_)
			=> {
				// all these three are just an expiry for us, we can sweep them
				// when they expire and don't have to do anything otherwise
				decide_action_expiry(&params)
			},
			ServerVtxoPolicy::HarkForfeit(_) => unimplemented!("next commit"),
			ServerVtxoPolicy::User(VtxoPolicy::Pubkey(..)) => {
				let params = params.with_policy_extras(PubkeyExtra {
					next_tx: self.fetch_progress(vtxo).await,
					server_may_own_ancestor: self.check_server_may_own_ancestor(vtxo).await,
				});

				decide_action_pubkey(&params)
			},
			ServerVtxoPolicy::User(VtxoPolicy::ServerHtlcSend(p)) => {
				let params = params.with_policy_extras(HtlcSendExtra {
					next_tx: self.fetch_progress(vtxo).await,
					htlc_expiry: p.htlc_expiry,
					has_preimage: self.check_have_payment_preimage(p.payment_hash).await,
				});
				decide_action_server_htlc_send(&params)
			},
			ServerVtxoPolicy::User(VtxoPolicy::ServerHtlcRecv(p)) => {
				let params = params.with_policy_extras(HtlcRecvExtra {
					next_tx: self.fetch_progress(vtxo).await,
					htlc_expiry: p.htlc_expiry,
					htlc_expiry_delta: p.htlc_expiry_delta,
				});
				decide_action_server_htlc_recv(&params)
			},
		};

		match &action {
			Action::Progress { deadline: Some(d), .. } if self.chain_tip_height > *d => {
				slog!(ProgressDeadlineExceeded,
					vtxo_id: vtxo.id(),
					deadline: *d,
					current_height: self.chain_tip_height,
				);
			},
			Action::Claim { deadline: Some(d) } if self.chain_tip_height > *d => {
				slog!(ClaimDeadlineExceeded,
					vtxo_id: vtxo.id(),
					deadline: *d,
					current_height: self.chain_tip_height,
				);
			},
			Action::Wait | Action::Progress { .. } | Action::Claim { .. } => {},
		}

		action
	}

	async fn build_params(
		&self,
		vtxo: &ServerVtxo,
		confirmed_at: BlockHeight,
	) -> ActionParams {
		ActionParams {
			vtxo_id: vtxo.id(),
			chain_tip_height: self.chain_tip_height,
			progress_grace_period: Some(self.config.progress_grace_period),
			expiry_height: vtxo.expiry_height(),
			exit_delta: vtxo.exit_delta(),
			confirmed_at: confirmed_at,
			policy_extras: (),
		}
	}

	/// Fetch the next tx in the offchain tx chain for this VTXO and whether it is signed
	async fn fetch_progress(&self, vtxo: &ServerVtxo) -> Option<(Txid, bool)> {
		let vtxo_state = self.db.get_server_vtxo_by_id(vtxo.id()).await
			.inspect_err(|e| warn!("DB error: {:#}", e))
			.ok()?;
		let oor_txid = vtxo_state.oor_spent_txid?;
		let vtx = self.db.get_virtual_transaction_by_txid(oor_txid).await
			.inspect_err(|e| warn!("DB error: {:#}", e))
			.ok()??;
		let has_sig = vtx.signed_tx.is_some();
		Some((oor_txid, has_sig))
	}

	async fn check_have_payment_preimage(&self, payment_hash: PaymentHash) -> bool {
		self.db.get_lightning_invoice_by_payment_hash(payment_hash).await
			.inspect_err(|e| warn!("DB error: {:#}", e))
			.ok().flatten()
			.and_then(|i| i.preimage).is_some()
	}

	async fn check_server_may_own_ancestor(&self, vtxo: &ServerVtxo) -> bool {
		let txid = vtxo.point().txid;
		self.db.get_virtual_transaction_by_txid(txid).await
			.inspect_err(|e| warn!("DB error: {:#}", e))
			.ok().flatten()
			.map(|vtx| vtx.server_may_own_descendant()).unwrap_or(false)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use bitcoin::hashes::Hash;

	fn test_vtxo_id() -> VtxoId {
		VtxoId::from_slice(&[0; 36]).unwrap()
	}

	/// We allow the client a few blocks to complete their exit before we
	/// start competing with them by broadcasting the next tx. The server
	/// prefers that the client pays the fees for the exit.
	#[test]
	fn pubkey_waits_before_progress() {
		let params = ActionParams {
			vtxo_id: test_vtxo_id(),
			chain_tip_height: 105,
			progress_grace_period: Some(6),
			expiry_height: 1000,
			exit_delta: 144,
			confirmed_at: 100,
			policy_extras: PubkeyExtra {
				next_tx: None,
				server_may_own_ancestor: true,
			},
		};
		assert_eq!(decide_action_pubkey(&params), Action::Wait);
	}

	/// When progress is available and the wait period has passed,
	/// the server broadcasts the next transaction.
	#[test]
	fn pubkey_continues_after_wait_period() {
		let txid = Txid::from_byte_array([1; 32]);
		let params = ActionParams {
			vtxo_id: test_vtxo_id(),
			chain_tip_height: 106,
			progress_grace_period: Some(6),
			expiry_height: 1000,
			exit_delta: 144,
			confirmed_at: 100,
			policy_extras: PubkeyExtra {
				next_tx: Some((txid, true)),
				server_may_own_ancestor: true,
			},
		};
		// deadline = confirmed_at + exit_delta = 100 + 144 = 244
		assert_eq!(decide_action_pubkey(&params), Action::Progress { txid, deadline: Some(244) });
	}

	/// If no progress is available, the server waits even if the wait
	/// period has passed.
	#[test]
	fn pubkey_waits_without_progress() {
		let params = ActionParams {
			vtxo_id: test_vtxo_id(),
			chain_tip_height: 106,
			progress_grace_period: Some(6),
			expiry_height: 1000,
			exit_delta: 144,
			confirmed_at: 100,
			policy_extras: PubkeyExtra {
				next_tx: None,
				server_may_own_ancestor: true,
			},
		};
		assert_eq!(decide_action_pubkey(&params), Action::Wait);
	}

	/// If progress exists but the signature is missing, the server waits.
	#[test]
	fn pubkey_waits_without_signature() {
		let txid = Txid::from_byte_array([1; 32]);
		let params = ActionParams {
			vtxo_id: test_vtxo_id(),
			chain_tip_height: 106,
			progress_grace_period: Some(6),
			expiry_height: 1000,
			exit_delta: 144,
			confirmed_at: 100,
			policy_extras: PubkeyExtra {
				server_may_own_ancestor: true,
				next_tx: Some((txid, false)),
			},
		};
		assert_eq!(decide_action_pubkey(&params), Action::Wait);
	}

	/// When server does not own an ancestor, it cannot attempt to progress.
	#[test]
	fn pubkey_waits_when_server_does_not_own_ancestor() {
		let txid = Txid::from_byte_array([1; 32]);
		let params = ActionParams {
			vtxo_id: test_vtxo_id(),
			chain_tip_height: 106,
			progress_grace_period: Some(6),
			expiry_height: 1000,
			exit_delta: 144,
			confirmed_at: 100,
			policy_extras: PubkeyExtra {
				next_tx: Some((txid, true)),
				server_may_own_ancestor: false,
			},
		};
		// Even with a valid progress tx, server_may_own_ancestor: false means we wait
		assert_eq!(decide_action_pubkey(&params), Action::Wait);
	}

	/// Server waits for the safety margin before broadcasting progress,
	/// allowing the client to complete their exit first.
	#[test]
	fn htlc_send_waits_before_progress() {
		let txid = Txid::from_byte_array([1; 32]);
		let params = ActionParams {
			vtxo_id: test_vtxo_id(),
			chain_tip_height: 105,
			progress_grace_period: Some(6),
			expiry_height: 1000,
			exit_delta: 144,
			confirmed_at: 100,
			policy_extras: HtlcSendExtra {
				next_tx: Some((txid, true)),
				htlc_expiry: 500,
				has_preimage: false,
			},
		};
		assert_eq!(decide_action_server_htlc_send(&params), Action::Wait);
	}

	/// When progress is available and the wait period has passed,
	/// the server broadcasts the progress transaction.
	#[test]
	fn htlc_send_continues_after_wait_period() {
		let txid = Txid::from_byte_array([1; 32]);
		let params = ActionParams {
			vtxo_id: test_vtxo_id(),
			chain_tip_height: 106,
			progress_grace_period: Some(6),
			expiry_height: 1000,
			exit_delta: 144,
			confirmed_at: 100,
			policy_extras: HtlcSendExtra {
				next_tx: Some((txid, true)),
				htlc_expiry: 500,
				has_preimage: false,
			},
		};
		// deadline = min(htlc_expiry, confirmed_at + 2*exit_delta) = min(500, 100 + 288) = 388
		assert_eq!(decide_action_server_htlc_send(&params), Action::Progress { txid, deadline: Some(388) });
	}

	/// Server has the preimage but must wait until the claim height
	/// (confirmed_at + exit_delta) before it can claim.
	#[test]
	fn htlc_send_waits_with_preimage_before_claim_height() {
		let params = ActionParams {
			vtxo_id: test_vtxo_id(),
			chain_tip_height: 243,
			progress_grace_period: Some(6),
			expiry_height: 1000,
			exit_delta: 144,
			confirmed_at: 100,
			policy_extras: HtlcSendExtra {
				next_tx: None,
				htlc_expiry: 500,
				has_preimage: true,
			},
		};
		// claim_height = confirmed_at + exit_delta = 100 + 144 = 244
		// chain_tip (243) < claim_height (244), so wait
		assert_eq!(decide_action_server_htlc_send(&params), Action::Wait);
	}

	/// Server claims using the preimage once the claim height is reached.
	#[test]
	fn htlc_send_claims_with_preimage_at_claim_height() {
		let params = ActionParams {
			vtxo_id: test_vtxo_id(),
			chain_tip_height: 244,
			progress_grace_period: Some(6),
			expiry_height: 1000,
			exit_delta: 144,
			confirmed_at: 100,
			policy_extras: HtlcSendExtra {
				next_tx: None,
				htlc_expiry: 500,
				has_preimage: true,
			},
		};
		// claim_height = 100 + 144 = 244, chain_tip >= claim_height
		// deadline = min(500, 100 + 288) = 388
		assert_eq!(decide_action_server_htlc_send(&params), Action::Claim { deadline: Some(388) });
	}

	/// Without a preimage or progress tx, the server can only wait.
	#[test]
	fn htlc_send_waits_without_preimage_and_progress() {
		let params = ActionParams {
			vtxo_id: test_vtxo_id(),
			chain_tip_height: 300,
			progress_grace_period: Some(6),
			expiry_height: 1000,
			exit_delta: 144,
			confirmed_at: 100,
			policy_extras: HtlcSendExtra {
				next_tx: None,
				htlc_expiry: 500,
				has_preimage: false,
			},
		};
		assert_eq!(decide_action_server_htlc_send(&params), Action::Wait);
	}

	/// Server waits for the safety margin before broadcasting progress.
	#[test]
	fn htlc_recv_waits_before_progress() {
		let txid = Txid::from_byte_array([1; 32]);
		let params = ActionParams {
			vtxo_id: test_vtxo_id(),
			chain_tip_height: 105,
			progress_grace_period: Some(6),
			expiry_height: 1000,
			exit_delta: 144,
			confirmed_at: 100,
			policy_extras: HtlcRecvExtra {
				next_tx: Some((txid, true)),
				htlc_expiry: 500,
				htlc_expiry_delta: 40,
			},
		};
		assert_eq!(decide_action_server_htlc_recv(&params), Action::Wait);
	}

	/// When progress is available and the wait period has passed,
	/// the server broadcasts the progress transaction.
	#[test]
	fn htlc_recv_continues_after_wait_period() {
		let txid = Txid::from_byte_array([1; 32]);
		let params = ActionParams {
			vtxo_id: test_vtxo_id(),
			chain_tip_height: 106,
			progress_grace_period: Some(6),
			expiry_height: 1000,
			exit_delta: 144,
			confirmed_at: 100,
			policy_extras: HtlcRecvExtra {
				next_tx: Some((txid, true)),
				htlc_expiry: 500,
				htlc_expiry_delta: 40,
			},
		};
		// deadline = confirmed_at + htlc_expiry_delta + exit_delta = 100 + 40 + 144 = 284
		assert_eq!(decide_action_server_htlc_recv(&params), Action::Progress { txid, deadline: Some(284) });
	}

	/// Server must wait until the claim height before it can claim.
	/// claim_height = max(htlc_expiry, confirmed_at + exit_delta)
	#[test]
	fn htlc_recv_waits_before_claim_height() {
		let params = ActionParams {
			vtxo_id: test_vtxo_id(),
			chain_tip_height: 499,
			progress_grace_period: Some(6),
			expiry_height: 1000,
			exit_delta: 144,
			confirmed_at: 100,
			policy_extras: HtlcRecvExtra {
				next_tx: None,
				htlc_expiry: 500,
				htlc_expiry_delta: 40,
			},
		};
		// claim_height = max(500, 100 + 144) = max(500, 244) = 500
		// chain_tip (499) < claim_height (500), so wait
		assert_eq!(decide_action_server_htlc_recv(&params), Action::Wait);
	}

	/// Server claims once the claim height is reached.
	#[test]
	fn htlc_recv_claims_at_claim_height() {
		let params = ActionParams {
			vtxo_id: test_vtxo_id(),
			chain_tip_height: 500,
			progress_grace_period: Some(6),
			expiry_height: 1000,
			exit_delta: 144,
			confirmed_at: 100,
			policy_extras: HtlcRecvExtra {
				next_tx: None,
				htlc_expiry: 500,
				htlc_expiry_delta: 40,
			},
		};
		// claim_height = max(500, 244) = 500, chain_tip >= claim_height
		// deadline = 100 + 40 + 144 = 284
		assert_eq!(decide_action_server_htlc_recv(&params), Action::Claim { deadline: Some(284) });
	}
}

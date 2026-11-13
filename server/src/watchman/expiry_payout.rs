//! The watchman side of expiry payouts. When a tree expires, the watchman
//! decides who owns each of its VTXOs.

use std::sync::Arc;

use bitcoin::Transaction;
use tokio::task::JoinSet;
use tracing::{info, warn};

use ark::{ServerVtxo, ServerVtxoPolicy, VtxoPolicy};

use crate::bitcoind as bcd;
use crate::database::{BlockTable, SpendState};
use crate::database::expiry_payout::decision::verify_expiry_tip;

use super::Watchman;

impl Watchman {
	/// Run the sweep pass. In payout mode it runs as a background task, so
	/// that a long pass does not delay the reactions. A pass that is asked
	/// for while one runs starts when that one ends.
	pub(super) async fn run_sweeps(self: &Arc<Self>, tasks: &mut JoinSet<()>, pending: &mut bool) {
		if self.db.expiry_payouts() {
			self.enqueue_expiry_sweep(tasks, pending);
		} else {
			self.process_sweeps_logged().await;
		}
	}

	pub(super) fn enqueue_expiry_sweep(self: &Arc<Self>, tasks: &mut JoinSet<()>, pending: &mut bool) {
		if tasks.is_empty() {
			let watchman = Arc::clone(self);
			tasks.spawn(async move { watchman.process_sweeps_logged().await; });
		} else {
			*pending = true;
		}
	}

	/// Broadcast a claim transaction. In payout mode the claim inputs stay
	/// locked through the broadcast, so an expiry decision cannot take them
	/// at the same time.
	pub(super) async fn broadcast_claim(&self, vtxos: &[ServerVtxo], tx: &Transaction) -> anyhow::Result<()> {
		if !self.db.expiry_payouts() {
			bcd::broadcast_tx(&self.bitcoind, tx).await?;
			return Ok(());
		}
		self.db.write(async |t| {
			t.lock_watchman_claim_inputs(vtxos).await?;
			bcd::broadcast_tx(&self.bitcoind, tx).await?;
			Ok(())
		}).await
	}

	/// The sweep pass of a server in payout mode: claim the outputs that
	/// belong to the server and decide the expired trees.
	pub(super) async fn process_expiry_sweeps(&self) -> anyhow::Result<()> {
		// A co-signed board whose funding did not confirm by its expiry can
		// never be paid. A failure here must not stop the payouts.
		if let Some(view) = self.db.read(async |t| t.get_highest_block(BlockTable::Watchmand).await).await? {
			if let Err(error) = self.db.write(async |t| t.drop_unconfirmed_board_roots(view.height).await).await {
				warn!(error = %format_args!("{error:#}"), "Unconfirmed board roots remain on the frontier");
			}
		}
		// Forfeited offboard outputs and pool VTXOs belong to the server.
		// The upstream claim sweeps them, and the server pays its fee.
		let sweeps = self.scan_frontier().await?.sweeps;
		let ids = sweeps.iter().filter(|v| matches!(v.policy(), ServerVtxoPolicy::ServerOwned
			| ServerVtxoPolicy::User(VtxoPolicy::Pubkey(_))))
			.map(|v| v.id()).collect::<Vec<_>>();
		let states = self.db.read(async |t| t.get_existing_server_vtxos_by_id(&ids).await).await?;
		let mut claims = Vec::new();
		for vtxo in &sweeps {
			let state = states.get(&vtxo.id()).map(|state| state.spend_state);
			let owned = match (vtxo.policy(), state) {
				(ServerVtxoPolicy::ServerOwned, Some(SpendState::OffboardForfeit)) => true,
				(ServerVtxoPolicy::User(VtxoPolicy::Pubkey(policy)), Some(SpendState::Pool)) => {
					policy.user_pubkey == vtxo.server_pubkey() || self.db.read(async |t|
						t.fetch_ephemeral_tweak(policy.user_pubkey).await
					).await?.is_some()
				},
				_ => false,
			};
			if owned {
				self.update_mempool_spend(vtxo.id()).await;
				claims.push(vtxo.clone());
			}
		}
		if !claims.is_empty() { self.process_claims(claims).await?; }
		self.expiry_decision_pass(sweeps).await;
		Ok(())
	}

	/// Decide the payout of each expired root. An error holds only its root.
	async fn expiry_decision_pass(&self, mut roots: Vec<ServerVtxo>) {
		// An exposed user VTXO follows its own claim and refund rules.
		roots.retain(|root| !matches!(root.policy(), ServerVtxoPolicy::User(_)));
		roots.sort_by_key(|root| root.expiry_height());
		for root in roots {
			let id = root.id();
			if let Err(error) = self.decide_expiry_root(root).await {
				warn!(root = %id, error = %format_args!("{error:#}"), "Expiry payout decision failed");
			}
		}
	}

	/// Decide one root: one expiry payout and one payout transaction. Each
	/// root reads the current watchman tip, so a new block does not stop a
	/// long pass.
	async fn decide_expiry_root(&self, root: ServerVtxo) -> anyhow::Result<()> {
		let Some(view) = self.db.read(async |tx| tx.get_highest_block(BlockTable::Watchmand).await).await? else {
			return Ok(());
		};
		verify_expiry_tip(view, &self.bitcoind).await?;
		let Some(plan) = self.db.read(async |tx| tx.plan_expiry_root(view, root.clone()).await).await? else {
			return Ok(());
		};
		let id = self.db.write(async |tx| tx.commit_expiry_root(view, plan).await).await?;
		info!(expiry_payout_id = id, root = %root.id(), "Expiry payout decision committed");
		Ok(())
	}
}

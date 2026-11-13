//! The watchman side of expiry payouts. When a tree expires, the watchman
//! decides who owns each of its VTXOs, then pays the owners from the tree
//! root in one transaction. A fee bump never changes the owner outputs.

use std::collections::BTreeSet;
use std::sync::Arc;

use anyhow::Context;
use bdk_wallet::error::CreateTxError;
use bitcoin::{psbt, sighash, Amount, FeeRate, Sequence, Transaction, Weight};
use tokio::task::JoinSet;
use tracing::{info, warn};

use ark::{ServerVtxo, ServerVtxoPolicy, VtxoPolicy};
use ark::vtxo::policy::signing::VtxoSigner;
use bitcoin_ext::{BlockRef, TxStatus};

use crate::bitcoind as bcd;
use crate::database::{BlockTable, SpendState};
use crate::database::expiry_payout::decision::verify_expiry_tip;
use crate::database::expiry_payout::payout::PendingExpiryPayout;
use crate::wallet::{BdkWalletExt, PersistedWallet};

use super::{saturating_add_feerates, Watchman};

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
	/// belong to the server, decide the expired trees and pay their owners.
	pub(super) async fn process_expiry_sweeps(&self) -> anyhow::Result<()> {
		// A co-signed board whose funding did not confirm by its expiry can
		// never be paid. A failure here must not stop the payouts.
		if let Some(view) = self.db.read(async |t| t.get_highest_block(BlockTable::Watchmand).await).await? {
			if let Err(error) = self.db.write(async |t| t.drop_unconfirmed_board_roots(view.height).await).await {
				warn!(error = %format_args!("{error:#}"), "Unconfirmed board roots remain on the frontier");
			}
		}
		// Decided payouts need no frontier scan, so publish them first.
		self.process_expiry_payouts().await?;
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
		self.process_expiry_payouts().await?;
		Ok(())
	}

	/// Build the payout transaction: the owner outputs and a drain to the
	/// operator. BDK adds confirmed watchman inputs only if the expired
	/// tree cannot pay the mining fee.
	async fn build_expiry_payout(
		&self, wallet: &mut PersistedWallet, group: &PendingExpiryPayout,
		view: BlockRef, target: FeeRate, prior: Option<&Transaction>,
	) -> anyhow::Result<(Transaction, Amount)> {
		let roots = group.inputs.iter().map(|root| root.point()).collect::<BTreeSet<_>>();
		let prior_sponsors = prior.into_iter().flat_map(|tx| &tx.input)
			.filter(|input| !roots.contains(&input.previous_output))
			.map(|input| {
				let owned = wallet.list_output().find(|out| out.outpoint == input.previous_output)
					.context("prior payout fee input is not a watchman output")?;
				ensure!(owned.chain_position.is_confirmed(),
					"prior payout fee input was not confirmed");
				Ok((input.previous_output, owned.txout,
					Weight::from_wu(u64::try_from(bitcoin::consensus::serialize(&input.witness).len())?),
					input.sequence))
			}).collect::<anyhow::Result<Vec<_>>>()?;
		let unspendable = wallet.payout_unspendable_outputs();
		let reserved = roots.iter().copied()
			.chain(prior_sponsors.iter().map(|(point, ..)| *point))
			.chain(unspendable.iter().copied()).collect::<BTreeSet<_>>();
		let mut available_sponsors = wallet.list_unspent()
			.filter(|out| out.chain_position.is_confirmed() && !reserved.contains(&out.outpoint))
			.map(|out| (out.outpoint, out.txout.value)).collect::<Vec<_>>();
		available_sponsors.sort_by(|a, b| b.1.cmp(&a.1));
		let mut clauses = Vec::with_capacity(group.inputs.len());
		for root in &group.inputs {
			let clause = if *root.policy() == ServerVtxoPolicy::ServerOwned {
				None
			} else {
				Some(self.signer.find_signable_clause(root).await
					.with_context(|| format!("no expiry clause for {}", root.id()))?)
			};
			let sequence = clause.as_ref().and_then(|clause| clause.sequence())
				.unwrap_or(Sequence::ZERO);
			let witness_size = clause.as_ref().map(|clause| clause.witness_size(root))
				.unwrap_or(66);
			clauses.push((clause, Weight::from_wu(u64::try_from(witness_size)?), sequence));
		}
		let mut forced_sponsors = Vec::new();
		let mut psbt = loop {
			let mut builder = wallet.build_tx();
			builder.version(2)
				.nlocktime(view.height.to_locktime().context("invalid payout lock height")?)
				.set_exact_sequence(Sequence::ZERO)
				.only_witness_utxo()
				.unspendable(unspendable.clone())
				.drain_to(self.drain_spk.clone())
				.fee_rate(target);
			for (root, (_, weight, sequence)) in group.inputs.iter().zip(&clauses) {
				builder.add_foreign_utxo_with_sequence(root.point(), psbt::Input {
					witness_utxo: Some(root.txout()), ..Default::default()
				}, *weight, *sequence).context("adding the expired tree to the payout")?;
			}
			for (outpoint, txout, weight, sequence) in &prior_sponsors {
				builder.add_foreign_utxo_with_sequence(*outpoint, psbt::Input {
					witness_utxo: Some(txout.clone()), ..Default::default()
				}, *weight, *sequence).context("reusing confirmed watchman fee input")?;
			}
			for point in &forced_sponsors {
				builder.add_utxo(*point).context("adding watchman payout sponsor")?;
			}
			builder.set_recipients(group.payouts.iter()
				.map(|out| (out.script_pubkey.clone(), out.value)).collect());
			match builder.finish() {
				Ok(psbt) => break psbt,
				Err(CreateTxError::CoinSelection(ref missing))
					if group.payouts.is_empty() && missing.needed == self.drain_spk.minimal_non_dust()
						&& forced_sponsors.len() < available_sponsors.len() => {
					// BDK adds no input when the drain is the only output and
					// falls below dust, so add a confirmed watchman input.
					forced_sponsors.push(available_sponsors[forced_sponsors.len()].0);
				},
				Err(error) => return Err(error).context("funding expiry payout"),
			}
		};
		wallet.sign_known_inputs(&mut psbt)?;
		let prevouts = psbt.inputs.iter().map(|input| input.witness_utxo.clone()
			.context("payout PSBT lacks a witness prevout"))
			.collect::<anyhow::Result<Vec<_>>>()?;
		let mut tx = psbt.unsigned_tx.clone();
		for (index, input) in tx.input.iter_mut().enumerate() {
			if !group.inputs.iter().any(|root| root.point() == input.previous_output) {
				input.witness = psbt.inputs[index].final_script_witness.clone()
					.context("watchman fee input was not finalized")?;
			}
		}
		let prevouts_ref = sighash::Prevouts::All(&prevouts);
		let mut cache = sighash::SighashCache::new(&mut tx);
		for (root, (clause, _, _)) in group.inputs.iter().zip(&clauses) {
			let index = cache.transaction().input.iter().position(|input|
				input.previous_output == root.point())
				.context("expired tree disappeared from payout")?;
			let witness = if let Some(clause) = clause {
				self.signer.sign_input_with_clause(root, clause, index, &mut cache, &prevouts_ref).await?
			} else {
				self.signer.sign_input_with_keyspend(root, index, &mut cache, &prevouts_ref).await?
			};
			*cache.witness_mut(index).context("missing payout witness slot")? = witness;
		}
		let input_amount = prevouts.iter().try_fold(Amount::ZERO, |sum, out|
			sum.checked_add(out.value).context("payout input overflow"))?;
		let output_amount = tx.output.iter().try_fold(Amount::ZERO, |sum, out|
			sum.checked_add(out.value).context("payout output overflow"))?;
		let fee = input_amount.checked_sub(output_amount).context("payout overspends inputs")?;
		ensure!(fee >= target.fee_wu(tx.weight()).context("payout fee overflow")?,
			"payout fee falls below target");
		Ok((tx, fee))
	}

	/// Publish or fee bump the transaction of each decided payout.
	async fn process_expiry_payouts(&self) -> anyhow::Result<()> {
		let groups = self.db.read(async |t| t.pending_expiry_payouts().await).await?;
		for group in groups {
			// A block can arrive while a payout is built, so each payout reads
			// the current watchman tip.
			let Some(view) = self.db.read(async |t| t.get_highest_block(BlockTable::Watchmand).await).await? else { break; };
			let id = group.id;
			if let Err(error) = self.process_expiry_payout(view, group).await {
				warn!(expiry_payout_id = id, error = %format_args!("{error:#}"), "Expiry payout remains pending");
			}
		}
		Ok(())
	}

	async fn process_expiry_payout(&self, view: BlockRef, group: PendingExpiryPayout) -> anyhow::Result<()> {
		let target = self.fee_estimator.regular();
		let mut bump_target = target;
		let mut bump = false;
		if let Some((latest, latest_fee)) = &group.latest {
			let status = bcd::tx_status(&self.bitcoind, latest.compute_txid()).await?;
			let latest_rate = *latest_fee / latest.weight();
			bump = latest_rate < target;
			if matches!(status, TxStatus::Confirmed(_)) || (matches!(status, TxStatus::Mempool) && !bump) {
				self.db.write(async |t| t.mark_expiry_payout_broadcast(group.id).await).await?;
				return Ok(());
			}
			if bump {
				bump_target = target.max(saturating_add_feerates(
					latest_rate, self.config.incremental_relay_fee));
			}
		}
		verify_expiry_tip(view, &self.bitcoind).await?;
		let mut wallet = self.watchman_wallet.lock().await;
		let payout = self.db.write(async |t| {
			if let Some((latest, _)) = &group.latest {
				// A crash can store an attempt without the wallet changes that
				// follow it. Restore them before a replacement.
				for root in &group.inputs { wallet.insert_txout(root.point(), root.txout()); }
				wallet.commit_tx(latest);
			}
			let (payout, fee) = match (&group.latest, bump) {
				(Some((latest, _)), true) => self.build_expiry_payout(
					&mut wallet, &group, view, bump_target, Some(latest)).await?,
				(Some((latest, fee)), false) => (latest.clone(), *fee),
				(None, _) => self.build_expiry_payout(&mut wallet, &group, view, target, None).await?,
			};
			if group.latest.as_ref().map(|(tx, _)| tx) != Some(&payout) {
				let checks = bcd::test_mempool_accept(&self.bitcoind, &[&payout]).await
					.context("preflighting expiry payout")?;
				ensure!(checks.len() == 1 && checks[0].allowed,
					"Core preflight rejected expiry payout: {:?}",
					checks.first().and_then(|check| check.reject_reason.as_deref()));
			}
			t.store_expiry_attempt(view, group.id, &payout, fee, &self.drain_spk,
				self.config.expiry_payout_max_fee_rate).await?;
			for root in &group.inputs { wallet.insert_txout(root.point(), root.txout()); }
			wallet.commit_tx(&payout);
			if let Some(change) = wallet.staged() {
				t.store_changeset(wallet.kind(), change).await?;
			}
			Ok(payout)
		}).await?;
		// Keep staged changes on any database failure, as persist() does.
		let _ = wallet.take_staged();
		crate::telemetry::set_wallet_balance(wallet.kind(), wallet.balance());
		drop(wallet);
		verify_expiry_tip(view, &self.bitcoind).await?;
		if !matches!(bcd::tx_status(&self.bitcoind, payout.compute_txid()).await?, TxStatus::Confirmed(_)) {
			bcd::broadcast_tx(&self.bitcoind, &payout).await?;
		}
		self.db.write(async |t| t.mark_expiry_payout_broadcast(group.id).await).await?;
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

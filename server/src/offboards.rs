
use std::borrow::BorrowMut;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use bitcoin::{Amount, FeeRate, OutPoint, Psbt, ScriptBuf, Transaction, Txid};
use bitcoin::secp256k1::{schnorr, Keypair};
use tracing::{error, warn};

use ark::{musig, VtxoId};
use ark::challenges::OffboardRequestChallenge;
use ark::fees::{validate_and_subtract_fee_min_dust, VtxoFeeInfo};
use ark::offboard::{OffboardForfeitContext, OffboardRequest};
use bitcoin_ext::{BlockHeight, P2TR_DUST};
use bitcoin_ext::rpc::RpcApi;

use crate::{Server, SECP};
use crate::error::ContextExt;
use crate::flux::OwnedVtxoFluxGuard;
use crate::wallet::{BdkWalletExt, PersistedWallet, WalletUtxosGuard};


#[derive(Debug)]
pub struct OffboardResponse {
	pub offboard_tx: Transaction,
	pub forfeit_cosign_nonces: Vec<musig::PublicNonce>,
}

/// The state for a pending offboard session
///
/// This session state locks the UTXOs that are used in this offboard and they are
/// released automatically when this state is dropped because of the guard.
pub struct PendingOffboard {
	offboard_tx: Psbt,
	input_vtxos_guard: OwnedVtxoFluxGuard,
	wallet_input_guard: WalletUtxosGuard,
	connector_key: Keypair,
	forfeit_pub_nonces: Vec<musig::PublicNonce>,
	forfeit_sec_nonces: Vec<musig::SecretNonce>,
}

impl Server {
	/// Returns a vector with all the UTXOs currently in use by a pending offboard
	pub fn pending_offboard_utxos(&self) -> Vec<OutPoint> {
		let mut guard = self.pending_offboards.lock();

		// clean up old offboards
		for (offboard_txid, opt) in guard.remove_older(self.config.offboard_session_timeout) {
			if let Some(removed) = opt {
				let utxos = removed.wallet_input_guard.utxos().to_vec();
				let vtxos = removed.input_vtxos_guard.vtxos().to_vec();
				slog!(OffboardSessionTimeout, offboard_txid, utxos, vtxos);
			}
		}

		guard.values()
			.filter_map(|o| o.as_ref())
			.map(|p| p.offboard_tx.unsigned_tx.input.iter().map(|i| i.previous_output))
			.flatten().collect()
	}

	fn offboard_feerate(&self) -> FeeRate {
		self.config.offboard_feerate
	}

	pub(crate) async fn start_offboard_retry_task(self: Arc<Self>) {
		tokio::spawn(async move {
			let _worker = self.rtmgr.spawn("OffboardRetry");

			let mut interval = tokio::time::interval(Duration::from_secs(30));
			interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
			loop {
				tokio::select! {
					_ = interval.tick() => {},
					_ = self.rtmgr.shutdown_signal() => return,
				}

				match self.db.get_uncommitted_offboards().await {
					Ok(txs) => {
						let mut guard = self.rounds_wallet.lock().await;
						for tx in txs {
							if let Err(e) = self.commit_offboard(&mut guard, &tx.tx, tx.txid).await {
								warn!("Failed to commit pending offboard {}: {:#}", tx.txid, e);
							}
						}
					},
					Err(e) => error!("Error fetching uncommitted offboards: {:#}", e),
				}
			}
		});
	}

	#[tracing::instrument(skip(self, request, input_vtxos, ownership_proofs))]
	pub async fn prepare_offboard(
		&self,
		request: OffboardRequest,
		input_vtxos: Vec<VtxoId>,
		ownership_proofs: Vec<schnorr::Signature>,
	) -> anyhow::Result<OffboardResponse> {
		// TODO(pc): Make this dynamic and check whether this is a valid historical fee rate.
		if self.offboard_feerate() != request.fee_rate {
			return badarg!(
				"fee rate does not match the configured offboard fee rate: provided = {}, expected = {}",
				request.fee_rate, self.offboard_feerate(),
			);
		}
		request.validate().badarg("invalid offboard request")?;

		// We keep the VTXO flux lock for the duration of the session, this means
		// that if the user bails a session he has to wait for it to time out
		// (currently set to 30 secs)
		// The motivation is that otherwise the following attack would be super easy:
		// - start offboard session for vtxo
		// - send arkoor to self to create new vtxo
		// - repeat 100 times
		// => all our money locked
		let input_vtxos_guard = self.vtxos_in_flux.try_lock(&input_vtxos)
			.context("some VTXO is already locked by another process")?;

		// Check no duplicates in inputs
		if input_vtxos.iter().collect::<HashSet<_>>().len() != input_vtxos.len() {
			return badarg!("duplicate input vtxo");
		}

		if ownership_proofs.len() != input_vtxos.len() {
			return badarg!("wrong number of ownership proofs");
		}

		let vtxos = self.db.get_user_vtxos_by_id(&input_vtxos).await?;
		if let Some(v) = vtxos.iter().find(|v| !v.is_spendable()) {
			return badarg!("VTXO {} is already spent", v.vtxo_id);
		}

		// Validate the request parameters
		let tip = self.chain_tip().height;
		let fee_info = vtxos.iter().map(|v| VtxoFeeInfo::from_vtxo_and_tip(&v.vtxo, tip));
		let gross_amount = vtxos.iter().map(|v| v.vtxo.amount()).sum::<Amount>();

		// If the user is trying to perform a send-onchain then we add fees onto the request amount.
		// If the user is performing an offboard then we deduct fees from the total VTXO sum.
		let net_amount = if request.deduct_fees_from_gross_amount {
			let fee = self.config.fees.offboard.calculate(
				&request.script_pubkey,
				gross_amount,
				request.fee_rate,
				fee_info
			).context("unable to calculate fee for offboard")?;
			let net_amount = validate_and_subtract_fee_min_dust(gross_amount, fee)?;
			if net_amount != request.net_amount {
				return badarg!(
					"offboard net amount does not match expected amount: provided = {}, expected = {}",
					net_amount, request.net_amount,
				);
			}
			net_amount
		} else {
			let fee = self.config.fees.offboard.calculate(
				&request.script_pubkey,
				request.net_amount,
				request.fee_rate,
				fee_info
			).context("unable to calculate fee for offboard")?;
			let total = request.net_amount.checked_add(fee).context("request amount + fee overflow")?;
			if total != gross_amount {
				return badarg!(
					"offboard gross amount does not match expected amount: provided = {} ({} fee), expected = {}",
					total, fee, gross_amount,
				);
			}
			request.net_amount
		};

		// check ownership proofs
		let challenge = OffboardRequestChallenge::new(&request, input_vtxos.iter().copied());
		for (input, proof) in vtxos.iter().zip(&ownership_proofs) {
			challenge.verify_input_vtxo_sig(&input.vtxo, proof)
				.with_badarg(|| format!("invalid ownership proof for vtxo {}", input.vtxo.id()))?;
		}

		// Even if we need multiple connectors, we just need a single output now,
		// the multi-connector fan-out tx can be constructed at-forfeit-claim-time.
		let connector_key = Keypair::new(&*SECP, &mut bitcoin::secp256k1::rand::thread_rng());
		let connector_spk = ScriptBuf::new_p2tr(
			&*SECP, connector_key.public_key().x_only_public_key().0, None,
		);
		let connector_amt = P2TR_DUST * input_vtxos.len() as u64;

		let mut wallet_guard = self.rounds_wallet.lock().await;
		let offboard_tx = {
			let trusted_height = match self.config.round_tx_untrusted_input_confirmations {
				0 => None,
				n => Some(tip.saturating_sub(n as BlockHeight - 1)),
			};
			let unavailable = wallet_guard.unavailable_outputs(trusted_height);
			let mut b = wallet_guard.build_tx();
			b.ordering(bdk_wallet::TxOrdering::Untouched);
			b.current_height(tip);
			b.unspendable(unavailable);
			// NB: order is important here, we need to respect `ROUND_TX_VTXO_TREE_VOUT` and `ROUND_TX_CONNECTOR_VOUT`
			b.add_recipient(request.script_pubkey, net_amount);
			b.add_recipient(connector_spk, connector_amt);
			b.fee_rate(request.fee_rate);
			b.finish().context("bdk failed to create offboard tx")?
		};
		// we need to lock the inputs
		let wallet_input_guard = wallet_guard.lock_wallet_utxos(
			offboard_tx.unsigned_tx.input.iter().map(|i| i.previous_output),
		).context("bdk selected unavailable UTXOs")?;
		drop(wallet_guard);

		let (forfeit_sec_nonces, forfeit_pub_nonces) = (0..input_vtxos.len()).map(|_| {
			musig::nonce_pair(self.server_key.leak_ref())
		}).collect::<(Vec<_>, Vec<_>)>();

		let ret = OffboardResponse {
			offboard_tx: offboard_tx.unsigned_tx.clone(),
			forfeit_cosign_nonces: forfeit_pub_nonces.clone(),
		};

		let offboard_txid = offboard_tx.unsigned_tx.compute_txid();
		slog!(PreparedOffboard, offboard_txid, input_vtxos, net_amount, gross_amount,
			fee_rate: request.fee_rate, wallet_utxos: wallet_input_guard.utxos().to_vec(),
		);

		let state = PendingOffboard {
			input_vtxos_guard: input_vtxos_guard.into_owned(),
			connector_key, forfeit_pub_nonces, forfeit_sec_nonces, offboard_tx, wallet_input_guard,
		};
		assert!(self.pending_offboards.lock().insert_some(offboard_txid, state).is_none(),
			"should be impossible to get same txid when inputs are locked",
		);

		Ok(ret)
	}

	/// Commit the offboard with the wallet, broadcast it and mark committed in db
	///
	/// If you pass an owned wallet guard, it will be dropped when no longer needed.
	async fn commit_offboard(
		&self,
		mut wallet_guard: impl BorrowMut<tokio::sync::MutexGuard<'_, PersistedWallet>>,
		offboard_tx: &Transaction,
		offboard_txid: Txid,
	) -> anyhow::Result<()> {
		wallet_guard.borrow_mut().commit_tx(offboard_tx);
		wallet_guard.borrow_mut().persist().await
			.context("persisting wallet")?;
		drop(wallet_guard);
		self.tx_nursery.broadcast_tx(offboard_tx.clone()).await
			.context("broadcasting tx")?;
		self.db.mark_offboard_committed(offboard_txid).await
			.context("marking offboard committed")?;
		Ok(())
	}

	#[tracing::instrument(skip(self, user_pub_nonces, user_partial_sigs))]
	pub async fn finish_offboard(
		&self,
		offboard_txid: Txid,
		user_pub_nonces: &[musig::PublicNonce],
		user_partial_sigs: &[musig::PartialSignature],
	) -> anyhow::Result<Transaction> {
		// we remove the state immediatelly. the user authenticates himself by
		// knowing the txid and we only give them one chance
		let state = self.pending_offboards.lock().take(&offboard_txid)
			.badarg("unknown offboard txid")?;
		let input_vtxos = state.input_vtxos_guard.vtxos();
		let offboard_txid = state.offboard_tx.unsigned_tx.compute_txid();

		if user_pub_nonces.len() != input_vtxos.len() {
			return badarg!("incorrect number of public nonces");
		}
		if user_partial_sigs.len() != input_vtxos.len() {
			return badarg!("incorrect number of partial signatures");
		}

		let vtxos = self.db.get_user_vtxos_by_id(input_vtxos).await?;
		let forfeit_ctx = OffboardForfeitContext::new(&vtxos, &state.offboard_tx.unsigned_tx);

		let _forfeit_txs = forfeit_ctx.check_finalize_transactions(
			self.server_key.leak_ref(),
			&state.connector_key,
			&state.forfeit_pub_nonces,
			state.forfeit_sec_nonces,
			user_pub_nonces,
			user_partial_sigs,
		).badarg("invalid partial forfeit signatures")?;

		//TODO(stevenroose) use the forfeit txs here with sweeper

		// Mark transactions as having server-owned descendants before completing offboard
		let txids = vtxos.iter()
			.flat_map(|v| v.vtxo.transactions().map(|item| item.tx.compute_txid()))
			.collect::<Vec<_>>();
		self.db.mark_server_may_own_descendants(&txids).await
			.context("virtual tx update failed, user might not have called register_vtxos")?;

		let mut wallet_guard = self.rounds_wallet.lock().await;
		let signed_tx = wallet_guard.finish_tx(state.offboard_tx)
			.context("error signing offboard tx")?;

		let [mempool_accept] = self.bitcoind.test_mempool_accept(&[&signed_tx])
			.context("bitcoin node down")?.try_into().unwrap();
		if !mempool_accept.allowed {
			slog!(OffboardTxRejected, offboard_txid, input_vtxos: input_vtxos.to_vec(),
				raw_offboardtx: bitcoin::consensus::serialize(&signed_tx),
				wallet_utxos: state.wallet_input_guard.utxos().to_vec(),
				reject_reason: mempool_accept.reject_reason.clone().unwrap_or_default(),
			);
			bail!("mempool rejected offboard tx: {:?}", mempool_accept.reject_reason);
		}

		// now we will first persist this offboard in our db, then commit and
		// broadcast the tx and then mark the offboard as committed

		slog!(SignedOffboard, offboard_txid, input_vtxos: input_vtxos.to_vec(),
			wallet_utxos: state.wallet_input_guard.utxos().to_vec(),
		);

		// nb catch the error and don't print it, as it might contain the signed offboard tx
		if let Err(e) = self.db.register_offboard(
			input_vtxos.iter().copied(),
			&signed_tx,
		).await {
			error!("Failed to register offboard {} in db: {:#}", offboard_txid, e);
			bail!("failed to register offboard in db, please start over");
		}

		if let Err(e) = self.commit_offboard(
			&mut wallet_guard,
			&signed_tx,
			offboard_txid,
		).await {
			// we will later retry
			slog!(CommitOffboardFailed, offboard_txid, error: format!("{:#}", e),
				input_vtxos: input_vtxos.to_vec(),
				raw_offboardtx: bitcoin::consensus::serialize(&signed_tx),
				wallet_utxos: state.wallet_input_guard.utxos().to_vec(),
			);
		}

		Ok(signed_tx)
	}
}

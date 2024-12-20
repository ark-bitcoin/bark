
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Context;
use bdk_bitcoind_rpc::bitcoincore_rpc::RpcApi;
use bdk_wallet::ChangeSet;
use bitcoin::absolute::LockTime;
use bitcoin::consensus::encode::serialize_hex;
use bitcoin::{psbt, sighash, taproot, Amount, FeeRate, OutPoint, Sequence, Transaction, Txid, Weight, Witness};

use ark::BlockHeight;
use ark::util::KeypairExt;

use crate::database::StoredRound;
use crate::psbtext::{PsbtInputExt, RoundMeta};
use crate::{App, SECP};



struct SweepInput {
	point: OutPoint,
	amount: Amount,
	weight: Weight,
	psbt: psbt::Input,
}

impl SweepInput {
	/// Calculate the surplus that can be gained from sweeping this input.
	///
	/// This is calculated as the inputs value subtracted with the cost
	/// of spending it with the given fee rate.
	///
	/// If negative, returns [None].
	fn surplus(&self, feerate: FeeRate) -> Option<Amount> {
		self.amount.checked_sub(feerate * self.weight)
	}
}

struct ExpiredRound {
	txid: Txid,
	round: StoredRound,
}

impl ExpiredRound {
	fn new(txid: Txid, round: StoredRound) -> Self {
		Self { txid, round }
	}

	fn sweeps(&self) -> Vec<SweepInput> {
		let mut ret = Vec::with_capacity(2);

		let (
			spend_cb, spend_script, spend_lv, spend_merkle,
		) = self.round.signed_tree.spec.expiry_scriptspend(self.round.signed_tree.spec.round_tx_cosign_pk());
		let mut psbt_in = psbt::Input{
			witness_utxo: Some(self.round.tx.output[0].clone()),
			sighash_type: Some(sighash::TapSighashType::Default.into()),
			tap_internal_key: Some(self.round.signed_tree.spec.round_tx_cosign_pk()),
			tap_scripts: [(spend_cb, (spend_script, spend_lv))].into_iter().collect(),
			tap_merkle_root: Some(spend_merkle),
			non_witness_utxo: None,
			..Default::default()
		};
		psbt_in.set_round_meta(self.txid, RoundMeta::Vtxo);
		ret.push(SweepInput {
			point: OutPoint::new(self.txid, 0),
			amount: self.round.tx.output[0].value,
			weight: ark::tree::signed::NODE_SPEND_WEIGHT,
			psbt: psbt_in,
		});

		// Then add the connector output.
		// NB this is safe because we will use SIGHASH_ALL.
		let mut psbt_in = psbt::Input {
			witness_utxo: Some(self.round.tx.output[1].clone()),
			sighash_type: Some(sighash::TapSighashType::Default.into()),
			tap_internal_key: Some(self.round.signed_tree.spec.asp_pk.x_only_public_key().0),
			non_witness_utxo: None,
			..Default::default()
		};
		psbt_in.set_round_meta(self.txid, RoundMeta::Connector);
		ret.push(SweepInput {
			point: OutPoint::new(self.txid, 1),
			amount: self.round.tx.output[1].value,
			weight: ark::connectors::INPUT_WEIGHT,
			psbt: psbt_in,
		});

		ret
	}
}

struct RoundSweeper {
	app: Arc<App>,
}

impl RoundSweeper {
	fn load(app: Arc<App>) -> anyhow::Result<RoundSweeper> {
		Ok(RoundSweeper {
			app: app,
		})
	}

	/// Create a sweep tx.
	//
	// This is a separate method as a workaround for Rust issue
	// https://github.com/rust-lang/cargo/issues/14844
	// It can be inlined when that is fixed.
	// Alternatively, BDK will make TxBuilder Send, that would also solve the issue:
	// https://github.com/bitcoindevkit/bdk/pull/1737
	async fn create_sweep_tx(
		&self,
		tip: BlockHeight,
		expired_rounds: &[ExpiredRound],
		feerate: FeeRate,
	) -> anyhow::Result<(Transaction, ChangeSet)> {
		let mut wallet = self.app.wallet.lock().await;
		let drain_addr = wallet.reveal_next_address(bdk_wallet::KeychainKind::Internal).address;

		let mut txb = wallet.build_tx();
		txb.ordering(bdk_wallet::TxOrdering::Untouched);
		txb.nlocktime(LockTime::from_height(tip as u32).expect("actual height"));

		for round in expired_rounds {
			for sweep in round.sweeps() {
				txb.add_foreign_utxo_with_sequence(sweep.point,
					sweep.psbt, sweep.weight, Sequence::ZERO,
				).expect("bdk rejected foreign utxo");
			}
		}

		txb.drain_to(drain_addr.script_pubkey());
		txb.fee_rate(feerate);
		let mut psbt = txb.finish().expect("bdk failed to create round sweep tx");


		// SIGNING

		let mut shc = sighash::SighashCache::new(&psbt.unsigned_tx);
		let prevouts = psbt.inputs.iter()
			.map(|i| i.witness_utxo.clone().unwrap())
			.collect::<Vec<_>>();

		let connector_keypair = self.app.asp_key.for_keyspend();
		for (idx, input) in psbt.inputs.iter_mut().enumerate() {
			if let Some((_round, meta)) = input.get_round_meta().context("corrupt psbt")? {
				match meta {
					RoundMeta::Vtxo => {
						let (control, (script, lv)) = input.tap_scripts.iter().next()
							.context("corrupt psbt: missing tap_scripts")?;
						let leaf_hash = taproot::TapLeafHash::from_script(script, *lv);
						let sighash = shc.taproot_script_spend_signature_hash(
							idx,
							&sighash::Prevouts::All(&prevouts),
							leaf_hash,
							sighash::TapSighashType::Default,
						).expect("all prevouts provided");
						trace!("Signing expired VTXO input for sighash {}", sighash);
						let sig = SECP.sign_schnorr(&sighash.into(), &self.app.asp_key);
						let wit = Witness::from_slice(
							&[&sig[..], script.as_bytes(), &control.serialize()],
						);
						debug_assert_eq!(wit.size(), ark::tree::signed::NODE_SPEND_WEIGHT.to_wu() as usize);
						input.final_script_witness = Some(wit);
					},
					RoundMeta::Connector => {
						let sighash = shc.taproot_key_spend_signature_hash(
							idx,
							&sighash::Prevouts::All(&prevouts),
							sighash::TapSighashType::Default,
						).expect("all prevouts provided");
						trace!("Signing expired connector input for sighash {}", sighash);
						let sig = SECP.sign_schnorr(&sighash.into(), &connector_keypair);
						input.final_script_witness = Some(Witness::from_slice(&[sig[..].to_vec()]));
					},
				}
			}
		}

		let opts = bdk_wallet::SignOptions {
			trust_witness_utxo: true,
			..Default::default()
		};
		let finalized = wallet.sign(&mut psbt, opts)?;
		assert!(finalized);
		let signed = psbt.extract_tx()?;
		let now = SystemTime::now().duration_since(UNIX_EPOCH).expect("Unix epoch is in the past").as_secs();
		wallet.apply_unconfirmed_txs([(Arc::new(signed.clone()), now)]);
		let changeset = wallet.take_staged().expect("inserted new tx");
		Ok((signed, changeset))
	}

	async fn sweep_rounds(
		&mut self,
	) -> anyhow::Result<()> {
		let feerate = self.app.config.sweep_tx_fallback_feerate;

		let tip = self.app.bitcoind.get_block_count()? as BlockHeight;
		let expired_rounds = self.app.db.get_expired_rounds(tip)?.into_iter().map(|txid| {
			let round = self.app.db.get_round(txid)?.expect("db has round");
			Ok(ExpiredRound::new(txid, round))
		}).collect::<anyhow::Result<Vec<_>>>()?;

		// Check if it's worth it to sweep.
		let all_sweeps = expired_rounds.iter()
			.map(|r| r.sweeps().into_iter())
			.flatten()
			.filter(|s| {
				// Filter out sweeps that don't give any surplus at our feerate.
				if s.surplus(feerate).is_none() {
					slog!(UneconomicalSweepInput, outpoint: s.point, value: s.amount);
					false
				} else {
					true
				}
			})
			.collect::<Vec<_>>();
		let surplus = all_sweeps.iter().map(|s| s.surplus(feerate).unwrap()).sum::<Amount>();
		if surplus < self.app.config.sweep_threshold {
			slog!(NotSweeping, available_surplus: surplus, nb_inputs: all_sweeps.len());
			return Ok(());
		}

		slog!(SweepingRounds, total_surplus: surplus, inputs: all_sweeps.iter().map(|s| s.point).collect());
		for r in &expired_rounds {
			for i in r.sweeps() {
				slog!(SweepingOutput, outpoint: i.point, amount: i.amount, surplus: i.surplus(feerate).unwrap());
			}
		}

		let (signed, changeset) = self.create_sweep_tx(tip, &expired_rounds, feerate).await?;
		self.app.db.store_changeset(&changeset).await?;

		let txid = signed.compute_txid();
		debug!("Broadcasting round tx {}", txid);
		if let Err(e) = self.app.bitcoind.send_raw_transaction(&signed) {
			error!("Couldn't broadcast round tx: {}; tx: {}", e, serialize_hex(&signed));
		}
		slog!(SweepComplete, txid, surplus: surplus);

		//TODO(stevenroose) instead of doing this now, we should store the above tx
		// and only remove the round when it confirms
		for round in expired_rounds {
			debug!("Removing round with id {} because UTXOs spent", round.txid);
			self.app.db.remove_round(round.txid)?;
		}

		Ok(())
	}
}

/// Run a process that will periodically check for expired rounds and
/// sweep them into our internal wallet.
pub async fn run_expired_round_sweeper(
	app: Arc<App>,
	mut sweep_trigger_rx: tokio::sync::mpsc::Receiver<()>,
) -> anyhow::Result<()> {

	let mut state = RoundSweeper::load(app).context("failed to load RoundSweeper state")?;

	info!("Starting expired round sweep loop");
	loop {
		tokio::select! {
			() = tokio::time::sleep(state.app.config.round_sweep_interval) => {},
			Some(()) = sweep_trigger_rx.recv() => {
				info!("Received RPC trigger to sweep rounds");
			},
		}

		state.sweep_rounds().await?;
	}
}

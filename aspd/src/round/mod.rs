

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Context;
use bdk_bitcoind_rpc::bitcoincore_rpc::{RawTx, RpcApi};
use bitcoin::{Amount, FeeRate, OutPoint, Transaction};
use bitcoin::hashes::Hash;
use bitcoin::locktime::absolute::LockTime;
use bitcoin::secp256k1::{rand, schnorr, Keypair, PublicKey};
use tokio::time::Instant;
use ark::{musig, OffboardRequest, VtxoRequest, Vtxo, VtxoId};
use ark::connectors::ConnectorChain;
use ark::musig::MusigPubNonce;
use ark::tree::signed::{UnsignedVtxoTree, VtxoTreeSpec};

use crate::{txindex, App, SECP};

#[derive(Debug, Clone)]
pub enum RoundEvent {
	Start {
		id: u64,
		offboard_feerate: FeeRate,
	},
	VtxoProposal {
		id: u64,
		unsigned_round_tx: Transaction,
		vtxos_spec: VtxoTreeSpec,
		cosign_agg_nonces: Vec<musig::MusigAggNonce>,
	},
	RoundProposal {
		id: u64,
		cosign_sigs: Vec<schnorr::Signature>,
		forfeit_nonces: HashMap<VtxoId, Vec<musig::MusigPubNonce>>,
	},
	Finished {
		id: u64,
		signed_round_tx: txindex::Tx,
	},
}

#[derive(Debug)]
pub enum RoundInput {
	RegisterPayment {
		inputs: Vec<Vtxo>,
		vtxo_requests: Vec<VtxoRequest>,
		/// One set of nonces per vtxo request.
		cosign_pub_nonces: Vec<Vec<musig::MusigPubNonce>>,
		offboards: Vec<OffboardRequest>,
	},
	VtxoSignatures {
		pubkey: PublicKey,
		signatures: Vec<musig::MusigPartialSignature>,
	},
	ForfeitSignatures {
		signatures: Vec<(VtxoId, Vec<musig::MusigPubNonce>, Vec<musig::MusigPartialSignature>)>,
	},
}

fn validate_payment(
	inputs: &[Vtxo],
	outputs: &[VtxoParticipant],
	offboards: &[OffboardRequest],
	offboard_feerate: FeeRate,
) -> anyhow::Result<()> {
	let mut in_set = HashSet::with_capacity(inputs.len());
	let mut in_sum = Amount::ZERO;
	for input in inputs {
		in_sum += input.amount();
		if in_sum > Amount::MAX_MONEY{
			bail!("total input amount overflow");
		}
		if !in_set.insert(input.id()) {
			bail!("duplicate input");
		}
	}

	let mut out_sum = Amount::ZERO;
	for output in outputs {
		out_sum += output.req.amount;
		if out_sum > in_sum {
			bail!("total output amount exceeds total input amount");
		}
	}
	for offboard in offboards {
		let fee = match offboard.fee(offboard_feerate) {
			Some(v) => v,
			None => bail!("invalid offboard address"),
		};
		out_sum += offboard.amount + fee;
		if out_sum > in_sum {
			bail!("total output amount (with offboards) exceeds total input amount");
		}
	}

	Ok(())
}

fn validate_forfeit_sigs(
	connectors: &ConnectorChain,
	user_nonces: &[musig::MusigPubNonce],
	part_sigs: &[musig::MusigPartialSignature],
) -> anyhow::Result<()> {
	if user_nonces.len() != connectors.len() || part_sigs.len() != connectors.len() {
		bail!("not enough forfeit signatures provided");
	}

	Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VtxoParticipant {
	pub req: VtxoRequest,
	pub nonces: Vec<MusigPubNonce>,
}

pub struct CollectingPayments {
	round_id: u64,
	attempt_number: usize,
	max_output_vtxos: usize,
	offboard_feerate: FeeRate,

	allowed_inputs: Option<HashSet<VtxoId>>,
	all_inputs: HashMap<VtxoId, Vtxo>,
	all_outputs: Vec<VtxoParticipant>,
	/// Keep track of which input vtxos belong to which inputs.
	inputs_per_cosigner: HashMap<PublicKey, Vec<VtxoId>>,
	all_offboards: Vec<OffboardRequest>,

	//TODO(stevenroose) this can become a notify once we multitask
	proceed: bool,
	// proceed: tokio::sync::Notify,
}

impl CollectingPayments {
	fn new(round_id: u64, attempt_number: usize, max_output_vtxos: usize, offboard_feerate: FeeRate) -> CollectingPayments {
		CollectingPayments {
			round_id, attempt_number, max_output_vtxos, offboard_feerate,

			allowed_inputs: None,
			//TODO(stevenroose) allocate this more effectively
			all_inputs: HashMap::new(),
			all_outputs: Vec::new(),
			inputs_per_cosigner: HashMap::new(),
			all_offboards: Vec::new(),

			proceed: false,
			// proceed: tokio::sync::Notify::new(),
		}
	}

	fn register_payment(
		&mut self,
		inputs: Vec<Vtxo>,
		outputs: Vec<VtxoParticipant>,
		offboards: Vec<OffboardRequest>,
	) -> anyhow::Result<()> {
		if self.all_outputs.len() + outputs.len() > self.max_output_vtxos {
			warn!("Got payment we don't have space for, dropping");
			bail!("not enough outputs left in this round, try next round");
		}
		//TODO(stevenroose) verify ownership over inputs

		if let Some(ref allowed) = self.allowed_inputs {
			// This means we're not trying first time and we filter inputs.
			if let Some(bad) = inputs.iter().find(|i| !allowed.contains(&i.id())) {
				bail!("input vtxo {} has been banned for this round", bad.id());
			}
		}

		//TODO(stevenroose) check that vtxos exist!

		validate_payment(&inputs, &outputs, &offboards, self.offboard_feerate)
			.context("bad payment")?;
		for out in &outputs {
			if self.inputs_per_cosigner.contains_key(&out.req.cosign_pk) {
				bail!("duplicate cosign key {}", out.req.cosign_pk);
			}
		}

		// Ok we accept the round, register it.

		slog!(RoundPaymentRegistered, round_id: self.round_id, attempt_number: self.attempt_number, nb_inputs: inputs.len(), nb_outputs: outputs.len(), nb_offboards: offboards.len());
		let input_ids = inputs.iter().map(|v| v.id()).collect::<Vec<_>>();
		self.all_inputs.extend(inputs.into_iter().map(|v| (v.id(), v)));
		for out in &outputs {
			assert!(self.inputs_per_cosigner.insert(out.req.cosign_pk, input_ids.clone()).is_none());
		}
		self.all_outputs.extend(outputs);
		self.all_offboards.extend(offboards);

		// Check whether our round is full.
		const REGULAR_PAYMENT_NB_OUTPUTS: usize = 2;
		if self.all_outputs.len() + REGULAR_PAYMENT_NB_OUTPUTS >= self.max_output_vtxos {
			slog!(FullRound, round_id: self.round_id, attempt_number: self.attempt_number, nb_outputs: self.all_outputs.len(), max_output_vtxos: self.max_output_vtxos);
			self.proceed = true;
			// self.proceed.notify_one();
		}
		Ok(())
	}
}

pub struct SigningVtxoTree {
	round_id: u64,
	attempt_number: usize,

	cosign_part_sigs: HashMap<PublicKey, Vec<musig::MusigPartialSignature>>,
	cosign_agg_nonces: Vec<musig::MusigAggNonce>,
	unsigned_vtxo_tree: UnsignedVtxoTree,

	// data from earlier
	all_inputs: HashMap<VtxoId, Vtxo>,
	user_cosign_nonces: HashMap<PublicKey, Vec<musig::MusigPubNonce>>,
	inputs_per_cosigner: HashMap<PublicKey, Vec<VtxoId>>,
	allowed_inputs: HashSet<VtxoId>,

	//TODO(stevenroose) this can become a notify once we multitask
	proceed: bool,
}

impl SigningVtxoTree {
	pub fn register_signature(
		&mut self,
		pubkey: PublicKey,
		signatures: Vec<musig::MusigPartialSignature>,
	) -> anyhow::Result<()> {
		// Check for duplicates.
		if self.cosign_part_sigs.contains_key(&pubkey) {
			trace!("User with pubkey {} submitted partial vtxo sigs again", pubkey);
			bail!("duplicate signatures for pubkey");
		}

		let req = match self.unsigned_vtxo_tree.spec.vtxos.iter().find(|v| v.cosign_pk == pubkey) {
			Some(r) => r,
			None => {
				trace!("Received signatures from non-signer: {}", pubkey);
				bail!("pubkey is not part of cosigner group");
			},
		};
		slog!(RoundVtxoSignaturesRegistered, round_id: self.round_id, attempt_number: self.attempt_number, nb_vtxo_signatures: signatures.len(), cosigner: pubkey);

		let res = self.unsigned_vtxo_tree.verify_branch_cosign_partial_sigs(
			&self.cosign_agg_nonces,
			req,
			&self.user_cosign_nonces.get(&req.cosign_pk).expect("vtxo part of round"),
			&signatures,
		);
		if let Err(e) = res {
			debug!("Received invalid partial vtxo sigs from signer: {}: {}", pubkey, e);
			bail!("invalid partial signatures: {}", e);
		}

		self.cosign_part_sigs.insert(pubkey, signatures);

		// Stop the loop once we have all.
		if self.cosign_part_sigs.len() == self.unsigned_vtxo_tree.nb_leaves() {
			self.proceed = true;
		}
		Ok(())
	}
}

pub struct SigningForfeits {
	round_id: u64,
	attempt_number: usize,

	forfeit_part_sigs: HashMap<VtxoId, (Vec<musig::MusigPubNonce>, Vec<musig::MusigPartialSignature>)>,

	// data from earlier
	all_inputs: HashMap<VtxoId, Vtxo>,
	allowed_inputs: HashSet<VtxoId>,

	// other public data
	connectors: ConnectorChain,

	//TODO(stevenroose) this can become a notify once we multitask
	proceed: bool,
}

impl SigningForfeits {
	pub fn register_forfeits(
		&mut self,
		signatures: Vec<(VtxoId, Vec<musig::MusigPubNonce>, Vec<musig::MusigPartialSignature>)>,
	) -> anyhow::Result<()> {
		slog!(ReceivedForfeitSignatures, round_id: self.round_id, attempt_number: self.attempt_number, nb_forfeits: signatures.len(), vtxo_ids: signatures.iter().map(|v| v.0).collect::<Vec<_>>());
		for (id, nonces, sigs) in signatures {
			if let Some(_vtxo) = self.all_inputs.get(&id) {
				match validate_forfeit_sigs(
					&self.connectors,
					&nonces,
					&sigs,
				) {
					Ok(()) => { self.forfeit_part_sigs.insert(id, (nonces, sigs)); },
					Err(e) => debug!("Invalid forfeit sigs for {}: {}", id, e),
				}
			} else {
				slog!(UnknownForfeitSignature, round_id: self.round_id, attempt_number: self.attempt_number, vtxo_id: id);
			}
		}

		// Check whether we have all and can skip the loop.
		if self.forfeit_part_sigs.len() == self.all_inputs.len() {
			self.proceed = true;
		}
		Ok(())
	}
}

pub enum RoundState {
	Idle,
	CollectingPayments(CollectingPayments),
	SigningVtxoTree(SigningVtxoTree),
	SigningForfeits(SigningForfeits),
}

/// This method is called from a tokio thread so it can be long-lasting.
pub async fn run_round_coordinator(
	app: Arc<App>,
	mut round_input_rx: tokio::sync::mpsc::UnboundedReceiver<RoundInput>,
	mut round_trigger_rx: tokio::sync::mpsc::Receiver<()>,
) -> anyhow::Result<()> {
	let cfg = &app.config;

	let round_tx_feerate = app.config.round_tx_feerate;
	let offboard_feerate = round_tx_feerate;

	// The maximum number of output vtxos per round based on the max number
	// of vtxo tree nonces we require users to provide.
	let max_output_vtxos = (cfg.nb_round_nonces * 3 ) / 4;

	// Whether we should sync the onchain wallet at the next round attempt.
	let mut sync_next_attempt = true;

	'round: loop {
		// Sleep for the round interval, but discard all incoming messages.
		tokio::pin! { let timeout = tokio::time::sleep(cfg.round_interval); }
		'sleep: loop {
			tokio::select! {
				() = &mut timeout => break 'sleep,
				Some(()) = round_trigger_rx.recv() => {
					info!("Starting round based on admin RPC trigger");
					sync_next_attempt = false; // start round fast
					break 'sleep;
				},
				_ = round_input_rx.recv() => {},
			}
		}

		let round_id = (SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() /
			cfg.round_interval.as_millis()) as u64;
		slog!(RoundStarted, round_id);

		// Start new round, announce.
		let _ = app.rounds().round_event_tx.send(RoundEvent::Start { id: round_id, offboard_feerate });

		// Allocate this data once per round so that we can keep them
		// Perhaps we could even keep allocations between all rounds, but time
		// in between attempts is way more critial than in between rounds.

		// In this loop we will try to finish the round and make new attempts.
		'attempt: for attempt_number in 1usize.. {
			slog!(AttemptingRound, round_id, attempt_number);
			if sync_next_attempt {
				app.sync_onchain_wallet().await.context("error syncing onchain wallet")?;
			}
			sync_next_attempt = true;

			let attempt_start = Instant::now();
			let mut state = CollectingPayments::new(round_id, attempt_number, max_output_vtxos, offboard_feerate);

			// Generate a one-time use signing key.
			let cosign_key = Keypair::new(&SECP, &mut rand::thread_rng());

			// Start receiving payments.
			tokio::pin! { let timeout = tokio::time::sleep(cfg.round_submit_time); }
			let receive_payments_start = Instant::now();
			'receive: loop {
				tokio::select! {
					() = &mut timeout => break 'receive,
					input = round_input_rx.recv() => match input.expect("broken channel") {
						RoundInput::RegisterPayment {
							inputs, vtxo_requests, cosign_pub_nonces, offboards,
						} => {
							let outputs = vtxo_requests.into_iter().zip(cosign_pub_nonces.into_iter())
								.map(|(req, nonces)| VtxoParticipant { req, nonces })
								.collect();
							if let Err(e) = state.register_payment(inputs, outputs, offboards) {
								slog!(RoundPaymentRegistrationFailed, round_id, attempt_number, error: e.to_string());
								continue 'receive;
							}

							if state.proceed {
								break 'receive;
							}
						},
						_ => trace!("unexpected message"),
					}
				}
			}
			let receive_payment_duration = Instant::now().duration_since(receive_payments_start);
			if state.all_inputs.is_empty() || (state.all_outputs.is_empty() && state.all_offboards.is_empty()) {
				slog!(NoRoundPayments, round_id, attempt_number, duration: receive_payment_duration, max_round_submit_time: cfg.round_submit_time);
				continue 'round;
			}
			slog!(ReceivedRoundPayments, round_id, attempt_number, nb_inputs: state.all_inputs.len(), nb_outputs: state.all_outputs.len(), duration: receive_payment_duration, max_round_submit_time: cfg.round_submit_time);

			// Since it's possible in testing that we only have to do onboards,
			// and since it's pretty annoying to deal with the case of no vtxos,
			// if there are no vtxos, we will just add a fake vtxo for the ASP.
			// In practice, in later versions, it is very likely that the ASP
			// will actually want to create change vtxos, so temporarily, this
			// dummy vtxo will be a placeholder for a potential change vtxo.
			let mut change_vtxo = if state.all_outputs.is_empty() {
				lazy_static::lazy_static! {
					static ref UNSPENDABLE: PublicKey =
						"031575a4c3ad397590ccf7aa97520a60635c3215047976afb9df220bc6b4241b0d".parse().unwrap();
				}
				let cosign_key = Keypair::new(&SECP, &mut rand::thread_rng());
				let (cosign_sec_nonces, cosign_pub_nonces) = {
					let mut secs = Vec::with_capacity(cfg.nb_round_nonces);
					let mut pubs = Vec::with_capacity(cfg.nb_round_nonces);
					for _ in 0..cfg.nb_round_nonces {
						let (s, p) = musig::nonce_pair(&cosign_key);
						secs.push(s);
						pubs.push(p);
					}
					(secs, pubs)
				};
				let req = VtxoRequest {
					pubkey: *UNSPENDABLE,
					amount: ark::fee::DUST,
					cosign_pk: cosign_key.public_key(),
				};
				state.all_outputs.push(VtxoParticipant {
					req: req.clone(),
					nonces: cosign_pub_nonces.clone(),
				});
				Some((req, cosign_key, cosign_sec_nonces, cosign_pub_nonces))
			} else {
				None
			};


			// ****************************************************************
			// * Vtxo tree construction and signing
			// *
			// * - We will always store vtxo tx data from top to bottom,
			// *   meaning from the root tx down to the leaves.
			// ****************************************************************

			let tip = app.bitcoind.get_block_count()? as u32;
			let expiry = tip + cfg.vtxo_expiry_delta as u32;
			slog!(ConstructingRoundVtxoTree, round_id, attempt_number, tip_block_height: tip, vtxo_expiry_block_height: expiry);

			let vtxos_spec = VtxoTreeSpec::new(
				state.all_outputs.iter().map(|p| p.req.clone()).collect(),
				app.asp_key.public_key(),
				cosign_key.public_key(),
				expiry,
				cfg.vtxo_exit_delta,
			);
			//TODO(stevenroose) this is inefficient, improve this with direct getter
			let nb_nodes = vtxos_spec.nb_nodes();
			assert!(nb_nodes <= cfg.nb_round_nonces);
			let connector_output = ConnectorChain::output(
				state.all_inputs.len(), app.asp_key.public_key(),
			);

			// Build round tx.
			//TODO(stevenroose) think about if we can release lock sooner
			let mut wallet = app.wallet.lock().await;
			let mut round_tx_psbt = {
				let mut b = wallet.build_tx();
				b.ordering(bdk_wallet::TxOrdering::Untouched);
				b.nlocktime(LockTime::from_height(tip).expect("actual height"));
				b.add_recipient(vtxos_spec.round_tx_spk(), vtxos_spec.total_required_value());
				b.add_recipient(connector_output.script_pubkey, connector_output.value);
				for offb in &state.all_offboards {
					b.add_recipient(offb.script_pubkey.clone(), offb.amount);
				}
				b.fee_rate(round_tx_feerate);
				b.finish().expect("bdk failed to create round tx")
			};
			let unsigned_round_tx = round_tx_psbt.clone().extract_tx()?;
			let vtxos_utxo = OutPoint::new(unsigned_round_tx.compute_txid(), 0);
			let conns_utxo = OutPoint::new(unsigned_round_tx.compute_txid(), 1);

			// Generate vtxo nonces and combine with user's nonces.
			let (cosign_sec_nonces, cosign_pub_nonces) = {
				let mut secs = Vec::with_capacity(nb_nodes);
				let mut pubs = Vec::with_capacity(nb_nodes);
				for _ in 0..nb_nodes {
					let (s, p) = musig::nonce_pair(&cosign_key);
					secs.push(s);
					pubs.push(p);
				}
				(secs, pubs)
			};
			let user_cosign_nonces = state.all_outputs.into_iter().map(|req| {
				(req.req.cosign_pk, req.nonces)
			}).collect::<HashMap<_, _>>();
			let cosign_agg_nonces = vtxos_spec.calculate_cosign_agg_nonces(
				&user_cosign_nonces, &cosign_pub_nonces,
			);

			// Send out vtxo proposal to signers.
			let send_vtxo_proposal_start = Instant::now();
			let _ = app.rounds().round_event_tx.send(RoundEvent::VtxoProposal {
				id: round_id,
				unsigned_round_tx: unsigned_round_tx.clone(),
				vtxos_spec: vtxos_spec.clone(),
				cosign_agg_nonces: cosign_agg_nonces.clone(),
			});

			let unsigned_vtxo_tree = vtxos_spec.into_unsigned_tree(vtxos_utxo);
			let mut state = SigningVtxoTree {
				round_id,
				attempt_number,
				cosign_agg_nonces,
				allowed_inputs: state.all_inputs.keys().copied().collect(),
				all_inputs: state.all_inputs,
				// Make sure we don't allow other inputs next attempt.
				cosign_part_sigs: HashMap::with_capacity(unsigned_vtxo_tree.nb_leaves()),
				unsigned_vtxo_tree,
				user_cosign_nonces,
				inputs_per_cosigner: state.inputs_per_cosigner,
				proceed: false,
			};
			// first add our own change (or dummy) vtxo
			if let Some((req, pk, sec, _pub)) = change_vtxo.take() {
				let sigs = state.unsigned_vtxo_tree.cosign_branch(
					&state.cosign_agg_nonces,
					&req,
					&pk,
					sec,
				).expect("we're in the tree");
				state.cosign_part_sigs.insert(pk.public_key(), sigs);
				state.proceed = true;
			}

			// Wait for signatures from users.
			slog!(AwaitingRoundSignatures, round_id, attempt_number, duration_since_sending: Instant::now().duration_since(send_vtxo_proposal_start), max_round_sign_time: cfg.round_sign_time);
			let vtxo_signatures_receive_start = Instant::now();
			tokio::pin! { let timeout = tokio::time::sleep(cfg.round_sign_time); }
			'receive: loop {
				if state.proceed {
					break 'receive;
				}
				tokio::select! {
					_ = &mut timeout => {
						warn!("Timed out receiving vtxo partial signatures.");
						for (pk, vtxos) in state.inputs_per_cosigner.iter() {
							if !state.cosign_part_sigs.contains_key(pk) {
								// Disallow all inputs by this cosigner.
								slog!(DroppingLateVtxoSignatureVtxos, round_id, attempt_number, disallowed_vtxos: vtxos.clone());
								for id in vtxos {
									state.allowed_inputs.remove(id);
								}
							}
						}
						continue 'attempt;
					},
					input = round_input_rx.recv() => match input.expect("broken channel") {
						RoundInput::VtxoSignatures { pubkey, signatures } => {
							if let Err(e) = state.register_signature(pubkey, signatures) {
								slog!(VtxoSignatureRegistrationFailed, round_id, attempt_number, error: e.to_string());
								continue 'receive;
							}
						},
						_ => trace!("unexpected message"),
					}
				}
			}
			slog!(ReceivedRoundVtxoSignatures, round_id, attempt_number, duration: Instant::now().duration_since(vtxo_signatures_receive_start), max_round_sign_time: cfg.round_sign_time);

			// Combine the vtxo signatures.
			let combine_signatures_start = Instant::now();
			let asp_cosign_sigs = state.unsigned_vtxo_tree.cosign_tree(
				&state.cosign_agg_nonces,
				&cosign_key,
				cosign_sec_nonces,
			);
			debug_assert_eq!(state.unsigned_vtxo_tree.verify_all_cosign_partial_sigs(
				cosign_key.public_key(),
				&state.cosign_agg_nonces,
				&cosign_pub_nonces,
				&asp_cosign_sigs,
			), Ok(()));
			let cosign_sigs = state.unsigned_vtxo_tree.combine_partial_signatures(
				&state.cosign_agg_nonces,
				&state.cosign_part_sigs,
				asp_cosign_sigs,
			).context("failed to combine partial vtxo cosign signatures")?;
			debug_assert_eq!(state.unsigned_vtxo_tree.verify_cosign_sigs(&cosign_sigs), Ok(()));

			// Then construct the final signed vtxo tree.
			let signed_vtxos = state.unsigned_vtxo_tree
				.into_signed_tree(cosign_sigs)
				.into_cached_tree();
			slog!(CreatedSignedVtxoTree, round_id, attempt_number, nb_vtxo_signatures: signed_vtxos.spec.cosign_sigs.len(), duration: Instant::now().duration_since(combine_signatures_start));


			// ****************************************************************
			// * Broadcast signed vtxo tree and gather forfeit signatures
			// ****************************************************************

			// Prepare nonces for forfeit txs.
			// We need to prepare N nonces for each of N inputs.
			let mut forfeit_pub_nonces = HashMap::with_capacity(state.all_inputs.len());
			let mut forfeit_sec_nonces = HashMap::with_capacity(state.all_inputs.len());
			for id in state.all_inputs.keys() {
				let mut secs = Vec::with_capacity(state.all_inputs.len());
				let mut pubs = Vec::with_capacity(state.all_inputs.len());
				for _ in 0..state.all_inputs.len() {
					let (s, p) = musig::nonce_pair(&app.asp_key);
					secs.push(s);
					pubs.push(p);
				}
				forfeit_pub_nonces.insert(*id, pubs);
				forfeit_sec_nonces.insert(*id, secs);
			}

			// Send out round proposal to signers.
			let send_round_proposal_start = Instant::now();
			let _ = app.rounds().round_event_tx.send(RoundEvent::RoundProposal {
				id: round_id,
				cosign_sigs: signed_vtxos.spec.cosign_sigs.clone(),
				forfeit_nonces: forfeit_pub_nonces.clone(),
			});

			let connectors = ConnectorChain::new(
				state.all_inputs.len(), conns_utxo, app.asp_key.public_key(),
			);

			let mut state = SigningForfeits {
				round_id,
				attempt_number,
				forfeit_part_sigs: HashMap::with_capacity(state.all_inputs.len()),
				all_inputs: state.all_inputs,
				allowed_inputs: state.allowed_inputs,
				connectors,
				proceed: false,
			};

			// Wait for signatures from users.
			slog!(AwaitingRoundForfeits, round_id, attempt_number, duration_since_sending: Instant::now().duration_since(send_round_proposal_start), max_round_sign_time: cfg.round_sign_time);
			let receive_forfeit_signatures_start = Instant::now();
			tokio::pin! { let timeout = tokio::time::sleep(cfg.round_sign_time); }
			'receive: loop {
				tokio::select! {
					_ = &mut timeout => {
						warn!("Timed out receiving forfeit signatures.");
						for vtxo in state.all_inputs.keys() {
							if !state.forfeit_part_sigs.contains_key(vtxo) {
								slog!(DroppingLateForfeitSignatureVtxo, round_id, attempt_number, disallowed_vtxo: vtxo.clone());
								state.allowed_inputs.remove(vtxo);
							}
						}
						continue 'attempt;
					}
					input = round_input_rx.recv() => match input.expect("broken channel") {
						RoundInput::ForfeitSignatures { signatures } => {
							if let Err(e) = state.register_forfeits(signatures) {
								slog!(ForfeitRegistrationFailed, round_id, attempt_number, error: e.to_string());
								continue 'receive;
							}

							if state.proceed {
								break 'receive;
							}
						},
						_ => trace!("unexpected message"),
					}
				}
			}
			slog!(ReceivedRoundForfeits, round_id, attempt_number, nb_forfeits: state.forfeit_part_sigs.len(), duration: Instant::now().duration_since(receive_forfeit_signatures_start), max_round_sign_time: cfg.round_sign_time);

			// Finish the forfeit signatures.
			let mut forfeit_sigs = HashMap::with_capacity(state.all_inputs.len());
			let mut missing_forfeits = HashSet::new();
			for (id, vtxo) in &state.all_inputs {
				if let Some((user_nonces, partial_sigs)) = state.forfeit_part_sigs.get(id) {
					let sec_nonces = forfeit_sec_nonces.remove(id).unwrap().into_iter();
					let pub_nonces = forfeit_pub_nonces.get(id).unwrap();
					let connectors = state.connectors.connectors();
					let mut sigs = Vec::with_capacity(state.all_inputs.len());
					for (i, (conn, sec)) in connectors.zip(sec_nonces.into_iter()).enumerate() {
						let (sighash, _) = ark::forfeit::forfeit_sighash(&vtxo, conn);
						let agg_nonce = musig::nonce_agg(&[&user_nonces[i], &pub_nonces[i]]);
						let (_, sig) = musig::partial_sign(
							[app.asp_key.public_key(), vtxo.spec().user_pubkey],
							agg_nonce,
							&app.asp_key,
							sec,
							sighash.to_byte_array(),
							Some(vtxo.spec().exit_taptweak().to_byte_array()),
							Some(&[&partial_sigs[i]]),
						);
						sigs.push(sig.expect("should be signed"));
					}
					forfeit_sigs.insert(*id, sigs);
				} else {
					missing_forfeits.insert(*id);
				}
			}

			if !missing_forfeits.is_empty() {
				for input in missing_forfeits {
					slog!(MissingForfeits, round_id, attempt_number, input);
				}

				slog!(RestartMissingForfeits, round_id, attempt_number);
				continue 'attempt;
			}



			// ****************************************************************
			// * Finish the round
			// ****************************************************************

			// Sign the on-chain tx.
			let sign_start = Instant::now();
			let opts = bdk_wallet::SignOptions {
				trust_witness_utxo: true,
				..Default::default()
			};
			let finalized = wallet.sign(&mut round_tx_psbt, opts)?;
			assert!(finalized);
			let signed_round_tx = round_tx_psbt.extract_tx()?;
			let now = SystemTime::now().duration_since(UNIX_EPOCH).expect("Unix epoch is in the past").as_secs();
			wallet.apply_unconfirmed_txs([(Arc::new(signed_round_tx.clone()), now)]);
			if let Some(change) = wallet.take_staged() {
				app.db.store_changeset(&change).await?;
			}
			drop(wallet); // we no longer need the lock
			slog!(BroadcastingFinalizedRoundTransaction, round_id, attempt_number, tx_hex: signed_round_tx.raw_hex(), signing_time: Instant::now().duration_since(sign_start));
			let signed_round_tx = app.txindex.broadcast_tx(signed_round_tx).await;

			// Send out the finished round to users.
			trace!("Sending out finish event.");
			let _ = app.rounds().round_event_tx.send(RoundEvent::Finished {
				id: round_id,
				signed_round_tx: signed_round_tx.clone(),
			});

			// Store forfeit txs and round info in database.
			for (id, vtxo) in state.all_inputs {
				let forfeit_sigs = forfeit_sigs.remove(&id).unwrap();
				slog!(StoringForfeitVtxo, round_id, attempt_number, out_point: vtxo.point());
				app.db.set_vtxo_forfeited(id, forfeit_sigs)?;
			}

			trace!("Storing round result");
			app.txindex.register_batch(signed_vtxos.all_signed_txs().iter().cloned()).await;
			app.txindex.register_batch(state.connectors.iter_signed_txs(&app.asp_key)).await;
			app.db.store_round(signed_round_tx.tx.clone(), signed_vtxos, state.connectors.len())?;

			slog!(RoundFinished, round_id, attempt_number, txid: signed_round_tx.txid, vtxo_expiry_block_height: expiry, duration: Instant::now().duration_since(attempt_start));

			// Sync our wallet so that it sees the broadcasted tx.
			app.sync_onchain_wallet().await.context("error syncing onchain wallet")?;
			break 'attempt;
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use ark::{fee, Vtxo, VtxoRequest, VtxoSpec};
	use bitcoin::secp256k1::{PublicKey, Secp256k1};
	use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
	use std::collections::HashSet;
	use std::str::FromStr;

	fn generate_pubkey() -> PublicKey {
		let secp = Secp256k1::new();
		let (_secret_key, public_key) = secp.generate_keypair(&mut rand::thread_rng());
		public_key
	}

	fn get_asp_pubkey() -> PublicKey {
		PublicKey::from_str(
			"02e6642fd69bd211f93f7f1f36ca51a26a5290eb2dd1b0d8279a87bb0d480c8443",
		).unwrap()
	}

	fn create_vtxo_spec(amount: u64) -> VtxoSpec {
		VtxoSpec {
			user_pubkey: generate_pubkey(),
			asp_pubkey: get_asp_pubkey(),
			expiry_height: 100_000,
			exit_delta: 2016,
			amount: Amount::from_sat(amount),
		}
	}

	fn create_round_vtxo(vtxo_spec: VtxoSpec) -> Vtxo {
		let tx = Transaction {
			version: bitcoin::transaction::Version(3),
			lock_time: bitcoin::absolute::LockTime::ZERO,
			input: vec![TxIn {
				previous_output: OutPoint::null(),
				sequence: Sequence::MAX,
				script_sig: ScriptBuf::new(),
				witness: Witness::new(),
			}],
			output: vec![
				TxOut {
					script_pubkey: vtxo_spec.exit_spk(),
					value: vtxo_spec.amount,
				},
				fee::dust_anchor(),
			],
		};

		Vtxo::Round {
			spec: vtxo_spec,
			leaf_idx: 0,
			exit_branch: vec![tx],
		}
	}

	fn create_vtxo_request(amount: u64) -> VtxoRequest {
		VtxoRequest {
			pubkey: generate_pubkey(),
			amount: Amount::from_sat(amount),
			cosign_pk: generate_pubkey(),
		}
	}

	fn create_vtxo_participant(amount: u64) -> VtxoParticipant {
		VtxoParticipant {
			req: create_vtxo_request(amount),
			nonces: vec![],
		}
	}

	#[test]
	fn test_register_payment_valid() {
		const INPUT_AMOUNT: u64 = 400;
		const OUTPUT_AMOUNT: u64 = 400;

		let vtxo_spec = create_vtxo_spec(INPUT_AMOUNT);
		let vtxo = create_round_vtxo(vtxo_spec);
		let inputs = vec![vtxo];

		let outputs = vec![create_vtxo_participant(OUTPUT_AMOUNT)];
		let offboards = vec![];

		let mut collecting_payments = CollectingPayments::new(0, 0, 2, FeeRate::MIN);
		let result = collecting_payments.register_payment(
			inputs,
			outputs.clone(),
			offboards,
		);

		assert!(result.is_ok(), "register_payment failed with valid inputs");
		assert_eq!(collecting_payments.all_inputs.len(), 1);
		assert_eq!(collecting_payments.all_outputs.len(), 1);
		assert_eq!(collecting_payments.all_offboards.len(), 0);
		assert_eq!(collecting_payments.inputs_per_cosigner.len(), 1);
		assert_eq!(
			collecting_payments.inputs_per_cosigner.get(&outputs[0].req.cosign_pk).unwrap().len(),
			1
		);
	}

	#[test]
	fn test_register_payment_output_exceeds_input() {
		const INPUT_AMOUNT: u64 = 400;
		const OUTPUT_AMOUNT: u64 = INPUT_AMOUNT + 100;

		let vtxo_spec = create_vtxo_spec(INPUT_AMOUNT);
		let vtxo = create_round_vtxo(vtxo_spec);
		let inputs = vec![vtxo];

		let outputs = vec![create_vtxo_participant(OUTPUT_AMOUNT)];
		let offboards = vec![];

		let mut collecting_payments = CollectingPayments::new(0, 0, 2, FeeRate::MIN);
		let result = collecting_payments.register_payment(
			inputs,
			outputs,
			offboards,
		);

		assert!(
			result.is_err(),
			"register_payment should fail when output exceeds input"
		);
	}

	#[test]
	fn test_register_payment_duplicate_inputs() {
		const INPUT_AMOUNT: u64 = 400;
		const OUTPUT_AMOUNT: u64 = 300;

		let vtxo_spec = create_vtxo_spec(INPUT_AMOUNT);
		let vtxo = create_round_vtxo(vtxo_spec);
		let inputs = vec![vtxo.clone(), vtxo.clone()];

		let outputs = vec![create_vtxo_participant(OUTPUT_AMOUNT)];
		let offboards = vec![];

		let mut collecting_payments = CollectingPayments::new(0, 0, 2, FeeRate::MIN);
		let result = collecting_payments.register_payment(
			inputs,
			outputs,
			offboards,
		);

		assert!(
			result.is_err(),
			"register_payment should fail when duplicate inputs are provided"
		);
	}

	#[test]
	fn test_register_payment_exceeds_max_outputs() {
		const INPUT_AMOUNT: u64 = 400;
		const OUTPUT_AMOUNT_1: u64 = 100;
		const OUTPUT_AMOUNT_2: u64 = 300;

		let vtxo_spec = create_vtxo_spec(INPUT_AMOUNT);
		let vtxo = create_round_vtxo(vtxo_spec);
		let inputs = vec![vtxo];

		let outputs = vec![
			create_vtxo_participant(OUTPUT_AMOUNT_1),
			create_vtxo_participant(OUTPUT_AMOUNT_2),
		];
		let offboards = vec![];

		let mut collecting_payments = CollectingPayments::new(0, 0, 1, FeeRate::MIN);
		let result = collecting_payments.register_payment(
			inputs,
			outputs,
			offboards,
		);

		assert!(
			result.is_err(),
			"register_payment should fail when outputs exceed max_output_vtxos"
		);
	}

	#[test]
	fn test_register_payment_disallowed_input() {
		const INPUT_AMOUNT: u64 = 400;
		const OUTPUT_AMOUNT: u64 = 300;

		let vtxo_spec = create_vtxo_spec(INPUT_AMOUNT);
		let vtxo = create_round_vtxo(vtxo_spec);
		let inputs = vec![vtxo.clone()];

		let outputs = vec![create_vtxo_participant(OUTPUT_AMOUNT)];
		let offboards = vec![];

		let mut collecting_payments = CollectingPayments::new(0, 0, 2, FeeRate::MIN);
		collecting_payments.allowed_inputs = Some(HashSet::new());

		let result = collecting_payments.register_payment(
			inputs,
			outputs,
			offboards,
		);

		assert!(
			result.is_err(),
			"register_payment should fail when input is not allowed"
		);
	}

	#[test]
	fn test_register_payment_duplicate_cosign_pubkey() {
		const INPUT_AMOUNT: u64 = 400;
		const OUTPUT_AMOUNT_1: u64 = 200;
		const OUTPUT_AMOUNT_2: u64 = 200;

		let vtxo_spec1 = create_vtxo_spec(INPUT_AMOUNT);
		let vtxo1 = create_round_vtxo(vtxo_spec1);
		let inputs1 = vec![vtxo1];

		let outputs1 = vec![create_vtxo_participant(OUTPUT_AMOUNT_1)];

		let vtxo_spec2 = create_vtxo_spec(INPUT_AMOUNT);
		let vtxo2 = create_round_vtxo(vtxo_spec2);
		let inputs2 = vec![vtxo2];

		let outputs2 = vec![{
			let mut ret = create_vtxo_participant(OUTPUT_AMOUNT_2);
			ret.req.cosign_pk = outputs1[0].req.cosign_pk;
			ret
		}];

		let offboards = vec![];
		let mut collecting_payments = CollectingPayments::new(0, 0, 2, FeeRate::MIN);

		let result1 = collecting_payments.register_payment(
			inputs1,
			outputs1,
			offboards.clone(),
		);
		assert!(result1.is_ok(), "First register_payment should succeed");

		let result2 = collecting_payments.register_payment(
			inputs2,
			outputs2,
			offboards,
		);
		assert!(result2.is_err());
		assert!(result2.err().unwrap().to_string().contains("duplicate cosign key"));
	}

	#[test]
	fn test_register_multiple_payments() {
		const INPUT_AMOUNT_1: u64 = 400;
		const OUTPUT_AMOUNT_1: u64 = 300;

		let vtxo_spec1 = create_vtxo_spec(INPUT_AMOUNT_1);
		let vtxo1 = create_round_vtxo(vtxo_spec1);
		let inputs1 = vec![vtxo1];

		let outputs1 = vec![create_vtxo_participant(OUTPUT_AMOUNT_1)];

		let offboards = vec![];
		let mut collecting_payments = CollectingPayments::new(0, 0, 4, FeeRate::MIN);

		let result1 = collecting_payments.register_payment(
			inputs1,
			outputs1.clone(),
			offboards.clone(),
		);
		assert!(result1.is_ok(), "First register_payment should succeed");

		const INPUT_AMOUNT_2: u64 = 400;
		const OUTPUT_AMOUNT_2: u64 = 300;

		let vtxo_spec2 = create_vtxo_spec(INPUT_AMOUNT_2);
		let vtxo2 = create_round_vtxo(vtxo_spec2);
		let inputs2 = vec![vtxo2];

		let outputs2 = vec![create_vtxo_participant(OUTPUT_AMOUNT_2)];

		let result2 = collecting_payments.register_payment(
			inputs2,
			outputs2.clone(),
			offboards,
		);

		assert!(result2.is_ok(), "Second register_payment should succeed");
		assert_eq!(collecting_payments.all_inputs.len(), 2);
		assert_eq!(collecting_payments.all_outputs.len(), 2);
		assert_eq!(collecting_payments.inputs_per_cosigner.len(), 2);
		assert!(collecting_payments.inputs_per_cosigner.contains_key(&outputs1[0].req.cosign_pk));
		assert!(collecting_payments.inputs_per_cosigner.contains_key(&outputs2[0].req.cosign_pk));
	}

	#[test]
	fn test_register_payment_proceed_set() {
		const INPUT_AMOUNT_1: u64 = 400;
		const OUTPUT_AMOUNT_1: u64 = 200;

		let vtxo_spec1 = create_vtxo_spec(INPUT_AMOUNT_1);
		let vtxo1 = create_round_vtxo(vtxo_spec1);
		let inputs1 = vec![vtxo1];

		let outputs1 = vec![create_vtxo_participant(OUTPUT_AMOUNT_1)];

		let offboards = vec![];
		let mut collecting_payments = CollectingPayments::new(0, 0, 4, FeeRate::MIN);

		let result1 = collecting_payments.register_payment(
			inputs1,
			outputs1,
			offboards.clone(),
		);
		assert!(result1.is_ok(), "First register_payment should succeed");
		assert!(
			!collecting_payments.proceed,
			"Proceed should not be set after first registration"
		);

		const INPUT_AMOUNT_2: u64 = 400;
		const OUTPUT_AMOUNT_2: u64 = 200;

		let vtxo_spec2 = create_vtxo_spec(INPUT_AMOUNT_2);
		let vtxo2 = create_round_vtxo(vtxo_spec2);
		let inputs2 = vec![vtxo2];

		let outputs2 = vec![create_vtxo_participant(OUTPUT_AMOUNT_2)];

		let result2 = collecting_payments.register_payment(
			inputs2,
			outputs2,
			offboards,
		);
		assert!(result2.is_ok(), "Second register_payment should succeed");
		assert!(
			collecting_payments.proceed,
			"Proceed should be set after second registration"
		);
	}
}

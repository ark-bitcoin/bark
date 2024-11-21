

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Context;
use ark::musig::MusigPubNonce;
use bdk_bitcoind_rpc::bitcoincore_rpc::RpcApi;
use bitcoin::consensus::encode::serialize_hex;
use bitcoin::{Amount, FeeRate, OutPoint, Sequence, Transaction};
use bitcoin::hashes::Hash;
use bitcoin::locktime::absolute::LockTime;
use bitcoin::secp256k1::{rand, schnorr, Keypair, PublicKey};

use ark::{musig, OffboardRequest, VtxoRequest, Vtxo, VtxoId};
use ark::connectors::ConnectorChain;
use ark::tree::signed::{UnsignedVtxoTree, VtxoTreeSpec};

use crate::{SECP, App};
use crate::database::ForfeitVtxo;

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
		signed_round_tx: Transaction,
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

pub struct VtxoParticipant {
	pub req: VtxoRequest,
	pub nonces: Vec<MusigPubNonce>,
}

pub struct CollectingPayments {
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
	fn new(max_output_vtxos: usize, offboard_feerate: FeeRate) -> CollectingPayments {
		CollectingPayments {
			max_output_vtxos, offboard_feerate,

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

		trace!("Received {} inputs, {} outputs and {} offboards from user",
			inputs.len(), outputs.len(), offboards.len());
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
			warn!("Round is full, got {} outputs", self.all_outputs.len());
			self.proceed = true;
			// self.proceed.notify_one();
		}
		Ok(())
	}
}

pub struct SigningVtxoTree {
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
		trace!("Received {} signatures from cosigner {}", signatures.len(), pubkey);

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
			trace!("We received all signatures before timing out, continuing!");
			self.proceed = true;
		} else {
			trace!("Still missing {} signatures",
				self.unsigned_vtxo_tree.nb_leaves() - self.cosign_part_sigs.len(),
			);
		}
		Ok(())
	}
}

pub struct SigningForfeits {
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
		trace!("Received vtxo signatures for {:?}",
			signatures.iter().map(|v| v.0).collect::<Vec<_>>(),
		);
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
				debug!("User provided forfeit sigs for unknown input {}", id);
			}
		}

		// Check whether we have all and can skip the loop.
		if self.forfeit_part_sigs.len() == self.all_inputs.len() {
			debug!("We received all signatures, continuing round...");
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
		info!("Starting round {}", round_id);
		slog!(RoundStarted, round_id);

		// Start new round, announce.
		let _ = app.rounds().round_event_tx.send(RoundEvent::Start { id: round_id, offboard_feerate });

		// Allocate this data once per round so that we can keep them
		// Perhaps we could even keep allocations between all rounds, but time
		// in between attempts is way more critial than in between rounds.

		// In this loop we will try to finish the round and make new attempts.
		'attempt: loop {
			if sync_next_attempt {
				let balance = app.sync_onchain_wallet().await.context("error syncing onchain wallet")?;
				info!("Current wallet balance: {}", balance);
			}
			sync_next_attempt = true;

			let mut state = CollectingPayments::new(max_output_vtxos, offboard_feerate);

			// Generate a one-time use signing key.
			let cosign_key = Keypair::new(&SECP, &mut rand::thread_rng());

			// Start receiving payments.
			tokio::pin! { let timeout = tokio::time::sleep(cfg.round_submit_time); }
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
								trace!("Error registering payment: {}", e);
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
			if state.all_inputs.is_empty() || (state.all_outputs.is_empty() && state.all_offboards.is_empty()) {
				info!("Nothing to do this round, sitting it out...");
				continue 'round;
			}
			info!("Received {} inputs and {} outputs for round", state.all_inputs.len(), state.all_outputs.len());

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
			debug!("Current tip is {}, so round vtxos will expire at {}", tip, expiry);

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
			let spendable_utxos = app.spendable_expired_rounds(tip)?;
			if !spendable_utxos.is_empty() {
				debug!("Will be spending {} round-related UTXOs with total value of {}",
					spendable_utxos.len(), spendable_utxos.iter().map(|v| v.amount()).sum::<Amount>(),
				);
				for u in &spendable_utxos {
					trace!("Including round-related UTXO {} with value {}", u.point, u.amount());
				}
			}
			//TODO(stevenroose) think about if we can release lock sooner
			let mut wallet = app.wallet.lock().await;
			let mut round_tx_psbt = {
				let mut b = wallet.build_tx();
				b.ordering(bdk_wallet::TxOrdering::Untouched);
				b.nlocktime(LockTime::from_height(tip).expect("actual height"));
				for utxo in &spendable_utxos {
					b.add_foreign_utxo_with_sequence(
						utxo.point, utxo.psbt.clone(), utxo.weight, Sequence::ZERO,
					).expect("bdk rejected foreign utxo");
				}
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
			let _ = app.rounds().round_event_tx.send(RoundEvent::VtxoProposal {
				id: round_id,
				unsigned_round_tx: unsigned_round_tx.clone(),
				vtxos_spec: vtxos_spec.clone(),
				cosign_agg_nonces: cosign_agg_nonces.clone(),
			});

			let unsigned_vtxo_tree = vtxos_spec.into_unsigned_tree(vtxos_utxo);
			let mut state = SigningVtxoTree {
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
			debug!("Starting wait for vtxo signatures...");
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
								for id in vtxos {
									trace!("Dropping vtxo {}", id);
									state.allowed_inputs.remove(id);
								}
							}
						}
						continue 'attempt;
					},
					input = round_input_rx.recv() => match input.expect("broken channel") {
						RoundInput::VtxoSignatures { pubkey, signatures } => {
							if let Err(e) = state.register_signature(pubkey, signatures) {
								trace!("Error in received vtxo tree signatures: {}", e);
								continue 'receive;
							}
						},
						_ => trace!("unexpected message"),
					}
				}
			}
			debug!("Done receiving vtxo signatures.");

			// Combine the vtxo signatures.
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
			let signed_vtxos = state.unsigned_vtxo_tree.into_signed_tree(cosign_sigs);


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
			debug!("Sending round proposal event");
			let _ = app.rounds().round_event_tx.send(RoundEvent::RoundProposal {
				id: round_id,
				cosign_sigs: signed_vtxos.cosign_sigs.clone(),
				forfeit_nonces: forfeit_pub_nonces.clone(),
			});

			let connectors = ConnectorChain::new(
				state.all_inputs.len(), conns_utxo, app.asp_key.public_key(),
			);

			let mut state = SigningForfeits {
				forfeit_part_sigs: HashMap::with_capacity(state.all_inputs.len()),
				all_inputs: state.all_inputs,
				allowed_inputs: state.allowed_inputs,
				connectors,
				proceed: false,
			};

			// Wait for signatures from users.
			debug!("Starting wait for forfeit signatures...");
			tokio::pin! { let timeout = tokio::time::sleep(cfg.round_sign_time); }
			'receive: loop {
				tokio::select! {
					_ = &mut timeout => {
						warn!("Timed out receiving forfeit signatures.");
						for vtxo in state.all_inputs.keys() {
							if !state.forfeit_part_sigs.contains_key(vtxo) {
								trace!("Dropping vtxo {}", vtxo);
								state.allowed_inputs.remove(vtxo);
							}
						}
						continue 'attempt;
					}
					input = round_input_rx.recv() => match input.expect("broken channel") {
						RoundInput::ForfeitSignatures { signatures } => {
							if let Err(e) = state.register_forfeits(signatures) {
								trace!("Error in received vtxo tree signatures: {}", e);
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
						let agg_nonce = musig::nonce_agg([user_nonces[i], pub_nonces[i]]);
						let (_, sig) = musig::partial_sign(
							[app.asp_key.public_key(), vtxo.spec().user_pubkey],
							agg_nonce,
							&app.asp_key,
							sec,
							sighash.to_byte_array(),
							Some(vtxo.spec().exit_taptweak().to_byte_array()),
							Some(&[partial_sigs[i]]),
						);
						sigs.push(sig.expect("should be signed"));
					}
					forfeit_sigs.insert(*id, sigs);
				} else {
					missing_forfeits.insert(*id);
				}
			}
			//TODO(stevenroose) do something with missing forfeits


			// ****************************************************************
			// * Finish the round
			// ****************************************************************

			// Sign the on-chain tx.
			app.sign_round_utxo_inputs(&mut round_tx_psbt).context("signing round inputs")?;
			let opts = bdk_wallet::SignOptions {
				trust_witness_utxo: true,
				..Default::default()
			};
			let finalized = wallet.sign(&mut round_tx_psbt, opts)?;
			assert!(finalized);
			let signed_round_tx = round_tx_psbt.extract_tx()?;
			wallet.insert_tx(signed_round_tx.clone());
			if let Some(change) = wallet.take_staged() {
				app.db.store_changeset(&change).await?;
			}
			drop(wallet); // we no longer need the lock

			// Broadcast over bitcoind.
			debug!("Broadcasting round tx {}", signed_round_tx.compute_txid());
			if let Err(e) = app.bitcoind.send_raw_transaction(&signed_round_tx) {
				error!("Couldn't broadcast round tx: {}; tx: {}", e, serialize_hex(&signed_round_tx));
			}

			// Send out the finished round to users.
			trace!("Sending out finish event.");
			let _ = app.rounds().round_event_tx.send(RoundEvent::Finished {
				id: round_id,
				signed_round_tx: signed_round_tx.clone(),
			});

			// Store forfeit txs and round info in database.
			let round_id = signed_round_tx.compute_txid();
			for (id, vtxo) in state.all_inputs {
				let forfeit_sigs = forfeit_sigs.remove(&id).unwrap();
				let point = vtxo.point();
				trace!("Storing forfeit vtxo for vtxo {}", point);
				app.db.store_forfeit_vtxo(ForfeitVtxo { vtxo, forfeit_sigs })?;
			}

			trace!("Storing round result");
			app.db.store_round(signed_round_tx.clone(), signed_vtxos)?;

			//TODO(stevenroose) we should have a system that actually tracks that this tx is
			// getting confirmed!
			let spent_rounds = spendable_utxos.iter().map(|u| u.point.txid).collect::<HashSet<_>>();
			for round in spent_rounds {
				debug!("Removing round with id {} because UTXOs spent", round);
				app.db.remove_round(round)?;
			}

			info!("Finished round {} with tx {}", round_id, signed_round_tx.compute_txid());

			// Sync our wallet so that it sees the broadcasted tx.
			app.sync_onchain_wallet().await.context("error syncing onchain wallet")?;
			break 'attempt;
		}
	}
}

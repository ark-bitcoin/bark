

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Context;
use bdk_bitcoind_rpc::bitcoincore_rpc::RpcApi;
use bitcoin::{Amount, FeeRate, OutPoint, Sequence, Transaction};
use bitcoin::hashes::Hash;
use bitcoin::locktime::absolute::LockTime;
use bitcoin::secp256k1::{rand, Keypair, PublicKey};
use bitcoin::sighash::TapSighash;

use ark::{musig, OffboardRequest, VtxoRequest, Vtxo, VtxoId};
use ark::connectors::ConnectorChain;
use ark::tree::signed::{SignedVtxoTree, VtxoTreeSpec};

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
		round_tx: Transaction,
		vtxos_spec: VtxoTreeSpec,
		cosigners: Vec<PublicKey>,
		cosign_agg_nonces: Vec<musig::MusigAggNonce>,
	},
	RoundProposal {
		id: u64,
		round_tx: Transaction,
		vtxos: SignedVtxoTree,
		forfeit_nonces: HashMap<VtxoId, Vec<musig::MusigPubNonce>>,
	},
	Finished {
		id: u64,
		round_tx: Transaction,
		vtxos: SignedVtxoTree,
	},
}

#[derive(Debug)]
pub enum RoundInput {
	RegisterPayment {
		inputs: Vec<Vtxo>,
		outputs: Vec<VtxoRequest>,
		offboards: Vec<OffboardRequest>,
		cosign_pubkey: PublicKey,
		public_nonces: Vec<musig::MusigPubNonce>,
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
	outputs: &[VtxoRequest],
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
		out_sum += output.amount;
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

/// Validate the vtxo tree signatures from the given user.
fn validate_partial_vtxo_sigs(
	cosigners: impl IntoIterator<Item = PublicKey>,
	agg_nonces: &[musig::MusigAggNonce],
	sighashes: &[TapSighash],
	taptweak: [u8; 32],
	user_pubkey: PublicKey,
	user_pub_nonces: &[musig::MusigPubNonce],
	user_signatures: &[musig::MusigPartialSignature],
) -> bool {
	let key_agg = musig::tweaked_key_agg(cosigners, taptweak).0;
	for i in 0..agg_nonces.len() {
		let session = musig::MusigSession::new(
			&musig::SECP,
			&key_agg,
			agg_nonces[i],
			musig::zkp::Message::from_digest(sighashes[i].to_byte_array()),
		);
		let success = session.partial_verify(
			&musig::SECP,
			&key_agg,
			user_signatures[i].clone(),
			user_pub_nonces[i],
			musig::pubkey_to(user_pubkey),
		);
		if !success {
			debug!("User provided invalid partial vtxo sig for node {}", i);
			return false;
		}
	}
	true
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

pub struct CollectingPayments {
	max_output_vtxos: usize,
	offboard_feerate: FeeRate,

	allowed_inputs: Option<HashSet<VtxoId>>,
	all_inputs: HashMap<VtxoId, Vtxo>,
	all_outputs: Vec<VtxoRequest>,
	all_offboards: Vec<OffboardRequest>,
	cosigners: HashSet<PublicKey>,
	cosigner_vtxos: HashMap<PublicKey, Vec<VtxoId>>,
	cosign_pub_nonces: HashMap<PublicKey, Vec<musig::MusigPubNonce>>,

	//TODO(stevenroose) this can become a notify once we multitask
	proceed: bool,
	// proceed: tokio::sync::Notify,
}

impl CollectingPayments {
	fn new(max_output_vtxos: usize, offboard_feerate: FeeRate) -> CollectingPayments {
		CollectingPayments {
			max_output_vtxos, offboard_feerate,

			allowed_inputs: None,
			all_inputs: HashMap::new(),
			all_outputs: Vec::new(),
			all_offboards: Vec::new(),
			cosigners: HashSet::new(),
			cosigner_vtxos: HashMap::new(),
			cosign_pub_nonces: HashMap::new(),

			proceed: false,
			// proceed: tokio::sync::Notify::new(),
		}
	}

	fn register_payment(
		&mut self,
		inputs: Vec<Vtxo>,
		outputs: Vec<VtxoRequest>,
		offboards: Vec<OffboardRequest>,
		cosign_pubkey: PublicKey,
		public_nonces: Vec<musig::MusigPubNonce>,
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

		trace!("Received {} inputs, {} outputs and {} offboards from user",
			inputs.len(), outputs.len(), offboards.len());
		let vtxo_ids = inputs.iter().map(|v| v.id()).collect();
		self.all_inputs.extend(inputs.into_iter().map(|v| (v.id(), v)));
		self.all_outputs.extend(outputs);
		self.all_offboards.extend(offboards);
		//TODO(stevenroose) handle duplicate cosign key
		assert!(self.cosigners.insert(cosign_pubkey));
		self.cosigner_vtxos.insert(cosign_pubkey, vtxo_ids);
		self.cosign_pub_nonces.insert(cosign_pubkey, public_nonces);

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

	// data from earlier
	all_inputs: HashMap<VtxoId, Vtxo>,
	cosigners: HashSet<PublicKey>,
	cosign_pub_nonces: HashMap<PublicKey, Vec<musig::MusigPubNonce>>,
	allowed_inputs: HashSet<VtxoId>,
	cosigner_vtxos: HashMap<PublicKey, Vec<VtxoId>>,

	// other global data
	cosign_agg_nonces: Vec<musig::MusigAggNonce>,
	cosign_sighashes: Vec<TapSighash>,
	vtxos_spec: VtxoTreeSpec,

	//TODO(stevenroose) this can become a notify once we multitask
	proceed: bool,
}

impl SigningVtxoTree {
	pub fn register_signature(
		&mut self,
		pubkey: PublicKey,
		signatures: Vec<musig::MusigPartialSignature>,
	) -> anyhow::Result<()> {
		if !self.cosigners.contains(&pubkey) {
			trace!("Received signatures from non-signer: {}", pubkey);
			bail!("pubkey is not part of cosigner group");
		}
		trace!("Received signatures from cosigner {}", pubkey);

		if self.cosign_part_sigs.contains_key(&pubkey) {
			trace!("User with pubkey {} submitted partial vtxo sigs again", pubkey);
			bail!("duplicate signatures for pubkey");
		}
		if validate_partial_vtxo_sigs(
			self.cosigners.iter().copied(),
			&self.cosign_agg_nonces,
			&self.cosign_sighashes,
			self.vtxos_spec.cosign_taptweak().to_byte_array(),
			pubkey,
			self.cosign_pub_nonces.get(&pubkey).expect("user is cosigner"),
			&signatures,
		) {
			self.cosign_part_sigs.insert(pubkey, signatures);
		} else {
			debug!("Received invalid partial vtxo sigs from signer: {}", pubkey);
			bail!("invalid partial vtxo signatures");
		}

		// Stop the loop once we have all.
		if self.cosign_part_sigs.len() == self.cosigners.len() - 1 {
			self.proceed = true;
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
				//TODO(stevenroose) actually validate forfeit txs
				// probably make one method that both validates and cross-signs
				// the forfeit txs at the same time to save memory and not
				// double-create the musig context
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
			state.cosigners.insert(cosign_key.public_key());

			// Start receiving payments.
			tokio::pin! { let timeout = tokio::time::sleep(cfg.round_submit_time); }
			'receive: loop {
				tokio::select! {
					() = &mut timeout => break 'receive,
					input = round_input_rx.recv() => match input.expect("broken channel") {
						RoundInput::RegisterPayment {
							inputs, outputs, offboards, cosign_pubkey, public_nonces,
						} => {
							if let Err(e) = state.register_payment(
								inputs, outputs, offboards, cosign_pubkey, public_nonces,
							) {
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
			if state.all_outputs.is_empty() {
				lazy_static::lazy_static! {
					static ref UNSPENDABLE: PublicKey =
						"031575a4c3ad397590ccf7aa97520a60635c3215047976afb9df220bc6b4241b0d".parse().unwrap();
				}
				state.all_outputs.push(VtxoRequest {
					pubkey: *UNSPENDABLE,
					amount: ark::fee::DUST,
				});
			}


			// ****************************************************************
			// * Vtxo tree construction and signing
			// *
			// * - We will always store vtxo tx data from top to bottom,
			// *   meaning from the root tx down to the leaves.
			// ****************************************************************

			let tip = app.bitcoind.get_block_count()? as u32;
			let expiry = tip + cfg.vtxo_expiry_delta as u32;
			debug!("Current tip is {}, so round vtxos will expire at {}", tip, expiry);

			let cosign_agg_pk = musig::combine_keys(state.cosigners.iter().copied());
			let vtxos_spec = VtxoTreeSpec::new(
				state.all_outputs.clone(),
				cosign_agg_pk,
				app.master_key.public_key(),
				expiry,
				cfg.vtxo_exit_delta,
				cfg.vtxo_node_anchors,
			);
			//TODO(stevenroose) this is inefficient, improve this with direct getter
			let nb_nodes = vtxos_spec.build_unsigned_tree(OutPoint::null()).nb_nodes();
			assert!(nb_nodes <= cfg.nb_round_nonces);
			let connector_output = ConnectorChain::output(
				state.all_inputs.len(), app.master_key.public_key(),
			);

			// Build round tx.
			let spendable_utxos = app.spendable_expired_vtxos(tip)?;
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
				b.add_recipient(vtxos_spec.cosign_spk(), vtxos_spec.total_required_value());
				b.add_recipient(connector_output.script_pubkey, connector_output.value);
				for offb in &state.all_offboards {
					b.add_recipient(offb.script_pubkey.clone(), offb.amount);
				}
				b.fee_rate(round_tx_feerate);
				b.finish().expect("bdk failed to create round tx")
			};
			let round_tx = round_tx_psbt.clone().extract_tx()?;
			let vtxos_utxo = OutPoint::new(round_tx.compute_txid(), 0);
			let conns_utxo = OutPoint::new(round_tx.compute_txid(), 1);

			// Generate vtxo nonces and combine with user's nonces.
			let (sec_vtxo_nonces, pub_vtxo_nonces) = {
				let mut secs = Vec::with_capacity(nb_nodes);
				let mut pubs = Vec::with_capacity(nb_nodes);
				for _ in 0..nb_nodes {
					let (s, p) = musig::nonce_pair(&cosign_key);
					secs.push(s);
					pubs.push(p);
				}
				(secs, pubs)
			};
			let cosign_agg_nonces = {
				let mut ret = Vec::with_capacity(nb_nodes);
				let mut buf = Vec::with_capacity(state.cosigners.len());
				for i in 0..nb_nodes {
					buf.clear();
					buf.push(pub_vtxo_nonces[i]);
					buf.extend(state.cosign_pub_nonces.values().map(|n| n[i]));
					ret.push(musig::MusigAggNonce::new(&musig::SECP, &buf));
				}
				ret
			};
			let cosign_sighashes = vtxos_spec.sighashes(vtxos_utxo);
			assert_eq!(cosign_sighashes.len(), cosign_agg_nonces.len());

			// Send out vtxo proposal to signers.
			let _ = app.rounds().round_event_tx.send(RoundEvent::VtxoProposal {
				id: round_id,
				round_tx: round_tx.clone(),
				vtxos_spec: vtxos_spec.clone(),
				cosigners: state.cosigners.iter().copied().collect(),
				cosign_agg_nonces: cosign_agg_nonces.clone(),
			});

			let mut state = SigningVtxoTree {
				cosign_part_sigs: HashMap::with_capacity(state.cosigners.len()),
				allowed_inputs: state.all_inputs.keys().copied().collect(),
				all_inputs: state.all_inputs,
				cosigners: state.cosigners,
				cosign_pub_nonces: state.cosign_pub_nonces,
				cosigner_vtxos: state.cosigner_vtxos,
				// Make sure we don't allow other inputs next attempt.
				cosign_agg_nonces,
				cosign_sighashes,
				vtxos_spec,
				proceed: false,
			};

			// Wait for signatures from users.
			tokio::pin! { let timeout = tokio::time::sleep(cfg.round_sign_time); }
			'receive: loop {
				tokio::select! {
					_ = &mut timeout => {
						warn!("Timed out receiving vtxo partial signatures.");
						for (pk, vtxos) in state.cosigner_vtxos.iter() {
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

							if state.proceed {
								break 'receive;
							}
						},
						_ => trace!("unexpected message"),
					}
				}
			}

			// Combine the vtxo signatures.
			#[cfg(debug_assertions)]
			let mut partial_sigs = Vec::with_capacity(nb_nodes);
			let mut final_vtxo_sigs = Vec::with_capacity(nb_nodes);
			for (i, sec_nonce) in sec_vtxo_nonces.into_iter().enumerate() {
				let others = state.cosign_part_sigs.values().map(|s| s[i].clone()).collect::<Vec<_>>();
				let (_partial, final_sig) = musig::partial_sign(
					state.cosigners.iter().copied(),
					state.cosign_agg_nonces[i],
					&cosign_key,
					sec_nonce,
					state.cosign_sighashes[i].to_byte_array(),
					Some(state.vtxos_spec.cosign_taptweak().to_byte_array()),
					Some(&others),
				);
				final_vtxo_sigs.push(final_sig.expect("we provided others"));
				#[cfg(debug_assertions)]
				partial_sigs.push(_partial);
			}
			#[cfg(debug_assertions)]
			debug_assert!(validate_partial_vtxo_sigs(
				state.cosigners.iter().copied(),
				&state.cosign_agg_nonces,
				&state.cosign_sighashes,
				state.vtxos_spec.cosign_taptweak().to_byte_array(),
				cosign_key.public_key(),
				&pub_vtxo_nonces,
				&partial_sigs,
			), "our own partial signatures were wrong");

			// Then construct the final signed vtxo tree.
			let signed_vtxos = SignedVtxoTree::new(state.vtxos_spec, vtxos_utxo, final_vtxo_sigs);
			debug_assert!(signed_vtxos.validate_signatures().is_ok(), "invalid signed vtxo tree");


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
					let (s, p) = musig::nonce_pair(&app.master_key);
					secs.push(s);
					pubs.push(p);
				}
				forfeit_pub_nonces.insert(*id, pubs);
				forfeit_sec_nonces.insert(*id, secs);
			}

			// Send out round proposal to signers.
			let _ = app.rounds().round_event_tx.send(RoundEvent::RoundProposal {
				id: round_id,
				round_tx: round_tx.clone(),
				vtxos: signed_vtxos.clone(),
				forfeit_nonces: forfeit_pub_nonces.clone(),
			});

			let connectors = ConnectorChain::new(
				state.all_inputs.len(), conns_utxo, app.master_key.public_key(),
			);

			let mut state = SigningForfeits {
				forfeit_part_sigs: HashMap::with_capacity(state.all_inputs.len()),
				all_inputs: state.all_inputs,
				allowed_inputs: state.allowed_inputs,
				connectors,
				proceed: false,
			};

			// Wait for signatures from users.
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
							[app.master_key.public_key(), vtxo.spec().user_pubkey],
							agg_nonce,
							&app.master_key,
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
			let round_tx = round_tx_psbt.extract_tx()?;
			if let Some(change) = wallet.take_staged() {
				app.db.store_changeset(&change).await?;
			}
			drop(wallet); // we no longer need the lock

			// Broadcast over bitcoind.
			debug!("Broadcasting round tx {}", round_tx.compute_txid());
			let bc = app.bitcoind.send_raw_transaction(&round_tx);
			if let Err(e) = bc {
				warn!("Couldn't broadcast round tx: {}", e);
			}

			// Send out the finished round to users.
			trace!("Sending out finish event.");
			let _ = app.rounds().round_event_tx.send(RoundEvent::Finished {
				id: round_id,
				vtxos: signed_vtxos.clone(),
				round_tx: round_tx.clone(),
			});

			// Store forfeit txs and round info in database.
			let round_id = round_tx.compute_txid();
			for (id, vtxo) in state.all_inputs {
				let forfeit_sigs = forfeit_sigs.remove(&id).unwrap();
				let point = vtxo.point();
				trace!("Storing forfeit vtxo for vtxo {}", point);
				app.db.store_forfeit_vtxo(ForfeitVtxo { vtxo, forfeit_sigs })?;
			}

			trace!("Storing round result");
			app.db.store_round(round_tx.clone(), signed_vtxos)?;

			//TODO(stevenroose) we should have a system that actually tracks that this tx is
			// getting confirmed!
			let spent_rounds = spendable_utxos.iter().map(|u| u.point.txid).collect::<HashSet<_>>();
			for round in spent_rounds {
				debug!("Removing round with id {} because UTXOs spent", round);
				app.db.remove_round(round)?;
			}

			info!("Finished round {} with tx {}", round_id, round_tx.compute_txid());

			// Sync our wallet so that it sees the broadcasted tx.
			app.sync_onchain_wallet().await.context("error syncing onchain wallet")?;
			break 'attempt;
		}
	}
}

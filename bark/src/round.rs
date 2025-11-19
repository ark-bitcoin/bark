//! Round State Machine
//!
//!

use std::{cmp, iter};
use std::borrow::Cow;
use std::convert::Infallible;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use std::collections::{HashMap, HashSet};

use anyhow::Context;
use bdk_esplora::esplora_client::Amount;
use bip39::rand;
use bitcoin::consensus::encode::{serialize_hex, deserialize};
use bitcoin::key::Keypair;
use bitcoin::secp256k1::{schnorr, PublicKey};
use bitcoin::{Address, Network, OutPoint, Transaction, Txid};
use bitcoin::consensus::Params;
use bitcoin::hashes::Hash;
use futures::future::try_join_all;
use futures::{Stream, StreamExt};
use log::{debug, error, info, trace, warn};

use ark::{OffboardRequest, ProtocolEncoding, SignedVtxoRequest, Vtxo, VtxoId, VtxoRequest};
use ark::connectors::ConnectorChain;
use ark::musig::{self, DangerousSecretNonce, PublicNonce, SecretNonce};
use ark::rounds::{
	RoundAttempt, RoundEvent, RoundFinished, RoundId, RoundSeq, MIN_ROUND_TX_OUTPUTS, ROUND_TX_CONNECTOR_VOUT, ROUND_TX_VTXO_TREE_VOUT
};
use ark::tree::signed::{SignedVtxoTreeSpec, VtxoTreeSpec};
use bitcoin_ext::{TxStatus, P2TR_DUST};
use bitcoin_ext::rpc::RpcApi;
use server_rpc::protos;

use crate::{SECP, Wallet};
use crate::movement::{MovementDestination, MovementId, MovementStatus};
use crate::movement::update::MovementUpdate;
use crate::onchain::{ChainSource, ChainSourceClient};
use crate::persist::StoredRoundState;
use crate::subsystem::{BarkSubsystem, RoundMovement};

/// Bitcoin's block time of 10 minutes.
const BLOCK_TIME: Duration = Duration::from_secs(10 * 60);


/// Struct to communicate your specific participation for an Ark round.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoundParticipation {
	#[serde(with = "ark::encode::serde::vec")]
	pub inputs: Vec<Vtxo>,
	/// The output VTXOs that we request in the round,
	/// including change
	pub outputs: Vec<VtxoRequest>,
	pub offboards: Vec<OffboardRequest>,
}

impl RoundParticipation {
	pub fn to_movement_update(&self, network: Network) -> anyhow::Result<MovementUpdate> {
		let params = Params::from(network);
		let input_amount = self.inputs.iter().map(|i| i.amount()).sum::<Amount>();
		let output_amount = self.outputs.iter().map(|r| r.amount).sum::<Amount>();
		let offboard_amount = self.offboards.iter().map(|r| r.amount).sum::<Amount>();
		let fee = input_amount - output_amount - offboard_amount;
		let intended = -offboard_amount.to_signed()?;
		let mut sent_to = Vec::with_capacity(self.offboards.len());
		for o in &self.offboards {
			let address = Address::from_script(&o.script_pubkey, &params)?;
			sent_to.push(MovementDestination::new(address.to_string(), o.amount));
		}
		Ok(MovementUpdate::new()
			.consumed_vtxos(&self.inputs)
			.intended_balance(intended)
			.effective_balance(intended - fee.to_signed()?)
			.fee(fee)
			.sent_to(sent_to)
		)
	}
}

#[derive(Debug, Clone)]
pub enum RoundStatus {
	/// The round was successful and is fully confirmed
	Confirmed {
		funding_txid: Txid,
	},
	/// Round successful but not fully confirmed
	Unconfirmed {
		funding_txid: Txid,
	},
	/// We have unsigned funding transactions that might confirm
	Pending {
		unsigned_funding_txids: Vec<Txid>,
	},
	/// The round failed
	Failed {
		error: String,
	},
}

impl RoundStatus {
	/// Whether this is the final state and it won't change anymore
	pub fn is_final(&self) -> bool {
		match self {
			Self::Confirmed { .. } => true,
			Self::Unconfirmed { .. } => false,
			Self::Pending { .. } => false,
			Self::Failed { .. } => true,
		}
	}

	/// Whether it looks like the round succeeded
	pub fn is_success(&self) -> bool {
		match self {
			Self::Confirmed { .. } => true,
			Self::Unconfirmed { .. } => true,
			Self::Pending { .. } => false,
			Self::Failed { .. } => false,
		}
	}
}

/// State of the progress of a round participation
///
/// An instance of this struct is kept all the way from the intention of joining
/// the next round, until either the round fully confirms or it fails and we are
/// sure it won't have any effect on our wallet.
///
/// As soon as we have signed forfeit txs for the round, we keep track of this
/// round attempt until we see another attempt we participated in confirm or
/// we gain confidence that the failed attempt will never confirm.
pub struct RoundState {
	/// Our participation in this round
	pub(crate) participation: RoundParticipation,

	/// The flow of the round in case it is still ongoing with the server
	pub(crate) flow: RoundFlowState,

	/// A potential final state for each round-attempt
	pub(crate) unconfirmed_rounds: Vec<UnconfirmedRound>,

	/// The ID of the [Movement] associated with this round
	pub(crate) movement_id: Option<MovementId>,
}

impl RoundState {
	fn new(participation: RoundParticipation, movement_id: Option<MovementId>) -> Self {
		Self {
			participation,
			movement_id,
			flow: RoundFlowState::WaitingToStart,
			unconfirmed_rounds: Vec::new(),
		}
	}

	/// Our participation in this round
	pub fn participation(&self) -> &RoundParticipation {
		&self.participation
	}

	pub fn flow(&self) -> &RoundFlowState {
		&self.flow
	}

	pub fn unconfirmed_rounds(&self) -> &[UnconfirmedRound] {
		&self.unconfirmed_rounds
	}

	/// Whether the interactive part of the round has finished
	pub fn round_has_finished(&self) -> bool {
		match self.flow {
			RoundFlowState::WaitingToStart => false,
			RoundFlowState::Ongoing { .. } => false,
			RoundFlowState::Success => true,
			RoundFlowState::Failed { .. } => true,
		}
	}

	async fn try_start_attempt(&mut self, wallet: &Wallet, attempt: &RoundAttempt) {
		match start_attempt(wallet, &self.participation, attempt).await {
			Ok(state) => {
				self.flow = RoundFlowState::Ongoing {
					round_seq: attempt.round_seq,
					attempt_seq: attempt.attempt_seq,
					state: state,
				};
			},
			Err(e) => {
				self.flow = RoundFlowState::Failed {
					error: format!("{:#}", e),
				};
			},
		}
	}

	/// Processes the given event and returns true if some update was made to the state
	pub async fn process_event(
		&mut self,
		wallet: &Wallet,
		event: &RoundEvent,
	) -> bool {
		let _: Infallible = match self.flow {
			RoundFlowState::WaitingToStart => {
				if let RoundEvent::Attempt(e) = event && e.attempt_seq == 0 {
					trace!("Joining round attempt {}:{}", e.round_seq, e.attempt_seq);
					self.try_start_attempt(wallet, e).await;
					return true;
				} else {
					trace!("Ignoring {} event (seq {}:{}), waiting for round to start",
						event.kind(), event.round_seq(), event.attempt_seq(),
					);
					return false;
				}
			},
			RoundFlowState::Ongoing { round_seq, attempt_seq, ref mut state } => {
				// here we catch the cases where we're in a wrong flow

				if event.round_seq() > round_seq {
					// new round started, we don't support multiple parallel rounds,
					// this means we failed
					self.flow = RoundFlowState::Failed {
						error: format!("round {} started while we were on {}",
							event.round_seq(), round_seq,
						),
					};
					return true;
				}

				if event.attempt_seq() < attempt_seq {
					trace!("ignoring replayed message from old attempt");
					return false;
				}

				if let RoundEvent::Attempt(e) = event && e.attempt_seq > attempt_seq {
					trace!("Joining new round attempt {}:{}", e.round_seq, e.attempt_seq);
					self.try_start_attempt(wallet, e).await;
					return true;
				}
				trace!("Processing event {} for round attempt {}:{} in state {}",
					event.kind(), round_seq, attempt_seq, state.kind(),
				);

				let mut updated = false;
				match progress_attempt(state, wallet, &self.participation, event).await {
					AttemptProgressResult::NotUpdated => {},
					AttemptProgressResult::Updated { new_state, new_unconfirmed_round } => {
						if let Some(r) = new_unconfirmed_round {
							self.unconfirmed_rounds.push(r);
						}
						*state = new_state;
						updated = true;
					},
					AttemptProgressResult::Failed(e) => {
						self.flow = RoundFlowState::Failed { error: format!("{:#}", e) };
						updated = true;
					},
					AttemptProgressResult::Finished { signed_round_tx, vtxos } => {
						assert!(!self.unconfirmed_rounds.is_empty());

						// we need to update our UnconfirmedRound with the signed tx
						let txid = signed_round_tx.compute_txid();
						if let Some(round) = self.unconfirmed_rounds.iter_mut()
							.find(|r| r.funding_txid() == txid)
						{
							round.funding_tx = signed_round_tx;

							if let Err(e) = persist_round_success(
								wallet,
								&self.participation,
								self.movement_id,
								&vtxos,
								&round.funding_tx,
							).await {
								error!("Error while storing succesful round: {:#}", e);
								//TODO(stevenroose) make sure we call this again timely!
							}

							self.flow = RoundFlowState::Success;
						} else {
							self.flow = RoundFlowState::Failed {
								error: format!("server sent signed round tx {}, \
									but we don't have a state for that", txid,),
							};
						};
						updated = true;
					},
				}
				return updated;
			},
			RoundFlowState::Success { .. } | RoundFlowState::Failed { .. } => return false,
		};
	}

	/// Sync the round's status and return it
	///
	/// When success or failure is returned, the round state can be eliminated
	pub async fn sync(&mut self, wallet: &Wallet) -> anyhow::Result<RoundStatus> {
		let mut confirmed_funding_txid = None;
		let mut idx = 0;
		while idx < self.unconfirmed_rounds.len() {
			let round = self.unconfirmed_rounds.get_mut(idx).unwrap();

			let was_signed = round.is_tx_signed();
			let res = round.sync(wallet).await;

			// if we just saw the signed tx, issue the new VTXOs and mark movement as OK
			//TODO(stevenroose) after we make `persist_round_success` idempotent,
			// just always go into this branch when we have a signed tx to make
			// sure a db failure get fixed on the next call of `sync`.
			if !was_signed && round.is_tx_signed() {
				if let Err(e) = persist_round_success(
					wallet,
					&self.participation,
					self.movement_id,
					&round.new_vtxos,
					&round.funding_tx,
				).await {
					error!("Error storing state after seeing signed funding tx: {:#?}", e);
					idx += 1;
					continue;
				}
			}

			//TODO(stevenroose) after the persist methods are idempotent, also
			// persist the round as failed here if a signed round tx is no longer in
			// the mempool

			let _: Infallible = match res {
				Ok(UnconfirmedRoundStatus::Confirmed) => {
					confirmed_funding_txid = Some(round.funding_txid());
					// let's not remove this one just to be sure we can't
					// accidentally lose track of it
					// we should remove the entire state after this anyway
					idx += 1;
					continue;
				},
				Ok(UnconfirmedRoundStatus::DoubleSpent { double_spender }) => {
					debug!("Round with round txid {} got double spent by tx {:?}",
						round.funding_tx.compute_txid(), double_spender,
					);
					self.unconfirmed_rounds.swap_remove(idx);
					continue; // skip idx increment
				},
				Ok(UnconfirmedRoundStatus::Unconfirmed) => {
					idx += 1;
					continue;
				},
				Err(e) => {
					warn!("Error syncing status of unconfirmed round: {:#}", e);
					trace!("Error syncing status of unconfirmed round: err={:#}; state={:?}",
						e, round,
					);
					idx += 1;
					continue;
				}
			};
		}

		let status = if let Some(funding_txid) = confirmed_funding_txid {
			if let Some(movement_id) = self.movement_id {
				update_funding_txid(funding_txid, movement_id, wallet).await?;
				wallet.movements.finish_movement(movement_id, MovementStatus::Finished).await?;
			}

			RoundStatus::Confirmed { funding_txid }
		} else if self.unconfirmed_rounds.is_empty() {
			match self.flow {
				RoundFlowState::WaitingToStart | RoundFlowState::Ongoing { .. } => {
					RoundStatus::Pending { unsigned_funding_txids: vec![] }
				}
				RoundFlowState::Success => {
					persist_round_failure(wallet, &self.participation, self.movement_id)
						.await
						.context("failed to persist round failure")?;
					RoundStatus::Failed {
						error: "all pending round funding transactions have been double spent".into(),
					}
				},
				RoundFlowState::Failed { ref error } => {
					persist_round_failure(wallet, &self.participation, self.movement_id)
						.await
						.context("failed to persist round failure")?;
					RoundStatus::Failed { error: error.clone() }
				},
			}
		} else if let Some(signed) = self.unconfirmed_rounds.iter().find(|r| r.is_tx_signed()) {
			let funding_txid = signed.funding_txid();
			if let Some(movement_id) = self.movement_id {
				update_funding_txid(funding_txid, movement_id, wallet).await?;
			}

			RoundStatus::Unconfirmed { funding_txid }
		} else {
			RoundStatus::Pending {
				unsigned_funding_txids: self.unconfirmed_rounds.iter()
					.map(|r| r.funding_txid())
					.collect(),
			}
		};
		Ok(status)
	}

	/// Once we know the signed round funding tx, this returns the output VTXOs
	/// for this round.
	pub fn output_vtxos(&self) -> Option<&[Vtxo]> {
		for round in self.unconfirmed_rounds.iter() {
			if round.is_tx_signed() {
				return Some(&round.new_vtxos);
			}
		}
		None
	}

	/// Returns the input VTXOs that are locked in this round, but only
	/// if no output VTXOs were issued yet.
	pub fn locked_pending_inputs(&self) -> &[Vtxo] {
		if self.unconfirmed_rounds.iter().any(|r| r.is_tx_signed()) {
			// new vtxos aready issued
			return &[];
		}

		match self.flow {
			RoundFlowState::WaitingToStart
				| RoundFlowState::Ongoing { .. }
				| RoundFlowState::Success =>
			{
				&self.participation.inputs
			},
			RoundFlowState::Failed { .. } => {
				// inputs already unlocked
				&[]
			},
		}
	}
}

/// The state of the process flow of a round
///
/// This tracks the progress of the interactive part of the round, from
/// waiting to start until finishing either succesfully or with a failure.
pub enum RoundFlowState {
	WaitingToStart,
	Ongoing {
		round_seq: RoundSeq,
		attempt_seq: usize,
		state: AttemptState,
	},
	Success,
	Failed {
		error: String,
	},
}

/// The state of a single round attempt
///
/// For each attempt that we participate in, we keep the state of our concrete
/// participation.
pub enum AttemptState {
	AwaitingAttempt,
	AwaitingUnsignedVtxoTree {
		cosign_keys: Vec<Keypair>,
		secret_nonces: Vec<Vec<DangerousSecretNonce>>,
	},
	AwaitingRoundProposal {
		unsigned_round_tx: Transaction,
		vtxos_spec: VtxoTreeSpec,
	},
	AwaitingFinishedRound {
		unsigned_round_tx: Transaction,
		new_vtxos: Vec<Vtxo>,
	},
}

impl AttemptState {
	/// The state kind represented as a string
	fn kind(&self) -> &'static str {
		match self {
			Self::AwaitingAttempt => "AwaitingAttempt",
			Self::AwaitingUnsignedVtxoTree { .. } => "AwaitingUnsignedVtxoTree",
			Self::AwaitingRoundProposal { .. } => "AwaitingRoundProposal",
			Self::AwaitingFinishedRound { .. } => "AwaitingFinishedRound",
		}
	}
}

/// Result from trying to progress an ongoing round attempt
enum AttemptProgressResult {
	Finished {
		signed_round_tx: Transaction,
		vtxos: Vec<Vtxo>,
	},
	Failed(anyhow::Error),
	/// When the state changes, this variant is returned
	///
	/// If during the processing, we have signed any forfeit txs and tried
	/// sending them to the server, the [UnconfirmedRound] instance is returned
	/// so that it can be stored in the state.
	Updated {
		new_state: AttemptState,
		new_unconfirmed_round: Option<UnconfirmedRound>,
	},
	NotUpdated,
}

/// Participate in the new round attempt by submitting our round participation
async fn start_attempt(
	wallet: &Wallet,
	participation: &RoundParticipation,
	event: &RoundAttempt,
) -> anyhow::Result<AttemptState> {
	let mut srv = wallet.require_server().context("server not available")?;

	// Assign cosign pubkeys to the payment requests.
	let cosign_keys = iter::repeat_with(|| Keypair::new(&SECP, &mut rand::thread_rng()))
		.take(participation.outputs.len())
		.collect::<Vec<_>>();
	let vtxo_reqs = participation.outputs.iter().zip(cosign_keys.iter()).map(|(p, ck)| {
		SignedVtxoRequest { vtxo: p.clone(), cosign_pubkey: Some(ck.public_key()) }
	}).collect::<Vec<_>>();

	// Prepare round participation info.
	// For each of our requested vtxo output, we need a set of public and secret nonces.
	let cosign_nonces = cosign_keys.iter()
		.map(|key| {
			let mut secs = Vec::with_capacity(srv.info.nb_round_nonces);
			let mut pubs = Vec::with_capacity(srv.info.nb_round_nonces);
			for _ in 0..srv.info.nb_round_nonces {
				let (s, p) = musig::nonce_pair(key);
				secs.push(s);
				pubs.push(p);
			}
			(secs, pubs)
		})
		.take(vtxo_reqs.len())
		.collect::<Vec<(Vec<SecretNonce>, Vec<PublicNonce>)>>();

	// The round has now started. We can submit our payment.
	debug!("Submitting payment request with {} inputs, {} vtxo outputs and {} offboard outputs",
		participation.inputs.len(), vtxo_reqs.len(), participation.offboards.len(),
	);

	srv.client.submit_payment(protos::SubmitPaymentRequest {
		input_vtxos: participation.inputs.iter().map(|vtxo| {
			let keypair = wallet.get_vtxo_key(&vtxo)
				.expect("owned vtxo key should be in database");

			protos::InputVtxo {
				vtxo_id: vtxo.id().to_bytes().to_vec(),
				ownership_proof: {
					let sig = event.challenge.sign_with(
						vtxo.id(), &vtxo_reqs, &participation.offboards, keypair,
					);
					sig.serialize().to_vec()
				},
			}
		}).collect(),
		vtxo_requests: vtxo_reqs.iter().zip(cosign_nonces.iter()).map(|(r, n)| {
			protos::SignedVtxoRequest {
				vtxo: Some(protos::VtxoRequest {
					amount: r.vtxo.amount.to_sat(),
					policy: r.vtxo.policy.serialize(),
				}),
				cosign_pubkey: r.cosign_pubkey.expect("just set").serialize().to_vec(),
				public_nonces: n.1.iter().map(|n| n.serialize().to_vec()).collect(),
			}
		}).collect(),
		offboard_requests: participation.offboards.iter().map(|r| {
			protos::OffboardRequest {
				amount: r.amount.to_sat(),
				offboard_spk: r.script_pubkey.to_bytes(),
			}
		}).collect(),
	}).await.context("Ark server refused our payment submission")?;

	Ok(AttemptState::AwaitingUnsignedVtxoTree {
		cosign_keys: cosign_keys,
		secret_nonces: cosign_nonces.into_iter()
			.map(|(sec, _pub)| sec.into_iter().map(DangerousSecretNonce::new).collect())
			.collect(),
	})
}

async fn progress_attempt(
	state: &AttemptState,
	wallet: &Wallet,
	part: &RoundParticipation,
	event: &RoundEvent,
) -> AttemptProgressResult {
	// we will match only the states and messages required to make progress,
	// all else we ignore, except an unexpected finish

	match (state, event) {

		(
			AttemptState::AwaitingUnsignedVtxoTree { cosign_keys, secret_nonces },
			RoundEvent::VtxoProposal(e),
		) => {
			match sign_vtxo_tree(
				wallet, part, &cosign_keys, &secret_nonces, &e.unsigned_round_tx, &e.vtxos_spec, &e.cosign_agg_nonces,
			).await {
				Ok(()) => {
					AttemptProgressResult::Updated {
						new_state: AttemptState::AwaitingRoundProposal {
							unsigned_round_tx: e.unsigned_round_tx.clone(),
							vtxos_spec: e.vtxos_spec.clone(),
						},
						new_unconfirmed_round: None,
					}
				},
				Err(e) => AttemptProgressResult::Failed(e),
			}
		},

		(
			AttemptState::AwaitingRoundProposal { unsigned_round_tx, vtxos_spec },
			RoundEvent::RoundProposal(e),
		) => {
			match sign_forfeits(
				wallet, part, unsigned_round_tx, vtxos_spec, &e.cosign_sigs, &e.forfeit_nonces, e.connector_pubkey,
			).await {
				Ok((new_vtxos, forfeit_sigs)) => {
					let round = UnconfirmedRound::new(unsigned_round_tx.clone(), new_vtxos.clone());
					match submit_forfeit_sigs(wallet, forfeit_sigs).await {
						Ok(()) => AttemptProgressResult::Updated {
							new_state: AttemptState::AwaitingFinishedRound {
								unsigned_round_tx: unsigned_round_tx.clone(),
								new_vtxos: new_vtxos,
							},
							new_unconfirmed_round: Some(round),
						},
						Err(e) => {
							warn!("Error sending forfeit sigs to server: {:#}", e);
							AttemptProgressResult::Updated {
								new_state: AttemptState::AwaitingAttempt,
								new_unconfirmed_round: Some(round),
							}
						},
					}
				},
				Err(e) => AttemptProgressResult::Failed(e),
			}
		},

		(
			AttemptState::AwaitingFinishedRound { unsigned_round_tx, new_vtxos },
			RoundEvent::Finished(RoundFinished { signed_round_tx, .. }),
		) => {
			if unsigned_round_tx.compute_txid() != signed_round_tx.compute_txid() {
				return AttemptProgressResult::Failed(anyhow!(
					"signed funding tx ({}) doesn't match tx received before ({})",
					signed_round_tx.compute_txid(), unsigned_round_tx.compute_txid(),
				));
			}

			AttemptProgressResult::Finished {
				signed_round_tx: signed_round_tx.clone(),
				vtxos: new_vtxos.clone(),
			}
		},

		// unexpected finish
		(state, RoundEvent::Finished(RoundFinished { .. })) => {
			AttemptProgressResult::Failed(anyhow!(
				"unexpectedly received a finished round while we were in state {}",
				state.kind(),
			))
		},

		(state, _) => {
			trace!("Ignoring round event {} in state {}", event.kind(), state.kind());
			AttemptProgressResult::NotUpdated
		},
	}
}

async fn sign_vtxo_tree(
	wallet: &Wallet,
	participation: &RoundParticipation,
	cosign_keys: &[Keypair],
	secret_nonces: &[impl AsRef<[DangerousSecretNonce]>],
	unsigned_round_tx: &Transaction,
	vtxo_tree: &VtxoTreeSpec,
	cosign_agg_nonces: &[musig::AggregatedNonce],
) -> anyhow::Result<()> {
	let srv = wallet.require_server().context("server not available")?;

	if unsigned_round_tx.output.len() < MIN_ROUND_TX_OUTPUTS {
		bail!("server sent round tx with less than 2 outputs: {}",
			serialize_hex(&unsigned_round_tx),
		);
	}

	let vtxos_utxo = OutPoint::new(unsigned_round_tx.compute_txid(), ROUND_TX_VTXO_TREE_VOUT);

	let my_vtxos = participation.outputs.iter().zip(cosign_keys.iter())
		.map(|(r, k)| SignedVtxoRequest {
			vtxo: r.clone(),
			cosign_pubkey: Some(k.public_key()),
		})
		.collect::<Vec<_>>();

	// Check that the proposal contains our inputs.
	{
		let mut my_vtxos = participation.outputs.iter().collect::<Vec<_>>();
		for vtxo_req in vtxo_tree.iter_vtxos() {
			if let Some(i) = my_vtxos.iter().position(|v| {
				v.policy == vtxo_req.vtxo.policy && v.amount == vtxo_req.vtxo.amount
			}) {
				my_vtxos.swap_remove(i);
			}
		}
		if !my_vtxos.is_empty() {
			bail!("server didn't include all of our vtxos, missing: {:?}", my_vtxos);
		}

		let mut my_offbs = participation.offboards.to_vec();
		for offb in unsigned_round_tx.output.iter().skip(2) {
			if let Some(i) = my_offbs.iter().position(|o| o.to_txout() == *offb) {
				my_offbs.swap_remove(i);
			}
		}
		if !my_offbs.is_empty() {
			bail!("server didn't include all of our offboards, missing: {:?}", my_offbs);
		}
	}

	// Make vtxo signatures from top to bottom, just like sighashes are returned.
	let unsigned_vtxos = vtxo_tree.clone().into_unsigned_tree(vtxos_utxo);
	let iter = my_vtxos.iter().zip(cosign_keys).zip(secret_nonces);
	let _ = try_join_all(iter.map(|((req, key), sec)| async {
		let leaf_idx = unsigned_vtxos.spec.leaf_idx_of(req).expect("req included");
		let secret_nonces = sec.as_ref().iter().map(|s| s.to_sec_nonce()).collect();
		let part_sigs = unsigned_vtxos.cosign_branch(
			&cosign_agg_nonces, leaf_idx, key, secret_nonces,
		).context("failed to cosign branch: our request not part of tree")?;

		info!("Sending {} partial vtxo cosign signatures for pk {}",
			part_sigs.len(), key.public_key(),
		);

		let _ = srv.clone().client.provide_vtxo_signatures(protos::VtxoSignaturesRequest {
			pubkey: key.public_key().serialize().to_vec(),
			signatures: part_sigs.iter().map(|s| s.serialize().to_vec()).collect(),
		}).await.context("error sending vtxo signatures")?;
		Result::<(), anyhow::Error>::Ok(())
	})).await.context("error sending VTXO signatures")?;

	Ok(())
}

/// Sign the forfeit signatures but doesn't submit them yet
async fn sign_forfeits(
	wallet: &Wallet,
	participation: &RoundParticipation,
	unsigned_round_tx: &Transaction,
	vtxo_tree: &VtxoTreeSpec,
	vtxo_cosign_sigs: &[schnorr::Signature],
	forfeit_nonces: &HashMap<VtxoId, Vec<musig::PublicNonce>>,
	connector_pubkey: PublicKey,
) -> anyhow::Result<(Vec<Vtxo>, HashMap<VtxoId, Vec<(musig::PublicNonce, musig::PartialSignature)>>)> {
	let srv = wallet.require_server().context("server not available")?;

	let round_txid = unsigned_round_tx.compute_txid();
	let vtxos_utxo = OutPoint::new(round_txid, ROUND_TX_VTXO_TREE_VOUT);
	let vtxo_tree = vtxo_tree.clone().into_unsigned_tree(vtxos_utxo);

	// Validate the vtxo tree and cosign signatures.
	if vtxo_tree.verify_cosign_sigs(&vtxo_cosign_sigs).is_err() {
		// bad server!
		bail!("Received incorrect vtxo cosign signatures from server");
	}

	let signed_vtxos = vtxo_tree.into_signed_tree(vtxo_cosign_sigs.to_vec());

	// Check that the connector key is correct.
	let conn_txout = unsigned_round_tx.output.get(ROUND_TX_CONNECTOR_VOUT as usize)
		.expect("checked before");
	let expected_conn_txout = ConnectorChain::output(forfeit_nonces.len(), connector_pubkey);
	if *conn_txout != expected_conn_txout {
		bail!("round tx from server has unexpected connector output: {:?} (expected {:?})",
			conn_txout, expected_conn_txout,
		);
	}

	let conns_utxo = OutPoint::new(round_txid, ROUND_TX_CONNECTOR_VOUT);

	// Make forfeit signatures.
	let connectors = ConnectorChain::new(
		forfeit_nonces.values().next().unwrap().len(),
		conns_utxo,
		connector_pubkey,
	);

	let forfeit_sigs = participation.inputs.iter().map(|vtxo| {
		let keypair = wallet.get_vtxo_key(&vtxo)?;

		let sigs = connectors.connectors().enumerate().map(|(i, (conn, _))| {
			let (sighash, _tx) = ark::forfeit::forfeit_sighash_exit(
				vtxo, conn, connector_pubkey,
			);
			let srv_nonce = forfeit_nonces.get(&vtxo.id())
				.with_context(|| format!("missing srv forfeit nonce for {}", vtxo.id()))?
				.get(i)
				.context("srv didn't provide enough forfeit nonces")?;

			let (nonce, sig) = musig::deterministic_partial_sign(
				&keypair,
				[srv.info.server_pubkey],
				&[srv_nonce],
				sighash.to_byte_array(),
				Some(vtxo.output_taproot().tap_tweak().to_byte_array()),
			);
			Ok((nonce, sig))
		}).collect::<anyhow::Result<Vec<_>>>()?;

		Ok((vtxo.id(), sigs))
	})
		.collect::<anyhow::Result<HashMap<_, _>>>()
		.context("error signing forfeits")?;

	let signed_vtxos = signed_vtxos.into_cached_tree();

	let mut expected_vtxos = participation.outputs.iter().collect::<Vec<_>>();
	let total_nb_expected_vtxos = expected_vtxos.len();

	let mut new_vtxos = vec![];
	for (idx, req) in signed_vtxos.spec.spec.vtxos.iter().enumerate() {
		if let Some(expected_idx) = expected_vtxos.iter().position(|r| **r == req.vtxo) {
			let vtxo = signed_vtxos.build_vtxo(idx).expect("correct leaf idx");

			// validate the received vtxos
			// This is more like a sanity check since we crafted them ourselves.
			vtxo.validate(&unsigned_round_tx)
				.context("constructed invalid vtxo from tree")?;

			info!("New VTXO from round: {} ({}, {})",
				vtxo.id(), vtxo.amount(), vtxo.policy_type(),
			);

			new_vtxos.push(vtxo);
			expected_vtxos.swap_remove(expected_idx);
		}
	}

	if !expected_vtxos.is_empty() {
		if expected_vtxos.len() == total_nb_expected_vtxos {
			// we must have done something wrong
			bail!("None of our VTXOs were present in round!");
		} else {
			bail!("Server included some of our VTXOs but not all: {} missing: {:?}",
				expected_vtxos.len(), expected_vtxos,
			);
		}
	}
	Ok((new_vtxos, forfeit_sigs))
}

async fn submit_forfeit_sigs(
	wallet: &Wallet,
	forfeit_sigs: HashMap<VtxoId, Vec<(musig::PublicNonce, musig::PartialSignature)>>,
) -> anyhow::Result<()> {
	let mut srv = wallet.require_server().context("server not available")?;

	debug!("Sending {} sets of forfeit signatures for our inputs", forfeit_sigs.len());
	srv.client.provide_forfeit_signatures(protos::ForfeitSignaturesRequest {
		signatures: forfeit_sigs.into_iter().map(|(id, sigs)| {
			protos::ForfeitSignatures {
				input_vtxo_id: id.to_bytes().to_vec(),
				pub_nonces: sigs.iter().map(|s| s.0.serialize().to_vec()).collect(),
				signatures: sigs.iter().map(|s| s.1.serialize().to_vec()).collect(),
			}
		}).collect(),
	}).await.context("failed to submit forfeit signatures")?;

	Ok(())
}

//TODO(stevenroose) should be made idempotent
async fn persist_round_success(
	wallet: &Wallet,
	participation: &RoundParticipation,
	movement_id: Option<MovementId>,
	new_vtxos: &[Vtxo],
	signed_round_tx: &Transaction,
) -> anyhow::Result<()> {
	debug!("Persisting newly finished round. {} new vtxos, {} offboards, movement ID {:?}",
		new_vtxos.len(), participation.offboards.len(), movement_id,
	);

	let store_result = wallet.store_spendable_vtxos(new_vtxos);
	let spent_result = wallet.mark_vtxos_as_spent(&participation.inputs);
	let update_result = if let Some(movement_id) = movement_id {
		wallet.movements.update_movement(movement_id, MovementUpdate::new()
			.produced_vtxos(new_vtxos)
			.metadata([("funding_txid".into(), serde_json::to_value(signed_round_tx.compute_txid())?)])
		).await
	} else {
		Ok(())
	};
	match (store_result, spent_result, update_result) {
		(Ok(()), Ok(()), Ok(())) => Ok(()),
		(Err(e), _, _) => Err(e),
		(_, Err(e), _) => Err(e),
		(_, _, Err(e)) => Err(anyhow!(
			"Failed to update movement after round success: {:#}", e
		)),
	}
}

//TODO(stevenroose) should be made idempotent
async fn persist_round_failure(
	wallet: &Wallet,
	participation: &RoundParticipation,
	movement_id: Option<MovementId>,
) -> anyhow::Result<()> {
	debug!("Attempting to persist the failure of a round with the movement ID {:?}", movement_id);
	let unlock_result = wallet.unlock_vtxos(&participation.inputs);
	let finish_result = if let Some(movement_id) = movement_id {
		wallet.movements.finish_movement(movement_id, MovementStatus::Failed).await
	} else {
		Ok(())
	};
	if let Err(e) = &finish_result {
		error!("Failed to mark movement as failed: {:#}", e);
	}
	match (unlock_result, finish_result) {
		(Ok(()), Ok(())) => Ok(()),
		(Err(e), _) => Err(e),
		(_, Err(e)) => Err(anyhow!("Failed to mark movement as failed: {:#}", e)),
	}
}

async fn update_funding_txid(
	funding_txid: Txid,
	movement_id: MovementId,
	wallet: &Wallet,
) -> anyhow::Result<()> {
	wallet.movements.update_movement(
		movement_id,
		MovementUpdate::new()
			.metadata([("funding_txid".into(), serde_json::to_value(&funding_txid)?)])
	).await.context("Unable to update funding txid of round")
}

/// Track any round for which we signed forfeit txs
///
/// Any round for which we signed forfeit txs will be tracked in an object like this.
/// Both when the round finished successfully or not. The funding tx in this object
/// can thus be unsigned.
#[derive(Debug)]
pub struct UnconfirmedRound {
	/// This round tx is not necessarily signed
	pub(crate) funding_tx: Transaction,
	pub(crate) new_vtxos: Vec<Vtxo>,

	// Some information for double spend detection

	/// A txid that double spends each input of the round tx
	pub(crate) double_spenders: Vec<Option<Txid>>,

	/// The time at which we first noticed we got double spent
	///
	/// We use this when the user is using bitcoind because in bitcoind it's
	/// impossible to detect which txs spend a UTXO. So in order to detect
	/// whether our tx is double spend, we will just abort the round
	/// if we are out of the mempool for double the expected time to be
	/// deeply double spent.
	pub(crate) first_double_spent_at: Option<SystemTime>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum UnconfirmedRoundStatus {
	/// The round's funding tx confirmed deeply
	Confirmed,
	/// The round's funding tx was double spent deeply
	DoubleSpent {
		/// We can't always know the double spender
		double_spender: Option<Txid>,
	},
	Unconfirmed,
}

impl UnconfirmedRound {
	/// Create a new instance of the [AwaitingConfirmation] state for
	/// a round that was synced from the server, but we have lost context for.
	pub fn new(
		funding_tx: Transaction,
		new_vtxos: Vec<Vtxo>,
	) -> Self {
		UnconfirmedRound {
			new_vtxos: new_vtxos,
			double_spenders: vec![None; funding_tx.input.len()],
			funding_tx: funding_tx,
			first_double_spent_at: None,
		}
	}

	pub fn funding_txid(&self) -> Txid {
		self.funding_tx.compute_txid()
	}

	/// Whether we have a signed tx
	fn is_tx_signed(&self) -> bool {
		!self.funding_tx.input.iter().any(|i| i.witness.is_empty())
	}

	/// Check if our version of the round tx is signed and if not try replace it
	async fn maybe_update_tx(&mut self, txid: Txid, chain: &ChainSource) {
		if !self.is_tx_signed() {
			if let Ok(Some(tx)) = chain.get_tx(&txid).await {
				assert_eq!(txid, tx.compute_txid());
				debug!("Retrieved signed version of round tx {}", txid);
				self.funding_tx = tx;
			}
		}
	}

	/// Check if the round tx was double spent and if so
	/// returns a UnconfirmedRoundStatus::DoubleSpent.
	async fn check_if_double_spent(
		&mut self,
		wallet: &Wallet,
	) -> anyhow::Result<Option<UnconfirmedRoundStatus>> {

		let round_txid = self.funding_txid();
		match wallet.chain.inner() {
			ChainSourceClient::Esplora(c) => {
				let mut confirmed = None;
				for (idx, input) in self.funding_tx.input.iter().enumerate() {
					if let Some(txid) = self.double_spenders[idx] {
						match wallet.chain.tx_status(txid).await? {
							TxStatus::Confirmed(b) => {
								confirmed = cmp::max(confirmed, Some((b.height, txid)));
								continue;
							},
							TxStatus::Mempool => continue,
							TxStatus::NotFound => self.double_spenders[idx] = None,
						}
					}

					let info = c.get_output_status(
						&input.previous_output.txid, input.previous_output.vout as u64,
					).await?;
					match info {
						None => warn!("Input {} of round tx {} not found by chain source",
							input.previous_output, round_txid,
						),
						Some(info) => {
							if !info.spent || info.txid == Some(round_txid) {
								continue;
							}

							let txid = info.txid.context("expected txid")?;
							self.double_spenders[idx] = Some(txid);
							let status = info.status.context("expected status")?;
							if let Some(height) = status.block_height {
								// NB we rely on Ord impl that sorts tuples first by first item
								confirmed = cmp::max(confirmed, Some((height, txid)));
							}
						},
					}
				}

				if let Some((height, txid)) = confirmed {
					let confirmations = wallet.chain.tip().await? - (height - 1);
					if confirmations >= wallet.config.round_tx_required_confirmations {
						return Ok(Some(UnconfirmedRoundStatus::DoubleSpent {
							double_spender: Some(txid),
						}));
					}
					debug!("Round tx {} double spent by tx {} with {} confirmations",
						round_txid, txid, confirmations,
					);
				}

				Ok(None)
			},
			ChainSourceClient::Bitcoind(b) => {
				// check whether our round tx is double spent
				let mut doublespent = false;
				for inp in &self.funding_tx.input {
					let OutPoint { txid, vout } = inp.previous_output;
					if b.get_tx_out(&txid, vout, Some(false))?.is_none() {
						doublespent = true;
						break;
					}
				}

				if doublespent {
					let now = SystemTime::now();
					let since = self.first_double_spent_at.get_or_insert(now);
					let req_confs = wallet.config.round_tx_required_confirmations;
					//TODO(stevenroose) maybe also do 5 days?
					let req_time = 2 * req_confs * BLOCK_TIME;
					if let Ok(time) = now.duration_since(*since) && time > req_time {
						return Ok(Some(UnconfirmedRoundStatus::DoubleSpent {
							double_spender: None,
						}));
					}
				} else {
					self.first_double_spent_at.take();
				}

				Ok(None)
			},
		}
	}

	// NB we must never restart again from here
	pub(crate) async fn sync(
		&mut self,
		wallet: &Wallet,
	) -> anyhow::Result<UnconfirmedRoundStatus> {
		let txid = self.funding_txid();
		match wallet.chain.tx_status(txid).await? {
			TxStatus::NotFound => {
				debug!("Round funding tx {} no longer found in mempool", txid);
				if let Some(res) = self.check_if_double_spent(wallet).await? {
					return Ok(res);
				}
				if self.is_tx_signed() {
					// try to broadcast
					let _ = wallet.chain.broadcast_tx(&self.funding_tx).await;
				}
				Ok(UnconfirmedRoundStatus::Unconfirmed)
			},
			TxStatus::Mempool => {
				debug!("Round funding tx {} still in mempool, waiting for confirmations", txid);
				self.first_double_spent_at = None;
				self.maybe_update_tx(txid, &wallet.chain).await;
				Ok(UnconfirmedRoundStatus::Unconfirmed)
			},
			TxStatus::Confirmed(block) => {
				self.first_double_spent_at = None;
				self.maybe_update_tx(txid, &wallet.chain).await;
				let confirmations = {
					let tip = wallet.chain.tip().await?;
					tip - block.height + 1
				};
				debug!("Round funding tx {} has {} confirmations", txid, confirmations);

				if confirmations >= wallet.config.round_tx_required_confirmations {
					//TODO(stevenroose) ensure vtxos are created
					// we currently make the movement when the round finishes, and
					// we currently don't have a way to not accidentally do this twice.
					// Should probably have some idempotent VTXO state/movement API
					// so that here we can call this again in the case of:
					// - initial call after finished round failed
					// - we recovered from a round we didn't get finish message from
					// - we synced a round from when we were offline
					Ok(UnconfirmedRoundStatus::Confirmed)
				} else {
					Ok(UnconfirmedRoundStatus::Unconfirmed)
				}
			},
		}
	}
}


impl Wallet {
	/// Start a new round participation
	///
	/// This function will store the state in the db and mark the VTXOs as locked.
	pub async fn join_next_round(
		&self,
		participation: RoundParticipation,
		movement_kind: Option<RoundMovement>,
	) -> anyhow::Result<StoredRoundState> {
		// verify if our participation makes sense
		if let Some(payreq) = participation.outputs.iter().find(|p| p.amount < P2TR_DUST) {
			bail!("VTXO amount must be at least {}, requested {}", P2TR_DUST, payreq.amount);
		}
		if let Some(offb) = participation.offboards.iter().find(|o| o.amount < P2TR_DUST) {
			bail!("Offboard amount must be at least {}, requested {}", P2TR_DUST, offb.amount);
		}

		let movement_id = if let Some(kind) = movement_kind {
			let movement_id = self.movements.new_movement(
				self.subsystem_ids[&BarkSubsystem::Round], kind.to_string(),
			).await?;
			let update = participation.to_movement_update(self.chain.network())?;
			self.movements.update_movement(movement_id, update).await?;
			Some(movement_id)
		} else {
			None
		};
		let state = RoundState::new(participation, movement_id);

		let id = self.db.store_round_state_lock_vtxos(&state)?;
		Ok(StoredRoundState { id, state })
	}

	/// Get all pending round states
	pub fn pending_round_states(&self) -> anyhow::Result<Vec<StoredRoundState>> {
		self.db.load_round_states()
	}

	/// Sync pending rounds that have finished but are waiting for confirmations
	pub async fn sync_pending_rounds(&self) -> anyhow::Result<()> {
		let states = self.db.load_round_states()?;
		if !states.is_empty() {
			debug!("Syncing {} pending round states...", states.len());

			tokio_stream::iter(states).for_each_concurrent(10, |mut state| async move {
				// not processing events here
				if !state.state.round_has_finished() {
					return;
				}

				match state.state.sync(self).await {
					Ok(RoundStatus::Confirmed { funding_txid }) => {
						info!("Round confirmed. Funding tx {}", funding_txid);
						if let Err(e) = self.db.remove_round_state(&state) {
							warn!("Error removing finished round state from db: {:#}", e);
						}
					},
					Ok(RoundStatus::Unconfirmed { funding_txid }) => {
						info!("Waiting for confirmations for round funding tx {}", funding_txid);
						if let Err(e) = self.db.update_round_state(&state) {
							warn!("Error updating pending round state in db: {:#}", e);
						}
					},
					Ok(RoundStatus::Pending { unsigned_funding_txids: txs }) => {
						info!("Round still pending, potential funding txs: {:?}", txs);
						if let Err(e) = self.db.update_round_state(&state) {
							warn!("Error updating pending round state in db: {:#}", e);
						}
					},
					Ok(RoundStatus::Failed { error }) => {
						error!("Round failed: {}", error);
						if let Err(e) = self.db.remove_round_state(&state) {
							warn!("Error removing finished round state from db: {:#}", e);
						}
					},
					Err(e) => {
						warn!("Error syncing round: {:#}", e);
						return;
					},
				}
			}).await;
		}

		// also sync recovered states if we have any
		let recovered = self.db.load_recovered_rounds()?;
		if !recovered.is_empty() {
			debug!("Syncing {} recovered past rounds...", recovered.len());

			tokio_stream::iter(recovered).for_each_concurrent(10, |mut state| async move {
				match state.sync(self).await {
					Ok(UnconfirmedRoundStatus::Confirmed) => {
						info!("Recovered old round with funding txid {} confirmed",
							state.funding_txid(),
						);
						if let Err(e) = self.db.remove_recovered_round(state.funding_txid()) {
							warn!("Error removing finished recovered round from db: {:#}", e);
						}
					},
					Ok(UnconfirmedRoundStatus::DoubleSpent { double_spender }) => {
						debug!("Old recovered round {} invalidated because double spent by {:?}",
							state.funding_txid(), double_spender,
						);
						if let Err(e) = self.db.remove_recovered_round(state.funding_txid()) {
							warn!("Error invalidated recovered round from db: {:#}", e);
						}
					},
					Ok(UnconfirmedRoundStatus::Unconfirmed) => {},
					Err(e) => debug!("Error trying to progress recovered past round: {:#}", e),
				}
			}).await;
		}

		Ok(())
	}

	/// Fetch last round event from server
	async fn get_last_round_event(&self) -> anyhow::Result<RoundEvent> {
		let mut srv = self.require_server()?;
		let e = srv.client.last_round_event(protos::Empty {}).await?.into_inner();
		Ok(RoundEvent::try_from(e).context("invalid event format from server")?)
	}

	/// Try to make incrimental progress on all pending round states
	///
	/// If the `last_round_event` argument is not provided, it will be fetched
	/// from the server.
	pub async fn progress_ongoing_rounds(
		&self,
		last_round_event: Option<&RoundEvent>,
	) -> anyhow::Result<()> {
		let states = self.db.load_round_states()?;

		// so we can fill an owned one in case we lazily fetch one
		let mut last_round_event = last_round_event.map(|e| Cow::Borrowed(e));

		// NB we want to try make progress on all states,
		// so we shouldn't error/abort early
		for mut state in states {
			if !state.state.round_has_finished() {
				let event = match last_round_event {
					Some(ref e) => e,
					None => match self.get_last_round_event().await {
						Ok(e) => {
							last_round_event = Some(Cow::Owned(e));
							last_round_event.as_ref().unwrap()
						},
						Err(e) => {
							warn!("Couldn't make progress on an ongoing round: {:#}", e);
							continue;
						},
					},
				};

				let updated = state.state.process_event(self, event.as_ref()).await;
				if updated {
					self.db.update_round_state(&state)?;
				}
			}

			let status = state.state.sync(self).await?;
			if status.is_final() {
				info!("Round finished with result: {:?}", status);
				if let Err(e) = self.db.remove_round_state(&state) {
					warn!("Failed to remove finished round from db: {:#}", e);
				}
			}
		}

		Ok(())
	}

	pub async fn subscribe_round_events(&self)
		-> anyhow::Result<impl Stream<Item = anyhow::Result<RoundEvent>> + Unpin>
	{
		let mut srv = self.require_server()?;
		let events = srv.client.subscribe_rounds(protos::Empty {}).await?
			.into_inner().map(|m| {
				let m = m.context("received error on event stream")?;
				let e = RoundEvent::try_from(m.clone())
					.with_context(|| format!("error converting rpc round event: {:?}", m))?;
				trace!("Received round event: {}", e);
				Ok::<_, anyhow::Error>(e)
			});
		Ok(events)
	}

	/// Participate in a round
	///
	/// This function will start a new round participation and block until
	/// the round is finished.
	/// After this method returns the round state will be kept active until
	/// the round tx fully confirms.
	pub(crate) async fn participate_round(
		&self,
		participation: RoundParticipation,
		movement_kind: Option<RoundMovement>,
	) -> anyhow::Result<RoundStatus> {
		let mut state = self.join_next_round(participation, movement_kind).await?;

		info!("Waiting for a round start...");
		let mut events = self.subscribe_round_events().await?;

		loop {
			if state.state.round_has_finished() {
				return Ok(state.state.sync(self).await?);
			}

			let event = events.next().await
				.context("events stream broke")?
				.context("error on event stream")?;
			if state.state.process_event(self, &event).await {
				self.db.update_round_state(&state)?;
			}
		}
	}

	/// Look for past rounds that might contain some of our VTXOs
	///
	/// Afterwards, call [Wallet::sync_pending_rounds] to make progress on these.
	pub async fn start_sync_past_rounds(&self) -> anyhow::Result<()> {
		let mut srv = self.require_server()?;

		let fresh_rounds = srv.client.get_fresh_rounds(protos::FreshRoundsRequest {
			last_round_txid: None,
		}).await?.into_inner().txids.into_iter()
			.map(|txid| RoundId::from_slice(&txid))
			.collect::<Result<Vec<_>, _>>()?;

		if fresh_rounds.is_empty() {
			debug!("No new rounds to sync");
			return Ok(());
		}

		debug!("Received {} new rounds from ark", fresh_rounds.len());

		let last_pk_index = self.db.get_last_vtxo_key_index()?.unwrap_or_default();
		let pubkeys = (0..=last_pk_index).map(|idx| {
			self.vtxo_seed.derive_keypair(idx).public_key()
		}).collect::<HashSet<_>>();

		let pending_states = Arc::new(self.db.load_recovered_rounds()?.into_iter()
			.map(|s| (s.funding_txid(), s))
			.collect::<HashMap<_, _>>());

		let results = tokio_stream::iter(fresh_rounds).map(|round_id| {
			let pubkeys = pubkeys.clone();
			let mut srv = srv.clone();
			let pending_states = pending_states.clone();

			async move {
				//TODO(stevenroose) detect if we already are aware
				if pending_states.contains_key(&round_id.as_round_txid()) {
					debug!("Skipping round {} because it already exists", round_id);
					return Ok::<_, anyhow::Error>(());
				}

				let req = protos::RoundId {
					txid: round_id.as_round_txid().to_byte_array().to_vec(),
				};
				let round = srv.client.get_round(req).await?.into_inner();

				let tree = SignedVtxoTreeSpec::deserialize(&round.signed_vtxos)
					.context("invalid signed vtxo tree from srv")?
					.into_cached_tree();

				let mut reqs = Vec::new();
				let mut vtxos = vec![];
				for (idx, dest) in tree.spec.spec.vtxos.iter().enumerate() {
					if pubkeys.contains(&dest.vtxo.policy.user_pubkey()) {
						let vtxo = tree.build_vtxo(idx).expect("correct leaf idx");

						if self.db.get_wallet_vtxo(vtxo.id())?.is_none() {
							debug!("Built new vtxo {} with value {}", vtxo.id(), vtxo.amount());
							reqs.push(dest.vtxo.clone());
							vtxos.push(vtxo);
						} else {
							debug!("Not adding vtxo {} because it already exists", vtxo.id());
						}
					}
				}

				let round_tx = deserialize::<Transaction>(&round.funding_tx)?;

				let state = UnconfirmedRound::new(round_tx, vtxos);
				self.db.store_recovered_round(&state)?;

				Ok(())
			}
		})
			.buffer_unordered(10)
			.collect::<Vec<_>>()
			.await;

		for result in results {
			if let Err(e) = result {
				return Err(e).context("failed to sync round");
			}
		}

		Ok(())
	}
}

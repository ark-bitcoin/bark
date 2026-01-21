//!
//! Round State Machine
//!

use std::iter;
use std::borrow::Cow;
use std::convert::Infallible;

use anyhow::Context;
use ark::vtxo::VtxoValidationError;
use bdk_esplora::esplora_client::Amount;
use bip39::rand;
use bitcoin::{OutPoint, SignedAmount, Transaction, Txid};
use bitcoin::consensus::encode::{deserialize, serialize_hex};
use bitcoin::hashes::Hash;
use bitcoin::hex::DisplayHex;
use bitcoin::key::Keypair;
use bitcoin::secp256k1::schnorr;
use futures::future::try_join_all;
use futures::{Stream, StreamExt};
use log::{debug, error, info, trace, warn};

use ark::{ProtocolEncoding, SignedVtxoRequest, Vtxo, VtxoRequest};
use ark::forfeit::{HashLockedForfeitBundle, HashLockedForfeitNonces};
use ark::musig::{self, DangerousSecretNonce, PublicNonce, SecretNonce};
use ark::rounds::{
	RoundAttempt, RoundEvent, RoundFinished, RoundSeq, MIN_ROUND_TX_OUTPUTS,
	ROUND_TX_VTXO_TREE_VOUT,
};
use ark::tree::signed::{LeafVtxoCosignContext, UnlockHash, VtxoTreeSpec};
use bitcoin_ext::TxStatus;
use server_rpc::{protos, ServerConnection, TryFromBytes};

use crate::{SECP, Wallet};
use crate::movement::{MovementId, MovementStatus};
use crate::movement::update::MovementUpdate;
use crate::persist::{RoundStateId, StoredRoundState};
use crate::subsystem::{RoundMovement, Subsystem};


/// The type string for the hArk leaf transition
const HARK_TRANSITION_KIND: &str = "hash-locked-cosigned";


/// Struct to communicate your specific participation for an Ark round.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoundParticipation {
	#[serde(with = "ark::encode::serde::vec")]
	pub inputs: Vec<Vtxo>,
	/// The output VTXOs that we request in the round,
	/// including change
	pub outputs: Vec<VtxoRequest>,
}

impl RoundParticipation {
	pub fn to_movement_update(&self) -> anyhow::Result<MovementUpdate> {
		let input_amount = self.inputs.iter().map(|i| i.amount()).sum::<Amount>();
		let output_amount = self.outputs.iter().map(|r| r.amount).sum::<Amount>();
		let fee = input_amount - output_amount;
		Ok(MovementUpdate::new()
			.consumed_vtxos(&self.inputs)
			.intended_balance(SignedAmount::ZERO)
			.effective_balance( - fee.to_signed()?)
			.fee(fee)
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
	/// Round didn't finish yet
	Pending,
	/// The round failed
	Failed {
		error: String,
	},
	/// User canceled the round
	Canceled,
}

impl RoundStatus {
	/// Whether this is the final state and it won't change anymore
	pub fn is_final(&self) -> bool {
		match self {
			Self::Confirmed { .. } => true,
			Self::Unconfirmed { .. } => false,
			Self::Pending => false,
			Self::Failed { .. } => true,
			Self::Canceled => true,
		}
	}

	/// Whether it looks like the round succeeded
	pub fn is_success(&self) -> bool {
		match self {
			Self::Confirmed { .. } => true,
			Self::Unconfirmed { .. } => true,
			Self::Pending => false,
			Self::Failed { .. } => false,
			Self::Canceled => false,
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
//
//TODO(stevenroose) move the id in here and have the state persist itself with the wallet
// to have better control. this way we can touch db before we sent forfeit sigs
pub struct RoundState {
	/// Round is fully done
	pub(crate) done: bool,

	/// Our participation in this round
	pub(crate) participation: RoundParticipation,

	/// The flow of the round in case it is still ongoing with the server
	pub(crate) flow: RoundFlowState,

	/// The new output vtxos of this round participation
	///
	/// After we finish the interactive part, we fill this with the uncompleted
	/// VTXOs which we then try to complete with the unlock preimage.
	pub(crate) new_vtxos: Vec<Vtxo>,

	/// Whether we sent our forfeit signatures to the server
	///
	/// If we did this and the server refused to reveal our new VTXOs,
	/// we will be forced to exit.
	//TODO(stevenroose) implement exit when this is true and we can't make progress
	// probably based on the input vtxos becoming close to expiry
	pub(crate) sent_forfeit_sigs: bool,

	/// The ID of the [Movement] associated with this round
	pub(crate) movement_id: Option<MovementId>,
}

impl RoundState {
	fn new_interactive(
		participation: RoundParticipation,
		movement_id: Option<MovementId>,
	) -> Self {
		Self {
			participation,
			movement_id,
			flow: RoundFlowState::InteractivePending,
			new_vtxos: Vec::new(),
			sent_forfeit_sigs: false,
			done: false,
		}
	}

	#[allow(unused)]
	fn new_non_interactive(
		participation: RoundParticipation,
		unlock_hash: UnlockHash,
		movement_id: Option<MovementId>,
	) -> Self {
		Self {
			participation,
			movement_id,
			flow: RoundFlowState::NonInteractivePending { unlock_hash },
			new_vtxos: Vec::new(),
			sent_forfeit_sigs: false,
			done: false,
		}
	}

	/// Our participation in this round
	pub fn participation(&self) -> &RoundParticipation {
		&self.participation
	}

	/// the unlock hash if already known
	pub fn unlock_hash(&self) -> Option<UnlockHash> {
		match self.flow {
			RoundFlowState::NonInteractivePending { unlock_hash } => Some(unlock_hash),
			RoundFlowState::InteractivePending => None,
			RoundFlowState::InteractiveOngoing { .. } => None,
			RoundFlowState::Failed { .. } => None,
			RoundFlowState::Canceled => None,
			RoundFlowState::Finished { unlock_hash, .. } => Some(unlock_hash),
		}
	}

	pub fn funding_tx(&self) -> Option<&Transaction> {
		match self.flow {
			RoundFlowState::NonInteractivePending { .. } => None,
			RoundFlowState::InteractivePending => None,
			RoundFlowState::InteractiveOngoing { .. } => None,
			RoundFlowState::Failed { .. } => None,
			RoundFlowState::Canceled => None,
			RoundFlowState::Finished { ref funding_tx, .. } => Some(funding_tx),
		}
	}

	/// Whether the interactive part of the round is still ongoing
	pub fn ongoing_participation(&self) -> bool {
		match self.flow {
			RoundFlowState::NonInteractivePending { .. } => false,
			RoundFlowState::InteractivePending => true,
			RoundFlowState::InteractiveOngoing { .. } => true,
			RoundFlowState::Failed { .. } => false,
			RoundFlowState::Canceled => false,
			RoundFlowState::Finished { .. } => false,
		}
	}

	/// Tries to cancel the round and returns whether it was succesfully canceled
	/// or if it was already canceled or failed
	pub async fn try_cancel(&mut self, wallet: &Wallet) -> anyhow::Result<bool> {
		let ret = match self.flow {
			RoundFlowState::NonInteractivePending { .. } => todo!("we have to cancel with server!"),
			RoundFlowState::Canceled => true,
			RoundFlowState::Failed { .. } => true,
			RoundFlowState::InteractivePending | RoundFlowState::InteractiveOngoing { .. } => {
				self.flow = RoundFlowState::Canceled;
				true
			},
			RoundFlowState::Finished { .. } => false,
		};
		if ret {
			persist_round_failure(wallet, &self.participation, self.movement_id).await
				.context("failed to persist round failure for cancelation")?;
		}
		Ok(ret)
	}

	async fn try_start_attempt(&mut self, wallet: &Wallet, attempt: &RoundAttempt) {
		match start_attempt(wallet, &self.participation, attempt).await {
			Ok(state) => {
				self.flow = RoundFlowState::InteractiveOngoing {
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
			RoundFlowState::InteractivePending => {
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
			RoundFlowState::InteractiveOngoing { round_seq, attempt_seq, ref mut state } => {
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

				return match progress_attempt(state, wallet, &self.participation, event).await {
					AttemptProgressResult::NotUpdated => false,
					AttemptProgressResult::Updated { new_state } => {
						*state = new_state;
						true
					},
					AttemptProgressResult::Failed(e) => {
						debug!("Round failed with error: {:#}", e);
						self.flow = RoundFlowState::Failed {
							error: format!("{:#}", e),
						};
						true
					},
					AttemptProgressResult::Finished { funding_tx, vtxos, unlock_hash } => {
						self.new_vtxos = vtxos;
						let funding_txid = funding_tx.compute_txid();
						self.flow = RoundFlowState::Finished { funding_tx, unlock_hash };
						if let Some(mid) = self.movement_id {
							if let Err(e) = update_funding_txid(wallet, mid, funding_txid).await {
								warn!("Error updating the round funding txid: {:#}", e);
							}
						}
						true
					},
				};
			},
			RoundFlowState::NonInteractivePending { .. }
				| RoundFlowState::Finished { .. }
				| RoundFlowState::Failed { .. }
				| RoundFlowState::Canceled => return false,
		};
	}

	/// Sync the round's status and return it
	///
	/// When success or failure is returned, the round state can be eliminated
	//TODO(stevenroose) make RoundState manage its own db record
	pub async fn sync(&mut self, wallet: &Wallet) -> anyhow::Result<RoundStatus> {
		match self.flow {
			RoundFlowState::Finished { ref funding_tx, .. } if self.done => {
				Ok(RoundStatus::Confirmed {
					funding_txid: funding_tx.compute_txid(),
				})
			},

			RoundFlowState::InteractivePending | RoundFlowState::InteractiveOngoing { .. } => {
				Ok(RoundStatus::Pending)
			},
			RoundFlowState::Failed { ref error } => {
				persist_round_failure(wallet, &self.participation, self.movement_id).await
					.context("failed to persist round failure")?;
				Ok(RoundStatus::Failed { error: error.clone() })
			},
			RoundFlowState::Canceled => {
				persist_round_failure(wallet, &self.participation, self.movement_id).await
					.context("failed to persist round failure")?;
				Ok(RoundStatus::Canceled)
			},

			RoundFlowState::NonInteractivePending { unlock_hash } => {
				match progress_non_interactive(wallet, &self.participation, unlock_hash).await {
					Ok(HarkProgressResult::RoundPending) => Ok(RoundStatus::Pending),
					Ok(HarkProgressResult::Ok { funding_tx, new_vtxos }) => {
						let funding_txid = funding_tx.compute_txid();
						self.new_vtxos = new_vtxos;
						self.flow = RoundFlowState::Finished {
							funding_tx: funding_tx.clone(),
							unlock_hash: unlock_hash,
						};

						persist_round_success(
							wallet,
							&self.participation,
							self.movement_id,
							&self.new_vtxos,
							&funding_tx,
						).await.context("failed to store successful round in DB!")?;

						self.done = true;

						Ok(RoundStatus::Confirmed { funding_txid })
					},
					Ok(HarkProgressResult::FundingTxUnconfirmed { funding_txid }) => {
						if let Some(mid) = self.movement_id {
							update_funding_txid(wallet, mid, funding_txid).await
								.context("failed to update funding txid in DB")?;
						}
						Ok(RoundStatus::Unconfirmed { funding_txid })
					},

					//TODO(stevenroose) should we mark as failed for these cases?

					Err(HarkForfeitError::Err(e)) => {
						//TODO(stevenroose) we failed here but we might actualy be able to
						// succeed if we retry. should we implement some kind of limited
						// retry after which we mark as failed?
						Err(e.context("error progressing non-interactive round"))
					},
					Err(HarkForfeitError::SentForfeits(e)) => {
						self.sent_forfeit_sigs = true;
						Err(e.context("error progressing non-interactive round \
							after sending forfeit tx signatures"))
					},
				}
			},
			// interactive part finished, but didn't forfeit yet
			RoundFlowState::Finished { ref funding_tx, unlock_hash } => {
				let funding_txid = funding_tx.compute_txid();
				let confirmed = check_funding_tx_confirmations(
					wallet, funding_txid, &funding_tx,
				).await.context("error checking funding tx confirmations")?;
				if !confirmed {
					trace!("Funding tx {} not yet deeply enough confirmed", funding_txid);
					return Ok(RoundStatus::Unconfirmed { funding_txid });
				}

				match hark_vtxo_swap(
					wallet, &self.participation, &mut self.new_vtxos, &funding_tx, unlock_hash,
				).await {
					Ok(()) => {
						persist_round_success(
							wallet,
							&self.participation,
							self.movement_id,
							&self.new_vtxos,
							&funding_tx,
						).await.context("failed to store successful round in DB!")?;

						self.done = true;

						Ok(RoundStatus::Confirmed { funding_txid })
					},
					Err(HarkForfeitError::Err(e)) => {
						Err(e.context("error forfeiting VTXOs after round"))
					},
					Err(HarkForfeitError::SentForfeits(e)) => {
						self.sent_forfeit_sigs = true;
						Err(e.context("error after having signed and sent \
							forfeit signatures to server"))
					},
				}
			},
		}
	}

	/// Once we know the signed round funding tx, this returns the output VTXOs
	/// for this round.
	pub fn output_vtxos(&self) -> Option<&[Vtxo]> {
		if self.new_vtxos.is_empty() {
			None
		} else {
			Some(&self.new_vtxos)
		}
	}

	/// Returns the input VTXOs that are locked in this round, but only
	/// if no output VTXOs were issued yet.
	pub fn locked_pending_inputs(&self) -> &[Vtxo] {
		//TODO(stevenroose) consider if we can't just drop the state after forfeit exchange
		match self.flow {
			RoundFlowState::NonInteractivePending { .. }
				| RoundFlowState::InteractivePending
				| RoundFlowState::InteractiveOngoing { .. }
			=> {
				&self.participation.inputs
			},
			RoundFlowState::Finished { .. } => if self.done {
				// inputs already unlocked
				&[]
			} else {
				&self.participation.inputs
			},
			RoundFlowState::Failed { .. }
				| RoundFlowState::Canceled
			=> {
				// inputs already unlocked
				&[]
			},
		}
	}

	/// The balance pending in this round
	///
	/// This becomes zero once the new round VTXOs are unlocked.
	pub fn pending_balance(&self) -> Amount {
		if self.done {
			return Amount::ZERO;
		}

		match self.flow {
			RoundFlowState::NonInteractivePending { .. }
				| RoundFlowState::InteractivePending
				| RoundFlowState::InteractiveOngoing { .. }
				| RoundFlowState::Finished { .. }
			=> {
				self.participation.outputs.iter().map(|o| o.amount).sum()
			},
			RoundFlowState::Failed { .. } | RoundFlowState::Canceled => {
				Amount::ZERO
			},
		}
	}
}

/// The state of the process flow of a round
///
/// This tracks the progress of the interactive part of the round, from
/// waiting to start until finishing either succesfully or with a failure.
pub enum RoundFlowState {
	/// We don't do flow and we just wait for the round to finish
	NonInteractivePending {
		unlock_hash: UnlockHash,
	},

	/// Waiting for round to happen
	InteractivePending,
	/// Interactive part ongoing
	InteractiveOngoing {
		round_seq: RoundSeq,
		attempt_seq: usize,
		state: AttemptState,
	},

	/// Interactive part finished, waiting for confirmation
	Finished {
		funding_tx: Transaction,
		unlock_hash: UnlockHash,
	},

	/// Failed during round
	Failed {
		error: String,
	},

	/// User canceled round
	Canceled,
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
		unlock_hash: UnlockHash,
	},
	AwaitingFinishedRound {
		unsigned_round_tx: Transaction,
		vtxos_spec: VtxoTreeSpec,
		unlock_hash: UnlockHash,
	},
}

impl AttemptState {
	/// The state kind represented as a string
	fn kind(&self) -> &'static str {
		match self {
			Self::AwaitingAttempt => "AwaitingAttempt",
			Self::AwaitingUnsignedVtxoTree { .. } => "AwaitingUnsignedVtxoTree",
			Self::AwaitingFinishedRound { .. } => "AwaitingFinishedRound",
		}
	}
}

/// Result from trying to progress an ongoing round attempt
enum AttemptProgressResult {
	Finished {
		funding_tx: Transaction,
		vtxos: Vec<Vtxo>,
		unlock_hash: UnlockHash,
	},
	Failed(anyhow::Error),
	/// When the state changes, this variant is returned
	///
	/// If during the processing, we have signed any forfeit txs and tried
	/// sending them to the server, the [UnconfirmedRound] instance is returned
	/// so that it can be stored in the state.
	Updated {
		new_state: AttemptState,
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
	let ark_info = srv.ark_info().await?;

	// Assign cosign pubkeys to the payment requests.
	let cosign_keys = iter::repeat_with(|| Keypair::new(&SECP, &mut rand::thread_rng()))
		.take(participation.outputs.len())
		.collect::<Vec<_>>();

	// Prepare round participation info.
	// For each of our requested vtxo output, we need a set of public and secret nonces.
	let cosign_nonces = cosign_keys.iter()
		.map(|key| {
			let mut secs = Vec::with_capacity(ark_info.nb_round_nonces);
			let mut pubs = Vec::with_capacity(ark_info.nb_round_nonces);
			for _ in 0..ark_info.nb_round_nonces {
				let (s, p) = musig::nonce_pair(key);
				secs.push(s);
				pubs.push(p);
			}
			(secs, pubs)
		})
		.take(participation.outputs.len())
		.collect::<Vec<(Vec<SecretNonce>, Vec<PublicNonce>)>>();


	// The round has now started. We can submit our payment.
	debug!("Submitting payment request with {} inputs and {} vtxo outputs",
		participation.inputs.len(), participation.outputs.len(),
	);

	let signed_reqs = participation.outputs.iter()
		.zip(cosign_keys.iter())
		.zip(cosign_nonces.iter())
		.map(|((req, cosign_key), (_sec, pub_nonces))| {
			SignedVtxoRequest {
				vtxo: req.clone(),
				cosign_pubkey: cosign_key.public_key(),
				nonces: pub_nonces.clone(),
			}
		})
		.collect::<Vec<_>>();

	let mut input_vtxos = Vec::with_capacity(participation.inputs.len());
	for vtxo in participation.inputs.iter() {
		let keypair = wallet.get_vtxo_key(vtxo).await
			.map_err(HarkForfeitError::Err)?;
		input_vtxos.push(protos::InputVtxo {
			vtxo_id: vtxo.id().to_bytes().to_vec(),
			ownership_proof: {
				let sig = event.challenge
					.sign_with(vtxo.id(), &signed_reqs, &keypair);
				sig.serialize().to_vec()
			},
		});
	}

	let resp = srv.client.submit_payment(protos::SubmitPaymentRequest {
		input_vtxos: input_vtxos,
		vtxo_requests: signed_reqs.into_iter().map(Into::into).collect(),
		#[allow(deprecated)]
		offboard_requests: vec![],
	}).await.context("Ark server refused our payment submission")?;

	Ok(AttemptState::AwaitingUnsignedVtxoTree {
		unlock_hash: UnlockHash::from_bytes(&resp.into_inner().unlock_hash)?,
		cosign_keys: cosign_keys,
		secret_nonces: cosign_nonces.into_iter()
			.map(|(sec, _pub)| sec.into_iter()
				.map(DangerousSecretNonce::dangerous_from_secret_nonce)
				.collect())
			.collect(),
	})
}

/// just an internal type; need Error trait to work with anyhow
#[derive(Debug, thiserror::Error)]
enum HarkForfeitError {
	/// An error happened after we sent forfeit signatures to the server
	#[error("error after forfeits were sent: {0}")]
	SentForfeits(anyhow::Error),
	/// An error happened before we sent forfeit signatures to the server
	#[error("error before forfeits were sent: {0}")]
	Err(anyhow::Error),
}

async fn hark_cosign_leaf(
	wallet: &Wallet,
	srv: &mut ServerConnection,
	funding_tx: &Transaction,
	vtxo: &mut Vtxo,
) -> anyhow::Result<()> {
	let key = wallet.pubkey_keypair(&vtxo.user_pubkey()).await
		.context("error fetching keypair").map_err(HarkForfeitError::Err)?
		.with_context(|| format!(
			"keypair {} not found for VTXO {}", vtxo.user_pubkey(), vtxo.id(),
		))?.1;
	let (ctx, cosign_req) = LeafVtxoCosignContext::new(vtxo, funding_tx, &key);
	let cosign_resp = srv.client.request_leaf_vtxo_cosign(
		protos::LeafVtxoCosignRequest::from(cosign_req),
	).await
		.with_context(|| format!("error requesting leaf cosign for vtxo {}", vtxo.id()))?
		.into_inner().try_into()
		.context("bad leaf vtxo cosign response")?;
	ensure!(ctx.finalize(vtxo, cosign_resp),
		"failed to finalize VTXO leaf signature for VTXO {}", vtxo.id(),
	);

	Ok(())
}

/// Finish the hArk VTXO swap protocol
///
/// This includes:
/// - requesting cosignature of the locked hArk leaves
/// - sending forfeit txs to the server in return for the unlock preimage
///
/// NB all the actions in this function are idempotent, meaning that the server
/// allows them to be done multiple times. this means that if this function calls
/// fails, it's safe to just call it again at a later time
async fn hark_vtxo_swap(
	wallet: &Wallet,
	participation: &RoundParticipation,
	output_vtxos: &mut [Vtxo],
	funding_tx: &Transaction,
	unlock_hash: UnlockHash,
) -> Result<(), HarkForfeitError> {
	let mut srv = wallet.require_server().map_err(HarkForfeitError::Err)?;

	// first get the leaves signed
	for vtxo in output_vtxos.iter_mut() {
		hark_cosign_leaf(wallet, &mut srv, funding_tx, vtxo).await
			.map_err(HarkForfeitError::Err)?;
	}

	// then do the forfeit dance

	let server_nonces = srv.client.request_forfeit_nonces(protos::ForfeitNoncesRequest {
		unlock_hash: unlock_hash.to_byte_array().to_vec(),
		vtxo_ids: participation.inputs.iter().map(|v| v.id().to_bytes().to_vec()).collect(),
	}).await
		.context("request forfeits nonces call failed")
		.map_err(HarkForfeitError::Err)?
		.into_inner().public_nonces.into_iter()
		.map(|b| HashLockedForfeitNonces::from_bytes(b))
		.collect::<Result<Vec<_>, _>>()
		.context("invalid forfeit nonces")
		.map_err(HarkForfeitError::Err)?;

	if server_nonces.len() != participation.inputs.len() {
		return Err(HarkForfeitError::Err(anyhow!(
			"server sent {} nonce pairs, expected {}",
			server_nonces.len(), participation.inputs.len(),
		)));
	}

	let mut forfeit_bundles = Vec::with_capacity(participation.inputs.len());
	for (input, nonces) in participation.inputs.iter().zip(server_nonces.into_iter()) {
		let user_key = wallet.pubkey_keypair(&input.user_pubkey()).await
			.ok().flatten().with_context(|| format!(
				"failed to fetch keypair for vtxo user pubkey {}", input.user_pubkey(),
			)).map_err(HarkForfeitError::Err)?.1;
		forfeit_bundles.push(HashLockedForfeitBundle::forfeit_vtxo(
			&input, unlock_hash, &user_key, &nonces,
		))
	}

	let preimage = srv.client.forfeit_vtxos(protos::ForfeitVtxosRequest {
		forfeit_bundles: forfeit_bundles.iter().map(|b| b.serialize()).collect(),
	}).await
		.context("forfeit vtxos call failed")
		.map_err(HarkForfeitError::SentForfeits)?
		.into_inner().unlock_preimage.as_slice().try_into()
		.context("invalid preimage length")
		.map_err(HarkForfeitError::SentForfeits)?;

	for vtxo in output_vtxos.iter_mut() {
		if !vtxo.provide_unlock_preimage(preimage) {
			return Err(HarkForfeitError::SentForfeits(anyhow!(
				"invalid preimage {} for vtxo {} with supposed unlock hash {}",
				preimage.as_hex(), vtxo.id(), unlock_hash,
			)));
		}

		// then validate the vtxo works
		vtxo.validate(&funding_tx).with_context(|| format!(
			"new VTXO {} does not pass validation after hArk forfeit protocol", vtxo.id(),
		)).map_err(HarkForfeitError::SentForfeits)?;
	}

	Ok(())
}

fn check_vtxo_fails_hash_lock(funding_tx: &Transaction, vtxo: &Vtxo) -> anyhow::Result<()> {
	match vtxo.validate(funding_tx) {
		Err(VtxoValidationError::GenesisTransition {
			genesis_idx, genesis_len, transition_kind, ..
		}) if genesis_idx + 1 == genesis_len && transition_kind == HARK_TRANSITION_KIND => Ok(()),
		Ok(()) => Err(anyhow!("new un-unlocked VTXO should fail validation but doesn't: {}",
			vtxo.serialize_hex(),
		)),
		Err(e) => Err(anyhow!("new VTXO {} failed validation: {:#}", vtxo.id(), e)),
	}
}

fn check_round_matches_participation(
	part: &RoundParticipation,
	new_vtxos: &[Vtxo],
	funding_tx: &Transaction,
) -> anyhow::Result<()> {
	ensure!(new_vtxos.len() == part.outputs.len(),
		"unexpected number of VTXOs: got {}, expected {}", new_vtxos.len(), part.outputs.len(),
	);

	for (vtxo, req) in new_vtxos.iter().zip(&part.outputs) {
		ensure!(vtxo.amount() == req.amount,
			"unexpected VTXO amount: got {}, expected {}", vtxo.amount(), req.amount,
		);
		ensure!(*vtxo.policy() == req.policy,
			"unexpected VTXO policy: got {:?}, expected {:?}", vtxo.policy(), req.policy,
		);

		// We accept the VTXO if only the hArk transition (last) failure happens
		check_vtxo_fails_hash_lock(funding_tx, vtxo)?;
	}

	Ok(())
}

/// Check the confirmation status of a funding tx
///
/// Returns true if the funding tx is confirmed deeply enough for us to accept it.
/// The required number of confirmations depends on the wallet's configuration.
///
/// Returns false if the funding tx seems valid but not confirmed yet.
///
/// Returns an error if the chain source fails or if we can't submit the tx to the
/// mempool, suggesting it might be double spent.
async fn check_funding_tx_confirmations(
	wallet: &Wallet,
	funding_txid: Txid,
	funding_tx: &Transaction,
) -> anyhow::Result<bool> {
	let tip = wallet.chain.tip().await.context("chain source error")?;
	let conf_height = tip - wallet.config.round_tx_required_confirmations + 1;
	let tx_status = wallet.chain.tx_status(funding_txid).await.context("chain source error")?;
	trace!("Round funding tx {} confirmation status: {:?} (tip={})",
		funding_txid, tx_status, tip,
	);
	match tx_status {
		TxStatus::Confirmed(b) if b.height <= conf_height => Ok(true),
		TxStatus::Mempool | TxStatus::Confirmed(_) => {
			if wallet.config.round_tx_required_confirmations == 0 {
				debug!("Accepting round funding tx without confirmations because of configuration");
				Ok(true)
			} else {
				trace!("Hark round funding tx not confirmed (deep enough) yet: {:?}", tx_status);
				Ok(false)
			}
		},
		TxStatus::NotFound => {
			// let's try to submit it to our mempool
			//TODO(stevenroose) change this to an explicit "testmempoolaccept" so that we can
			// reliably distinguish the cases of our chain source having issues and the tx
			// actually being rejected which suggests the round was double-spent
			if let Err(e) = wallet.chain.broadcast_tx(&funding_tx).await {
				Err(anyhow!("hark funding tx {} server sent us is rejected by mempool (hex={}): {:#}",
					funding_txid, serialize_hex(funding_tx), e,
				))
			} else {
				trace!("hark funding tx {} was not in mempool but we broadcast it", funding_txid);
				Ok(false)
			}
		},
	}
}

enum HarkProgressResult {
	RoundPending,
	FundingTxUnconfirmed {
		funding_txid: Txid,
	},
	Ok {
		funding_tx: Transaction,
		new_vtxos: Vec<Vtxo>,
	},
}

async fn progress_non_interactive(
	wallet: &Wallet,
	participation: &RoundParticipation,
	unlock_hash: UnlockHash,
) -> Result<HarkProgressResult, HarkForfeitError> {
	let mut srv = wallet.require_server().map_err(HarkForfeitError::Err)?;

	let resp = srv.client.round_participation_status(protos::RoundParticipationStatusRequest {
		unlock_hash: unlock_hash.to_byte_array().to_vec(),
	}).await
		.context("error checking round participation status")
		.map_err(HarkForfeitError::Err)?.into_inner();
	let status = protos::RoundParticipationStatus::try_from(resp.status)
		.context("unknown status from server")
		.map_err(HarkForfeitError::Err)	?;

	if status == protos::RoundParticipationStatus::RoundPartPending {
		trace!("Hark round still pending");
		return Ok(HarkProgressResult::RoundPending);
	}

	// Since we got here, we clearly don't think we're finished.
	// So even if the server thinks we did the dance before, we need the
	// cosignature on the leaf tx so we need to do the dance again.
	// "Guilty feet have got no rhythm."
	if status == protos::RoundParticipationStatus::RoundPartReleased {
		let preimage = resp.unlock_preimage.as_ref().map(|p| p.as_hex());
		warn!("Server says preimage was already released for hArk participation \
			with unlock hash {}. Supposed preimage: {:?}", unlock_hash, preimage,
		);
	}

	let funding_tx_bytes = resp.round_funding_tx
		.context("funding txid should be provided when status is not pending")
		.map_err(HarkForfeitError::Err)?;
	let funding_tx = deserialize::<Transaction>(&funding_tx_bytes)
		.context("invalid funding txid")
		.map_err(HarkForfeitError::Err)?;
	let funding_txid = funding_tx.compute_txid();
	trace!("Funding tx for round participation with unlock hash {}: {} ({})",
		unlock_hash, funding_tx.compute_txid(), funding_tx_bytes.as_hex(),
	);

	// Check the confirmation status of the funding tx
	match check_funding_tx_confirmations(wallet, funding_txid, &funding_tx).await {
		Ok(true) => {},
		Ok(false) => return Ok(HarkProgressResult::FundingTxUnconfirmed { funding_txid }),
		Err(e) => return Err(HarkForfeitError::Err(e.context("checking funding tx confirmations"))),
	}

	let mut new_vtxos = resp.output_vtxos.into_iter()
		.map(|v| Vtxo::from_bytes(v))
		.collect::<Result<Vec<_>, _>>()
		.context("invalid output VTXOs from server")
		.map_err(HarkForfeitError::Err)?;

	// Check that the vtxos match our participation in the exact order
	check_round_matches_participation(participation, &new_vtxos, &funding_tx)
		.context("new VTXOs received from server don't match our participation")
		.map_err(HarkForfeitError::Err)?;

	hark_vtxo_swap(wallet, participation, &mut new_vtxos, &funding_tx, unlock_hash).await
		.context("error forfeiting hArk VTXOs")
		.map_err(HarkForfeitError::SentForfeits)?;

	Ok(HarkProgressResult::Ok { funding_tx, new_vtxos })
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
			AttemptState::AwaitingUnsignedVtxoTree { cosign_keys, secret_nonces, unlock_hash },
			RoundEvent::VtxoProposal(e),
		) => {
			trace!("Received VtxoProposal: {:#?}", e);
			match sign_vtxo_tree(
				wallet,
				part,
				&cosign_keys,
				&secret_nonces,
				&e.unsigned_round_tx,
				&e.vtxos_spec,
				&e.cosign_agg_nonces,
			).await {
				Ok(()) => {
					AttemptProgressResult::Updated {
						new_state: AttemptState::AwaitingFinishedRound {
							unsigned_round_tx: e.unsigned_round_tx.clone(),
							vtxos_spec: e.vtxos_spec.clone(),
							unlock_hash: *unlock_hash,
						},
					}
				},
				Err(e) => {
					trace!("Error signing VTXO tree: {:#}", e);
					AttemptProgressResult::Failed(e)
				},
			}
		},

		(
			AttemptState::AwaitingFinishedRound { unsigned_round_tx, vtxos_spec, unlock_hash },
			RoundEvent::Finished(RoundFinished { cosign_sigs, signed_round_tx, .. }),
		) => {
			if unsigned_round_tx.compute_txid() != signed_round_tx.compute_txid() {
				return AttemptProgressResult::Failed(anyhow!(
					"signed funding tx ({}) doesn't match tx received before ({})",
					signed_round_tx.compute_txid(), unsigned_round_tx.compute_txid(),
				));
			}

			if let Err(e) = wallet.chain.broadcast_tx(&signed_round_tx).await {
				warn!("Failed to broadcast signed round tx: {:#}", e);
			}

			match construct_new_vtxos(
				part, unsigned_round_tx, vtxos_spec, cosign_sigs,
			).await {
				Ok(v) => AttemptProgressResult::Finished {
					funding_tx: signed_round_tx.clone(),
					vtxos: v,
					unlock_hash: *unlock_hash,
				},
				Err(e) => AttemptProgressResult::Failed(anyhow!(
					"failed to construct new VTXOs for round: {:#}", e,
				)),
			}
		},

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

	// Check that the proposal contains our inputs.
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

	let unsigned_vtxos = vtxo_tree.clone().into_unsigned_tree(vtxos_utxo);
	let iter = participation.outputs.iter().zip(cosign_keys).zip(secret_nonces);
	trace!("Sending vtxo signatures to server...");
	let _ = try_join_all(iter.map(|((req, key), sec)| async {
		let leaf_idx = unsigned_vtxos.spec.leaf_idx_of_req(req).expect("req included");
		let secret_nonces = sec.as_ref().iter().map(|s| s.to_sec_nonce()).collect();
		let part_sigs = unsigned_vtxos.cosign_branch(
			&cosign_agg_nonces, leaf_idx, key, secret_nonces,
		).context("failed to cosign branch: our request not part of tree")?;

		info!("Sending {} partial vtxo cosign signatures for pk {}",
			part_sigs.len(), key.public_key(),
		);

		let _ = srv.client.clone().provide_vtxo_signatures(protos::VtxoSignaturesRequest {
			pubkey: key.public_key().serialize().to_vec(),
			signatures: part_sigs.iter().map(|s| s.serialize().to_vec()).collect(),
		}).await.context("error sending vtxo signatures")?;

		Result::<(), anyhow::Error>::Ok(())
	})).await.context("error sending VTXO signatures")?;
	trace!("Done sending vtxo signatures to server");

	Ok(())
}

async fn construct_new_vtxos(
	participation: &RoundParticipation,
	unsigned_round_tx: &Transaction,
	vtxo_tree: &VtxoTreeSpec,
	vtxo_cosign_sigs: &[schnorr::Signature],
) -> anyhow::Result<Vec<Vtxo>> {
	let round_txid = unsigned_round_tx.compute_txid();
	let vtxos_utxo = OutPoint::new(round_txid, ROUND_TX_VTXO_TREE_VOUT);
	let vtxo_tree = vtxo_tree.clone().into_unsigned_tree(vtxos_utxo);

	// Validate the vtxo tree and cosign signatures.
	if vtxo_tree.verify_cosign_sigs(&vtxo_cosign_sigs).is_err() {
		// bad server!
		bail!("Received incorrect vtxo cosign signatures from server");
	}

	let signed_vtxos = vtxo_tree
		.into_signed_tree(vtxo_cosign_sigs.to_vec())
		.into_cached_tree();

	let mut expected_vtxos = participation.outputs.iter().collect::<Vec<_>>();
	let total_nb_expected_vtxos = expected_vtxos.len();

	let mut new_vtxos = vec![];
	for (idx, req) in signed_vtxos.spec.spec.vtxos.iter().enumerate() {
		if let Some(expected_idx) = expected_vtxos.iter().position(|r| **r == req.vtxo) {
			let vtxo = signed_vtxos.build_vtxo(idx);

			// validate the received vtxos
			// This is more like a sanity check since we crafted them ourselves.
			check_vtxo_fails_hash_lock(unsigned_round_tx, &vtxo)
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
	Ok(new_vtxos)
}

//TODO(stevenroose) should be made idempotent
async fn persist_round_success(
	wallet: &Wallet,
	participation: &RoundParticipation,
	movement_id: Option<MovementId>,
	new_vtxos: &[Vtxo],
	funding_tx: &Transaction,
) -> anyhow::Result<()> {
	debug!("Persisting newly finished round. {} new vtxos, movement ID {:?}",
		new_vtxos.len(), movement_id,
	);

	// we first try all actions that need to happen and only afterwards return errors
	// so that we achieve maximum success

	let store_result = wallet.store_spendable_vtxos(new_vtxos).await
		.context("failed to store new VTXOs");
	let spent_result = wallet.mark_vtxos_as_spent(&participation.inputs).await
		.context("failed to mark input VTXOs as spent");
	let update_result = if let Some(mid) = movement_id {
		wallet.movements.finish_movement_with_update(
			mid,
			MovementStatus::Successful,
			MovementUpdate::new()
				.produced_vtxos(new_vtxos)
				.metadata([("funding_txid".into(), serde_json::to_value(funding_tx.compute_txid())?)]),
		).await.context("failed to mark movement as finished")
	} else {
		Ok(())
	};

	store_result?;
	spent_result?;
	update_result?;

	Ok(())
}

//TODO(stevenroose) should be made idempotent
async fn persist_round_failure(
	wallet: &Wallet,
	participation: &RoundParticipation,
	movement_id: Option<MovementId>,
) -> anyhow::Result<()> {
	debug!("Attempting to persist the failure of a round with the movement ID {:?}", movement_id);
	let unlock_result = wallet.unlock_vtxos(&participation.inputs).await;
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
	wallet: &Wallet,
	movement_id: MovementId,
	funding_txid: Txid,
) -> anyhow::Result<()> {
	wallet.movements.update_movement(
		movement_id,
		MovementUpdate::new()
			.metadata([("funding_txid".into(), serde_json::to_value(&funding_txid)?)])
	).await.context("Unable to update funding txid of round")
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
		let movement_id = if let Some(kind) = movement_kind {
			Some(self.movements.new_movement_with_update(
				Subsystem::ROUND,
				kind.to_string(),
				participation.to_movement_update()?
			).await?)
		} else {
			None
		};
		let state = RoundState::new_interactive(participation, movement_id);

		let id = self.db.store_round_state_lock_vtxos(&state).await?;
		Ok(StoredRoundState { id, state })
	}

	pub async fn join_non_interactive_round(
		&self,
		participation: RoundParticipation,
		movement_kind: Option<RoundMovement>,
	) -> anyhow::Result<StoredRoundState> {
		let movement_id = if let Some(kind) = movement_kind {
			let movement_id = self.movements.new_movement(
				Subsystem::ROUND, kind.to_string(),
			).await?;
			let update = participation.to_movement_update()?;
			self.movements.update_movement(movement_id, update).await?;
			Some(movement_id)
		} else {
			None
		};
		let state = RoundState::new_interactive(participation, movement_id);

		let id = self.db.store_round_state_lock_vtxos(&state).await?;
		Ok(StoredRoundState { id, state })
	}

	/// Get all pending round states
	pub async fn pending_round_states(&self) -> anyhow::Result<Vec<StoredRoundState>> {
		self.db.load_round_states().await
	}

	/// Sync pending rounds that have finished but are waiting for confirmations
	pub async fn sync_pending_rounds(&self) -> anyhow::Result<()> {
		let states = self.db.load_round_states().await?;
		if !states.is_empty() {
			debug!("Syncing {} pending round states...", states.len());

			tokio_stream::iter(states).for_each_concurrent(10, |mut state| async move {
				// not processing events here
				if state.state.ongoing_participation() {
					return;
				}

				let status = state.state.sync(self).await;
				trace!("Synced round #{}, status: {:?}", state.id, status);
				match status {
					Ok(RoundStatus::Confirmed { funding_txid }) => {
						info!("Round confirmed. Funding tx {}", funding_txid);
						if let Err(e) = self.db.remove_round_state(&state).await {
							warn!("Error removing confirmed round state from db: {:#}", e);
						}
					},
					Ok(RoundStatus::Unconfirmed { funding_txid }) => {
						info!("Waiting for confirmations for round funding tx {}", funding_txid);
						if let Err(e) = self.db.update_round_state(&state).await {
							warn!("Error updating pending round state in db: {:#}", e);
						}
					},
					Ok(RoundStatus::Pending) => {
						if let Err(e) = self.db.update_round_state(&state).await {
							warn!("Error updating pending round state in db: {:#}", e);
						}
					},
					Ok(RoundStatus::Failed { error }) => {
						error!("Round failed: {}", error);
						if let Err(e) = self.db.remove_round_state(&state).await {
							warn!("Error removing failed round state from db: {:#}", e);
						}
					},
					Ok(RoundStatus::Canceled) => {
						error!("Round canceled");
						if let Err(e) = self.db.remove_round_state(&state).await {
							warn!("Error removing canceled round state from db: {:#}", e);
						}
					},
					Err(e) => warn!("Error syncing round: {:#}", e),
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

	async fn inner_process_event(
		&self,
		states: impl IntoIterator<Item = &mut StoredRoundState>,
		event: Option<&RoundEvent>,
	) {
		tokio_stream::iter(states).for_each_concurrent(3, |state| async move {
			if let Some(event) = event && state.state.ongoing_participation() {
				let updated = state.state.process_event(self, &event).await;
				if updated {
					if let Err(e) = self.db.update_round_state(&state).await {
						error!("Error storing round state #{} after progress: {:#}", state.id, e);
					}
				}
			}

			match state.state.sync(self).await {
				Err(e) => warn!("Error syncing round #{}: {:#}", state.id, e),
				Ok(s) if s.is_final() => {
					info!("Round #{} finished with result: {:?}", state.id, s);
					if let Err(e) = self.db.remove_round_state(&state).await {
						warn!("Failed to remove finished round #{} from db: {:#}", state.id, e);
					}
				},
				Ok(s) => {
					trace!("Round state #{} is now in state {:?}", state.id, s);
					if let Err(e) = self.db.update_round_state(&state).await {
						warn!("Error storing round state #{}: {:#}", state.id, e);
					}
				},
			}
		}).await;
	}

	/// Try to make incremental progress on all pending round states
	///
	/// If the `last_round_event` argument is not provided, it will be fetched
	/// from the server.
	pub async fn progress_pending_rounds(
		&self,
		last_round_event: Option<&RoundEvent>,
	) -> anyhow::Result<()> {
		let mut states = self.db.load_round_states().await?;
		info!("Processing {} rounds...", states.len());

		let mut last_round_event = last_round_event.map(|e| Cow::Borrowed(e));
		if states.iter().any(|s| s.state.ongoing_participation()) && last_round_event.is_none() {
			match self.get_last_round_event().await {
				Ok(e) => last_round_event = Some(Cow::Owned(e)),
				Err(e) => {
					warn!("Error fetching round event, \
						failed to progress ongoing rounds: {:#}", e);
				},
			}
		}

		let event = last_round_event.as_ref().map(|c| c.as_ref());
		self.inner_process_event(states.iter_mut(), event).await;

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

	/// A blocking call that will try to perform a full round participation
	/// for all ongoing rounds
	///
	/// Returns only once a round has happened on the server.
	pub async fn participate_ongoing_rounds(&self) -> anyhow::Result<()> {
		let mut states = self.db.load_round_states().await?;
		states.retain(|s| s.state.ongoing_participation());

		if states.is_empty() {
			info!("No pending round states");
			return Ok(());
		}

		let mut events = self.subscribe_round_events().await?;

		info!("Participating with {} round states...", states.len());

		loop {
			let event = events.next().await
				.context("events stream broke")?
				.context("error on event stream")?;

			self.inner_process_event(states.iter_mut(), Some(&event)).await;

			states.retain(|s| s.state.ongoing_participation());
			if states.is_empty() {
				info!("All rounds handled");
				return Ok(());
			}
		}
	}

	/// Will cancel all pending rounds that can safely be canceled
	///
	/// All rounds that have not started yet can safely be canceled,
	/// as well as rounds where we have not yet signed any forfeit txs.
	pub async fn cancel_all_pending_rounds(&self) -> anyhow::Result<()> {
		let states = self.db.load_round_states().await?;
		for mut state in states {
			match state.state.try_cancel(self).await {
				Ok(true) => {
					if let Err(e) = self.db.remove_round_state(&state).await {
						warn!("Error removing canceled round state from db: {:#}", e);
					}
				},
				Ok(false) => {},
				Err(e) => warn!("Error trying to cancel round #{}: {:#}", state.id, e),
			}
		}
		Ok(())
	}

	/// Try to cancel the given round
	pub async fn cancel_pending_round(&self, id: RoundStateId) -> anyhow::Result<()> {
		let states = self.db.load_round_states().await?;
		for mut state in states {
			if state.id != id {
				continue;
			}

			if state.state.try_cancel(self).await.context("failed to cancel round")? {
				self.db.remove_round_state(&state).await
					.context("error removing canceled round state from db")?;
			} else {
				bail!("failed to cancel round");
			}
			return Ok(());
		}
		bail!("round not found")
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
			if !state.state.ongoing_participation() {
				return Ok(state.state.sync(self).await?);
			}

			let event = events.next().await
				.context("events stream broke")?
				.context("error on event stream")?;
			if state.state.process_event(self, &event).await {
				self.db.update_round_state(&state).await?;
			}
		}
	}
}

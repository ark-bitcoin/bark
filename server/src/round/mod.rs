

use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Context;
use bitcoin::consensus::encode::serialize;
use bitcoin::{Amount, FeeRate, OutPoint, Psbt, Txid};
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{rand, Keypair, PublicKey};
use bitcoin_ext::{BlockHeight, P2TR_DUST, P2WSH_DUST};
use log::{debug, error, info, log_enabled, trace, warn};
use opentelemetry::global;
use opentelemetry::global::BoxedTracer;
use opentelemetry::trace::{SpanKind, TraceContextExt, Tracer, TracerProvider};
use tokio::sync::{mpsc, oneshot, OwnedMutexGuard};
use tracing::info_span;
use tracing_opentelemetry::OpenTelemetrySpanExt;

use ark::{
	OffboardRequest, ProtocolEncoding, SignedVtxoRequest, Vtxo, VtxoId, VtxoIdInput, VtxoPolicy,
	VtxoRequest,
};
use ark::challenges::RoundAttemptChallenge;
use ark::connectors::ConnectorChain;
use ark::musig::{self, DangerousSecretNonce, PublicNonce, SecretNonce};
use ark::rounds::{
	RoundAttempt, RoundEvent, RoundFinished, RoundProposal, RoundSeq, VtxoProposal,
	ROUND_TX_CONNECTOR_VOUT, ROUND_TX_VTXO_TREE_VOUT,
};
use ark::tree::signed::{CachedSignedVtxoTree, UnsignedVtxoTree, VtxoTreeSpec};
use server_log::{LogMsg, RoundVtxoCreated};
use server_rpc::protos;

use crate::{telemetry, Server, SECP};
use crate::database::forfeits::ForfeitState;
use crate::error::{ContextExt, NotFound};
use crate::flux::{VtxoFluxLock, OwnedVtxoFluxLock};
use crate::secret::Secret;
use crate::telemetry::{MetricsService, RoundStep, SpanExt, TimedRoundStep};
use crate::wallet::{BdkWalletExt, PersistedWallet, WalletUtxoGuard};

#[macro_export]
macro_rules! server_rslog {
	($struct:ident, $step:expr, $( $args:tt )*) => {
		slog!($struct,
			round_seq: $step.round_seq(),
			attempt_seq: $step.attempt_seq(),
			server_duration: $step.duration(),
			$( $args )*
		);
	};
	($struct:ident, $step:expr) => { server_rslog!($struct, $step, ); };
}

#[macro_export]
macro_rules! client_rslog {
	($struct:ident, $step:expr, $( $args:tt )*) => {
		slog!($struct,
			round_seq: $step.round_seq(),
			attempt_seq: $step.attempt_seq(),
			client_duration: $step.duration(),
			$( $args )*
		);
	};
	($struct:ident, $step:expr) => { client_rslog!($struct, $step, ); };
}

#[derive(Debug)]
pub enum RoundInput {
	RegisterPayment {
		inputs: Vec<VtxoIdInput>,
		vtxo_requests: Vec<VtxoParticipant>,
		offboards: Vec<OffboardRequest>,
	},
	VtxoSignatures {
		pubkey: PublicKey,
		signatures: Vec<musig::PartialSignature>,
	},
	ForfeitSignatures {
		signatures: Vec<(VtxoId, Vec<musig::PublicNonce>, Vec<musig::PartialSignature>)>,
	},
}

fn validate_forfeit_sigs(
	vtxo: &Vtxo,
	connectors: &ConnectorChain,
	connector_pk: PublicKey,
	server_nonces: &[musig::PublicNonce],
	user_nonces: &[musig::PublicNonce],
	part_sigs: &[musig::PartialSignature],
) -> anyhow::Result<()> {
	if user_nonces.len() != connectors.len() || part_sigs.len() != connectors.len() {
		bail!("not enough forfeit signatures provided");
	}

	let (key_agg, _) = musig::tweaked_key_agg(
		[vtxo.user_pubkey(), vtxo.server_pubkey()],
		vtxo.output_taproot().tap_tweak().to_byte_array(),
	);
	for (idx, (conn, _tx)) in connectors.connectors().enumerate() {
		let (sighash, _tx) = ark::forfeit::connector_forfeit_sighash_exit(
			vtxo, conn, connector_pk,
		);
		let part_sig = part_sigs.get(idx).expect("we checked length");
		let server_nonce = server_nonces.get(idx).expect("we checked length");
		let user_nonce = user_nonces.get(idx).expect("we checked length");
		let agg_nonce = musig::nonce_agg(&[&user_nonce, &server_nonce]);

		let session = musig::Session::new(
			&key_agg,
			agg_nonce,
			&sighash.to_byte_array(),
		);
		let success = session.partial_verify(
			&key_agg,
			part_sig,
			user_nonce,
			musig::pubkey_to(vtxo.user_pubkey()),
		);
		if !success {
			bail!("Invalid partial forfeit signature");
		}
	}
	Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VtxoParticipant {
	pub req: SignedVtxoRequest,
	pub nonces: Vec<PublicNonce>,
}

impl TryFrom<protos::SignedVtxoRequest> for VtxoParticipant {
	type Error = anyhow::Error;
	fn try_from(v: protos::SignedVtxoRequest) -> Result<Self, Self::Error> {
		let vtxo = v.vtxo.context("incomplete message")?;
		Ok(VtxoParticipant {
			req: SignedVtxoRequest {
				vtxo: VtxoRequest {
					amount: Amount::from_sat(vtxo.amount),
					policy: VtxoPolicy::deserialize(&vtxo.policy)
						.badarg("invalid VtxoPolicy")?,
				},
				cosign_pubkey: Some(PublicKey::from_slice(&v.cosign_pubkey)
					.badarg("malformed cosign pubkey")?),
			},
			nonces: v.public_nonces.into_iter().map(|n| {
				TryFrom::try_from(&n[..]).ok()
					.and_then(|b| musig::PublicNonce::from_byte_array(&b).ok())
					.badarg("invalid public nonce")
			}).collect::<Result<Vec<_>, _>>()?,
		})
	}
}

#[derive(Clone)]
pub struct RoundData {
	max_output_vtxos: usize,
	nb_vtxo_nonces: usize,
	offboard_feerate: FeeRate,
	max_vtxo_amount: Option<Amount>,
}

pub struct CollectingPayments {
	round_data: RoundData,

	round_attempt_challenge: RoundAttemptChallenge,

	/// All inputs that have participated in the previous attempt.
	locked_inputs: OwnedVtxoFluxLock,

	cosign_key: Keypair,
	allowed_inputs: Option<HashSet<VtxoId>>,
	all_inputs: HashMap<VtxoId, Vtxo>,
	all_outputs: Vec<VtxoParticipant>,
	/// Keep track of which input vtxos belong to which inputs.
	inputs_per_cosigner: HashMap<PublicKey, Vec<VtxoId>>,
	all_offboards: Vec<OffboardRequest>,

	common_round_tx_input: Option<WalletUtxoGuard>,

	round_step: TimedRoundStep,

	proceed: bool,
}

impl CollectingPayments {
	fn new(
		round_seq: RoundSeq,
		attempt_seq: usize,
		round_data: RoundData,
		locked_inputs: OwnedVtxoFluxLock,
		allowed_inputs: Option<HashSet<VtxoId>>,
		common_round_tx_input: Option<WalletUtxoGuard>,
	) -> CollectingPayments {
		CollectingPayments {
			round_data,
			round_attempt_challenge: RoundAttemptChallenge::generate(),
			locked_inputs,
			allowed_inputs,

			// Generate a one-time use signing key.
			cosign_key: Keypair::new(&SECP, &mut rand::thread_rng()),

			all_inputs: HashMap::new(),
			all_outputs: Vec::new(),
			inputs_per_cosigner: HashMap::new(),
			all_offboards: Vec::new(),

			common_round_tx_input,

			round_step: RoundStep::AttemptInitiation.with_instant(round_seq, attempt_seq),

			proceed: false,
		}
	}

	fn first_attempt(&self) -> bool {
		assert_eq!(self.round_step.attempt_seq() == 0, self.allowed_inputs.is_none());
		self.round_step.attempt_seq() == 0
	}

	/// Returns whether there are no valid inputs left in the round
	/// and we need to start a new round.
	fn need_new_round(&self) -> bool {
		!self.first_attempt() && self.allowed_inputs.as_ref().unwrap().is_empty()
	}

	fn have_payments(&self) -> bool {
		!self.all_inputs.is_empty() && (!self.all_outputs.is_empty() || !self.all_offboards.is_empty())
	}

	fn attempt_seq(&self) -> usize {
		self.round_step.attempt_seq()
	}

	fn next_step(&mut self, step: RoundStep) -> TimedRoundStep {
		self.round_step = self.round_step.proceed(step);
		self.round_step
	}

	fn validate_payment_amounts(
		&self,
		inputs: &[Vtxo],
		outputs: &[VtxoParticipant],
		offboards: &[OffboardRequest],
	) -> anyhow::Result<()> {
		let mut in_set = HashSet::with_capacity(inputs.len());
		let mut in_sum = Amount::ZERO;
		for input in inputs {
			in_sum += input.amount();
			if in_sum > Amount::MAX_MONEY{
				return badarg!("total input amount overflow");
			}
			if !in_set.insert(input.id()) {
				return badarg!("duplicate input");
			}
		}

		let mut out_sum = Amount::ZERO;
		for output in outputs {
			if output.req.vtxo.amount < P2TR_DUST {
				return badarg!("vtxo amount must be at least {}", P2TR_DUST);
			}

			match output.req.vtxo.policy {
				// HTLCs are not included in the sum because they don't spend any
				// round input. Instead, they are funded by provided the payment
				// hash and handled in the `collect_htlcs` method.
				VtxoPolicy::ServerHtlcRecv { .. } => {
					continue;
				},
				VtxoPolicy::ServerHtlcSend { .. } => {
					return badarg!("invalid vtxo policy: {:?}", output.req.vtxo.policy);
				},
				VtxoPolicy::Pubkey { .. } => {
					out_sum += output.req.vtxo.amount;
				},
			}

			if out_sum > in_sum {
				return badarg!("total output amount ({out_sum}) exceeds total input amount ({in_sum})");
			}
		}
		for offboard in offboards {
			if offboard.amount < P2TR_DUST {
				return badarg!("offboard amount must be at least {}", P2TR_DUST);
			}

			let fee = offboard.fee(self.round_data.offboard_feerate)
				.badarg("invalid offboard request")?;
			out_sum += offboard.amount + fee;
			if out_sum > in_sum {
				return badarg!("total output amount with offboard ({out_sum}) exceeds total input amount ({in_sum})");
			}
		}

		Ok(())
	}

	/// This methods does checks on the user input that can be done fast and without
	/// the need to fetch the input vtxos.
	fn validate_payment_data(
		&self,
		inputs: &[VtxoIdInput],
		outputs: &[VtxoParticipant],
	) -> anyhow::Result<()> {
		for out in outputs {
			if out.nonces.len() != self.round_data.nb_vtxo_nonces {
				client_rslog!(RoundUserBadNbNonces, self.round_step,
					nb_cosign_nonces: out.nonces.len(),
				);
				bail!("incorrect number of cosign nonces per set");
			}

			if let Some(cosign_pk) = out.req.cosign_pubkey {
				if self.inputs_per_cosigner.contains_key(&cosign_pk) {
					client_rslog!(RoundUserDuplicateCosignPubkey, self.round_step,
						cosign_pubkey: cosign_pk,
					);
					bail!("duplicate cosign key {}", cosign_pk);
				}
			}
		}

		if let Some(max) = self.round_data.max_vtxo_amount {
			for out in outputs {
				if out.req.vtxo.amount > max {
					client_rslog!(RoundUserBadOutputAmount, self.round_step,
						amount: out.req.vtxo.amount,
					);
					return badarg!("output exceeds maximum vtxo amount of {max}");
				}
			}
		}

		if self.all_outputs.len() + outputs.len() > self.round_data.max_output_vtxos {
			warn!("Got payment we don't have space for, dropping");
			bail!("not enough outputs left in this round, try next round");
		}
		//TODO(stevenroose) verify ownership over inputs

		let mut unique_inputs = HashSet::with_capacity(inputs.len());
		for input in inputs {
			if !unique_inputs.insert(input) {
				client_rslog!(RoundUserVtxoDuplicateInput, self.round_step,
					vtxo: input.vtxo_id,
				);
				bail!("user provided duplicate inputs");
			}
			if self.all_inputs.contains_key(&input.vtxo_id) {
				client_rslog!(RoundUserVtxoAlreadyRegistered, self.round_step,
					vtxo: input.vtxo_id,
				);
				bail!("vtxo {} already registered", input.vtxo_id);
			}
		}

		if let Some(ref allowed) = self.allowed_inputs {
			// This means we're not trying first time and we filter inputs.
			if let Some(bad) = inputs.iter().find(|i| !allowed.contains(&i.vtxo_id)) {
				client_rslog!(RoundUserVtxoNotAllowed, self.round_step,
					vtxo: bad.vtxo_id,
				);
				bail!("input vtxo {} has been banned for this round", bad.vtxo_id);
			}
		}

		Ok(())
	}

	/// Fetch and check whether the vtxos are owned by user and
	/// weren't already spent, then return them.
	///
	/// There is no guarantee that the vtxos is still all unspent by
	/// the time this call returns. The caller should ensure no changes
	/// are made to them meanwhile.
	async fn check_fetch_round_input_vtxos(
		&self,
		srv: &Server,
		inputs: &[VtxoIdInput],
	) -> anyhow::Result<Vec<Vtxo>> {
		let ids = inputs.iter().map(|i| i.vtxo_id).collect::<Vec<_>>();

		let mut ret  = Vec::with_capacity(inputs.len());
		match srv.db.get_vtxos_by_id(&ids).await {
			Ok(vtxos) => {
				// Check if the input vtxos exist, unspent and owned by user.
				for v in vtxos {
					if !v.is_spendable() {
						bail!("vtxo {} is not spendable", v.vtxo_id)
					}
					ret.push(v.vtxo);
				}
				Ok(ret)
			},
			Err(e) => {
				if let Some(nf) = e.downcast_ref::<NotFound>() {
					for id in nf.identifiers() {
						client_rslog!(RoundUserVtxoUnknown, self.round_step,
							vtxo: Some(VtxoId::from_str(id).expect("should be a valid vtxoid")),
						);
					}
				}
				Err(e)
			},
		}
	}

	async fn process_payment(
		&mut self,
		srv: &Server,
		inputs: Vec<VtxoIdInput>,
		vtxo_requests: Vec<VtxoParticipant>,
		offboards: Vec<OffboardRequest>,
	) -> anyhow::Result<()> {
		if vtxo_requests.is_empty() && offboards.is_empty() {
			return badarg!("invalid request: zero outputs and zero offboards");
		}

		self.validate_payment_data(&inputs, &vtxo_requests)?;

		let input_ids = inputs.iter().map(|i| i.vtxo_id).collect::<Vec<_>>();
		let lock = match srv.vtxos_in_flux.lock(&input_ids) {
			Ok(l) => l,
			Err(id) => {
				client_rslog!(RoundUserVtxoInFlux, self.round_step,
					vtxo: id,
				);
				bail!("vtxo {id} already in flux");
			},
		};

		// Check if the input vtxos exist and are unspent.
		let input_vtxos = match self.check_fetch_round_input_vtxos(srv, &inputs).await {
			Ok(i) => i,
			Err(e) => {
				let ret = if let Some(id) = e.downcast_ref::<VtxoId>().cloned() {
					client_rslog!(RoundUserVtxoUnknown, self.round_step,
						vtxo: Some(id),
					);
					Err(e).not_found([id], "input vtxo does not exist")
				} else {
					Err(e)
				};
				return ret;
			}
		};


		let ownership_proof_by_vtxo_id = inputs.iter()
			.map(|v| (v.vtxo_id, v.ownership_proof)).collect::<HashMap<_,_>>();
		let v_reqs = vtxo_requests.iter().map(|v| v.req.clone()).collect::<Vec<_>>();
		for input in &input_vtxos {
			let sig = ownership_proof_by_vtxo_id.get(&input.id()).expect("all vtxos were found");
			self.round_attempt_challenge.verify_input_vtxo_sig(input, &v_reqs, &offboards, sig)
				.context(format!("ownership proof is invalid: vtxo {}, proof: {}", input.id(), sig))?;
		}

		if let Err(e) = self.validate_payment_amounts(&input_vtxos, &vtxo_requests, &offboards) {
			client_rslog!(RoundPaymentRegistrationFailed, self.round_step,
				error: e.to_string(),
			);
			return Err(e).context("registration failed");
		}

		if let Err(e) = srv.check_vtxos_not_exited(&input_vtxos).await {
			client_rslog!(RoundPaymentRegistrationFailed, self.round_step,
				error: e.to_string(),
			);
			return Err(e).context("registration failed");
		}

		// Finally, we are done
		self.register_payment(lock, input_vtxos, vtxo_requests, offboards);

		Ok(())
	}

	fn register_payment(
		&mut self,
		lock: VtxoFluxLock,
		inputs: Vec<Vtxo>,
		vtxo_requests: Vec<VtxoParticipant>,
		offboards: Vec<OffboardRequest>,
	) {
		client_rslog!(RoundPaymentRegistered, self.round_step,
			nb_inputs: inputs.len(),
			nb_outputs: vtxo_requests.len(),
			nb_offboards: offboards.len(),
		);

		// If we're adding inputs for the first time, also add them to locked_inputs.
		if self.first_attempt() {
			self.locked_inputs.absorb(lock);
		}

		let input_ids = inputs.iter().map(|v| v.id()).collect::<Vec<_>>();
		self.all_inputs.extend(inputs.into_iter().map(|v| (v.id(), v)));

		self.inputs_per_cosigner.reserve(vtxo_requests.len());
		for req in &vtxo_requests {
			if let Some(cosign_pk) = req.req.cosign_pubkey {
				assert!(
					self.inputs_per_cosigner.insert(cosign_pk, input_ids.clone()).is_none(),
					"should be checked before",
				);
			}
		}
		self.all_outputs.extend(vtxo_requests);

		self.all_offboards.extend(offboards);

		// Check whether our round is full.
		if self.all_outputs.len() == self.round_data.max_output_vtxos {
			server_rslog!(FullRound, self.round_step,
				nb_outputs: self.all_outputs.len(),
				max_output_vtxos: self.round_data.max_output_vtxos,
			);
			self.proceed = true;
		}
	}

	async fn progress(mut self, srv: &Server) -> Result<SigningVtxoTree, RoundError> {
		let tip = srv.chain_tip().height;
		let expiry_height = tip + srv.config.vtxo_lifetime as BlockHeight;

		let round_step = self.next_step(RoundStep::ConstructVtxoTree);
		let mut span = trace_round_step(&round_step);
		span.set_int_attr("expiry_height", expiry_height);
		span.set_int_attr("block_height", tip);

		// Since it's possible in testing that we only have to do offboards,
		// and since it's pretty annoying to deal with the case of no vtxos,
		// if there are no vtxos, we will just add a fake vtxo for the server.
		// In practice, in later versions, it is very likely that the server
		// will actually want to create change vtxos, so temporarily, this
		// dummy vtxo will be a placeholder for a potential change vtxo.
		let mut change_vtxo = if self.all_outputs.is_empty() {
			lazy_static::lazy_static! {
				static ref UNSPENDABLE: PublicKey =
					"031575a4c3ad397590ccf7aa97520a60635c3215047976afb9df220bc6b4241b0d".parse().unwrap();
			}
			let cosign_key = Keypair::new(&SECP, &mut rand::thread_rng());
			let (cosign_sec_nonces, cosign_pub_nonces) = {
				let mut secs = Vec::with_capacity(srv.config.nb_round_nonces);
				let mut pubs = Vec::with_capacity(srv.config.nb_round_nonces);
				for _ in 0..srv.config.nb_round_nonces {
					let (s, p) = musig::nonce_pair(&cosign_key);
					secs.push(s);
					pubs.push(p);
				}
				(secs, pubs)
			};
			let req = SignedVtxoRequest {
				vtxo: VtxoRequest {
					policy: VtxoPolicy::new_pubkey(*UNSPENDABLE),
					amount: P2WSH_DUST,
				},
				//TODO(stevenroose) try remove
				cosign_pubkey: Some(cosign_key.public_key()),
			};
			self.all_outputs.push(VtxoParticipant {
				req: req.clone(),
				nonces: cosign_pub_nonces.clone(),
			});
			Some((req, cosign_key, cosign_sec_nonces, cosign_pub_nonces))
		} else {
			None
		};

		let vtxos_spec = VtxoTreeSpec::new(
			self.all_outputs.iter().map(|p| p.req.clone()).collect(),
			srv.server_pubkey,
			expiry_height,
			srv.config.vtxo_exit_delta,
			vec![self.cosign_key.public_key()],
		);
		//TODO(stevenroose) this is inefficient, improve this with direct getter
		let nb_nodes = vtxos_spec.nb_nodes();
		assert!(nb_nodes <= srv.config.nb_round_nonces);
		let connector_key = Keypair::new(&*SECP, &mut rand::thread_rng());
		let connector_output = ConnectorChain::output(
			self.all_inputs.len(), connector_key.public_key(),
		);

		// Build round tx.
		//TODO(stevenroose) think about if we can release lock sooner
		let trusted_height = match srv.config.round_tx_untrusted_input_confirmations {
			0 => None,
			n => Some(tip.saturating_sub(n as BlockHeight - 1)),
		};
		let mut wallet_lock = srv.rounds_wallet.clone().lock_owned().await;
		let round_tx_psbt = {
			let unavailable = wallet_lock.unavailable_outputs(trusted_height);
			let mut b = wallet_lock.build_tx();
			b.ordering(bdk_wallet::TxOrdering::Untouched);
			b.current_height(tip);
			b.unspendable(unavailable);
			// NB: manual selection overrides unspendable
			if let Some(ref common_round_tx_input) = self.common_round_tx_input {
				let utxo = common_round_tx_input.utxo().clone();
				b.add_utxo(utxo).map_err(|e| RoundError::Recoverable(e.into()))?;
			}
			// NB: order is important here, we need to respect `ROUND_TX_VTXO_TREE_VOUT` and `ROUND_TX_CONNECTOR_VOUT`
			b.add_recipient(vtxos_spec.funding_tx_script_pubkey(), vtxos_spec.total_required_value());
			b.add_recipient(connector_output.script_pubkey, connector_output.value);
			for offb in &self.all_offboards {
				b.add_recipient(offb.script_pubkey.clone(), offb.amount);
			}
			b.fee_rate(srv.config.round_tx_feerate);
			match b.finish().context("bdk failed to create round tx") {
				Ok(psbt) => psbt,
				Err(e) => return Err(RoundError::Recoverable(e)),
			}
		};
		let res = round_tx_psbt.clone().extract_tx().context("failed to extract tx from psbt");
		let unsigned_round_tx = match res {
			Ok(tx) => tx,
			Err(e) => return Err(RoundError::Recoverable(e)),
		};

		let common_round_tx_input = match self.common_round_tx_input {
			Some(ref input) => input.clone(),
			None => {
				let common_round_tx_input = unsigned_round_tx.input.first()
					.expect("funded round tx should have an input").previous_output;
				wallet_lock.lock_wallet_utxo(common_round_tx_input)
			}
		};

		let round_txid = unsigned_round_tx.compute_txid();
		let vtxos_utxo = OutPoint::new(round_txid, ROUND_TX_VTXO_TREE_VOUT);

		// Generate vtxo nonces and combine with user's nonces.
		let (cosign_sec_nonces, cosign_pub_nonces) = {
			let mut secs = Vec::with_capacity(nb_nodes);
			let mut pubs = Vec::with_capacity(nb_nodes);
			for _ in 0..nb_nodes {
				let (s, p) = musig::nonce_pair(&self.cosign_key);
				secs.push(s);
				pubs.push(p);
			}
			(secs, pubs)
		};
		let user_cosign_nonces = self.all_outputs.iter().cloned()
			.filter(|r| r.req.cosign_pubkey.is_some())
			.map(|r| (r.req.cosign_pubkey.unwrap(), r.nonces))
			.collect::<HashMap<_, _>>();
		let res = vtxos_spec.calculate_cosign_agg_nonces(
			&user_cosign_nonces, &[&cosign_pub_nonces],
		);
		let cosign_agg_nonces = match res {
			Ok(n) => n,
			Err(e) => return Err(RoundError::Recoverable(anyhow!(
				"error calculating cosign agg nonces: {}", e,
			))),
		};

		server_rslog!(ConstructingRoundVtxoTree, round_step,
			tip_block_height: tip,
			vtxo_expiry_block_height: expiry_height,
		);
		telemetry::set_round_step_duration(round_step);

		let round_step = self.next_step(RoundStep::SendingVtxoProposal);
		let _span = trace_round_step(&round_step);

		// Send out a vtxo proposal to signers.
		srv.rounds.broadcast_event(RoundEvent::VtxoProposal(VtxoProposal {
			round_seq: round_step.round_seq(),
			attempt_seq: round_step.attempt_seq(),
			unsigned_round_tx: unsigned_round_tx.clone(),
			vtxos_spec: vtxos_spec.clone(),
			cosign_agg_nonces: cosign_agg_nonces.clone(),
		}));

		let unsigned_vtxo_tree = vtxos_spec.into_unsigned_tree(vtxos_utxo);
		let mut cosign_part_sigs = HashMap::with_capacity(unsigned_vtxo_tree.nb_leaves());
		let mut proceed = false;

		// first add our own change (or dummy) vtxo
		if let Some((req, pk, sec, _pub)) = change_vtxo.take() {
			let idx = unsigned_vtxo_tree.spec.leaf_idx_of(&req).expect("have change request");
			let sigs = unsigned_vtxo_tree.cosign_branch(&cosign_agg_nonces, idx, &pk, sec)
				.expect("correct key");
			cosign_part_sigs.insert(pk.public_key(), sigs);
			proceed = true;
		}

		server_rslog!(SendVtxoProposal, round_step);
		telemetry::set_round_step_duration(round_step);

		Ok(SigningVtxoTree {
			round_data: self.round_data,
			expiry_height,
			cosign_key: self.cosign_key,
			cosign_sec_nonces,
			cosign_pub_nonces,
			cosign_agg_nonces,
			all_inputs: self.all_inputs,
			locked_inputs: self.locked_inputs,
			cosign_part_sigs,
			unsigned_vtxo_tree,
			wallet_lock,
			round_tx_psbt,
			round_txid,
			connector_key,
			user_cosign_nonces,
			inputs_per_cosigner: self.inputs_per_cosigner,
			common_round_tx_input,
			round_step,
			proceed,
		})
	}

	fn total_input_amount(&self) -> Amount {
		self.all_inputs.values()
			.map(|vtxo| vtxo.amount())
			.sum()
	}
}

pub struct SigningVtxoTree {
	round_data: RoundData,
	expiry_height: BlockHeight,

	cosign_key: Keypair,
	cosign_sec_nonces: Vec<SecretNonce>,
	cosign_pub_nonces: Vec<PublicNonce>,
	cosign_part_sigs: HashMap<PublicKey, Vec<musig::PartialSignature>>,
	cosign_agg_nonces: Vec<musig::AggregatedNonce>,
	unsigned_vtxo_tree: UnsignedVtxoTree,
	wallet_lock: OwnedMutexGuard<PersistedWallet>,
	round_tx_psbt: Psbt,
	round_txid: Txid,
	connector_key: Keypair,

	// data from earlier
	all_inputs: HashMap<VtxoId, Vtxo>,
	user_cosign_nonces: HashMap<PublicKey, Vec<musig::PublicNonce>>,
	inputs_per_cosigner: HashMap<PublicKey, Vec<VtxoId>>,
	/// All inputs that have participated, but might have dropped out.
	locked_inputs: OwnedVtxoFluxLock,

	common_round_tx_input: WalletUtxoGuard,

	round_step: TimedRoundStep,

	proceed: bool,
}

impl SigningVtxoTree {
	fn next_step(&mut self, step: RoundStep) -> TimedRoundStep {
		self.round_step = self.round_step.proceed(step);
		self.round_step
	}

	pub fn register_signature(
		&mut self,
		pubkey: PublicKey,
		signatures: Vec<musig::PartialSignature>,
	) -> anyhow::Result<()> {
		// Check for duplicates.
		if self.cosign_part_sigs.contains_key(&pubkey) {
			trace!("User with pubkey {} submitted partial vtxo sigs again", pubkey);
			bail!("duplicate signatures for pubkey");
		}

		let req = match self.unsigned_vtxo_tree.spec.vtxos.iter().find(|v| v.cosign_pubkey == Some(pubkey)) {
			Some(r) => r,
			None => {
				trace!("Received signatures from non-signer: {}", pubkey);
				bail!("pubkey is not part of cosigner group");
			},
		};
		client_rslog!(RoundVtxoSignaturesRegistered, self.round_step,
			nb_vtxo_signatures: signatures.len(),
			cosigner: pubkey,
		);

		let res = self.unsigned_vtxo_tree.verify_branch_cosign_partial_sigs(
			&self.cosign_agg_nonces,
			req,
			&self.user_cosign_nonces.get(&pubkey).expect("vtxo part of round"),
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

	fn restart(self) -> CollectingPayments {
		let mut allowed_inputs = self.all_inputs.keys().copied().collect::<HashSet<_>>();
		for (pk, vtxos) in self.inputs_per_cosigner.iter() {
			if !self.cosign_part_sigs.contains_key(pk) {
				// Disallow all inputs by this cosigner.
				server_rslog!(DroppingLateVtxoSignatureVtxos, self.round_step,
					disallowed_vtxos: vtxos.clone(),
				);
				for id in vtxos {
					allowed_inputs.remove(id);
				}
			}
		}
		CollectingPayments::new(
			self.round_step.round_seq(),
			self.round_step.attempt_seq() + 1,
			self.round_data,
			self.locked_inputs,
			Some(allowed_inputs),
			Some(self.common_round_tx_input),
		)
	}

	fn progress(mut self, srv: &Server) -> SigningForfeits {
		// Combine the vtxo signatures.
		let round_step = self.next_step(RoundStep::CombineVtxoSignatures);
		let _span = trace_round_step(&round_step);

		let srv_cosign_sigs = self.unsigned_vtxo_tree.cosign_tree(
			&self.cosign_agg_nonces,
			&self.cosign_key,
			self.cosign_sec_nonces,
		);
		debug_assert_eq!(self.unsigned_vtxo_tree.verify_global_cosign_partial_sigs(
			self.cosign_key.public_key(),
			&self.cosign_agg_nonces,
			&self.cosign_pub_nonces,
			&srv_cosign_sigs,
		), Ok(()));
		let cosign_sigs = self.unsigned_vtxo_tree.combine_partial_signatures(
			&self.cosign_agg_nonces,
			&self.cosign_part_sigs,
			&[&srv_cosign_sigs],
		).expect("failed to combine partial vtxo cosign signatures: should have checked partials");
		debug_assert_eq!(self.unsigned_vtxo_tree.verify_cosign_sigs(&cosign_sigs), Ok(()));

		// Then construct the final signed vtxo tree.
		let signed_vtxos = self.unsigned_vtxo_tree
			.into_signed_tree(cosign_sigs)
			.into_cached_tree();

		// ****************************************************************
		// * Broadcast signed vtxo tree and gather forfeit signatures
		// ****************************************************************

		// Prepare nonces for forfeit txs.
		// We need to prepare N nonces for each of N inputs.
		let mut forfeit_pub_nonces = HashMap::with_capacity(self.all_inputs.len());
		let mut forfeit_sec_nonces = HashMap::with_capacity(self.all_inputs.len());
		for id in self.all_inputs.keys() {
			let mut secs = Vec::with_capacity(self.all_inputs.len());
			let mut pubs = Vec::with_capacity(self.all_inputs.len());
			for _ in 0..self.all_inputs.len() {
				let (s, p) = musig::nonce_pair(&srv.server_key.leak_ref());
				secs.push(s);
				pubs.push(p);
			}
			forfeit_pub_nonces.insert(*id, pubs);
			forfeit_sec_nonces.insert(*id, secs);
		}

		// Send out a round proposal to signers.
		srv.rounds.broadcast_event(RoundEvent::RoundProposal(RoundProposal {
			round_seq: round_step.round_seq(),
			attempt_seq: round_step.attempt_seq(),
			cosign_sigs: signed_vtxos.spec.cosign_sigs.clone(),
			forfeit_nonces: forfeit_pub_nonces.clone(),
			connector_pubkey: self.connector_key.public_key(),
		}));

		let conns_utxo = OutPoint::new(self.round_txid, ROUND_TX_CONNECTOR_VOUT);
		let connectors = ConnectorChain::new(
			self.all_inputs.len(), conns_utxo, self.connector_key.public_key(),
		);

		server_rslog!(CreatedSignedVtxoTree, round_step,
			nb_vtxo_signatures: signed_vtxos.spec.cosign_sigs.len(),
		);
		telemetry::set_round_step_duration(round_step);

		SigningForfeits {
			round_data: self.round_data,
			expiry_height: self.expiry_height,
			forfeit_sec_nonces: Some(forfeit_sec_nonces),
			forfeit_pub_nonces,
			forfeit_part_sigs: HashMap::with_capacity(self.all_inputs.len()),
			signed_vtxos,
			all_inputs: self.all_inputs,
			locked_inputs: self.locked_inputs,
			connectors,
			connector_key: self.connector_key,
			wallet_lock: self.wallet_lock,
			round_tx_psbt: self.round_tx_psbt,
			common_round_tx_input: self.common_round_tx_input,
			round_step,
			proceed: false,
		}
	}
}

pub struct SigningForfeits {
	round_data: RoundData,
	expiry_height: BlockHeight,

	forfeit_sec_nonces: Option<HashMap<VtxoId, Vec<SecretNonce>>>,
	forfeit_pub_nonces: HashMap<VtxoId, Vec<PublicNonce>>,
	forfeit_part_sigs: HashMap<VtxoId, (Vec<musig::PublicNonce>, Vec<musig::PartialSignature>)>,

	// data from earlier
	signed_vtxos: CachedSignedVtxoTree,
	all_inputs: HashMap<VtxoId, Vtxo>,
	/// All inputs that have participated, but might have dropped out.
	locked_inputs: OwnedVtxoFluxLock,

	// other public data
	connectors: ConnectorChain,
	connector_key: Keypair,

	wallet_lock: OwnedMutexGuard<PersistedWallet>,
	round_tx_psbt: Psbt,
	common_round_tx_input: WalletUtxoGuard,

	round_step: TimedRoundStep,

	proceed: bool,
}

impl SigningForfeits {
	fn round_seq(&self) -> RoundSeq {
		self.round_step.round_seq()
	}

	fn attempt_seq(&self) -> usize {
		self.round_step.attempt_seq()
	}

	fn next_step(&mut self, step: RoundStep) -> TimedRoundStep {
		self.round_step = self.round_step.proceed(step);
		self.round_step
	}

	pub fn register_forfeits(
		&mut self,
		signatures: Vec<(VtxoId, Vec<musig::PublicNonce>, Vec<musig::PartialSignature>)>,
	) -> anyhow::Result<()> {
		client_rslog!(ReceivedForfeitSignatures, self.round_step,
			nb_forfeits: signatures.len(),
			vtxo_ids: signatures.iter().map(|v| v.0).collect::<Vec<_>>(),
		);

		for (id, nonces, sigs) in signatures {
			if let Some(vtxo) = self.all_inputs.get(&id) {
				match validate_forfeit_sigs(
					vtxo,
					&self.connectors,
					self.connector_key.public_key(),
					self.forfeit_pub_nonces.get(&id).expect("vtxo part of round"),
					&nonces,
					&sigs,
				) {
					Ok(()) => { self.forfeit_part_sigs.insert(id, (nonces, sigs)); },
					Err(e) => debug!("Invalid forfeit sigs for {}: {}", id, e),
				}
			} else {
				client_rslog!(UnknownForfeitSignature, self.round_step, vtxo_id: id);
			}
		}

		// Check whether we have all and can skip the loop.
		if self.forfeit_part_sigs.len() == self.all_inputs.len() {
			self.proceed = true;
		}
		Ok(())
	}

	fn restart_missing_forfeits(self, missing: Option<HashSet<VtxoId>>) -> CollectingPayments {
		let allowed_inputs = if let Some(missing) = missing {
			for input in &missing {
				server_rslog!(MissingForfeits, self.round_step, input: *input);
			}

			self.all_inputs.keys().copied()
				.filter(|v| !missing.contains(v))
				.collect()
		} else {
			self.all_inputs.keys().copied().filter(|v| {
				if !self.forfeit_part_sigs.contains_key(v) {
					server_rslog!(MissingForfeits, self.round_step, input: *v);
					false
				} else {
					true
				}
			}).collect()
		};
		server_rslog!(RestartMissingForfeits, self.round_step);
		CollectingPayments::new(
			self.round_seq(),
			self.attempt_seq() + 1,
			self.round_data,
			self.locked_inputs,
			Some(allowed_inputs),
			Some(self.common_round_tx_input),
		)
	}

	fn check_forfeits(&self) -> Option<HashSet<VtxoId>> {
		// Check for partial signatures.
		let mut missing = HashSet::new();
		for id in self.all_inputs.keys() {
			if !self.forfeit_part_sigs.contains_key(id) {
				missing.insert(*id);
			}
		}

		if !missing.is_empty() {
			Some(missing)
		} else {
			None
		}
	}

	async fn finish(
		mut self,
		srv: &Server,
	) -> Result<(), RoundError> {
		// Sign the on-chain tx.
		let round_step = self.next_step(RoundStep::SignOnChainTransaction);
		let signed_round_tx = match self.wallet_lock.finish_tx(self.round_tx_psbt) {
			Ok(tx) => tx,
			Err(e) => return Err(RoundError::Recoverable(e.context("round tx signing error"))),
		};
		self.wallet_lock.commit_tx(&signed_round_tx);
		if let Err(e) = self.wallet_lock.persist().await {
			// Failing to persist the tx data at this point means that we might
			// accidentally re-use certain inputs if we reboot the server.
			// We keep the change set in the wallet if this happens.
			warn!("Failed to persist BDK wallet to db: {:?}", e);
		}

		drop(self.wallet_lock); // we no longer need the lock
		let signed_round_tx = srv.tx_nursery.broadcast_tx(signed_round_tx).await
			.map_err(|err| RoundError::Fatal(err.context("failed to broadcast round")))?;

		let round_txid = signed_round_tx.txid;

		// Send out the finished round to users.
		trace!("Sending out finish event.");
		srv.rounds.broadcast_event(RoundEvent::Finished(RoundFinished {
			round_seq: round_step.round_seq(),
			attempt_seq: round_step.attempt_seq(),
			signed_round_tx: signed_round_tx.tx.clone(),
		}));

		server_rslog!(BroadcastedFinalizedRoundTransaction, round_step,
			txid: round_txid,
		);
		telemetry::set_round_step_duration(round_step);

		let round_step = round_step.proceed(RoundStep::Persist);
		let mut span = trace_round_step(&round_step);
		span.set_int_attr("signed_vtxo_count", self.signed_vtxos.nb_leaves());
		span.set_int_attr("connectors_count", self.connectors.len());
		span.set_str_attr(telemetry::ATTRIBUTE_ROUND_ID, round_txid);

		trace!("Storing round result");
		if log_enabled!(RoundVtxoCreated::LEVEL) {
			for vtxo in self.signed_vtxos.all_vtxos() {
				server_rslog!(RoundVtxoCreated, round_step,
					vtxo_id: vtxo.id(),
					vtxo_type: vtxo.policy().policy_type(),
				);
			}
		}
		let mut sec_nonces = self.forfeit_sec_nonces.take().unwrap();
		let forfeit_vtxos = self.all_inputs.iter().map(|(id, vtxo)| {
			server_rslog!(StoringForfeitVtxo, round_step, out_point: vtxo.point());
			let (user_nonces, user_part_sigs) = self.forfeit_part_sigs.remove(id)
				.expect("missing part sigs");
			let forfeit_state = ForfeitState {
				round_id: round_txid.into(),
				user_nonces, user_part_sigs,
				pub_nonces: self.forfeit_pub_nonces.remove(id).expect("missing vtxo"),
				sec_nonces: sec_nonces.remove(id).expect("missing vtxo").into_iter()
					.map(|x| Secret::new(DangerousSecretNonce::new(x)))
					.collect(),
			};
			(*id, forfeit_state)
		}).collect();
		let result = srv.db.finish_round(
			round_step.round_seq(),
			&signed_round_tx.tx,
			&self.signed_vtxos,
			&self.connector_key.secret_key(),
			forfeit_vtxos,
		).await;
		telemetry::set_round_step_duration(round_step);
		if let Err(e) = result {
			server_rslog!(FatalStoringRound, round_step,
				error: format!("{:?}", e),
				signed_tx: serialize(&signed_round_tx.tx),
				vtxo_tree: self.signed_vtxos.spec.serialize(),
				connector_key: self.connector_key.secret_key(),
				forfeit_vtxos: self.all_inputs.keys().copied().collect(),
			);
			return Err(RoundError::Fatal(e));
		}

		server_rslog!(RoundFinished, round_step,
			txid: round_txid,
			vtxo_expiry_block_height: self.expiry_height,
			nb_input_vtxos: self.all_inputs.len(),
		);

		Ok(())
	}
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum RoundStateKind {
	/// see [`CollectingPayments`]
	CollectingPayments,
	/// see [`SigningVtxoTree`]
	SigningVtxoTree,
	/// see [`SigningForfeits`]
	SigningForfeits,
	FinishedEmpty,
	FinishedAbandoned,
	FinishedSuccess,
	FinishedError,
}

impl RoundStateKind {
	pub fn as_str(&self) -> &'static str {
		match self {
			RoundStateKind::CollectingPayments => "CollectingPayments",
			RoundStateKind::SigningVtxoTree => "SigningVtxoTree",
			RoundStateKind::SigningForfeits => "SigningForfeits",
			RoundStateKind::FinishedEmpty => "FinishedEmpty",
			RoundStateKind::FinishedAbandoned => "FinishedAbandoned",
			RoundStateKind::FinishedSuccess => "FinishedSuccess",
			RoundStateKind::FinishedError => "FinishedError",
		}
	}
	pub fn get_all() -> &'static [RoundStateKind] {
		&[
			RoundStateKind::CollectingPayments,
			RoundStateKind::SigningVtxoTree,
			RoundStateKind::SigningForfeits,
			RoundStateKind::FinishedEmpty,
			RoundStateKind::FinishedAbandoned,
			RoundStateKind::FinishedSuccess,
			RoundStateKind::FinishedError,
		]
	}
}

enum RoundState {
	CollectingPayments(CollectingPayments),
	SigningVtxoTree(SigningVtxoTree),
	SigningForfeits(SigningForfeits),
	Finished(RoundResult),
}

impl RoundState {
	fn kind(&self) -> RoundStateKind {
		match &self {
			Self::CollectingPayments(_) => RoundStateKind::CollectingPayments,
			Self::SigningVtxoTree(_) => RoundStateKind::SigningVtxoTree,
			Self::SigningForfeits(_) => RoundStateKind::SigningForfeits,
			Self::Finished(result) => {
				match result {
					RoundResult::Empty => RoundStateKind::FinishedEmpty,
					RoundResult::Abandoned => RoundStateKind::FinishedAbandoned,
					RoundResult::Success => RoundStateKind::FinishedSuccess,
					RoundResult::Err(_) => RoundStateKind::FinishedError,
				}
			}
		}
	}

	fn proceed(&self) -> bool {
		match self {
			Self::CollectingPayments(s) => s.proceed,
			Self::SigningVtxoTree(s) => s.proceed,
			Self::SigningForfeits(s) => s.proceed,
			Self::Finished(_) => false,
		}
	}

	fn collecting_payments(&mut self) -> &mut CollectingPayments {
		match self {
			RoundState::CollectingPayments(s) => s,
			_ => panic!("wrong state"),
		}
	}
	fn signing_vtxo_tree(&mut self) -> &mut SigningVtxoTree {
		match self {
			RoundState::SigningVtxoTree(s) => s,
			_ => panic!("wrong state"),
		}
	}
	fn into_signing_vtxo_tree(self) -> SigningVtxoTree {
		match self {
			RoundState::SigningVtxoTree(s) => s,
			_ => panic!("wrong state"),
		}
	}
	fn signing_forfeits(&mut self) -> &mut SigningForfeits {
		match self {
			RoundState::SigningForfeits(s) => s,
			_ => panic!("wrong state"),
		}
	}
	fn into_signing_forfeits(self) -> SigningForfeits {
		match self {
			RoundState::SigningForfeits(s) => s,
			_ => panic!("wrong state"),
		}
	}
	fn into_finished(self, result: RoundResult) -> Self {
		match self {
			RoundState::CollectingPayments(_)
			| RoundState::SigningVtxoTree(_)
			| RoundState::SigningForfeits(_) => RoundState::Finished(result),
			_ => panic!("wrong state"),
		}
	}

	fn result(self) -> Option<RoundResult> {
		match self {
			RoundState::CollectingPayments(_)
			| RoundState::SigningVtxoTree(_)
			| RoundState::SigningForfeits(_) => None,
			RoundState::Finished(result) => Some(result),
		}
	}

	async fn progress(self, srv: &Server) -> Result<Self, RoundError> {
		match self {
			Self::CollectingPayments(s) => Ok(s.progress(srv).await?.into()),
			Self::SigningVtxoTree(s) => Ok(s.progress(srv).into()),
			Self::SigningForfeits(_) => unreachable!("can't progress from signing forfeits"),
			Self::Finished(_) => unreachable!("can't progress from a final state"),
		}
	}

}

impl From<CollectingPayments> for RoundState {
	fn from(s: CollectingPayments) -> RoundState {
		RoundState::CollectingPayments(s)
	}
}

impl From<SigningVtxoTree> for RoundState {
	fn from(s: SigningVtxoTree) -> RoundState {
		RoundState::SigningVtxoTree(s)
	}
}

impl From<SigningForfeits> for RoundState {
	fn from(s: SigningForfeits) -> RoundState {
		RoundState::SigningForfeits(s)
	}
}

#[derive(Debug)]
enum RoundError {
	/// An error occurred, but we can just restart.
	Recoverable(anyhow::Error),
	/// A fatal error occurred that we can't recover from. Halt operations.
	Fatal(anyhow::Error),
}

#[derive(Debug)]
enum RoundResult {
	/// Nothing to do, skipping round.
	Empty,
	/// All users abandoned the round.
	Abandoned,
	/// Round finished with success.
	Success,
	/// Error.
	Err(RoundError),
}

impl From<RoundError> for RoundResult {
	fn from(e: RoundError) -> Self {
		Self::Err(e)
	}
}

async fn perform_round(
	srv: &Arc<Server>,
	round_input_rx: &mut mpsc::UnboundedReceiver<(RoundInput, oneshot::Sender<anyhow::Error>)>,
	round_seq: RoundSeq,
) -> RoundResult {
	let tracer_provider = global::tracer_provider().tracer(telemetry::Captaind::TRACER);

	let mut span = tracer_provider
		.span_builder(telemetry::TRACE_RUN_ROUND)
		.with_kind(SpanKind::Server)
		.start(&tracer_provider);
	span.set_int_attr(telemetry::ATTRIBUTE_ROUND_SEQ, round_seq.inner());

	let parent_context = opentelemetry::Context::current_with_span(span);

	let tracing_span = info_span!(telemetry::TRACE_RUN_ROUND);
	let _ = tracing_span.set_parent(parent_context.clone())
		.map_err(|e| error!("error setting tracing span ctx parent: {}", e));

	// this is to make sure slog has access to the span information.
	let _guard = tracing_span.enter();

	slog!(RoundStarted, round_seq);
	telemetry::set_round_seq(round_seq);

	let offboard_feerate = srv.config.round_tx_feerate;

	// Allocate this data once per round so that we can keep them
	// Perhaps we could even keep allocations between all rounds, but time
	// in between attempts is way more critial than in between rounds.

	let round_data = RoundData {
		// The maximum number of output vtxos per round based on the max number
		// of vtxo tree nonces we require users to provide.
		max_output_vtxos: (srv.config.nb_round_nonces * 3 ) / 4,
		nb_vtxo_nonces: srv.config.nb_round_nonces,
		max_vtxo_amount: srv.config.max_vtxo_amount,
		offboard_feerate,
	};

	let mut round_state = RoundState::CollectingPayments(CollectingPayments::new(
		round_seq, 0, round_data, srv.vtxos_in_flux.empty_lock().into_owned(), None, None,
	));
	telemetry::set_round_state(round_state.kind());

	// In this loop we will try to finish the round and make new attempts.
	'attempt: loop {
		if let Err(e) = srv.rounds_wallet.lock().await.sync(&srv.bitcoind, false).await {
			slog!(RoundSyncError, error: format!("{:?}", e));
		}

		let state = round_state.collecting_payments();

		// Release all vtxos in flux from a previous attempt
		state.locked_inputs.release_all();

		let mut span = trace_round_step(&state.round_step);
		span.set_bytes_attr("challenge", state.round_attempt_challenge.inner().as_slice());

		telemetry::set_round_attempt(state.attempt_seq());

		srv.rounds.broadcast_event(RoundEvent::Attempt(RoundAttempt {
			round_seq,
			attempt_seq: state.attempt_seq(),
			challenge: state.round_attempt_challenge,
		}));

		server_rslog!(AttemptingRound, state.round_step,
			challenge: state.round_attempt_challenge.inner().to_vec(),
		);
		telemetry::set_round_step_duration(state.round_step);

		// Start receiving payments.
		let round_step = state.next_step(RoundStep::ReceivePayments);
		let _span = trace_round_step(&round_step);

		tokio::pin! { let timeout = tokio::time::sleep(srv.config.round_submit_time); }
		'receive: loop {
			tokio::select! {
				() = &mut timeout => break 'receive,
				input = round_input_rx.recv() => {
					let (input, tx) = input.expect("broken channel");

					let res = match input {
						RoundInput::RegisterPayment { inputs, vtxo_requests, offboards } => {
							state.process_payment(
								srv, inputs, vtxo_requests, offboards,
							).await.map_err(|e| {
								debug!("error processing payment: {e}");
								e
							})
						},
						_ => badarg!("unexpected message. current step is payment registration"),
					};

					if let Err(e) = res {
						tx.send(e).expect("broken channel");
						continue 'receive;
					}

					if state.proceed {
						break 'receive;
					}
				}
			}
		}

		let input_volume = state.total_input_amount();
		let input_count = state.all_inputs.len();
		let output_count = state.all_outputs.len();
		let offboard_count = state.all_offboards.len();

		server_rslog!(ReceivedRoundPayments, round_step,
			max_round_submit_time: srv.config.round_submit_time,
			input_volume,
			input_count,
			output_count,
			offboard_count,
		);
		telemetry::set_round_step_duration(round_step);
		telemetry::set_round_metrics(input_volume, input_count, output_count, offboard_count);

		if !state.have_payments() {
			server_rslog!(NoRoundPayments, round_step,
				max_round_submit_time: srv.config.round_submit_time,
			);

			round_state = round_state.into_finished(RoundResult::Empty);

			telemetry::set_round_state(round_state.kind());

			return round_state.result().unwrap();
		}

		let mut span = tracer_provider
			.span_builder(telemetry::TRACE_RUN_ROUND_POPULATED)
			.with_kind(SpanKind::Internal)
			.start_with_context(&tracer_provider, &parent_context);
		span.set_int_attr(telemetry::ATTRIBUTE_ROUND_SEQ, round_seq.inner());
		span.set_int_attr(telemetry::ATTRIBUTE_ATTEMPT_SEQ, state.attempt_seq());
		span.set_int_attr("input_volume", input_volume.to_sat());
		span.set_int_attr("input_count", input_count);
		span.set_int_attr("output_count", output_count);
		span.set_int_attr("offboard_count", offboard_count);


		// ****************************************************************
		// * Vtxo tree construction and signing
		// *
		// * - We will always store vtxo tx data from top to bottom,
		// *   meaning from the root tx down to the leaves.
		// ****************************************************************
		round_state = match round_state.progress(srv).await {
			Ok(s) => s,
			Err(e) => return {
				round_state = RoundState::Finished(RoundResult::Err(e));

				telemetry::set_round_state(round_state.kind());

				round_state.result().unwrap()
			},
		};

		// Wait for signatures from users
		let round_step = round_state.signing_vtxo_tree().next_step(RoundStep::ReceiveVtxoSignatures);
		let _span = trace_round_step(&round_step);

		tokio::pin! { let timeout = tokio::time::sleep(srv.config.round_sign_time); }
		'receive: loop {
			if round_state.proceed() {
				break 'receive;
			}
			tokio::select! {
				_ = &mut timeout => {
					warn!("Timed out receiving vtxo partial signatures.");
					let new = round_state.into_signing_vtxo_tree().restart();
					let need_new_round = new.need_new_round();
					round_state = new.into();

					if need_new_round {
						server_rslog!(NeedNewRound, round_step,
							max_round_sign_time: srv.config.round_sign_time,
						);

						round_state = round_state.into_finished(RoundResult::Abandoned);

						telemetry::set_round_state(round_state.kind());

						return round_state.result().unwrap();
					}

					continue 'attempt;
				},
				input = round_input_rx.recv() => {
					let state = round_state.signing_vtxo_tree();
					let round_step = state.round_step;
					let (input, tx) = input.expect("broken channel");

					let res = match input {
						RoundInput::VtxoSignatures { pubkey, signatures } => {
							state.register_signature(pubkey, signatures).map_err(|e| {
								client_rslog!(VtxoSignatureRegistrationFailed, round_step,
									error: e.to_string(),
								);
								e
							})
						},
						RoundInput::RegisterPayment { .. } => {
							badarg!("Round already started. Message arrived late or round was full.")
						},
						_ => badarg!("unexpected message. current step is vtxo signatures submission"),
					};

					if let Err(e) = res {
						tx.send(e).expect("broken channel");
						continue 'receive;
					}

					if round_state.proceed() {
						break 'receive;
					}
				}
			}
		}

		server_rslog!(ReceivedRoundVtxoSignatures, round_step,
			max_round_sign_time: srv.config.round_sign_time,
		);
		telemetry::set_round_step_duration(round_step);

		let round_step = round_state.signing_vtxo_tree().next_step(RoundStep::ConstructRoundProposal);
		let _span = trace_round_step(&round_step);

		round_state = match round_state.progress(&srv).await {
			Ok(s) => s,
			Err(e) => return {
				round_state = RoundState::Finished(RoundResult::Err(e));

				telemetry::set_round_state(round_state.kind());

				round_state.result().unwrap()
			},
		};

		server_rslog!(SendVtxoProposal, round_step);
		telemetry::set_round_step_duration(round_step);

		// Wait for signatures from users.
		let round_step = round_state.signing_forfeits().next_step(RoundStep::ReceiveForfeitSignatures);
		let _span = trace_round_step(&round_step);

		tokio::pin! { let timeout = tokio::time::sleep(srv.config.round_sign_time); }

		'receive: loop {
			tokio::select! {
				_ = &mut timeout => {
					warn!("Timed out receiving forfeit signatures.");
					let new = round_state.into_signing_forfeits().restart_missing_forfeits(None);
					let need_new_round = new.need_new_round();
					round_state = new.into();

					if need_new_round {
						server_rslog!(NeedNewRound, round_step,
							max_round_sign_time: srv.config.round_sign_time,
						);

						round_state = round_state.into_finished(RoundResult::Abandoned);

						telemetry::set_round_state(round_state.kind());

						return round_state.result().unwrap();
					}

					continue 'attempt;
				}
				input = round_input_rx.recv() => {
					let (input, tx) = input.expect("broken channel");

					let res = match input {
						RoundInput::ForfeitSignatures { signatures } => {
							round_state
								.signing_forfeits()
								.register_forfeits(signatures)
								.map_err(|e| {
									client_rslog!(ForfeitRegistrationFailed, round_step,
										error: e.to_string(),
									);
									e
								})
						},
						RoundInput::RegisterPayment { .. } => {
							badarg!("Round already started. Message arrived late or round was full.")
						},
						_ => badarg!("unexpected message. current step is forfeit signatures submission"),
					};

					if let Err(e) = res {
						tx.send(e).expect("broken channel");
						continue 'receive;
					}

					if round_state.proceed() {
						break 'receive;
					}
				}
			}
		}

		server_rslog!(ReceivedRoundForfeits, round_step,
			max_round_sign_time: srv.config.round_sign_time,
			nb_forfeits: round_state.signing_forfeits().forfeit_part_sigs.len(),
		);
		telemetry::set_round_step_duration(round_step);

		let mut state = round_state.into_signing_forfeits();
		if let Some(missing) = state.check_forfeits() {
			round_state = RoundState::CollectingPayments(state.restart_missing_forfeits(Some(missing)));
			continue 'attempt;
		}

		// ****************************************************************
		// * Finish the round
		// ****************************************************************
		let round_step = state.next_step(RoundStep::FinalStage);
		let _span = trace_round_step(&round_step);

		round_state = match state.finish(&srv).await {
			Ok(()) => {
				RoundState::Finished(RoundResult::Success)
			},
			Err(e) => {
				RoundState::Finished(RoundResult::Err(e))
			},
		};

		telemetry::set_round_step_duration(round_step);
		telemetry::set_round_state(round_state.kind());

		return round_state.result().unwrap();
	}
}

fn trace_round_step(round_step: &TimedRoundStep) -> <BoxedTracer as Tracer>::Span {
	let tracer_provider = global::tracer_provider().tracer(telemetry::Captaind::TRACER);
	let parent_context = opentelemetry::Context::current();

	let mut span = tracer_provider
		.span_builder(round_step.as_str())
		.with_kind(SpanKind::Internal)
		.start_with_context(&tracer_provider, &parent_context);
	span.set_int_attr(telemetry::ATTRIBUTE_ROUND_SEQ, round_step.round_seq().inner());
	span.set_int_attr(telemetry::ATTRIBUTE_ATTEMPT_SEQ, round_step.attempt_seq());

	span
}

/// This method is called from a tokio thread so it can be long-lasting.
pub async fn run_round_coordinator(
	srv: &Arc<Server>,
	mut round_input_rx: mpsc::UnboundedReceiver<(RoundInput, oneshot::Sender<anyhow::Error>)>,
	mut round_trigger_rx: mpsc::Receiver<()>,
) -> anyhow::Result<()> {
	let _worker = srv.rtmgr.spawn_critical("RoundCoordinator");

	let mut round_seq = {
		// we offset by the time of our first release just to slightly reduce
		// absolute number size
		let epoch = UNIX_EPOCH + Duration::from_secs(1741015334);
		RoundSeq::new(SystemTime::now().duration_since(epoch).unwrap().as_secs())
	};

	loop {
		round_seq.increment();
		match perform_round(srv, &mut round_input_rx, round_seq).await {
			RoundResult::Success => {},
			RoundResult::Empty => {},
			// Round got abandoned, immediatelly start a new one.
			RoundResult::Abandoned => continue,
			// Internal error, retry immediatelly.
			RoundResult::Err(RoundError::Recoverable(e)) => {
				error!("Full round error stack trace: {:?}", e);
				slog!(RoundError, round_seq, error: format!("{:#}", e));
				continue;
			},
			// Fatal error, halt operations.
			RoundResult::Err(RoundError::Fatal(e)) => {
				error!("Fatal round error: {:?}", e);
				return Err(anyhow::anyhow!(e.to_string()))
			},
		}

		// We sync all wallets now so that we are sure it doesn't interfere with
		// rounds happening.
		if let Err(e) = srv.sync_wallets().await {
			slog!(RoundSyncError, error: format!("{:?}", e));
		};

		// Sleep for the round interval, but discard all incoming messages.
		tokio::pin! { let timeout = tokio::time::sleep(srv.config.round_interval); }
		'sleep: loop {
			tokio::select! {
				() = &mut timeout => break 'sleep,
				Some(()) = round_trigger_rx.recv() => {
					info!("Starting round based on admin RPC trigger");
					break 'sleep;
				},
				_ = round_input_rx.recv() => {},
				_ = srv.rtmgr.shutdown_signal() => {
					info!("Shutdown signal received. Exiting round coordinator loop...");
					return Ok(());
				}
			}
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	use std::collections::HashSet;
	use std::str::FromStr;

	use bitcoin::Amount;
	use bitcoin::secp256k1::{schnorr, PublicKey, Secp256k1};

	use ark::SignedVtxoRequest;
	use ark::vtxo::test::VTXO_VECTORS;

	use crate::flux::VtxosInFlux;

	lazy_static::lazy_static! {
		static ref TEST_SIG: schnorr::Signature = schnorr::Signature::from_str(
			"d1c14325e2fe4c44466be57376c4ea093e2d6524503d13be7511e57ec29e13508b507db59dfa9aede12e3e20d120013c268c3af0c7776e0e1e326ae6c9bbc171"
		).unwrap();
	}

	fn generate_pubkey() -> PublicKey {
		let secp = Secp256k1::new();
		let (_secret_key, pubkey) = secp.generate_keypair(&mut rand::thread_rng());
		pubkey
	}

	fn create_exit_participant(amount: u64, data: &RoundData) -> VtxoParticipant {
		let nonces = {
			let key = Keypair::new(&SECP, &mut rand::thread_rng());
			let (_sec, pb) = musig::nonce_pair(&key);
			vec![pb; data.nb_vtxo_nonces]
		};

		VtxoParticipant {
			req: SignedVtxoRequest {
				vtxo: VtxoRequest {
					policy: VtxoPolicy::new_pubkey(generate_pubkey()),
					amount: Amount::from_sat(amount),
				},
				cosign_pubkey: Some(generate_pubkey()),
			},
			nonces: nonces,
		}
	}

	fn create_collecting_payments(max_output_vtxos: usize) -> CollectingPayments {
		let round_data = RoundData {
			max_output_vtxos: max_output_vtxos,
			nb_vtxo_nonces: (max_output_vtxos * 4) / 3,
			offboard_feerate: FeeRate::ZERO,
			max_vtxo_amount: None,
		};
		CollectingPayments::new(0.into(), 0, round_data, OwnedVtxoFluxLock::dummy(), None, None)
	}

	#[test]
	fn test_register_payment_valid() {
		let mut state = create_collecting_payments(2);

		let inputs = vec![VTXO_VECTORS.round1_vtxo.clone()];
		let input_ids = inputs
			.iter()
			.map(|v| VtxoIdInput { vtxo_id: v.id(), ownership_proof: *TEST_SIG })
			.collect::<Vec<_>>();

		let outputs = vec![create_exit_participant(inputs[0].amount().to_sat(), &state.round_data)];

		state.validate_payment_data(&input_ids, &outputs).unwrap();
		state.validate_payment_amounts(&inputs, &outputs, &[]).unwrap();

		let flux = VtxosInFlux::new();
		state.register_payment(flux.empty_lock(), inputs, outputs.clone(), vec![]);
		assert_eq!(state.all_inputs.len(), 1);
		assert_eq!(state.all_outputs.len(), 1);
		assert_eq!(state.all_offboards.len(), 0);
		assert_eq!(state.inputs_per_cosigner.len(), 1);
		assert_eq!(1, state.inputs_per_cosigner.get(&outputs[0].req.cosign_pubkey.unwrap()).unwrap().len());
	}

	#[test]
	fn test_register_payment_output_exceeds_input() {
		let state = create_collecting_payments(2);

		let inputs = vec![VTXO_VECTORS.round1_vtxo.clone()];
		let input_ids = inputs
			.iter()
			.map(|v| VtxoIdInput { vtxo_id: v.id(), ownership_proof: *TEST_SIG })
			.collect::<Vec<_>>();

		let outputs = vec![create_exit_participant(
			inputs[0].amount().to_sat() + 100, &state.round_data,
		)];

		state.validate_payment_data(&input_ids, &outputs).unwrap();
		state.validate_payment_amounts(&inputs, &outputs, &[]).unwrap_err();
	}

	#[test]
	fn test_register_payment_duplicate_inputs() {
		let state = create_collecting_payments(2);

		let inputs = vec![
			VTXO_VECTORS.round1_vtxo.clone(), VTXO_VECTORS.round1_vtxo.clone(),
		];
		let input_ids = inputs
			.iter()
			.map(|v| VtxoIdInput { vtxo_id: v.id(), ownership_proof: *TEST_SIG })
			.collect::<Vec<_>>();

		let outputs = vec![create_exit_participant(
			inputs[0].amount().to_sat() - 100, &state.round_data,
		)];

		state.validate_payment_data(&input_ids, &outputs).unwrap_err();
	}

	#[test]
	fn test_register_payment_exceeds_max_outputs() {
		let state = create_collecting_payments(1);

		let inputs = vec![VTXO_VECTORS.round1_vtxo.clone(), VTXO_VECTORS.round1_vtxo.clone()];
		let input_ids = inputs
			.iter()
			.map(|v| VtxoIdInput { vtxo_id: v.id(), ownership_proof: *TEST_SIG })
			.collect::<Vec<_>>();

		let outputs = vec![
			create_exit_participant(100, &state.round_data),
			create_exit_participant(100, &state.round_data),
		];

		state.validate_payment_data(&input_ids, &outputs).unwrap_err();
	}

	#[test]
	fn test_register_payment_disallowed_input() {
		let mut state = create_collecting_payments(2);
		state.allowed_inputs = Some(HashSet::new());

		let inputs = vec![VTXO_VECTORS.round1_vtxo.clone()];
		let input_ids = inputs
			.iter()
			.map(|v| VtxoIdInput { vtxo_id: v.id(), ownership_proof: *TEST_SIG })
			.collect::<Vec<_>>();

		let outputs = vec![create_exit_participant(inputs[0].amount().to_sat(), &state.round_data)];

		state.validate_payment_data(&input_ids, &outputs).unwrap_err();
	}

	#[test]
	fn test_register_payment_duplicate_cosign_pubkey() {
		let mut state = create_collecting_payments(2);

		let inputs1 = vec![VTXO_VECTORS.round1_vtxo.clone()];
		let input_ids1 = inputs1
			.iter()
			.map(|v| VtxoIdInput { vtxo_id: v.id(), ownership_proof: *TEST_SIG })
			.collect::<Vec<_>>();
		let inputs2 = vec![VTXO_VECTORS.arkoor_htlc_out_vtxo.clone()];
		let input_ids2 = inputs2
			.iter()
			.map(|v| VtxoIdInput { vtxo_id: v.id(), ownership_proof: *TEST_SIG })
			.collect::<Vec<_>>();

		let outputs1 = vec![create_exit_participant(inputs1[0].amount().to_sat(), &state.round_data)];
		let mut outputs2 = vec![create_exit_participant(inputs2[0].amount().to_sat(), &state.round_data)];
		outputs2[0].req.cosign_pubkey = outputs1[0].req.cosign_pubkey;

		let flux = VtxosInFlux::new();
		state.validate_payment_data(&input_ids1, &outputs1).unwrap();
		state.register_payment(flux.empty_lock(), inputs1, outputs1, vec![]);
		state.validate_payment_data(&input_ids2, &outputs2).unwrap_err();
	}

	#[test]
	fn test_register_wrong_nb_cosign_nonces() {
		let state = create_collecting_payments(4);

		let inputs1 = vec![VTXO_VECTORS.round1_vtxo.clone()];
		let input_ids1 = inputs1
			.iter()
			.map(|v| VtxoIdInput { vtxo_id: v.id(), ownership_proof: *TEST_SIG })
			.collect::<Vec<_>>();

		let mut wrong_round_data = state.round_data.clone();
		wrong_round_data.nb_vtxo_nonces = state.round_data.nb_vtxo_nonces + 1;
		let outputs1 = vec![
			create_exit_participant(100, &wrong_round_data),
			create_exit_participant(100, &wrong_round_data),
		];

		state.validate_payment_data(&input_ids1, &outputs1).unwrap_err();
	}

	#[test]
	fn test_register_multiple_payments() {
		let mut state = create_collecting_payments(4);

		let inputs1 = vec![VTXO_VECTORS.round1_vtxo.clone()];
		let input_ids1 = inputs1
			.iter()
			.map(|v| VtxoIdInput { vtxo_id: v.id(), ownership_proof: *TEST_SIG })
			.collect::<Vec<_>>();
		let inputs2 = vec![VTXO_VECTORS.arkoor_htlc_out_vtxo.clone()];
		let input_ids2 = inputs2
			.iter()
			.map(|v| VtxoIdInput { vtxo_id: v.id(), ownership_proof: *TEST_SIG })
			.collect::<Vec<_>>();

		let outputs1 = vec![
			create_exit_participant(100, &state.round_data),
			create_exit_participant(100, &state.round_data),
		];
		let outputs2 = vec![
			create_exit_participant(100, &state.round_data),
			create_exit_participant(100, &state.round_data),
		];

		let flux = VtxosInFlux::new();
		state.validate_payment_data(&input_ids1, &outputs1).unwrap();
		state.register_payment(flux.empty_lock(), inputs1, outputs1.clone(), vec![]);
		state.validate_payment_data(&input_ids2, &outputs2).unwrap();
		state.register_payment(flux.empty_lock(), inputs2, outputs2.clone(), vec![]);

		assert_eq!(state.all_inputs.len(), 2);
		assert_eq!(state.all_outputs.len(), 4);
		assert_eq!(state.inputs_per_cosigner.len(), 4);
		assert!(state.inputs_per_cosigner.contains_key(&outputs1[0].req.cosign_pubkey.unwrap()));
		assert!(state.inputs_per_cosigner.contains_key(&outputs2[0].req.cosign_pubkey.unwrap()));
		assert!(state.proceed, "Proceed should be set after second registration");
	}
}

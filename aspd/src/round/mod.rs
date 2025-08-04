

use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Context;
use ark::vtxo::ServerHtlcRecvVtxoPolicy;
use aspd_log::{LogMsg, RoundVtxoCreated};
use aspd_rpc::protos;
use bitcoin::consensus::encode::serialize;
use bitcoin::{Amount, FeeRate, OutPoint, Psbt, Txid};
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{rand, Keypair, PublicKey};
use bitcoin_ext::bdk::WalletExt;
use bitcoin_ext::{BlockHeight, P2TR_DUST, P2WSH_DUST};
use log::{debug, error, info, log_enabled, trace, warn};
use opentelemetry::global;
use opentelemetry::trace::{SpanKind, TraceContextExt, Tracer, TracerProvider};
use tokio::sync::{mpsc, oneshot, OwnedMutexGuard};
use tokio::time::Instant;
use tracing::info_span;
use tracing_opentelemetry::OpenTelemetrySpanExt;

use ark::{
	OffboardRequest, ProtocolEncoding, SignedVtxoRequest, Vtxo, VtxoId, VtxoIdInput, VtxoPolicy,
	VtxoRequest,
};
use ark::connectors::ConnectorChain;
use ark::musig::{self, PublicNonce, SecretNonce};
use ark::rounds::{
	RoundAttempt, RoundEvent, RoundInfo, VtxoOwnershipChallenge,
	ROUND_TX_CONNECTOR_VOUT, ROUND_TX_VTXO_TREE_VOUT,
};
use ark::tree::signed::{CachedSignedVtxoTree, UnsignedVtxoTree, VtxoTreeSpec};

use crate::{database, Server, SECP};
use crate::database::model::{ForfeitState, DangerousSecretNonce, LightningHtlcSubscriptionStatus};
use crate::error::{AnyhowErrorExt, ContextExt, NotFound};
use crate::flux::{VtxoFluxLock, OwnedVtxoFluxLock};
use crate::telemetry::{self, SpanExt};
use crate::wallet::{BdkWalletExt, PersistedWallet};

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
	asp_nonces: &[musig::PublicNonce],
	user_nonces: &[musig::PublicNonce],
	part_sigs: &[musig::PartialSignature],
) -> anyhow::Result<()> {
	if user_nonces.len() != connectors.len() || part_sigs.len() != connectors.len() {
		bail!("not enough forfeit signatures provided");
	}

	let (key_agg, _) = musig::tweaked_key_agg(
		[vtxo.user_pubkey(), vtxo.asp_pubkey()],
		vtxo.output_taproot().tap_tweak().to_byte_array(),
	);
	for (idx, (conn, _tx)) in connectors.connectors().enumerate() {
		let (sighash, _tx) = ark::forfeit::forfeit_sighash_exit(
			vtxo, conn, connector_pk,
		);
		let part_sig = part_sigs.get(idx).expect("we checked length");
		let asp_nonce = asp_nonces.get(idx).expect("we checked length");
		let user_nonce = user_nonces.get(idx).expect("we checked length");
		let agg_nonce = musig::nonce_agg(&[&user_nonce, &asp_nonce]);

		let session = musig::Session::new(
			&musig::SECP,
			&key_agg,
			agg_nonce,
			&sighash.to_byte_array(),
		);
		let success = session.partial_verify(
			&musig::SECP,
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
				cosign_pubkey: PublicKey::from_slice(&v.cosign_pubkey)
					.badarg("malformed cosign pubkey")?,
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
	round_seq: usize,
	attempt_seq: usize,
	round_data: RoundData,

	vtxo_ownership_challenge: VtxoOwnershipChallenge,

	/// All inputs that have participated in the previous attempt.
	locked_inputs: OwnedVtxoFluxLock,

	cosign_key: Keypair,
	allowed_inputs: Option<HashSet<VtxoId>>,
	all_inputs: HashMap<VtxoId, Vtxo>,
	all_outputs: Vec<VtxoParticipant>,
	/// Keep track of which input vtxos belong to which inputs.
	inputs_per_cosigner: HashMap<PublicKey, Vec<VtxoId>>,
	all_offboards: Vec<OffboardRequest>,

	attempt_start: Instant,
	proceed: bool,
}

impl CollectingPayments {
	fn new(
		round_seq: usize,
		attempt_seq: usize,
		round_data: RoundData,
		locked_inputs: OwnedVtxoFluxLock,
		allowed_inputs: Option<HashSet<VtxoId>>,
	) -> CollectingPayments {
		CollectingPayments {
			round_seq,
			attempt_seq,
			round_data,
			vtxo_ownership_challenge: VtxoOwnershipChallenge::generate(),
			locked_inputs,
			allowed_inputs,

			// Generate a one-time use signing key.
			cosign_key: Keypair::new(&SECP, &mut rand::thread_rng()),

			all_inputs: HashMap::new(),
			all_outputs: Vec::new(),
			inputs_per_cosigner: HashMap::new(),
			all_offboards: Vec::new(),

			attempt_start: Instant::now(),
			proceed: false,
		}
	}

	fn first_attempt(&self) -> bool {
		assert_eq!(self.attempt_seq == 0, self.allowed_inputs.is_none());
		self.attempt_seq == 0
	}

	/// Returns whether there are no valid inputs left in the round
	/// and we need to start a new round.
	fn need_new_round(&self) -> bool {
		!self.first_attempt() && self.allowed_inputs.as_ref().unwrap().is_empty()
	}

	fn have_payments(&self) -> bool {
		!self.all_inputs.is_empty() && (!self.all_outputs.is_empty() || !self.all_offboards.is_empty())
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
				slog!(RoundUserBadNbNonces, round_seq: self.round_seq,
					attempt_seq: self.attempt_seq, nb_cosign_nonces: out.nonces.len(),
				);
				bail!("incorrect number of cosign nonces per set");
			}

			if self.inputs_per_cosigner.contains_key(&out.req.cosign_pubkey) {
				slog!(RoundUserDuplicateCosignPubkey, round_seq: self.round_seq,
					attempt_seq: self.attempt_seq, cosign_pubkey: out.req.cosign_pubkey,
				);
				bail!("duplicate cosign key {}", out.req.cosign_pubkey);
			}
		}

		if let Some(max) = self.round_data.max_vtxo_amount {
			for out in outputs {
				if out.req.vtxo.amount > max {
					slog!(RoundUserBadOutputAmount, round_seq: self.round_seq,
						attempt_seq: self.attempt_seq, amount: out.req.vtxo.amount,
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
				slog!(RoundUserVtxoDuplicateInput, round_seq: self.round_seq, attempt_seq: self.attempt_seq,
					vtxo: input.vtxo_id,
				);
				bail!("user provided duplicate inputs");
			}
			if self.all_inputs.contains_key(&input.vtxo_id) {
				slog!(RoundUserVtxoAlreadyRegistered, round_seq: self.round_seq, attempt_seq: self.attempt_seq,
					vtxo: input.vtxo_id,
				);
				bail!("vtxo {} already registered", input.vtxo_id);
			}
		}

		if let Some(ref allowed) = self.allowed_inputs {
			// This means we're not trying first time and we filter inputs.
			if let Some(bad) = inputs.iter().find(|i| !allowed.contains(&i.vtxo_id)) {
				slog!(RoundUserVtxoNotAllowed, round_seq: self.round_seq, attempt_seq: self.attempt_seq,
					vtxo: bad.vtxo_id,
				);
				bail!("input vtxo {} has been banned for this round", bad.vtxo_id);
			}
		}

		Ok(())
	}

	/// If a [SignedVtxoRequest] requests an [VtxoPolicy::ServerHtlcRecv], we check that
	/// there is an incoming HTLC with the same payment hash that is accepted and
	/// not already claimed.
	///
	/// Supported protocols:
	/// - Lightning Network
	async fn check_vtxo_request_htlcs(
		&self,
		db: &database::Db,
		reqs: &[VtxoParticipant],
	) -> anyhow::Result<()> {
		for req in reqs {
			if let VtxoPolicy::ServerHtlcRecv(ServerHtlcRecvVtxoPolicy { payment_hash, .. }) = req.req.vtxo.policy {
				let status = LightningHtlcSubscriptionStatus::Accepted;
				let htlc = db.get_htlc_subscription_by_payment_hash(payment_hash, status).await?;

				// TODO: check if a non-expired htlc vtxo with same payment_hash exists and bail if so

				if htlc.is_some() {
					continue;
				}

				return not_found!([payment_hash],
					"Cannot find accepted htlc for provided payment hash",
				);
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
		let mut ret  = Vec::with_capacity(inputs.len());

		let ids = inputs.iter().map(|i| i.vtxo_id).collect::<Vec<_>>();

		match srv.db.get_vtxos_by_id(&ids).await {
			Ok(v) => {
				// Check if the input vtxos exist, unspent and owned by user.
				for vtxo_state in v {
					let vtxo_id = vtxo_state.id;
					if !vtxo_state.is_spendable() {
						bail!("vtxo {} is not spendable: {:?}", vtxo_id, vtxo_state)
					}

					ret.push(vtxo_state.vtxo);
				}
				Ok(ret)
			},
			Err(e) => {
				if let Some(nf) = e.downcast_ref::<NotFound>() {
					for id in nf.identifiers() {
						slog!(RoundUserVtxoUnknown, round_seq: self.round_seq,
							vtxo: Some(VtxoId::from_str(id).expect("should be a valid vtxoid")));
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
				slog!(RoundUserVtxoInFlux, round_seq: self.round_seq, attempt_seq: self.attempt_seq, vtxo: id);
				bail!("vtxo {id} already in flux");
			},
		};

		self.check_vtxo_request_htlcs(&srv.db, &vtxo_requests).await?;

		// Check if the input vtxos exist and are unspent.
		let input_vtxos = match self.check_fetch_round_input_vtxos(srv, &inputs).await {
			Ok(i) => i,
			Err(e) => {
				let ret = if let Some(id) = e.downcast_ref::<VtxoId>().cloned() {
					slog!(RoundUserVtxoUnknown, round_seq: self.round_seq, vtxo: Some(id));
					Err(e).not_found([id], "input vtxo does not exist")
				} else {
					Err(e)
				};
				return ret;
			}
		};

		if let Err(e) = self.validate_payment_amounts(&input_vtxos, &vtxo_requests, &offboards) {
			slog!(RoundPaymentRegistrationFailed, round_seq: self.round_seq,
				attempt_seq: self.attempt_seq, error: e.to_string(),
			);
			return Err(e).context("registration failed");
		}

		if let Err(e) = srv.validate_board_inputs(&input_vtxos).await {
			slog!(RoundPaymentRegistrationFailed, round_seq: self.round_seq,
				attempt_seq: self.attempt_seq, error: e.to_string(),
			);
			return Err(e).context("registration failed");
		}

		// Finally we are done
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
		slog!(RoundPaymentRegistered, round_seq: self.round_seq, attempt_seq: self.attempt_seq,
			nb_inputs: inputs.len(), nb_outputs: vtxo_requests.len(), nb_offboards: offboards.len(),
		);

		// If we're adding inputs for the first time, also add them to locked_inputs.
		if self.first_attempt() {
			self.locked_inputs.absorb(lock);
		}

		let input_ids = inputs.iter().map(|v| v.id()).collect::<Vec<_>>();
		self.all_inputs.extend(inputs.into_iter().map(|v| (v.id(), v)));

		self.inputs_per_cosigner.reserve(vtxo_requests.len());
		for req in &vtxo_requests {
			assert!(self.inputs_per_cosigner.insert(req.req.cosign_pubkey, input_ids.clone()).is_none());
		}
		self.all_outputs.extend(vtxo_requests);

		self.all_offboards.extend(offboards);

		// Check whether our round is full.
		if self.all_outputs.len() == self.round_data.max_output_vtxos {
			slog!(FullRound, round_seq: self.round_seq, attempt_seq: self.attempt_seq,
				nb_outputs: self.all_outputs.len(), max_output_vtxos: self.round_data.max_output_vtxos,
			);
			self.proceed = true;
		}
	}

	async fn progress(mut self, srv: &Server) -> Result<SigningVtxoTree, RoundError> {
		let tip = srv.chain_tip().await.height;
		let expiry_height = tip + srv.config.vtxo_lifetime as BlockHeight;

		let tracer_provider = global::tracer_provider().tracer(telemetry::TRACER_ASPD);

		let parent_context = opentelemetry::Context::current();

		let mut span = tracer_provider
			.span_builder(telemetry::TRACE_RUN_ROUND_CONSTRUCT_VTXO_TREE)
			.start_with_context(&tracer_provider, &parent_context.clone());
		span.set_int_attr("expiry_height", expiry_height);
		span.set_int_attr("block_height", tip);

		slog!(ConstructingRoundVtxoTree, round_seq: self.round_seq, attempt_seq: self.attempt_seq,
			tip_block_height: tip, vtxo_expiry_block_height: expiry_height,
		);

		// Since it's possible in testing that we only have to do offboards,
		// and since it's pretty annoying to deal with the case of no vtxos,
		// if there are no vtxos, we will just add a fake vtxo for the ASP.
		// In practice, in later versions, it is very likely that the ASP
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
				cosign_pubkey: cosign_key.public_key(),
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
			srv.asp_key.public_key(),
			self.cosign_key.public_key(),
			expiry_height,
			srv.config.vtxo_exit_delta,
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
		let unspendable = wallet_lock.untrusted_utxos(trusted_height);
		let round_tx_psbt = {
			let mut b = wallet_lock.build_tx();
			b.ordering(bdk_wallet::TxOrdering::Untouched);
			b.current_height(tip);
			b.unspendable(unspendable);
			// NB: order is important here, we need to respect `ROUND_TX_VTXO_TREE_VOUT` and `ROUND_TX_CONNECTOR_VOUT`
			b.add_recipient(vtxos_spec.round_tx_script_pubkey(), vtxos_spec.total_required_value());
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
		let user_cosign_nonces = self.all_outputs.into_iter().map(|req| {
			(req.req.cosign_pubkey, req.nonces)
		}).collect::<HashMap<_, _>>();
		let cosign_agg_nonces = vtxos_spec.calculate_cosign_agg_nonces(
			&user_cosign_nonces, &cosign_pub_nonces,
		);

		// Send out vtxo proposal to signers.
		let _ = srv.rounds.round_event_tx.send(RoundEvent::VtxoProposal {
			round_seq: self.round_seq,
			unsigned_round_tx: unsigned_round_tx.clone(),
			vtxos_spec: vtxos_spec.clone(),
			cosign_agg_nonces: cosign_agg_nonces.clone(),
			connector_pubkey: connector_key.public_key(),
		});

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

		Ok(SigningVtxoTree {
			round_seq: self.round_seq,
			round_data: self.round_data,
			attempt_seq: self.attempt_seq,
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
			attempt_start: self.attempt_start,
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
	round_seq: usize,
	attempt_seq: usize,
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

	attempt_start: Instant,

	proceed: bool,
}

impl SigningVtxoTree {
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

		let req = match self.unsigned_vtxo_tree.spec.vtxos.iter().find(|v| v.cosign_pubkey == pubkey) {
			Some(r) => r,
			None => {
				trace!("Received signatures from non-signer: {}", pubkey);
				bail!("pubkey is not part of cosigner group");
			},
		};
		slog!(RoundVtxoSignaturesRegistered, round_seq: self.round_seq, attempt_seq: self.attempt_seq,
			nb_vtxo_signatures: signatures.len(), cosigner: pubkey,
		);

		let res = self.unsigned_vtxo_tree.verify_branch_cosign_partial_sigs(
			&self.cosign_agg_nonces,
			req,
			&self.user_cosign_nonces.get(&req.cosign_pubkey).expect("vtxo part of round"),
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
				slog!(DroppingLateVtxoSignatureVtxos, round_seq: self.round_seq,
					attempt_seq: self.attempt_seq, disallowed_vtxos: vtxos.clone(),
				);
				for id in vtxos {
					allowed_inputs.remove(id);
				}
			}
		}
		CollectingPayments::new(
			self.round_seq,
			self.attempt_seq + 1,
			self.round_data,
			self.locked_inputs,
			Some(allowed_inputs),
		)
	}

	fn progress(self, srv: &Server) -> SigningForfeits {
		// Combine the vtxo signatures.
		let combine_signatures_start = Instant::now();

		let tracer_provider = global::tracer_provider().tracer(telemetry::TRACER_ASPD);

		let parent_context = opentelemetry::Context::current();

		let _span = tracer_provider
			.span_builder(telemetry::TRACE_RUN_ROUND_COMBINE_VTXO_SIGNATURES)
			.start_with_context(&tracer_provider, &parent_context.clone());

		let asp_cosign_sigs = self.unsigned_vtxo_tree.cosign_tree(
			&self.cosign_agg_nonces,
			&self.cosign_key,
			self.cosign_sec_nonces,
		);
		debug_assert_eq!(self.unsigned_vtxo_tree.verify_all_cosign_partial_sigs(
			self.cosign_key.public_key(),
			&self.cosign_agg_nonces,
			&self.cosign_pub_nonces,
			&asp_cosign_sigs,
		), Ok(()));
		let cosign_sigs = self.unsigned_vtxo_tree.combine_partial_signatures(
			&self.cosign_agg_nonces,
			&self.cosign_part_sigs,
			asp_cosign_sigs,
		).expect("failed to combine partial vtxo cosign signatures: should have checked partials");
		debug_assert_eq!(self.unsigned_vtxo_tree.verify_cosign_sigs(&cosign_sigs), Ok(()));

		// Then construct the final signed vtxo tree.
		let signed_vtxos = self.unsigned_vtxo_tree
			.into_signed_tree(cosign_sigs)
			.into_cached_tree();
		slog!(CreatedSignedVtxoTree, round_seq: self.round_seq, attempt_seq: self.attempt_seq,
			nb_vtxo_signatures: signed_vtxos.spec.cosign_sigs.len(),
			duration: Instant::now().duration_since(combine_signatures_start),
		);

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
				let (s, p) = musig::nonce_pair(&srv.asp_key);
				secs.push(s);
				pubs.push(p);
			}
			forfeit_pub_nonces.insert(*id, pubs);
			forfeit_sec_nonces.insert(*id, secs);
		}

		// Send out round proposal to signers.
		let _ = srv.rounds.round_event_tx.send(RoundEvent::RoundProposal {
			round_seq: self.round_seq,
			cosign_sigs: signed_vtxos.spec.cosign_sigs.clone(),
			forfeit_nonces: forfeit_pub_nonces.clone(),
		});

		let conns_utxo = OutPoint::new(self.round_txid, ROUND_TX_CONNECTOR_VOUT);
		let connectors = ConnectorChain::new(
			self.all_inputs.len(), conns_utxo, self.connector_key.public_key(),
		);

		SigningForfeits {
			round_seq: self.round_seq,
			attempt_seq: self.attempt_seq,
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
			attempt_start: self.attempt_start,
			proceed: false,
		}
	}
}

pub struct SigningForfeits {
	round_seq: usize,
	attempt_seq: usize,
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
	attempt_start: Instant,

	proceed: bool,
}

impl SigningForfeits {
	pub fn register_forfeits(
		&mut self,
		signatures: Vec<(VtxoId, Vec<musig::PublicNonce>, Vec<musig::PartialSignature>)>,
	) -> anyhow::Result<()> {
		slog!(ReceivedForfeitSignatures, round_seq: self.round_seq, attempt_seq: self.attempt_seq,
			nb_forfeits: signatures.len(), vtxo_ids: signatures.iter().map(|v| v.0).collect::<Vec<_>>(),
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
				slog!(UnknownForfeitSignature, round_seq: self.round_seq,
					attempt_seq: self.attempt_seq, vtxo_id: id,
				);
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
				slog!(MissingForfeits, round_seq: self.round_seq,
					attempt_seq: self.attempt_seq, input: *input,
				);
			}

			self.all_inputs.keys().copied()
				.filter(|v| !missing.contains(v))
				.collect()
		} else {
			self.all_inputs.keys().copied().filter(|v| {
				if !self.forfeit_part_sigs.contains_key(v) {
					slog!(MissingForfeits, round_seq: self.round_seq,
						attempt_seq: self.attempt_seq, input: *v,
					);
					false
				} else {
					true
				}
			}).collect()
		};
		slog!(RestartMissingForfeits, round_seq: self.round_seq, attempt_seq: self.attempt_seq);
		CollectingPayments::new(
			self.round_seq,
			self.attempt_seq + 1,
			self.round_data,
			self.locked_inputs,
			Some(allowed_inputs),
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
		let sign_start = Instant::now();
		let signed_round_tx = match self.wallet_lock.finish_tx(self.round_tx_psbt) {
			Ok(tx) => tx,
			Err(e) => return Err(RoundError::Recoverable(e.context("round tx signing error"))),
		};
		self.wallet_lock.commit_tx(&signed_round_tx);
		if let Err(e) = self.wallet_lock.persist().await {
			// Failing to persist the tx data at this point means that we might
			// accidentally re-use certain inputs if we reboot the aspd.
			// We keep the change set in the wallet if this happens.
			warn!("Failed to persist BDK wallet to db: {:?}", e);
		}

		drop(self.wallet_lock); // we no longer need the lock
		let signed_round_tx = srv.tx_broadcast_handle.broadcast_tx(signed_round_tx).await
			.map_err(|err| RoundError::Fatal(err.context("failed to broadcast round")))?;

		let round_txid = signed_round_tx.txid;

		slog!(BroadcastedFinalizedRoundTransaction, round_seq: self.round_seq,
			attempt_seq: self.attempt_seq, txid: round_txid,
			signing_time: Instant::now().duration_since(sign_start),
		);

		// Send out the finished round to users.
		trace!("Sending out finish event.");
		let _ = srv.rounds.round_event_tx.send(RoundEvent::Finished {
			round_seq: self.round_seq,
			signed_round_tx: signed_round_tx.tx.clone(),
		});

		let tracer_provider = global::tracer_provider().tracer(telemetry::TRACER_ASPD);
		let parent_context = opentelemetry::Context::current();
		let mut span = tracer_provider
			.span_builder(telemetry::TRACE_RUN_ROUND_PERSIST)
			.start_with_context(&tracer_provider, &parent_context.clone());
		span.set_int_attr("signed-vtxo-count", self.signed_vtxos.nb_leaves());
		span.set_int_attr("connectors-count", self.connectors.len());

		trace!("Storing round result");
		if log_enabled!(RoundVtxoCreated::LEVEL) {
			for vtxo in self.signed_vtxos.all_vtxos() {
				slog!(RoundVtxoCreated, round_seq: self.round_seq, vtxo_id: vtxo.id(),
					vtxo_type: vtxo.policy().policy_type(),
				);
			}
		}
		let mut sec_nonces = self.forfeit_sec_nonces.take().unwrap();
		let forfeit_vtxos = self.all_inputs.iter().map(|(id, vtxo)| {
			slog!(StoringForfeitVtxo, round_seq: self.round_seq, attempt_seq: self.attempt_seq,
				out_point: vtxo.point(),
			);
			let (user_nonces, user_part_sigs) = self.forfeit_part_sigs.remove(id)
				.expect("missing part sigs");
			let forfeit_state = ForfeitState {
				round_id: round_txid.into(),
				user_nonces, user_part_sigs,
				pub_nonces: self.forfeit_pub_nonces.remove(id).expect("missing vtxo"),
				sec_nonces: sec_nonces.remove(id).expect("missing vtxo").into_iter()
					.map(DangerousSecretNonce::new)
					.collect(),
			};
			(*id, forfeit_state)
		}).collect();
		let result = srv.db.finish_round(
			&signed_round_tx.tx,
			&self.signed_vtxos,
			&self.connector_key.secret_key(),
			forfeit_vtxos,
		).await;
		if let Err(e) = result {
			slog!(FatalStoringRound, round_seq: self.round_seq, error: format!("{:?}", e),
				signed_tx: serialize(&signed_round_tx.tx),
				vtxo_tree: self.signed_vtxos.spec.serialize(),
				connector_key: self.connector_key.secret_key(),
				forfeit_vtxos: self.all_inputs.keys().copied().collect(),
			);
			return Err(RoundError::Fatal(e));
		}
		srv.forfeits.register_forfeits(self.all_inputs.keys().copied().collect())
			.expect("forfeit watcher shut down");

		slog!(RoundFinished, round_seq: self.round_seq, attempt_seq: self.attempt_seq,
			txid: round_txid, vtxo_expiry_block_height: self.expiry_height,
			duration: Instant::now().duration_since(self.attempt_start),
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
	fn kind(&self, ) -> RoundStateKind {
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
	round_seq: usize,
) -> RoundResult {
	let tracer_provider = global::tracer_provider().tracer(telemetry::TRACER_ASPD);

	let mut span = tracer_provider
		.span_builder(telemetry::TRACE_RUN_ROUND)
		.with_kind(SpanKind::Server)
		.start(&tracer_provider);
	span.set_int_attr(telemetry::ATTRIBUTE_ROUND_ID, round_seq);

	let parent_context = opentelemetry::Context::current_with_span(span);

	let tracing_span = info_span!(telemetry::TRACE_RUN_ROUND);
	tracing_span.set_parent(parent_context.clone());

	// this is to make sure slog has access to the span information.
	let _guard = tracing_span.enter();

	slog!(RoundStarted, round_seq);

	// Start new round, announce.
	let offboard_feerate = srv.config.round_tx_feerate;
	let _ = srv.rounds.round_event_tx.send(RoundEvent::Start(RoundInfo {
		round_seq,
		offboard_feerate,
	}));

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
		round_seq, 0, round_data, srv.vtxos_in_flux.empty_lock().into_owned(), None,
	));

	// In this loop we will try to finish the round and make new attempts.
	'attempt: loop {
		let attempt_seq = round_state.collecting_payments().attempt_seq;
		slog!(AttemptingRound, round_seq, attempt_seq);

		if let Err(e) = srv.rounds_wallet.lock().await.sync(&srv.bitcoind, false).await
		{
			slog!(RoundSyncError, error: format!("{:?}", e));
		}

		let mut span = tracer_provider
			.span_builder(telemetry::TRACE_RUN_ROUND_ATTEMPT)
			.with_kind(SpanKind::Internal)
			.start_with_context(&tracer_provider, &parent_context);
		span.set_int_attr(telemetry::ATTRIBUTE_ROUND_ID, round_seq);
		span.set_int_attr("attempt_seq", attempt_seq);

		// Release all vtxos in flux from previous attempt
		let state = round_state.collecting_payments();
		state.locked_inputs.release_all();

		let _ = srv.rounds.round_event_tx.send(RoundEvent::Attempt(RoundAttempt {
			round_seq,
			attempt_seq,
			challenge: state.vtxo_ownership_challenge
		}));
		// Start receiving payments.
		let receive_payments_start = Instant::now();

		let mut span = tracer_provider
			.span_builder(telemetry::TRACE_RUN_ROUND_RECEIVE_PAYMENTS)
			.with_kind(SpanKind::Internal)
			.start_with_context(&tracer_provider, &parent_context);
		span.set_int_attr(telemetry::ATTRIBUTE_ROUND_ID, round_seq);
		span.set_int_attr("attempt_seq", attempt_seq);

		tokio::pin! { let timeout = tokio::time::sleep(srv.config.round_submit_time); }
		'receive: loop {
			tokio::select! {
				() = &mut timeout => break 'receive,
				input = round_input_rx.recv() => {
					let (input, tx) = input.expect("broken channel");

					let res = match input {
						RoundInput::RegisterPayment { inputs, vtxo_requests, offboards } => {
							round_state.collecting_payments().process_payment(
								srv, inputs, vtxo_requests, offboards,
							).await.map_err(|e| {
								debug!("error processing payment: {e}");
								telemetry::set_round_metrics(round_seq, attempt_seq, round_state.kind());
								e
							})
						},
						_ => badarg!("unexpected message. current step is payment registration"),
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
		if !round_state.collecting_payments().have_payments() {
			let _span = tracer_provider
				.span_builder(telemetry::TRACE_RUN_ROUND_EMPTY)
				.with_kind(SpanKind::Internal)
				.start_with_context(&tracer_provider, &parent_context);

			slog!(NoRoundPayments, round_seq, attempt_seq,
				max_round_submit_time: srv.config.round_submit_time,
			);

			round_state = round_state.into_finished(RoundResult::Empty);

			telemetry::set_full_round_metrics(
				round_seq, attempt_seq, round_state.kind(), Amount::from_sat(0), 0,
			);

			return round_state.result().unwrap();
		}
		let receive_payment_duration = Instant::now().duration_since(receive_payments_start);
		slog!(ReceivedRoundPayments, round_seq, attempt_seq,
			nb_inputs: round_state.collecting_payments().all_inputs.len(),
			nb_outputs: round_state.collecting_payments().all_outputs.len(),
			duration: receive_payment_duration, max_round_submit_time: srv.config.round_submit_time,
		);

		let mut span = tracer_provider
			.span_builder(telemetry::TRACE_RUN_ROUND_POPULATED)
			.with_kind(SpanKind::Internal)
			.start_with_context(&tracer_provider, &parent_context);
		span.set_int_attr("attempt_seq", attempt_seq);
		span.set_int_attr("input-count", round_state.collecting_payments().all_inputs.len());
		span.set_int_attr("output-count", round_state.collecting_payments().all_outputs.len());
		span.set_int_attr("offboard-count", round_state.collecting_payments().all_offboards.len());

		// ****************************************************************
		// * Vtxo tree construction and signing
		// *
		// * - We will always store vtxo tx data from top to bottom,
		// *   meaning from the root tx down to the leaves.
		// ****************************************************************
		let send_vtxo_proposal_start = Instant::now();

		let mut span = tracer_provider
			.span_builder(telemetry::TRACE_RUN_ROUND_SEND_VTXO_PROPOSAL)
			.with_kind(SpanKind::Internal)
			.start_with_context(&tracer_provider, &parent_context);
		span.set_int_attr(telemetry::ATTRIBUTE_ROUND_ID, round_seq);
		span.set_int_attr("attempt_seq", attempt_seq);

		let input_count = round_state.collecting_payments().all_inputs.len();
		let input_volume = round_state.collecting_payments().total_input_amount();

		round_state = match round_state.progress(srv).await {
			Ok(s) => s,
			Err(e) => return {
				round_state = RoundState::Finished(RoundResult::Err(e));

				telemetry::set_full_round_metrics(
					round_seq, attempt_seq, round_state.kind(), input_volume, input_count,
				);

				round_state.result().unwrap()
			},
		};
		// Wait for signatures from users.
		slog!(AwaitingRoundSignatures, round_seq, attempt_seq,
			max_round_sign_time: srv.config.round_sign_time,
			duration_since_sending: Instant::now().duration_since(send_vtxo_proposal_start),
		);

		let vtxo_signatures_receive_start = Instant::now();

		let _span = tracer_provider
			.span_builder(telemetry::TRACE_RUN_ROUND_RECEIVE_VTXO_SIGNATURES)
			.with_kind(SpanKind::Internal)
			.start_with_context(&tracer_provider, &parent_context);

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
						round_state = round_state.into_finished(RoundResult::Abandoned);

						telemetry::set_full_round_metrics(
							round_seq, attempt_seq, round_state.kind(), input_volume, input_count,
						);

						return round_state.result().unwrap();
					}

					continue 'attempt;
				},
				input = round_input_rx.recv() => {
					let state = round_state.signing_vtxo_tree();
					let (input, tx) = input.expect("broken channel");

					let res = match input {
						RoundInput::VtxoSignatures { pubkey, signatures } => {
							state.register_signature(pubkey, signatures).map_err(|e| {
								slog!(VtxoSignatureRegistrationFailed, round_seq, attempt_seq,
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
		slog!(ReceivedRoundVtxoSignatures, round_seq, attempt_seq,
			duration: Instant::now().duration_since(vtxo_signatures_receive_start),
			max_round_sign_time: srv.config.round_sign_time,
		);

		let send_round_proposal_start = Instant::now();

		let mut span = tracer_provider
			.span_builder(telemetry::TRACE_RUN_ROUND_SEND_ROUND_PROPOSAL)
			.with_kind(SpanKind::Internal)
			.start_with_context(&tracer_provider, &parent_context);
		span.set_int_attr(telemetry::ATTRIBUTE_ROUND_ID, round_seq);
		span.set_int_attr("attempt_seq", attempt_seq);

		round_state = match round_state.progress(&srv).await {
			Ok(s) => s,
			Err(e) => return {
				round_state = RoundState::Finished(RoundResult::Err(e));

				telemetry::set_full_round_metrics(
					round_seq, attempt_seq, round_state.kind(), input_volume, input_count,
				);

				round_state.result().unwrap()
			},
		};

		// Wait for signatures from users.
		slog!(AwaitingRoundForfeits, round_seq, attempt_seq,
			max_round_sign_time: srv.config.round_sign_time,
			duration_since_sending: Instant::now().duration_since(send_round_proposal_start),
		);

		let receive_forfeit_signatures_start = Instant::now();

		let mut span = tracer_provider
			.span_builder(telemetry::TRACE_RUN_ROUND_RECEIVING_FORFEIT_SIGNATURES)
			.with_kind(SpanKind::Internal)
			.start_with_context(&tracer_provider, &parent_context);
		span.set_int_attr(telemetry::ATTRIBUTE_ROUND_ID, round_seq);
		span.set_int_attr("attempt_seq", attempt_seq);

		tokio::pin! { let timeout = tokio::time::sleep(srv.config.round_sign_time); }

		'receive: loop {
			tokio::select! {
				_ = &mut timeout => {
					warn!("Timed out receiving forfeit signatures.");
					let new = round_state.into_signing_forfeits().restart_missing_forfeits(None);
					let need_new_round = new.need_new_round();
					round_state = new.into();

					if need_new_round {
						round_state = round_state.into_finished(RoundResult::Abandoned);

						telemetry::set_full_round_metrics(
							round_seq, attempt_seq, round_state.kind(), input_volume, input_count,
						);

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
									slog!(ForfeitRegistrationFailed, round_seq, attempt_seq, error: e.to_string());
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
		slog!(ReceivedRoundForfeits, round_seq, attempt_seq,
			max_round_sign_time: srv.config.round_sign_time,
			nb_forfeits: round_state.signing_forfeits().forfeit_part_sigs.len(),
			duration: Instant::now().duration_since(receive_forfeit_signatures_start),
		);

		let state = round_state.into_signing_forfeits();
		if let Some(missing) = state.check_forfeits() {
			round_state = RoundState::CollectingPayments(state.restart_missing_forfeits(Some(missing)));
			continue 'attempt;
		}

		// ****************************************************************
		// * Finish the round
		// ****************************************************************
		let mut span = tracer_provider
			.span_builder(telemetry::TRACE_RUN_ROUND_FINALIZING)
			.with_kind(SpanKind::Internal)
			.start_with_context(&tracer_provider, &parent_context);
		span.set_int_attr(telemetry::ATTRIBUTE_ROUND_ID, round_seq);
		span.set_int_attr("attempt_seq", attempt_seq);

		round_state = match state.finish(&srv).await {
			Ok(()) => {
				RoundState::Finished(RoundResult::Success)
			},
			Err(e) => {
				RoundState::Finished(RoundResult::Err(e))
			},
		};

		telemetry::set_full_round_metrics(
			round_seq, attempt_seq, round_state.kind(), input_volume, input_count,
		);

		return round_state.result().unwrap();
	}
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
		SystemTime::now().duration_since(epoch).unwrap().as_secs() as usize
	};

	loop {
		round_seq += 1;
		match perform_round(srv, &mut round_input_rx, round_seq).await {
			RoundResult::Success => {},
			RoundResult::Empty => {},
			// Round got abandoned, immediatelly start a new one.
			RoundResult::Abandoned => continue,
			// Internal error, retry immediatelly.
			RoundResult::Err(RoundError::Recoverable(e)) => {
				error!("Full round error stack trace: {:?}", e);
				slog!(RoundError, round_seq, error: format!("{}", e.full_msg()));
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

		static ref TEST_ASP_PK: PublicKey = PublicKey::from_str(
			"02e6642fd69bd211f93f7f1f36ca51a26a5290eb2dd1b0d8279a87bb0d480c8443",
		).unwrap();
	}

	fn generate_pubkey() -> PublicKey {
		let secp = Secp256k1::new();
		let (_secret_key, public_key) = secp.generate_keypair(&mut rand::thread_rng());
		public_key
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
				cosign_pubkey: generate_pubkey(),
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
		CollectingPayments::new(0, 0, round_data, OwnedVtxoFluxLock::dummy(), None)
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
		assert_eq!(1, state.inputs_per_cosigner.get(&outputs[0].req.cosign_pubkey).unwrap().len());
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
		assert!(state.inputs_per_cosigner.contains_key(&outputs1[0].req.cosign_pubkey));
		assert!(state.inputs_per_cosigner.contains_key(&outputs2[0].req.cosign_pubkey));
		assert!(state.proceed, "Proceed should be set after second registration");
	}
}

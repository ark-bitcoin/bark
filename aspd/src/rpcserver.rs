
use std::fmt;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{self, AtomicBool};
use std::time::Instant;
use std::pin::Pin;
use std::future::Future;

use ark::rounds::RoundId;
use bitcoin::{Amount, ScriptBuf};
use bitcoin::hashes::Hash;
use bitcoin::hex::DisplayHex;
use bitcoin::secp256k1::{schnorr::Signature, PublicKey};
use lightning_invoice::Bolt11Invoice;
use opentelemetry::{global, Context, KeyValue};
use opentelemetry::trace::{get_active_span, Span, SpanKind, TraceContextExt, Tracer, TracerProvider};
use opentelemetry_semantic_conventions as semconv;
use opentelemetry_semantic_conventions::trace::RPC_GRPC_STATUS_CODE;
use tokio::sync::oneshot;
use tokio_stream::{Stream, StreamExt};
use tokio_stream::wrappers::BroadcastStream;

use ark::lightning::SignedBolt11Payment;
use ark::{musig, VtxoIdInput, OffboardRequest, Vtxo, VtxoId, VtxoRequest};
use aspd_rpc as rpc;
use tonic::async_trait;

use crate::error::{BadArgument, NotFound};
use crate::{telemetry, App};
use crate::round::RoundInput;


/// Whether or not to provide rich internal errors to RPC users.
///
/// We keep this static because it's hard to propagate the config
/// into all error conversions.
static RPC_RICH_ERRORS: AtomicBool = AtomicBool::new(false);

macro_rules! badarg {
	($($arg:tt)*) => { return $crate::badarg!($($arg)*).to_status(); };
}

macro_rules! not_found {
	($($arg:tt)*) => { return $crate::not_found!($($arg)*).to_status(); };
}

/// A trait to easily convert [anyhow] errors to tonic [Status].
trait ToStatus<T> {
	/// Convert the error into a tonic error.
	fn to_status(self) -> Result<T, tonic::Status>;
}

impl<T> ToStatus<T> for anyhow::Result<T> {
	fn to_status(self) -> Result<T, tonic::Status> {
		self.map_err(|e| {
			// NB it's important that not found goes first as a bad argument could
			// have been added afterwards
			if let Some(e) = e.downcast_ref::<NotFound>() {
				let mut metadata = tonic::metadata::MetadataMap::new();
				let ids = e.identifiers().join(",").parse().expect("non-ascii identifier");
				metadata.insert("identifiers", ids);
				tonic::Status::with_metadata(
					tonic::Code::NotFound,
					format!("not found: {:?}", e),
					metadata,
				)
			} else if let Some(e) = e.downcast_ref::<BadArgument>() {
				tonic::Status::invalid_argument(format!("bad user input: {:?}", e))
			} else {
				if RPC_RICH_ERRORS.load(atomic::Ordering::Relaxed) {
					tonic::Status::internal(format!("internal error: {:?}", e))
				} else {
					tonic::Status::internal("internal error")
				}
			}
		})
	}
}

/// A trait to add context to errors that return tonic [Status] errors.
trait StatusContext<T, E> {
	/// Shortcut for `.context(..).to_status()`.
	fn context<C>(self, context: C) -> Result<T, tonic::Status>
	where
		C: fmt::Display + Send + Sync + 'static;

	/// Shortcut for `.badarg(..).to_status()`.
	fn badarg<C>(self, context: C) -> Result<T, tonic::Status>
	where
		C: fmt::Display + Send + Sync + 'static;

	/// Shortcut for `.not_found(..).to_status()`.
	fn not_found<I, V, C>(self, ids: V, context: C) -> Result<T, tonic::Status>
	where
		V: IntoIterator<Item = I>,
		I: fmt::Display,
		C: fmt::Display + Send + Sync + 'static;
}

impl<R, T, E> StatusContext<T, E> for R
where
	R: crate::error::ContextExt<T, E>,
{
	fn context<C>(self, context: C) -> Result<T, tonic::Status>
	where
		C: fmt::Display + Send + Sync + 'static
	{
		anyhow::Context::context(self, context).to_status()
	}

	fn badarg<C>(self, context: C) -> Result<T, tonic::Status>
	where
		C: fmt::Display + Send + Sync + 'static
	{
		crate::error::ContextExt::badarg(self, context).to_status()
	}

	fn not_found<I, V, C>(self, ids: V, context: C) -> Result<T, tonic::Status>
	where
		V: IntoIterator<Item = I>,
		I: fmt::Display,
		C: fmt::Display + Send + Sync + 'static,
	{
		crate::error::ContextExt::not_found(self, ids, context).to_status()
	}
}


const RPC_SYSTEM_HTTP: &'static str = "http";
const RPC_SYSTEM_GRPC: &'static str = "grpc";

const RPC_UNKNOWN: &'static str = "Unknown";

const RPC_SERVICES: [&str; 2] = [RPC_SERVICE_ARK, RPC_SERVICE_ADMIN];

const RPC_SERVICE_ARK: &'static str = "ArkService";

const RPC_SERVICE_ARK_HANDSHAKE: &'static str = "handshake";
const RPC_SERVICE_ARK_GET_FRESH_ROUNDS: &'static str = "get_fresh_rounds";
const RPC_SERVICE_ARK_GET_ROUND: &'static str = "get_round";
const RPC_SERVICE_ARK_REQUEST_ONBOARD_COSIGN: &'static str = "request_onboard_cosign";
const RPC_SERVICE_ARK_REGISTER_ONBOARD_VTXOS: &'static str = "register_onboard_vtxos";
const RPC_SERVICE_ARK_REQUEST_OOR_COSIGN: &'static str = "request_oor_cosign";
const RPC_SERVICE_ARK_POST_OOR_MAILBOX: &'static str = "post_oor_mailbox";
const RPC_SERVICE_ARK_EMPTY_OOR_MAILBOX: &'static str = "empty_oor_mailbox";
const RPC_SERVICE_ARK_START_BOLT11_PAYMENT: &'static str = "start_bolt11_payment";
const RPC_SERVICE_ARK_FINISH_BOLT11_PAYMENT: &'static str = "finish_bolt11_payment";
const RPC_SERVICE_ARK_SUBSCRIBE_ROUNDS: &'static str = "subscribe_rounds";
const RPC_SERVICE_ARK_SUBMIT_PAYMENT: &'static str = "submit_payment";
const RPC_SERVICE_ARK_PROVIDE_VTXO_SIGNATURES: &'static str = "provide_vtxo_signatures";
const RPC_SERVICE_ARK_PROVIDE_FORFEIT_SIGNATURES: &'static str = "provide_forfeit_signatures";

const RPC_SERVICE_ARK_METHODS: [&str; 14] = [
	RPC_SERVICE_ARK_HANDSHAKE,
	RPC_SERVICE_ARK_GET_FRESH_ROUNDS,
	RPC_SERVICE_ARK_GET_ROUND,
	RPC_SERVICE_ARK_REQUEST_ONBOARD_COSIGN,
	RPC_SERVICE_ARK_REGISTER_ONBOARD_VTXOS,
	RPC_SERVICE_ARK_REQUEST_OOR_COSIGN,
	RPC_SERVICE_ARK_POST_OOR_MAILBOX,
	RPC_SERVICE_ARK_EMPTY_OOR_MAILBOX,
	RPC_SERVICE_ARK_START_BOLT11_PAYMENT,
	RPC_SERVICE_ARK_FINISH_BOLT11_PAYMENT,
	RPC_SERVICE_ARK_SUBSCRIBE_ROUNDS,
	RPC_SERVICE_ARK_SUBMIT_PAYMENT,
	RPC_SERVICE_ARK_PROVIDE_VTXO_SIGNATURES,
	RPC_SERVICE_ARK_PROVIDE_FORFEIT_SIGNATURES,
];

const RPC_SERVICE_ADMIN: &'static str = "AdminService";

const RPC_SERVICE_ADMIN_WALLET_STATUS: &'static str = "wallet_status";
const RPC_SERVICE_ADMIN_TRIGGER_ROUND: &'static str = "trigger_round";
const RPC_SERVICE_ADMIN_TRIGGER_SWEEP: &'static str = "trigger_sweep";
const RPC_SERVICE_ADMIN_STOP: &'static str = "stop";

const RPC_SERVICE_ADMIN_METHODS: [&str; 4] = [
	RPC_SERVICE_ADMIN_WALLET_STATUS,
	RPC_SERVICE_ADMIN_TRIGGER_ROUND,
	RPC_SERVICE_ADMIN_TRIGGER_SWEEP,
	RPC_SERVICE_ADMIN_STOP,
];


#[async_trait]
trait ReceiverExt {
	async fn wait_for_status(self) -> Result<(), tonic::Status>;
}

#[async_trait]
impl ReceiverExt for oneshot::Receiver<anyhow::Error> {
	/// Wait for an explicit Error sent in the channel
	///
	/// If the channel gets closed without any explicit error,
	/// success is assumed
	async fn wait_for_status(self) -> Result<(), tonic::Status> {
		if let Ok(e) = self.await {
			Err(e).to_status()?;
		}

		Ok(())
	}
}

#[derive(Clone, Debug)]
pub struct RpcMethodDetails {
	system: &'static str,
	service: &'static str,
	method: &'static str,
}

impl RpcMethodDetails {
	fn grpc_ark(method: &'static str) -> RpcMethodDetails {
		RpcMethodDetails {
			system: RPC_SYSTEM_GRPC,
			service: RPC_SERVICE_ARK,
			method,
		}
	}

	fn grpc_admin(method: &'static str) -> RpcMethodDetails {
		RpcMethodDetails {
			system: RPC_SYSTEM_GRPC,
			service: RPC_SERVICE_ADMIN,
			method,
		}
	}

	pub fn format_path(&self) -> String {
		format!("{}://{}/{}", self.system, self.service, self.method)
	}
}

fn add_tracing_attributes(attributes: Vec<KeyValue>) -> () {
	get_active_span(|span| {
		span.add_event("attach-attributes", attributes);
	})
}

#[tonic::async_trait]
impl rpc::server::ArkService for App {
	async fn handshake(
		&self,
		_req: tonic::Request<rpc::HandshakeRequest>,
	) -> Result<tonic::Response<rpc::HandshakeResponse>, tonic::Status> {
		let _ = RpcMethodDetails::grpc_ark(RPC_SERVICE_ARK_HANDSHAKE);

		let ret = rpc::HandshakeResponse {
			message: None,
			ark_info: Some(rpc::ArkInfo {
				network: self.config.network.to_string(),
				pubkey: self.asp_key.public_key().serialize().to_vec(),
				round_interval_secs: self.config.round_interval.as_secs() as u32,
				nb_round_nonces: self.config.nb_round_nonces as u32,
				vtxo_exit_delta: self.config.vtxo_exit_delta as u32,
				vtxo_expiry_delta: self.config.vtxo_expiry_delta as u32,
			}),
		};

		Ok(tonic::Response::new(ret))
	}

	async fn get_fresh_rounds(
		&self,
		req: tonic::Request<rpc::FreshRoundsRequest>,
	) -> Result<tonic::Response<rpc::FreshRounds>, tonic::Status> {
		let _ = RpcMethodDetails::grpc_ark(RPC_SERVICE_ARK_GET_FRESH_ROUNDS);

		add_tracing_attributes(vec![
			KeyValue::new("start_height", format!("{:?}", req.get_ref().start_height)),
		]);

		let ids = self.db.get_fresh_round_ids(req.get_ref().start_height).await
			.context("db error")?;

		let response = rpc::FreshRounds {
			txids: ids.into_iter().map(|t| t.to_byte_array().to_vec()).collect(),
		};

		Ok(tonic::Response::new(response))
	}

	async fn get_round(
		&self,
		req: tonic::Request<rpc::RoundId>,
	) -> Result<tonic::Response<rpc::RoundInfo>, tonic::Status> {
		let _ = RpcMethodDetails::grpc_ark(RPC_SERVICE_ARK_GET_ROUND);

		add_tracing_attributes(vec![KeyValue::new("txid", format!("{:?}", req.get_ref().txid))]);

		let id = RoundId::from_slice(req.get_ref().txid.as_slice())
			.badarg("invalid txid")?;


		let ret = self.db.get_round(id).await
			.context("db error")?
			.not_found([id], "round with txid {} not found")?;

		let response = rpc::RoundInfo {
			round_tx: bitcoin::consensus::serialize(&ret.tx),
			signed_vtxos: ret.signed_tree.encode(),
		};

		Ok(tonic::Response::new(response))
	}

	// onboard

	async fn request_onboard_cosign(
		&self,
		req: tonic::Request<rpc::OnboardCosignRequest>,
	) -> Result<tonic::Response<rpc::OnboardCosignResponse>, tonic::Status> {
		let _ = RpcMethodDetails::grpc_ark(RPC_SERVICE_ARK_REQUEST_ONBOARD_COSIGN);

		add_tracing_attributes(vec![KeyValue::new("user_part", format!("{:?}", req.get_ref().user_part))]);

		let user_part = ciborium::from_reader::<ark::onboard::UserPart, _>(
			&req.get_ref().user_part[..],
		).badarg("invalid user part")?;

		let asp_part = self.cosign_onboard(user_part).await.to_status()?;
		let response = rpc::OnboardCosignResponse {
			asp_part: {
				let mut buf = Vec::new();
				ciborium::into_writer(&asp_part, &mut buf).unwrap();

				buf
			},
		};

		Ok(tonic::Response::new(response))
	}

	async fn register_onboard_vtxo(
		&self,
		req: tonic::Request<rpc::OnboardVtxoRequest>,
	) -> Result<tonic::Response<rpc::Empty>, tonic::Status> {
		let _ = RpcMethodDetails::grpc_ark(RPC_SERVICE_ARK_REGISTER_ONBOARD_VTXOS);

		add_tracing_attributes(vec![
			KeyValue::new("onboard_vtxo", format!("{:?}", req.get_ref().onboard_vtxo.as_hex())),
			KeyValue::new("onboard_txid", format!("{:?}", req.get_ref().onboard_tx.as_hex())),
		]);

		let req = req.into_inner();
		let vtxo = Vtxo::decode(&req.onboard_vtxo)
			.badarg("invalid vtxo")?
			.into_onboard()
			.badarg("vtxo not an onboard vtxo")?;
		let onboard_tx = bitcoin::consensus::deserialize(&req.onboard_tx)
			.badarg("invalid onboard tx")?;
		self.register_onboard(vtxo, onboard_tx).await.to_status()?;

		Ok(tonic::Response::new(rpc::Empty {}))
	}

	// oor
	async fn request_oor_cosign(
		&self,
		req: tonic::Request<rpc::OorCosignRequest>,
	) -> Result<tonic::Response<rpc::OorCosignResponse>, tonic::Status> {
		let _ = RpcMethodDetails::grpc_ark(RPC_SERVICE_ARK_REQUEST_OOR_COSIGN);

		add_tracing_attributes(vec![
			KeyValue::new("payment", format!("{:?}", req.get_ref().payment)),
			KeyValue::new("pub_nonces", format!("{:?}", req.get_ref().pub_nonces)),
		]);

		let payment = ark::oor::OorPayment::decode(&req.get_ref().payment)
			.badarg("invalid oor payment request")?;

		let user_nonces = req.get_ref().pub_nonces.iter().map(|b| {
			musig::MusigPubNonce::from_slice(b)
				.badarg("invalid public nonce")
		}).collect::<Result<Vec<_>, _>>()?;

		if payment.inputs.len() != user_nonces.len() {
			badarg!("wrong number of user nonces");
		}

		let (nonces, sigs) = self.cosign_oor(&payment, &user_nonces).await.to_status()?;
		let response = rpc::OorCosignResponse {
			pub_nonces: nonces.into_iter().map(|n| n.serialize().to_vec()).collect(),
			partial_sigs: sigs.into_iter().map(|s| s.serialize().to_vec()).collect(),
		};

		Ok(tonic::Response::new(response))
	}

	async fn post_oor_mailbox(
		&self,
		req: tonic::Request<rpc::OorVtxo>,
	) -> Result<tonic::Response<rpc::Empty>, tonic::Status> {
		let _ = RpcMethodDetails::grpc_ark(RPC_SERVICE_ARK_POST_OOR_MAILBOX);

		add_tracing_attributes(vec![
			KeyValue::new("pubkey", format!("{:?}", req.get_ref().pubkey)),
			KeyValue::new("vtxo", format!("{:?}", req.get_ref().vtxo)),
		]);

		let pubkey = PublicKey::from_slice(&req.get_ref().pubkey)
			.badarg("invalid pubkey")?;

		let vtxo = Vtxo::decode(&req.get_ref().vtxo)
			.badarg("invalid vtxo")?;

		self.db.store_oor(pubkey, vtxo).await.to_status()?;

		Ok(tonic::Response::new(rpc::Empty{}))
	}

	async fn empty_oor_mailbox(
		&self,
		req: tonic::Request<rpc::OorVtxosRequest>,
	) -> Result<tonic::Response<rpc::OorVtxosResponse>, tonic::Status> {
		let _ = RpcMethodDetails::grpc_ark(RPC_SERVICE_ARK_EMPTY_OOR_MAILBOX);

		add_tracing_attributes(vec![
			KeyValue::new("pubkey", format!("{:?}", req.get_ref().pubkey)),
		]);

		let pubkey = PublicKey::from_slice(&req.get_ref().pubkey)
			.badarg("invalid pubkey")?;

		let vtxos = self.db.pull_oors(pubkey).await.to_status()?;

		let response = rpc::OorVtxosResponse {
			vtxos: vtxos.into_iter().map(|v| v.encode()).collect(),
		};

		Ok(tonic::Response::new(response))
	}

	// lightning

	async fn start_bolt11_payment(
		&self,
		req: tonic::Request<rpc::Bolt11PaymentRequest>,
	) -> Result<tonic::Response<rpc::Bolt11PaymentDetails>, tonic::Status> {
		let _ = RpcMethodDetails::grpc_ark(RPC_SERVICE_ARK_START_BOLT11_PAYMENT);

		add_tracing_attributes(
			vec![
				KeyValue::new("invoice", format!("{:?}", req.get_ref().invoice)),
				KeyValue::new("amount_sats", format!("{:?}", req.get_ref().amount_sats)),
			]);

		let invoice = Bolt11Invoice::from_str(&req.get_ref().invoice)
			.badarg("invalid invoice")?;
		invoice.check_signature().badarg("invalid invoice signature")?;

		let inv_amount = invoice.amount_milli_satoshis()
			.map(|v| Amount::from_sat(v.div_ceil(1000)));

		if let (Some(_), Some(inv)) = (req.get_ref().amount_sats, inv_amount) {
			badarg!("Invoice has amount of {} encoded. Please omit amount field", inv);
		}

		let amount = req.get_ref().amount_sats.map(|v| Amount::from_sat(v)).or(inv_amount)
			.badarg("amount field required for invoice without amount")?;

		let input_vtxos = req.get_ref().input_vtxos.iter().map(|v| Vtxo::decode(v))
			.collect::<Result<Vec<_>, _>>()
			.badarg("invalid vtxo")?;
		let user_pubkey = PublicKey::from_slice(&req.get_ref().user_pubkey)
			.badarg("invalid user pubkey")?;
		let user_nonces = req.get_ref().user_nonces.iter().map(|b| {
			musig::MusigPubNonce::from_slice(&b)
				.badarg("invalid public nonce")
		}).collect::<Result<Vec<_>, _>>()?;

		let (details, asp_nonces, part_sigs) = self.start_bolt11_payment(
			invoice, amount, input_vtxos, user_pubkey, &user_nonces,
		).await.context("error making payment")?;

		let response = rpc::Bolt11PaymentDetails {
			details: details.encode(),
			pub_nonces: asp_nonces.into_iter().map(|n| n.serialize().to_vec()).collect(),
			partial_sigs: part_sigs.into_iter().map(|s| s.serialize().to_vec()).collect(),
		};

		Ok(tonic::Response::new(response))
	}

	type FinishBolt11PaymentStream = Box<
		dyn Stream<Item = Result<rpc::Bolt11PaymentUpdate, tonic::Status>> + Unpin + Send + 'static
	>;

	async fn finish_bolt11_payment(
		&self,
		req: tonic::Request<rpc::SignedBolt11PaymentDetails>,
	) -> Result<tonic::Response<Self::FinishBolt11PaymentStream>, tonic::Status> {
		let _ = RpcMethodDetails::grpc_ark(RPC_SERVICE_ARK_FINISH_BOLT11_PAYMENT);

		add_tracing_attributes(vec![
			KeyValue::new("signed_payment", format!("{:?}", req.get_ref().signed_payment)),
		]);

		let signed = SignedBolt11Payment::decode(&req.get_ref().signed_payment)
			.badarg("invalid payment encoding")?;
		if let Err(e) = signed.validate_signatures(&crate::SECP) {
			badarg!("bad signatures on payment: {}", e);
		}

		let update_stream = self.finish_bolt11_payment(signed).await
			.context("Could not finalise")?;

		Ok(tonic::Response::new(Box::new(update_stream.map(|r| r.to_status()))))
	}

	// round

	type SubscribeRoundsStream = Box<
		dyn Stream<Item = Result<rpc::RoundEvent, tonic::Status>> + Unpin + Send + 'static
	>;

	async fn subscribe_rounds(
		&self,
		_req: tonic::Request<rpc::Empty>,
	) -> Result<tonic::Response<Self::SubscribeRoundsStream>, tonic::Status> {
		let _ = RpcMethodDetails::grpc_ark(RPC_SERVICE_ARK_SUBSCRIBE_ROUNDS);

		let chan = self.try_rounds().to_status()?.round_event_tx.subscribe();
		let stream = BroadcastStream::new(chan);

		Ok(tonic::Response::new(Box::new(stream.map(|e| {
			Ok(e.context("broken stream")?.into())
		}))))
	}

	async fn submit_payment(
		&self,
		req: tonic::Request<rpc::SubmitPaymentRequest>,
	) -> Result<tonic::Response<rpc::Empty>, tonic::Status> {
		let _ = RpcMethodDetails::grpc_ark(RPC_SERVICE_ARK_SUBMIT_PAYMENT);

		add_tracing_attributes(vec![
			KeyValue::new("input_vtxos_count", format!("{:?}", req.get_ref().input_vtxos.len())),
			KeyValue::new("vtxo_requests_count", format!("{:?}", req.get_ref().vtxo_requests.len())),
			KeyValue::new("offboard_requests_count", format!("{:?}", req.get_ref().offboard_requests.len())),
		]);

		let inputs =  req.get_ref().input_vtxos.iter().map(|input| {
			let vtxo_id = VtxoId::from_slice(&input.vtxo_id).badarg("invalid vtxo")?;
			let ownership_proof = Signature::from_slice(&input.ownership_proof).badarg("invalid round input signature")?;
			Ok(VtxoIdInput { vtxo_id, ownership_proof })
		}).collect::<Result<_, tonic::Status>>()?;

		let mut vtxo_requests = Vec::with_capacity(req.get_ref().vtxo_requests.len());
		let mut cosign_pub_nonces = Vec::with_capacity(req.get_ref().vtxo_requests.len());
		for r in req.get_ref().vtxo_requests.clone() {
			let amount = Amount::from_sat(r.amount);
			let pubkey= PublicKey::from_slice(&r.vtxo_public_key)
				.badarg("malformed pubkey")?;
			let cosign_pk = PublicKey::from_slice(&r.cosign_pubkey)
				.badarg("malformed cosign pubkey")?;
			vtxo_requests.push(VtxoRequest { amount, pubkey, cosign_pk });

			// Make sure users provided right number of nonces.
			if r.public_nonces.len() != self.config.nb_round_nonces {
				badarg!("need exactly {} public nonces", self.config.nb_round_nonces);
			}
			let public_nonces = r.public_nonces.into_iter()
				.take(self.config.nb_round_nonces)
				.map(|n| {
					musig::MusigPubNonce::from_slice(&n)
						.badarg("invalid public nonce")
				}).collect::<Result<Vec<_>, _>>()?;
			cosign_pub_nonces.push(public_nonces);
		}

		let offboards = req.get_ref().offboard_requests.iter().map(|r| {
			let amount = Amount::from_sat(r.amount);
			let script_pubkey = ScriptBuf::from_bytes(r.clone().offboard_spk);
			let ret = OffboardRequest { script_pubkey, amount };
			ret.validate().badarg("invalid offboard request")?;
			Ok(ret)
		}).collect::<Result<_, tonic::Status>>()?;

		let (tx, rx) = oneshot::channel();
		let inp = RoundInput::RegisterPayment {
			inputs, vtxo_requests, cosign_pub_nonces, offboards,
		};

		self.try_rounds().to_status()?.round_input_tx.send((inp, tx)).expect("input channel closed");
		rx.wait_for_status().await?;

		Ok(tonic::Response::new(rpc::Empty {}))
	}

	async fn provide_vtxo_signatures(
		&self,
		req: tonic::Request<rpc::VtxoSignaturesRequest>,
	) -> Result<tonic::Response<rpc::Empty>, tonic::Status> {
		let _ = RpcMethodDetails::grpc_ark(RPC_SERVICE_ARK_PROVIDE_VTXO_SIGNATURES);

		add_tracing_attributes(vec![
			KeyValue::new("pubkey", format!("{:?}", req.get_ref().pubkey)),
			KeyValue::new("signatures_count", format!("{:?}", req.get_ref().signatures.len())),
		]);

		let (tx, rx) = oneshot::channel();
		let inp = RoundInput::VtxoSignatures {
			pubkey: PublicKey::from_slice(&req.get_ref().pubkey)
				.badarg("invalid pubkey")?,
			signatures: req.get_ref().signatures.iter().map(|s| {
				musig::MusigPartialSignature::from_slice(s)
					.badarg("invalid signature")
			}).collect::<Result<_, _>>()?,
		};

		self.try_rounds().to_status()?.round_input_tx.send((inp, tx)).expect("input channel closed");
		rx.wait_for_status().await?;

		Ok(tonic::Response::new(rpc::Empty {}))
	}

	async fn provide_forfeit_signatures(
		&self,
		req: tonic::Request<rpc::ForfeitSignaturesRequest>,
	) -> Result<tonic::Response<rpc::Empty>, tonic::Status> {
		let _ = RpcMethodDetails::grpc_ark(RPC_SERVICE_ARK_PROVIDE_FORFEIT_SIGNATURES);

		add_tracing_attributes(vec![
			KeyValue::new("signatures_count", format!("{:?}", req.get_ref().signatures.len())),
		]);

		let (tx, rx) = oneshot::channel();
		let inp = RoundInput::ForfeitSignatures {
			signatures: req.get_ref().signatures.iter().map(|ff| {
				let id = VtxoId::from_slice(&ff.input_vtxo_id)
					.badarg("invalid vtxo id")?;
				let nonces = ff.pub_nonces.iter().map(|n| {
					musig::MusigPubNonce::from_slice(n)
						.badarg("invalid forfeit nonce")
				}).collect::<Result<_, _>>()?;
				let signatures = ff.signatures.iter().map(|s| {
					musig::MusigPartialSignature::from_slice(s)
						.badarg("invalid forfeit sig")
				}).collect::<Result<_, _>>()?;
				Ok((id, nonces, signatures))
			}).collect::<Result<_, tonic::Status>>()?
		};

		self.try_rounds().to_status()?.round_input_tx.send((inp, tx)).expect("input channel closed");
		rx.wait_for_status().await?;

		Ok(tonic::Response::new(rpc::Empty {}))
	}
}
#[tonic::async_trait]
impl rpc::server::AdminService for App {
	async fn wallet_status(
		&self,
		_req: tonic::Request<rpc::Empty>,
	) -> Result<tonic::Response<rpc::WalletStatusResponse>, tonic::Status> {
		let _ = RpcMethodDetails::grpc_admin(RPC_SERVICE_ADMIN_WALLET_STATUS);

		let response = rpc::WalletStatusResponse {
			// NB the order matters here, we want to sync first
			balance: self.sync_onchain_wallet().await.to_status()?.to_sat(),
			address: self.new_onchain_address().await.to_status()?.to_string(),
		};

		Ok(tonic::Response::new(response))
	}

	async fn trigger_round(
		&self,
		_req: tonic::Request<rpc::Empty>,
	) -> Result<tonic::Response<rpc::Empty>, tonic::Status> {
		let _ = RpcMethodDetails::grpc_admin(RPC_SERVICE_ADMIN_TRIGGER_ROUND);

		match self.try_rounds().to_status()?.round_trigger_tx.try_send(()) {
			Err(tokio::sync::mpsc::error::TrySendError::Closed(())) => {
				panic!("round scheduler closed");
			},
			Err(e) => warn!("Failed to send round trigger: {:?}", e),
			Ok(_) => trace!("round scheduler not closed"),
		}

		Ok(tonic::Response::new(rpc::Empty{}))
	}

	async fn trigger_sweep(
		&self,
		_req: tonic::Request<rpc::Empty>,
	) -> Result<tonic::Response<rpc::Empty>, tonic::Status> {
		let _ = RpcMethodDetails::grpc_admin(RPC_SERVICE_ADMIN_TRIGGER_SWEEP);

		match self.trigger_round_sweep_tx.as_ref().unwrap().try_send(()) {
			Err(tokio::sync::mpsc::error::TrySendError::Closed(())) => {
				panic!("sweep trigger channel closed");
			},
			Err(e) => warn!("Failed to send sweep trigger: {:?}", e),
			Ok(_) => trace!("round sweep not closed"),
		}

		Ok(tonic::Response::new(rpc::Empty{}))
	}

	async fn stop(
		&self,
		_req: tonic::Request<rpc::Empty>,
	) -> Result<tonic::Response<rpc::Empty>, tonic::Status> {
		let _ = RpcMethodDetails::grpc_admin(RPC_SERVICE_ADMIN_STOP);

		info!("Shutting down because of RPC stop command...");

		let _ = self.shutdown_channel.send(());

		Ok(tonic::Response::new(rpc::Empty {}))
	}
}


#[derive(Clone)]
pub struct TelemetryMetrics {
	tracer: Arc<opentelemetry::global::BoxedTracer>,
	in_progress_counter: opentelemetry::metrics::UpDownCounter<i64>,
	latency_histogram: opentelemetry::metrics::Histogram<u64>,
	request_counter: opentelemetry::metrics::Counter<u64>,
	error_counter: opentelemetry::metrics::Counter<u64>,
}

impl TelemetryMetrics {
	fn new() -> TelemetryMetrics {
		let meter = global::meter_provider().meter(telemetry::METER_ASPD);
		TelemetryMetrics {
			tracer: Arc::new(global::tracer_provider().tracer(telemetry::TRACER_ASPD)),
			in_progress_counter: meter.i64_up_down_counter(
				telemetry::METER_COUNTER_UD_GRPC_IN_PROCESS,
			).build(),
			latency_histogram: meter.u64_histogram(
				telemetry::METER_HISTOGRAM_GRPC_LATENCY,
			).build(),
			request_counter: meter.u64_counter(telemetry::METER_COUNTER_GRPC_REQUEST).build(),
			error_counter: meter.u64_counter(telemetry::METER_COUNTER_GRPC_ERROR).build(),
		}
	}
}

#[derive(Clone)]
pub struct TelemetryMetricsService<S> {
	inner: S,
	// NB this needs to be an Arc so we can pass it into our response future
	metrics: Arc<TelemetryMetrics>,
}

impl<S> TelemetryMetricsService<S> {
	fn new(inner: S) -> TelemetryMetricsService<S> {
		let metrics = Arc::new(TelemetryMetrics::new());
		TelemetryMetricsService { inner, metrics }
	}
}

impl<S, B> tower::Service<http::Request<B>> for TelemetryMetricsService<S>
where
	S: tower::Service<http::Request<B>> + Send + 'static,
	S::Future: Send + 'static,
	S::Error: std::fmt::Debug,
	B: http_body::Body + Send + 'static,
	B::Error: Into<tonic::codegen::StdError> + Send + 'static,
{
	type Response = S::Response;
	type Error = S::Error;
	type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

	fn poll_ready(
		&mut self,
		cx: &mut std::task::Context<'_>,
	) -> std::task::Poll<Result<(), Self::Error>> {
		self.inner.poll_ready(cx)
	}

	fn call(&mut self, req: http::Request<B>) -> Self::Future {
		let uri = req.uri();
		let headers = req.headers();
		let is_grpc = headers
			.get("content-type")
			.map_or(false, |ct| ct == "application/grpc");

		let mut rpc_method_details = RpcMethodDetails {
			system: RPC_SYSTEM_HTTP,
			service: RPC_UNKNOWN,
			method: RPC_UNKNOWN,
		};

		if is_grpc {
			rpc_method_details.system = RPC_SYSTEM_GRPC;
			if let Some((service, method)) = extract_service_method(&uri) {
				rpc_method_details.service = service;
				rpc_method_details.method = method;
			}
		}

		let attributes = [
			KeyValue::new(telemetry::ATTRIBUTE_SYSTEM, rpc_method_details.system),
			KeyValue::new(telemetry::ATTRIBUTE_SERVICE, rpc_method_details.service),
			KeyValue::new(telemetry::ATTRIBUTE_METHOD, rpc_method_details.method),
		];

		self.metrics.in_progress_counter.add(1, &attributes);

		let mut span = self.metrics.tracer
			.span_builder(rpc_method_details.format_path())
			.with_kind(SpanKind::Server)
			.start(&*self.metrics.tracer);
		span.set_attribute(KeyValue::new(semconv::trace::RPC_SYSTEM, rpc_method_details.system));
		span.set_attribute(KeyValue::new(semconv::trace::RPC_SERVICE, rpc_method_details.service));
		span.set_attribute(KeyValue::new(semconv::trace::RPC_METHOD, rpc_method_details.method));

		span.add_event(format!("Processing {} request", rpc_method_details.format_path()), vec![]);

		let span_context = Context::current_with_span(span);

		let metrics = self.metrics.clone();
		let start_time = Instant::now();
		let future = self.inner.call(req);
		Box::pin(async move {
			let res = future.await;

			let duration = start_time.elapsed();

			metrics.latency_histogram.record(duration.as_millis() as u64, &attributes);
			metrics.request_counter.add(1, &attributes);
			metrics.in_progress_counter.add(-1, &attributes);

			if let Err(ref status) = res {
				let error_string = format!("{:?}", status);

				metrics.error_counter.add(1, &[
					KeyValue::new(telemetry::ATTRIBUTE_SYSTEM, rpc_method_details.system),
					KeyValue::new(telemetry::ATTRIBUTE_SERVICE, rpc_method_details.service),
					KeyValue::new(telemetry::ATTRIBUTE_METHOD, rpc_method_details.method),
					KeyValue::new(telemetry::ATTRIBUTE_STATUS_CODE, error_string.clone()),
				]);

				trace!("Completed gRPC call: {} in {:?}, status: {}",
					rpc_method_details.format_path(), duration, error_string,
				);
			} else {
				span_context.span().set_attribute(KeyValue::new(RPC_GRPC_STATUS_CODE, tonic::Code::Ok as i64));

				trace!("Completed gRPC call: {} in {:?}, status: OK",
					rpc_method_details.format_path(), duration,
				);
			}

			res
		})
	}
}

#[derive(Clone)]
struct TelemetryMetricsLayer;

impl<S> tower::Layer<S> for TelemetryMetricsLayer {
	type Service = TelemetryMetricsService<S>;

	fn layer(&self, inner: S) -> Self::Service {
		TelemetryMetricsService::new(inner)
	}
}

fn pascal_to_snake(s: &str) -> String {
	let mut snake_case = String::new();

	for (i, c) in s.chars().enumerate() {
		if c.is_uppercase() {
			if i != 0 {
				snake_case.push('_');
			}
			snake_case.push(c.to_ascii_lowercase());
		} else {
			snake_case.push(c);
		}
	}

	snake_case
}

fn extract_service_method(url: &http::uri::Uri) -> Option<(&'static str, &'static str)> {
	// Find the last '/' in the URL
	let path = url.path();
	if let Some(last_slash_idx) = path.rfind('/') {
		let method = &path[last_slash_idx + 1..];
		let method_snake = pascal_to_snake(method);
		trace!("Extracting service method: {}", method_snake);
		let method_snake_ref: &str = &method_snake;

		// Find the last '.' before the method part
		let before_method = &path[..last_slash_idx];
		if let Some(dot_idx) = before_method.rfind('.') {
			let service = &before_method[dot_idx + 1..];
			trace!("Extracting service: {}", service);

			let service_ref = RPC_SERVICES
				.iter()
				.find(|&&m| m == service)
				.copied()?;

			let method_ref = RPC_SERVICE_ARK_METHODS
				.iter()
				.chain(RPC_SERVICE_ADMIN_METHODS.iter())
				.find(|&&m| m == method_snake_ref)
				.copied()?;

			return Some((service_ref, method_ref));
		}
	}

	None
}

/// Run the public gRPC endpoint.
pub async fn run_public_rpc_server(app: Arc<App>) -> anyhow::Result<()> {
	RPC_RICH_ERRORS.store(app.config.rpc_rich_errors, atomic::Ordering::Relaxed);

	let addr = app.config.rpc.public_address;
	info!("Starting public gRPC service on address {}", addr);
	let ark_server = rpc::server::ArkServiceServer::from_arc(app.clone());

	let mut shutdown = app.shutdown_channel.subscribe();
	if app.config.otel_collector_endpoint.is_some() {
		tonic::transport::Server::builder()
			.layer(TelemetryMetricsLayer)
			.add_service(ark_server)
			.serve_with_shutdown(addr, async move {
				shutdown.recv().await.expect("Shutdown channel failure");
				info!("Shutdown command received. Stopping gRPC server...");
			}).await
			.map_err(|e| {
				error!("Failed to start gRPC server on {}: {}", addr, e);
				e
			})?;
	} else {
		tonic::transport::Server::builder()
			.add_service(ark_server)
			.serve_with_shutdown(addr, async move {
				shutdown.recv().await.expect("Shutdown channel failure");
				info!("Shutdown command received. Stopping gRPC server...");
			}).await
			.map_err(|e| {
				error!("Failed to start gRPC server on {}: {}", addr, e);
				e
			})?;
	}

	info!("Terminated public gRPC service on address {}", addr);

	Ok(())
}

/// Run the public gRPC endpoint.
pub async fn run_admin_rpc_server(app: Arc<App>) -> anyhow::Result<()> {
	RPC_RICH_ERRORS.store(app.config.rpc_rich_errors, atomic::Ordering::Relaxed);

	let addr = app.config.rpc.admin_address.expect("shouldn't call this method otherwise");
	info!("Starting admin gRPC service on address {}", addr);
	let admin_server = rpc::server::AdminServiceServer::from_arc(app.clone());

	let mut shutdown = app.shutdown_channel.subscribe();
	if app.config.otel_collector_endpoint.is_some() {
		tonic::transport::Server::builder()
			.layer(TelemetryMetricsLayer)
			.add_service(admin_server)
			.serve_with_shutdown(addr, async move {
				shutdown.recv().await.expect("Shutdown channel failure");
				info!("Shutdown command received. Stopping gRPC server...");
			})
			.await
			.map_err(|e| {
				error!("Failed to start admin gRPC server on {}: {}", addr, e);

				e
			})?;
	} else {
		tonic::transport::Server::builder()
			.add_service(admin_server)
			.serve_with_shutdown(addr, async move {
				shutdown.recv().await.expect("Shutdown channel failure");
				info!("Shutdown command received. Stopping gRPC server...");
			})
			.await
			.map_err(|e| {
				error!("Failed to start admin gRPC server on {}: {}", addr, e);

				e
			})?;
	};

	info!("Terminated admin gRPC service on address {}", addr);

	Ok(())
}

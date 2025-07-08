
use std::fmt;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{self, AtomicBool};
use std::time::Instant;
use std::pin::Pin;
use std::future::Future;

use bip39::rand::Rng;
use bitcoin::{Amount, OutPoint, ScriptBuf, Transaction};
use bitcoin::hashes::{sha256, Hash};
use bitcoin::hex::DisplayHex;
use bitcoin::secp256k1::{rand, schnorr, PublicKey};
use lightning_invoice::Bolt11Invoice;
use log::{trace, info, warn, error};
use opentelemetry::{global, Context, KeyValue};
use opentelemetry::trace::{get_active_span, Span, SpanKind, TraceContextExt, Tracer, TracerProvider};
use tokio::sync::oneshot;
use tokio_stream::{Stream, StreamExt};
use tokio_stream::wrappers::BroadcastStream;

use ark::{musig, OffboardRequest, ProtocolEncoding, Vtxo, VtxoId, VtxoIdInput, VtxoPolicy, VtxoRequest};
use ark::rounds::RoundId;
use aspd_rpc::{self as rpc, protos, TryFromBytes};
use tonic::async_trait;

use crate::Server;
use crate::error::{AnyhowErrorExt, BadArgument, NotFound};
use crate::round::RoundInput;
use crate::telemetry::{self, ATTRIBUTE_VERSION, RPC_GRPC_STATUS_CODE};


/// Whether to provide rich internal errors to RPC users.
///
/// We keep this static because it's hard to propagate the config
/// into all error conversions.
static RPC_RICH_ERRORS: AtomicBool = AtomicBool::new(false);

/// The minimum 0.0.0-alpha.XXX version we serve.
pub const MIN_ALPHA_VERSION: usize = 10;

macro_rules! badarg {
	($($arg:tt)*) => { return $crate::error::badarg!($($arg)*).to_status(); };
}

#[allow(unused)]
macro_rules! not_found {
	($($arg:tt)*) => { return $crate::error::not_found!($($arg)*).to_status(); };
}


/// A trait to easily convert some errors to [tonic::Status].
trait ToStatus {
	fn to_status(self) -> tonic::Status;
}

impl ToStatus for anyhow::Error {
	fn to_status(self) -> tonic::Status {
		// NB tonic seems to have an undocumented limit on the body size
		// of error messages. We don't return the full stack trace, which
		// is included when we format the error with Debug.

		// NB it's important that not found goes first as a bad argument could
		// have been added afterwards
		trace!("RPC ERROR: {}", self.full_msg());
		if let Some(nf) = self.downcast_ref::<NotFound>() {
			let mut metadata = tonic::metadata::MetadataMap::new();
			let ids = nf.identifiers().join(",").parse().expect("non-ascii identifier");
			metadata.insert("identifiers", ids);
			tonic::Status::with_metadata(tonic::Code::NotFound, self.full_msg(), metadata)
		} else if let Some(_) = self.downcast_ref::<BadArgument>() {
			tonic::Status::invalid_argument(self.full_msg())
		} else {
			if RPC_RICH_ERRORS.load(atomic::Ordering::Relaxed) {
				tonic::Status::internal(self.full_msg())
			} else {
				tonic::Status::internal("internal error")
			}
		}
	}
}

/// A trait to easily convert some generic [Result]s into [tonic] [Result].
trait ToStatusResult<T> {
	/// Convert the error into a tonic error.
	fn to_status(self) -> Result<T, tonic::Status>;
}

impl<T, E: ToStatus> ToStatusResult<T> for Result<T, E> {
	fn to_status(self) -> Result<T, tonic::Status> {
		self.map_err(ToStatus::to_status)
	}
}

/// A trait to add context to errors that return tonic [tonic::Status] errors.
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
const RPC_SERVICE_ARK_REQUEST_BOARD_COSIGN: &'static str = "request_board_cosign";
const RPC_SERVICE_ARK_REGISTER_BOARD_VTXOS: &'static str = "register_board_vtxos";
const RPC_SERVICE_ARK_REQUEST_ARKOOR_PACKAGE_COSIGN: &'static str = "request_arkoor_package_cosign";
const RPC_SERVICE_ARK_POST_ARKOOR_PACKAGE_MAILBOX: &'static str = "post_arkoor_package_mailbox";
const RPC_SERVICE_ARK_EMPTY_ARKOOR_MAILBOX: &'static str = "empty_arkoor_mailbox";
const RPC_SERVICE_ARK_START_BOLT11_PAYMENT: &'static str = "start_bolt11_payment";
const RPC_SERVICE_ARK_FINISH_BOLT11_PAYMENT: &'static str = "finish_bolt11_payment";
const RPC_SERVICE_ARK_CHECK_BOLT11_PAYMENT: &'static str = "check_bolt11_payment";
const RPC_SERVICE_ARK_REVOKE_BOLT11_PAYMENT: &'static str = "revoke_bolt11_payment";
const RPC_SERVICE_ARK_START_BOLT11_ONBOARD: &'static str = "start_bolt11_onboard";
const RPC_SERVICE_ARK_SUBSCRIBE_BOLT11_ONBOARD: &'static str = "subscribe_bolt11_onboard";
const RPC_SERVICE_ARK_CLAIM_BOLT11_ONBOARD: &'static str = "claim_bolt11_onboard";
const RPC_SERVICE_ARK_SUBSCRIBE_ROUNDS: &'static str = "subscribe_rounds";
const RPC_SERVICE_ARK_SUBMIT_PAYMENT: &'static str = "submit_payment";
const RPC_SERVICE_ARK_PROVIDE_VTXO_SIGNATURES: &'static str = "provide_vtxo_signatures";
const RPC_SERVICE_ARK_PROVIDE_FORFEIT_SIGNATURES: &'static str = "provide_forfeit_signatures";

const RPC_SERVICE_ARK_METHODS: [&str; 19] = [
	RPC_SERVICE_ARK_HANDSHAKE,
	RPC_SERVICE_ARK_GET_FRESH_ROUNDS,
	RPC_SERVICE_ARK_GET_ROUND,
	RPC_SERVICE_ARK_REQUEST_BOARD_COSIGN,
	RPC_SERVICE_ARK_REGISTER_BOARD_VTXOS,
	RPC_SERVICE_ARK_REQUEST_ARKOOR_PACKAGE_COSIGN,
	RPC_SERVICE_ARK_POST_ARKOOR_PACKAGE_MAILBOX,
	RPC_SERVICE_ARK_EMPTY_ARKOOR_MAILBOX,
	RPC_SERVICE_ARK_START_BOLT11_PAYMENT,
	RPC_SERVICE_ARK_CHECK_BOLT11_PAYMENT,
	RPC_SERVICE_ARK_FINISH_BOLT11_PAYMENT,
	RPC_SERVICE_ARK_REVOKE_BOLT11_PAYMENT,
	RPC_SERVICE_ARK_START_BOLT11_ONBOARD,
	RPC_SERVICE_ARK_SUBSCRIBE_BOLT11_ONBOARD,
	RPC_SERVICE_ARK_CLAIM_BOLT11_ONBOARD,
	RPC_SERVICE_ARK_SUBSCRIBE_ROUNDS,
	RPC_SERVICE_ARK_SUBMIT_PAYMENT,
	RPC_SERVICE_ARK_PROVIDE_VTXO_SIGNATURES,
	RPC_SERVICE_ARK_PROVIDE_FORFEIT_SIGNATURES,
];

const RPC_SERVICE_ADMIN: &'static str = "AdminService";

const RPC_SERVICE_ADMIN_WALLET_SYNC: &'static str = "wallet_sync";
const RPC_SERVICE_ADMIN_WALLET_STATUS: &'static str = "wallet_status";
const RPC_SERVICE_ADMIN_TRIGGER_ROUND: &'static str = "trigger_round";
const RPC_SERVICE_ADMIN_TRIGGER_SWEEP: &'static str = "trigger_sweep";
const RPC_SERVICE_ADMIN_START_LIGHTNING_NODE: &'static str = "start_lightning_node";
const RPC_SERVICE_ADMIN_STOP_LIGHTNING_NODE: &'static str = "stop_lightning_node";
const RPC_SERVICE_ADMIN_STOP: &'static str = "stop";

const RPC_SERVICE_ADMIN_METHODS: [&str; 5] = [
	RPC_SERVICE_ADMIN_WALLET_SYNC,
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
impl rpc::server::ArkService for Server {
	async fn handshake(
		&self,
		req: tonic::Request<protos::HandshakeRequest>,
	) -> Result<tonic::Response<protos::HandshakeResponse>, tonic::Status> {
		let method_details = RpcMethodDetails::grpc_ark(RPC_SERVICE_ARK_HANDSHAKE);

		let version = req.into_inner().version;

		let alpha_version = version.strip_prefix("0.0.0-alpha").and_then(|alpha| {
			match alpha.strip_prefix(".") {
				Some(ver) => usize::from_str(ver).ok(),
				None => Some(0), // special value for master build
			}
		});

		let tracer_provider = global::tracer_provider().tracer(telemetry::TRACER_ASPD);

		let parent_context = Context::current();

		let mut span = tracer_provider
			.span_builder(method_details.method)
			.start_with_context(&tracer_provider, &parent_context);
		span.set_attribute(KeyValue::new(ATTRIBUTE_VERSION, version.clone()));

		telemetry::count_version(&version);

		// NB future note to always accept version "testing" which our tests use

		let ark_info = ark::ArkInfo {
			network: self.config.network,
			asp_pubkey: self.asp_key.public_key(),
			round_interval: self.config.round_interval,
			nb_round_nonces: self.config.nb_round_nonces,
			vtxo_exit_delta: self.config.vtxo_exit_delta,
			vtxo_expiry_delta: self.config.vtxo_expiry_delta,
			htlc_expiry_delta: self.config.htlc_expiry_delta,
			max_vtxo_amount: self.config.max_vtxo_amount,
			max_arkoor_depth: self.config.max_arkoor_depth,
		};

		let res = match alpha_version {
			// NB 0 represents master
			Some(0) => protos::HandshakeResponse {
				psa: self.config.handshake_psa.clone(),
				error: Some("You are running a manual build of bark; \
				it may be incompatible with the server.".into()),
				ark_info: Some(ark_info.into()),
			},
			None => protos::HandshakeResponse {
				psa: self.config.handshake_psa.clone(),
				error: Some("You're running an unknown version of bark.".into()),
				ark_info: Some(ark_info.into()),
			},
			Some(v) if v >= MIN_ALPHA_VERSION => protos::HandshakeResponse {
				psa: self.config.handshake_psa.clone(),
				error: None,
				ark_info: Some(ark_info.into()),
			},
			// this means < MIN_ALPHA_VERSION
			Some(_) => protos::HandshakeResponse {
				psa: None,
				error: Some("Your version of bark is incompatible with this server. \
					Please upgrade to a compatible version. \
					You can still do a unilateral exit.".into()),
				ark_info: None,
			},
		};

		Ok(tonic::Response::new(res))
	}

	async fn get_fresh_rounds(
		&self,
		req: tonic::Request<protos::FreshRoundsRequest>,
	) -> Result<tonic::Response<protos::FreshRounds>, tonic::Status> {
		let _ = RpcMethodDetails::grpc_ark(RPC_SERVICE_ARK_GET_FRESH_ROUNDS);
		let req = req.into_inner();

		add_tracing_attributes(vec![
			KeyValue::new("start_height", format!("{:?}", req.start_height)),
		]);

		let ids = self.db.get_fresh_round_ids(req.start_height).await
			.context("db error")?;

		let response = protos::FreshRounds {
			txids: ids.into_iter().map(|t| t.to_byte_array().to_vec()).collect(),
		};

		Ok(tonic::Response::new(response))
	}

	async fn get_round(
		&self,
		req: tonic::Request<protos::RoundId>,
	) -> Result<tonic::Response<protos::RoundInfo>, tonic::Status> {
		let _ = RpcMethodDetails::grpc_ark(RPC_SERVICE_ARK_GET_ROUND);
		let req = req.into_inner();

		add_tracing_attributes(vec![KeyValue::new("txid", format!("{:?}", req.txid))]);

		let id = RoundId::from_bytes(req.txid.as_slice())?;

		let ret = self.db.get_round(id).await
			.context("db error")?
			.not_found([id], "round with txid {} not found")?;

		let response = protos::RoundInfo {
			round_tx: bitcoin::consensus::serialize(&ret.tx),
			signed_vtxos: ret.signed_tree.serialize(),
		};

		Ok(tonic::Response::new(response))
	}

	// boarding

	async fn request_board_cosign(
		&self,
		req: tonic::Request<protos::BoardCosignRequest>,
	) -> Result<tonic::Response<protos::BoardCosignResponse>, tonic::Status> {
		let _ = RpcMethodDetails::grpc_ark(RPC_SERVICE_ARK_REQUEST_BOARD_COSIGN);
		let req = req.into_inner();

		add_tracing_attributes(vec![KeyValue::new("amount", req.amount.to_string())]);
		add_tracing_attributes(vec![KeyValue::new("user_pubkey", req.user_pubkey.as_hex().to_string())]);
		add_tracing_attributes(vec![KeyValue::new("expiry_height", req.expiry_height.to_string())]);
		add_tracing_attributes(vec![KeyValue::new("utxo", req.utxo.as_hex().to_string())]);

		let amount = Amount::from_sat(req.amount);
		let user_pubkey = PublicKey::from_bytes(&req.user_pubkey)?;
		let expiry_height = req.expiry_height;
		let utxo = OutPoint::from_bytes(&req.utxo)?;
		let pub_nonce = musig::PublicNonce::from_bytes(&req.pub_nonce)?;

		let resp = self.cosign_board(
			amount, user_pubkey, expiry_height, utxo, pub_nonce,
		).await.to_status()?;

		Ok(tonic::Response::new(resp.into()))
	}

	/// Registers a board vtxo
	///
	/// This method is idempotent
	async fn register_board_vtxo(
		&self,
		req: tonic::Request<protos::BoardVtxoRequest>,
	) -> Result<tonic::Response<protos::Empty>, tonic::Status> {
		let _ = RpcMethodDetails::grpc_ark(RPC_SERVICE_ARK_REGISTER_BOARD_VTXOS);
		let req = req.into_inner();

		add_tracing_attributes(vec![
			KeyValue::new("board_vtxo", format!("{:?}", req.board_vtxo.as_hex())),
			KeyValue::new("board_txid", format!("{:?}", req.board_tx.as_hex())),
		]);

		let vtxo = Vtxo::from_bytes(&req.board_vtxo)?;
		let board_tx = Transaction::from_bytes(&req.board_tx)?;
		self.register_board(vtxo, board_tx).await.to_status()?;

		Ok(tonic::Response::new(protos::Empty {}))
	}

	// oor
	async fn request_arkoor_package_cosign(
		&self,
		req: tonic::Request<protos::ArkoorPackageCosignRequest>,
	) -> Result<tonic::Response<protos::ArkoorPackageCosignResponse>, tonic::Status> {
		let _ = RpcMethodDetails::grpc_ark(RPC_SERVICE_ARK_REQUEST_ARKOOR_PACKAGE_COSIGN);
		let req = req.into_inner();

		add_tracing_attributes(vec![
			KeyValue::new("arkoors", format!("{:?}", req.arkoors)),
		]);

		let mut arkoor_args = vec![];
		for arkoor in req.arkoors.iter() {
			let input_id = VtxoId::from_bytes(&arkoor.input_id)?;
			let user_nonce = musig::PublicNonce::from_bytes(&arkoor.pub_nonce)?;
			let outputs = arkoor.outputs.iter().map(|o| {
				Ok(VtxoRequest {
					amount: Amount::from_sat(o.amount),
					policy: VtxoPolicy::from_bytes(&o.policy)?,
				})
			}).collect::<Result<Vec<_>, tonic::Status>>()?;
			arkoor_args.push((input_id, user_nonce, outputs))
		}

		let cosign_resp = self.cosign_oor_package(arkoor_args).await.to_status()?;

		Ok(tonic::Response::new(cosign_resp.into()))
	}

	async fn post_arkoor_package_mailbox(
		&self,
		req: tonic::Request<protos::ArkoorPackage>,
	) -> Result<tonic::Response<protos::Empty>, tonic::Status> {
		let _ = RpcMethodDetails::grpc_ark(RPC_SERVICE_ARK_POST_ARKOOR_PACKAGE_MAILBOX);
		let req = req.into_inner();

		add_tracing_attributes(vec![
			KeyValue::new("arkoors", format!("{:?}", req.arkoors)),
		]);


		let arkoor_package_id = rand::thread_rng().gen::<[u8; 32]>();

		for arkoor in req.arkoors {
			let pubkey = PublicKey::from_bytes(&arkoor.pubkey)?;
			let vtxo = Vtxo::from_bytes(&arkoor.vtxo)?;
			self.db.store_oor(pubkey, &arkoor_package_id, vtxo).await.to_status()?;
		}

		Ok(tonic::Response::new(protos::Empty{}))
	}

	async fn empty_arkoor_mailbox(
		&self,
		req: tonic::Request<protos::ArkoorVtxosRequest>,
	) -> Result<tonic::Response<protos::ArkoorVtxosResponse>, tonic::Status> {
		let _ = RpcMethodDetails::grpc_ark(RPC_SERVICE_ARK_EMPTY_ARKOOR_MAILBOX);
		let req = req.into_inner();

		add_tracing_attributes(vec![
			KeyValue::new("pubkey", format!("{:?}", req.pubkey)),
		]);

		let pubkey = PublicKey::from_bytes(&req.pubkey)?;
		let vtxos_by_package_id = self.db.pull_oors(pubkey).await.to_status()?;

		let response = protos::ArkoorVtxosResponse {
			packages: vtxos_by_package_id.into_iter().map(|(package_id, vtxos)| {
				protos::ArkoorMailboxPackage {
					arkoor_package_id: package_id.to_vec(),
					vtxos: vtxos.into_iter().map(|v| v.serialize()).collect(),
				}
			}).collect(),
		};

		Ok(tonic::Response::new(response))
	}

	// lightning

	async fn start_bolt11_payment(
		&self,
		req: tonic::Request<protos::Bolt11PaymentRequest>,
	) -> Result<tonic::Response<protos::ArkoorPackageCosignResponse>, tonic::Status> {
		let _ = RpcMethodDetails::grpc_ark(RPC_SERVICE_ARK_START_BOLT11_PAYMENT);
		let req = req.into_inner();

		add_tracing_attributes(
			vec![
				KeyValue::new("invoice", format!("{:?}", req.invoice)),
				KeyValue::new("amount_sats", format!("{:?}", req.user_amount_sat)),
				KeyValue::new("input_vtxo_ids", format!("{:?}", req.input_vtxo_ids)),
				KeyValue::new("user_nonces", format!("{:?}", req.user_nonces)),
			]);

		let invoice = Bolt11Invoice::from_str(&req.invoice)
			.badarg("invalid invoice")?;
		invoice.check_signature().badarg("invalid invoice signature")?;

		let inv_amount = invoice.amount_milli_satoshis()
			.map(|v| Amount::from_sat(v.div_ceil(1000)));

		if let (Some(_), Some(inv)) = (req.user_amount_sat, inv_amount) {
			badarg!("Invoice has amount of {} encoded. Please omit amount field", inv);
		}

		let amount = req.user_amount_sat.map(|v| Amount::from_sat(v)).or(inv_amount)
			.badarg("amount field required for invoice without amount")?;

		let input_ids = req.input_vtxo_ids.iter()
			.map(VtxoId::from_bytes)
			.collect::<Result<Vec<_>, _>>()?;

		let input_vtxos = self.db.get_vtxos_by_id(&input_ids).await
			.to_status()?.into_iter().map(|v| v.vtxo).collect::<Vec<_>>();

		let user_nonces = req.user_nonces.iter()
			.map(musig::PublicNonce::from_bytes)
			.collect::<Result<Vec<_>, _>>()?;

		let user_pubkey = PublicKey::from_bytes(&req.user_pubkey)?;

		let cosign_resp = self.start_bolt11_payment(
			invoice, amount, user_pubkey, input_vtxos, user_nonces
		).await.context("error making payment")?;

		Ok(tonic::Response::new(cosign_resp.into()))
	}

	async fn finish_bolt11_payment(
		&self,
		req: tonic::Request<protos::SignedBolt11PaymentDetails>,
	) -> Result<tonic::Response<protos::Bolt11PaymentResult>, tonic::Status> {
		let _ = RpcMethodDetails::grpc_ark(RPC_SERVICE_ARK_FINISH_BOLT11_PAYMENT);
		let req = req.into_inner();

		let htlc_vtxo_ids = req.htlc_vtxo_ids.iter()
			.map(VtxoId::from_bytes)
			.collect::<Result<Vec<_>, _>>()?;

		add_tracing_attributes(vec![
			KeyValue::new("invoice", format!("{:?}", req.invoice)),
			KeyValue::new("htlc_vtxo_ids", format!("{:?}", htlc_vtxo_ids)),
		]);

		let invoice = Bolt11Invoice::from_str(&req.invoice).badarg("invalid invoice")?;

		let res = self.finish_bolt11_payment(invoice, htlc_vtxo_ids, req.wait).await.to_status()?;
		Ok(tonic::Response::new(res))
	}

	async fn check_bolt11_payment(
		&self,
		req: tonic::Request<protos::CheckBolt11PaymentRequest>,
	) -> Result<tonic::Response<protos::Bolt11PaymentResult>, tonic::Status> {
		let _ = RpcMethodDetails::grpc_ark(RPC_SERVICE_ARK_CHECK_BOLT11_PAYMENT);
		let req = req.into_inner();

		let payment_hash = sha256::Hash::from_bytes(&req.hash)?;

		add_tracing_attributes(vec![
			KeyValue::new("payment_hash", payment_hash.to_string()),
		]);

		let res = self.check_bolt11_payment(payment_hash, req.wait).await.to_status()?;
		Ok(tonic::Response::new(res))
	}

	async fn revoke_bolt11_payment(
		&self,
		req: tonic::Request<protos::RevokeBolt11PaymentRequest>
	) -> Result<tonic::Response<protos::ArkoorPackageCosignResponse>, tonic::Status> {
		let _ = RpcMethodDetails::grpc_ark(RPC_SERVICE_ARK_REVOKE_BOLT11_PAYMENT);
		let req = req.into_inner();

		add_tracing_attributes(vec![
			KeyValue::new("htlc_vtxo_ids", format!("{:?}", req.htlc_vtxo_ids)),
			KeyValue::new("user_nonces", format!("{:?}", req.user_nonces)),
		]);

		let htlc_vtxo_ids = req.htlc_vtxo_ids.iter()
			.map(VtxoId::from_bytes)
			.collect::<Result<Vec<_>, _>>()?;

		let user_nonces = req.user_nonces.iter()
			.map(musig::PublicNonce::from_bytes)
			.collect::<Result<Vec<_>, _>>()?;

		let cosign_resp = self.revoke_bolt11_payment(htlc_vtxo_ids, user_nonces).await.to_status()?;
		Ok(tonic::Response::new(cosign_resp.into()))
	}

	async fn start_bolt11_onboard(
		&self,
		req: tonic::Request<protos::StartBolt11OnboardRequest>,
	) -> Result<tonic::Response<protos::StartBolt11OnboardResponse>, tonic::Status> {
		let _ = RpcMethodDetails::grpc_ark(RPC_SERVICE_ARK_START_BOLT11_ONBOARD);
		let req = req.into_inner();

		add_tracing_attributes(vec![
			KeyValue::new("payment_hash", format!("{:?}", req.payment_hash)),
			KeyValue::new("amount_sats", format!("{:?}", req.amount_sat)),
		]);

		let payment_hash = sha256::Hash::from_bytes(&req.payment_hash)?;
		let amount = Amount::from_sat(req.amount_sat);

		let resp = self.start_bolt11_onboard(payment_hash, amount).await.to_status()?;

		Ok(tonic::Response::new(resp))
	}

	async fn subscribe_bolt11_onboard(
		&self,
		req: tonic::Request<protos::SubscribeBolt11OnboardRequest>,
	) -> Result<tonic::Response<protos::SubscribeBolt11OnboardResponse>, tonic::Status> {
		let _ = RpcMethodDetails::grpc_ark(RPC_SERVICE_ARK_SUBSCRIBE_BOLT11_ONBOARD);
		let req = req.into_inner();

		let invoice = &req.bolt11;
		add_tracing_attributes(vec![
			KeyValue::new("bolt11", format!("{:?}", invoice)),
		]);

		let invoice = Bolt11Invoice::from_str(invoice).badarg("invalid invoice")?;

		let update = self.subscribe_bolt11_onboard(invoice).await.to_status()?;

		Ok(tonic::Response::new(update))
	}

	async fn claim_bolt11_onboard(
		&self,
		req: tonic::Request<protos::ClaimBolt11OnboardRequest>
	) -> Result<tonic::Response<protos::ArkoorCosignResponse>, tonic::Status> {
		let _ = RpcMethodDetails::grpc_ark(RPC_SERVICE_ARK_CLAIM_BOLT11_ONBOARD);
		let req = req.into_inner();

		let arkoor = req.arkoor.badarg("missing arkoor")?;

		add_tracing_attributes(vec![
			KeyValue::new("payment", arkoor.input_id.as_hex().to_string()),
			KeyValue::new("pub_nonce", arkoor.pub_nonce.as_hex().to_string()),
			KeyValue::new("payment_preimage", req.payment_preimage.as_hex().to_string()),
		]);

		let input_id = VtxoId::from_bytes(&arkoor.input_id)?;

		let output = arkoor.outputs.first().badarg("missing output")?;
		let pay_req = VtxoRequest {
			amount: Amount::from_sat(output.amount),
			policy: VtxoPolicy::from_bytes(&output.policy)?,
		};

		let user_nonce = musig::PublicNonce::from_bytes(&arkoor.pub_nonce)?;

		let payment_preimage: [u8; 32] = req.payment_preimage.as_slice()
			.try_into().badarg("invalid preimage, not 32 bytes")?;

		let cosign_resp = self.claim_bolt11_htlc(
			input_id,
			pay_req,
			user_nonce,
			&payment_preimage,
		).await.to_status()?;

		Ok(tonic::Response::new(cosign_resp.into()))
	}

	// round

	type SubscribeRoundsStream = Box<
		dyn Stream<Item = Result<protos::RoundEvent, tonic::Status>> + Unpin + Send + 'static
	>;

	async fn subscribe_rounds(
		&self,
		_req: tonic::Request<protos::Empty>,
	) -> Result<tonic::Response<Self::SubscribeRoundsStream>, tonic::Status> {
		let _ = RpcMethodDetails::grpc_ark(RPC_SERVICE_ARK_SUBSCRIBE_ROUNDS);

		let chan = self.rounds.round_event_tx.subscribe();
		let stream = BroadcastStream::new(chan);

		Ok(tonic::Response::new(Box::new(stream.map(|e| {
			Ok(e.context("broken stream")?.into())
		}))))
	}

	async fn submit_payment(
		&self,
		req: tonic::Request<protos::SubmitPaymentRequest>,
	) -> Result<tonic::Response<protos::Empty>, tonic::Status> {
		let _ = RpcMethodDetails::grpc_ark(RPC_SERVICE_ARK_SUBMIT_PAYMENT);
		let req = req.into_inner();

		add_tracing_attributes(vec![
			KeyValue::new("input_vtxos_count", format!("{:?}", req.input_vtxos.len())),
			KeyValue::new("vtxo_requests_count", format!("{:?}", req.vtxo_requests.len())),
			KeyValue::new("offboard_requests_count", format!("{:?}", req.offboard_requests.len())),
		]);

		let inputs =  req.input_vtxos.iter().map(|input| {
			let vtxo_id = VtxoId::from_bytes(&input.vtxo_id)?;
			let ownership_proof = schnorr::Signature::from_bytes(&input.ownership_proof)?;
			Ok(VtxoIdInput { vtxo_id, ownership_proof })
		}).collect::<Result<_, tonic::Status>>()?;

		let mut vtxo_requests = Vec::with_capacity(req.vtxo_requests.len());
		for r in req.vtxo_requests.clone() {
			// Make sure users provided right number of nonces.
			if r.public_nonces.len() != self.config.nb_round_nonces {
				badarg!("need exactly {} public nonces", self.config.nb_round_nonces);
			}
			vtxo_requests.push(r.try_into().badarg("invalid vtxo request")?);
		}

		let offboards = req.offboard_requests.iter().map(|r| {
			let amount = Amount::from_sat(r.amount);
			let script_pubkey = ScriptBuf::from_bytes(r.clone().offboard_spk);
			let ret = OffboardRequest { script_pubkey, amount };
			ret.validate().badarg("invalid offboard request")?;
			Ok(ret)
		}).collect::<Result<_, tonic::Status>>()?;

		let (tx, rx) = oneshot::channel();
		let inp = RoundInput::RegisterPayment { inputs, vtxo_requests, offboards };

		self.rounds.round_input_tx.send((inp, tx))
			.expect("input channel closed");
		rx.wait_for_status().await?;

		Ok(tonic::Response::new(protos::Empty {}))
	}

	async fn provide_vtxo_signatures(
		&self,
		req: tonic::Request<protos::VtxoSignaturesRequest>,
	) -> Result<tonic::Response<protos::Empty>, tonic::Status> {
		let _ = RpcMethodDetails::grpc_ark(RPC_SERVICE_ARK_PROVIDE_VTXO_SIGNATURES);
		let req = req.into_inner();

		add_tracing_attributes(vec![
			KeyValue::new("pubkey", format!("{:?}", req.pubkey)),
			KeyValue::new("signatures_count", format!("{:?}", req.signatures.len())),
		]);

		let (tx, rx) = oneshot::channel();
		let inp = RoundInput::VtxoSignatures {
			pubkey: PublicKey::from_bytes(&req.pubkey)?,
			signatures: req.signatures.iter()
				.map(musig::PartialSignature::from_bytes)
				.collect::<Result<_, _>>()?,
		};

		self.rounds.round_input_tx.send((inp, tx)).expect("input channel closed");
		rx.wait_for_status().await?;

		Ok(tonic::Response::new(protos::Empty {}))
	}

	async fn provide_forfeit_signatures(
		&self,
		req: tonic::Request<protos::ForfeitSignaturesRequest>,
	) -> Result<tonic::Response<protos::Empty>, tonic::Status> {
		let _ = RpcMethodDetails::grpc_ark(RPC_SERVICE_ARK_PROVIDE_FORFEIT_SIGNATURES);
		let req = req.into_inner();

		add_tracing_attributes(vec![
			KeyValue::new("signatures_count", format!("{:?}", req.signatures.len())),
		]);

		let (tx, rx) = oneshot::channel();
		let inp = RoundInput::ForfeitSignatures {
			signatures: req.signatures.iter().map(|ff| {
				let id = VtxoId::from_bytes(&ff.input_vtxo_id)?;
				let nonces = ff.pub_nonces.iter()
					.map(musig::PublicNonce::from_bytes)
					.collect::<Result<_, _>>()?;
				let signatures = ff.signatures.iter()
					.map(musig::PartialSignature::from_bytes)
					.collect::<Result<_, _>>()?;
				Ok((id, nonces, signatures))
			}).collect::<Result<_, tonic::Status>>()?
		};

		self.rounds.round_input_tx.send((inp, tx)).expect("input channel closed");
		rx.wait_for_status().await?;

		Ok(tonic::Response::new(protos::Empty {}))
	}
}

#[tonic::async_trait]
impl rpc::server::AdminService for Server {
	async fn wallet_sync(
		&self,
		_req: tonic::Request<protos::Empty>,
	) -> Result<tonic::Response<protos::Empty>, tonic::Status> {
		let _ = RpcMethodDetails::grpc_admin(RPC_SERVICE_ADMIN_WALLET_SYNC);

		self.sync_wallets().await.to_status()?;

		Ok(tonic::Response::new(protos::Empty {}))
	}

	async fn wallet_status(
		&self,
		_req: tonic::Request<protos::Empty>,
	) -> Result<tonic::Response<protos::WalletStatusResponse>, tonic::Status> {
		let _ = RpcMethodDetails::grpc_admin(RPC_SERVICE_ADMIN_WALLET_STATUS);

		let rounds = async {
			Ok(self.rounds_wallet.lock().await.status())
		};
		let forfeits = async {
			self.forfeits.wallet_status().await
		};

		let (rounds, forfeits) = tokio::try_join!(rounds, forfeits).to_status()?;

		Ok(tonic::Response::new(protos::WalletStatusResponse {
			rounds: Some(rounds.into()),
			forfeits: Some(forfeits.into()),
		}))
	}

	async fn trigger_round(
		&self,
		_req: tonic::Request<protos::Empty>,
	) -> Result<tonic::Response<protos::Empty>, tonic::Status> {
		let _ = RpcMethodDetails::grpc_admin(RPC_SERVICE_ADMIN_TRIGGER_ROUND);

		match self.rounds.round_trigger_tx.try_send(()) {
			Err(tokio::sync::mpsc::error::TrySendError::Closed(())) => {
				panic!("round scheduler closed");
			},
			Err(e) => warn!("Failed to send round trigger: {:?}", e),
			Ok(_) => trace!("round scheduler not closed"),
		}

		Ok(tonic::Response::new(protos::Empty{}))
	}

	async fn trigger_sweep(
		&self,
		_req: tonic::Request<protos::Empty>,
	) -> Result<tonic::Response<protos::Empty>, tonic::Status> {
		let _ = RpcMethodDetails::grpc_admin(RPC_SERVICE_ADMIN_TRIGGER_SWEEP);
		self.vtxo_sweeper.trigger_sweep()
			.context("VtxoSweeper down")?;
		Ok(tonic::Response::new(protos::Empty{}))
	}

	async fn start_lightning_node(
		&self,
		req: tonic::Request<protos::LightningNodeUri>,
	) -> Result<tonic::Response<protos::Empty>, tonic::Status> {
		let _ = RpcMethodDetails::grpc_admin(RPC_SERVICE_ADMIN_START_LIGHTNING_NODE);
		let req = req.into_inner();
		let uri = http::Uri::from_str(req.uri.as_str()).unwrap();
		let _ = self.cln.activate(uri);
		Ok(tonic::Response::new(protos::Empty{}))
	}

	async fn stop_lightning_node(
		&self,
		req: tonic::Request<protos::LightningNodeUri>,
	) -> Result<tonic::Response<protos::Empty>, tonic::Status> {
		let _ = RpcMethodDetails::grpc_admin(RPC_SERVICE_ADMIN_STOP_LIGHTNING_NODE);
		let req = req.into_inner();
		let uri = http::Uri::from_str(req.uri.as_str()).unwrap();
		let _ = self.cln.disable(uri);
		Ok(tonic::Response::new(protos::Empty{}))
	}

	async fn stop(
		&self,
		_req: tonic::Request<protos::Empty>,
	) -> Result<tonic::Response<protos::Empty>, tonic::Status> {
		let _ = RpcMethodDetails::grpc_admin(RPC_SERVICE_ADMIN_STOP);
		info!("Shutting down because of RPC stop command...");
		self.rtmgr.shutdown();
		Ok(tonic::Response::new(protos::Empty {}))
	}
}


#[derive(Clone)]
struct TelemetryMetricsService<S> {
	inner: S,
}

impl<S> TelemetryMetricsService<S> {
	fn new(inner: S) -> TelemetryMetricsService<S> {
		TelemetryMetricsService { inner }
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
			KeyValue::new(telemetry::RPC_SYSTEM, rpc_method_details.system),
			KeyValue::new(telemetry::RPC_SERVICE, rpc_method_details.service),
			KeyValue::new(telemetry::RPC_METHOD, rpc_method_details.method),
		];

		telemetry::add_grpc_in_progress(&attributes);

		let tracer = global::tracer(telemetry::TRACER_ASPD);

		let mut span = tracer
			.span_builder(rpc_method_details.format_path())
			.with_kind(SpanKind::Server)
			.start(&tracer);
		span.set_attribute(KeyValue::new(telemetry::RPC_SYSTEM, rpc_method_details.system));
		span.set_attribute(KeyValue::new(telemetry::RPC_SERVICE, rpc_method_details.service));
		span.set_attribute(KeyValue::new(telemetry::RPC_METHOD, rpc_method_details.method));

		span.add_event(format!("Processing {} request", rpc_method_details.format_path()), vec![]);

		let span_context = Context::current_with_span(span);

		let start_time = Instant::now();
		let future = self.inner.call(req);
		Box::pin(async move {
			let res = future.await;

			let duration = start_time.elapsed();

			telemetry::record_grpc_latency(duration, &attributes);
			telemetry::drop_grpc_in_progress(&attributes);

			if let Err(ref status) = res {
				let error_string = format!("{:?}", status);

				telemetry::add_grpc_error(&[
					KeyValue::new(telemetry::RPC_SYSTEM, rpc_method_details.system),
					KeyValue::new(telemetry::RPC_SERVICE, rpc_method_details.service),
					KeyValue::new(telemetry::RPC_METHOD, rpc_method_details.method),
					KeyValue::new(telemetry::ATTRIBUTE_ERROR, error_string.clone()),
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
pub async fn run_public_rpc_server(server: Arc<Server>) -> anyhow::Result<()> {
	RPC_RICH_ERRORS.store(server.config.rpc_rich_errors, atomic::Ordering::Relaxed);

	let _worker = server.rtmgr.spawn_critical("PublicRpcServer");

	let addr = server.config.rpc.public_address;
	info!("Starting public gRPC service on address {}", addr);
	let ark_server = rpc::server::ArkServiceServer::from_arc(server.clone());

	if server.config.otel_collector_endpoint.is_some() {
		tonic::transport::Server::builder()
			.layer(TelemetryMetricsLayer)
			.add_service(ark_server)
			.serve_with_shutdown(addr, server.rtmgr.shutdown_signal()).await
			.map_err(|e| {
				error!("Failed to start gRPC server on {}: {}", addr, e);
				e
			})?;
	} else {
		tonic::transport::Server::builder()
			.add_service(ark_server)
			.serve_with_shutdown(addr, server.rtmgr.shutdown_signal()).await
			.map_err(|e| {
				error!("Failed to start gRPC server on {}: {}", addr, e);
				e
			})?;
	}

	info!("Terminated public gRPC service on address {}", addr);

	Ok(())
}

/// Run the public gRPC endpoint.
pub async fn run_admin_rpc_server(server: Arc<Server>) -> anyhow::Result<()> {
	RPC_RICH_ERRORS.store(server.config.rpc_rich_errors, atomic::Ordering::Relaxed);

	let _worker = server.rtmgr.spawn_critical("AdminRpcServer");

	let addr = server.config.rpc.admin_address.expect("shouldn't call this method otherwise");
	info!("Starting admin gRPC service on address {}", addr);
	let admin_server = rpc::server::AdminServiceServer::from_arc(server.clone());

	if server.config.otel_collector_endpoint.is_some() {
		tonic::transport::Server::builder()
			.layer(TelemetryMetricsLayer)
			.add_service(admin_server)
			.serve_with_shutdown(addr, server.rtmgr.shutdown_signal()).await
			.map_err(|e| {
				error!("Failed to start admin gRPC server on {}: {}", addr, e);

				e
			})?;
	} else {
		tonic::transport::Server::builder()
			.add_service(admin_server)
			.serve_with_shutdown(addr, server.rtmgr.shutdown_signal()).await
			.map_err(|e| {
				error!("Failed to start admin gRPC server on {}: {}", addr, e);

				e
			})?;
	};

	info!("Terminated admin gRPC service on address {}", addr);

	Ok(())
}

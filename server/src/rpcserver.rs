
use std::fmt;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{self, AtomicBool};
use std::time::Duration;
use bip39::rand::Rng;
use bitcoin::{Amount, OutPoint, ScriptBuf, Transaction};
use bitcoin::hashes::Hash;
use bitcoin::hex::DisplayHex;
use bitcoin::secp256k1::{rand, schnorr, PublicKey};
use bitcoin_ext::AmountExt;
use lightning_invoice::Bolt11Invoice;
use log::{trace, info, warn};
use opentelemetry::KeyValue;
use opentelemetry::trace::get_active_span;
use tokio::sync::oneshot;
use tokio_stream::{Stream, StreamExt};
use tonic::async_trait;

use ark::{musig, OffboardRequest, ProtocolEncoding, Vtxo, VtxoId, VtxoIdInput, VtxoPolicy, VtxoRequest};
use ark::lightning::{Bolt12InvoiceExt, Invoice, Offer, OfferAmount};
use ark::rounds::RoundId;
use server_rpc::{self as rpc, protos, RequestExt, TryFromBytes};
use ark::lightning::{PaymentHash, Preimage};
use crate::Server;
use crate::error::{AnyhowErrorExt, BadArgument, NotFound};
use crate::grpcserver::middleware;
use crate::grpcserver::middleware::{
	RpcMethodDetails,
	RPC_SERVICE_ADMIN_START_LIGHTNING_NODE,
	RPC_SERVICE_ADMIN_STOP_LIGHTNING_NODE,
	RPC_SERVICE_ADMIN_TRIGGER_ROUND,
	RPC_SERVICE_ADMIN_TRIGGER_SWEEP,
	RPC_SERVICE_ADMIN_WALLET_STATUS,
	RPC_SERVICE_ADMIN_WALLET_SYNC,
	RPC_SERVICE_ARK_CHECK_LIGHTNING_PAYMENT,
	RPC_SERVICE_ARK_CLAIM_LIGHTNING_RECEIVE,
	RPC_SERVICE_ARK_EMPTY_ARKOOR_MAILBOX,
	RPC_SERVICE_ARK_FETCH_BOLT12_INVOICE,
	RPC_SERVICE_ARK_FINISH_LIGHTNING_PAYMENT,
	RPC_SERVICE_ARK_GET_ARK_INFO,
	RPC_SERVICE_ARK_GET_FRESH_ROUNDS,
	RPC_SERVICE_ARK_GET_ROUND,
	RPC_SERVICE_ARK_HANDSHAKE,
	RPC_SERVICE_ARK_LAST_ROUND_EVENT,
	RPC_SERVICE_ARK_POST_ARKOOR_PACKAGE_MAILBOX,
	RPC_SERVICE_ARK_PROVIDE_FORFEIT_SIGNATURES,
	RPC_SERVICE_ARK_PROVIDE_VTXO_SIGNATURES,
	RPC_SERVICE_ARK_REGISTER_BOARD_VTXOS,
	RPC_SERVICE_ARK_REQUEST_ARKOOR_PACKAGE_COSIGN,
	RPC_SERVICE_ARK_REQUEST_BOARD_COSIGN,
	RPC_SERVICE_ARK_REVOKE_LIGHTNING_PAYMENT,
	RPC_SERVICE_ARK_START_LIGHTNING_PAYMENT,
	RPC_SERVICE_ARK_START_LIGHTNING_RECEIVE,
	RPC_SERVICE_ARK_SUBMIT_PAYMENT,
	RPC_SERVICE_ARK_SUBSCRIBE_LIGHTNING_RECEIVE,
	RPC_SERVICE_ARK_SUBSCRIBE_ROUNDS,
};
use crate::round::RoundInput;
use crate::telemetry;


/// The minimum protocol version supported by the server.
///
/// For info on protocol versions, see [server_rpc] module documentation.
pub const MIN_PROTOCOL_VERSION: u64 = 1;

/// The maximum protocol version supported by the server.
///
/// For info on protocol versions, see [server_rpc] module documentation.
pub const MAX_PROTOCOL_VERSION: u64 = 1;

/// Whether to provide rich internal errors to RPC users.
///
/// We keep this static because it's hard to propagate the config
/// into all error conversions.
pub(crate) static RPC_RICH_ERRORS: AtomicBool = AtomicBool::new(false);

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
pub trait ToStatusResult<T> {
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

fn add_tracing_attributes(attributes: Vec<KeyValue>) -> () {
	get_active_span(|span| {
		span.add_event("attach-attributes", attributes);
	})
}

/// Get the protocol version sent by the user and check if it's supported.
#[allow(unused)]
fn validate_pver<T>(req: &tonic::Request<T>) -> Result<u64, tonic::Status> {
	let pver = req.pver()?;

	if !(MIN_PROTOCOL_VERSION..=MAX_PROTOCOL_VERSION).contains(&pver) {
		return Err(tonic::Status::invalid_argument("unsupported protocol version"));
	}

	Ok(pver)
}

#[tonic::async_trait]
impl rpc::server::ArkService for Server {
	async fn handshake(
		&self,
		req: tonic::Request<protos::HandshakeRequest>,
	) -> Result<tonic::Response<protos::HandshakeResponse>, tonic::Status> {
		let _ = RpcMethodDetails::grpc_ark(RPC_SERVICE_ARK_HANDSHAKE);
		let req = req.into_inner();

		telemetry::count_bark_version(req.bark_version);

		let ret = protos::HandshakeResponse {
			min_protocol_version: MIN_PROTOCOL_VERSION,
			max_protocol_version: MAX_PROTOCOL_VERSION,
			psa: self.config.handshake_psa.clone(),
		};
		Ok(tonic::Response::new(ret))
	}

	async fn get_ark_info(
		&self,
		_req: tonic::Request<protos::Empty>,
	) -> Result<tonic::Response<protos::ArkInfo>, tonic::Status> {
		let _ = RpcMethodDetails::grpc_ark(RPC_SERVICE_ARK_GET_ARK_INFO);

		let ark_info = ark::ArkInfo {
			network: self.config.network,
			server_pubkey: self.server_key.leak_ref().public_key(),
			round_interval: self.config.round_interval,
			nb_round_nonces: self.config.nb_round_nonces,
			vtxo_exit_delta: self.config.vtxo_exit_delta,
			vtxo_expiry_delta: self.config.vtxo_lifetime,
			htlc_expiry_delta: self.config.htlc_expiry_delta,
			max_vtxo_amount: self.config.max_vtxo_amount,
			max_arkoor_depth: self.config.max_arkoor_depth,
		};
		Ok(tonic::Response::new(ark_info.into()))
	}

	async fn get_fresh_rounds(
		&self,
		req: tonic::Request<protos::FreshRoundsRequest>,
	) -> Result<tonic::Response<protos::FreshRounds>, tonic::Status> {
		let _ = RpcMethodDetails::grpc_ark(RPC_SERVICE_ARK_GET_FRESH_ROUNDS);
		let req = req.into_inner();

		add_tracing_attributes(vec![
			KeyValue::new("last_round_txid", req.last_round_txid.clone().unwrap_or_default()),
		]);

		let txid = match req.last_round_txid {
			Some(t) => Some(RoundId::from_str(&t).badarg("invalid last_round_txid")?),
			None => None,
		};
		let lifetime = Duration::from_secs(10 * 60 * self.config.vtxo_lifetime as u64);
		let ids = self.db.get_fresh_round_ids(txid, lifetime).await
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
			KeyValue::new("pubkeys", format!("{:?}", req.pubkeys)),
		]);

		if req.pubkeys.len() > rpc::MAX_NB_MAILBOX_PUBKEYS {
			badarg!("too many pubkeys: max {}", rpc::MAX_NB_MAILBOX_PUBKEYS);
		}

		let pubkeys = req.pubkeys.iter()
			.map(PublicKey::from_bytes)
			.collect::<Result<Vec<_>, _>>()?;
		let vtxos_by_package_id = self.db.pull_oors(&pubkeys).await.to_status()?;

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

	async fn start_lightning_payment(
		&self,
		req: tonic::Request<protos::LightningPaymentRequest>,
	) -> Result<tonic::Response<protos::ArkoorPackageCosignResponse>, tonic::Status> {
		let _ = RpcMethodDetails::grpc_ark(RPC_SERVICE_ARK_START_LIGHTNING_PAYMENT);
		let req = req.into_inner();

		add_tracing_attributes(
			vec![
				KeyValue::new("invoice", format!("{:?}", req.invoice)),
				KeyValue::new("amount_sats", format!("{:?}", req.user_amount_sat)),
				KeyValue::new("input_vtxo_ids", format!("{:?}", req.input_vtxo_ids)),
				KeyValue::new("user_nonces", format!("{:?}", req.user_nonces)),
			]);

		let invoice = Invoice::from_str(&req.invoice).badarg("invalid invoice")?;
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

		let cosign_resp = self.start_lightning_payment(
			invoice, amount, user_pubkey, input_vtxos, user_nonces
		).await.context("error making payment")?;

		Ok(tonic::Response::new(cosign_resp.into()))
	}

	async fn finish_lightning_payment(
		&self,
		req: tonic::Request<protos::SignedLightningPaymentDetails>,
	) -> Result<tonic::Response<protos::LightningPaymentResult>, tonic::Status> {
		let _ = RpcMethodDetails::grpc_ark(RPC_SERVICE_ARK_FINISH_LIGHTNING_PAYMENT);
		let req = req.into_inner();

		let htlc_vtxo_ids = req.htlc_vtxo_ids.iter()
			.map(VtxoId::from_bytes)
			.collect::<Result<Vec<_>, _>>()?;

		add_tracing_attributes(vec![
			KeyValue::new("invoice", format!("{:?}", req.invoice)),
			KeyValue::new("htlc_vtxo_ids", format!("{:?}", htlc_vtxo_ids)),
		]);

		let invoice = Invoice::from_str(&req.invoice).badarg("invalid invoice")?;

		let res = self.finish_lightning_payment(invoice, htlc_vtxo_ids, req.wait).await.to_status()?;
		Ok(tonic::Response::new(res))
	}

	async fn check_lightning_payment(
		&self,
		req: tonic::Request<protos::CheckLightningPaymentRequest>,
	) -> Result<tonic::Response<protos::LightningPaymentResult>, tonic::Status> {
		let _ = RpcMethodDetails::grpc_ark(RPC_SERVICE_ARK_CHECK_LIGHTNING_PAYMENT);
		let req = req.into_inner();

		add_tracing_attributes(vec![
			KeyValue::new("payment_hash", req.hash.as_hex().to_string()),
		]);

		let payment_hash = PaymentHash::try_from(req.hash)
			.expect("payment hash must be 32 bytes");
		let res = self.check_lightning_payment(payment_hash, req.wait).await.to_status()?;
		Ok(tonic::Response::new(res))
	}

	async fn revoke_lightning_payment(
		&self,
		req: tonic::Request<protos::RevokeLightningPaymentRequest>
	) -> Result<tonic::Response<protos::ArkoorPackageCosignResponse>, tonic::Status> {
		let _ = RpcMethodDetails::grpc_ark(RPC_SERVICE_ARK_REVOKE_LIGHTNING_PAYMENT);
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

	async fn fetch_bolt12_invoice(
		&self,
		req: tonic::Request<protos::FetchBolt12InvoiceRequest>,
	) -> Result<tonic::Response<protos::FetchBolt12InvoiceResponse>, tonic::Status> {
		let _ = RpcMethodDetails::grpc_ark(RPC_SERVICE_ARK_FETCH_BOLT12_INVOICE);
		let req = req.into_inner();

		let offer = match Offer::try_from(req.offer.to_vec()) {
			Ok(offer) => offer,
			Err(_) => {
				badarg!("invalid offer");
			},
		};

		let amount = match req.amount_sat {
			Some(a) => { Amount::from_sat(a) },
			None if offer.amount().is_some() => {
				match offer.amount().unwrap() {
					OfferAmount::Bitcoin { amount_msats } => { Amount::from_msat_ceil(amount_msats) },
					_ => { badarg!("unsupported offer currency"); }
				}
			},
			None => {
				badarg!("amount_sat is required for bolt12 offers with no amount specified");
			},
		};

		let invoice = self.fetch_bolt12_invoice(offer, amount).await.to_status()?;

		Ok(tonic::Response::new(protos::FetchBolt12InvoiceResponse {
			invoice: invoice.bytes(),
		}))
	}

	async fn start_lightning_receive(
		&self,
		req: tonic::Request<protos::StartLightningReceiveRequest>,
	) -> Result<tonic::Response<protos::StartLightningReceiveResponse>, tonic::Status> {
		let _ = RpcMethodDetails::grpc_ark(RPC_SERVICE_ARK_START_LIGHTNING_RECEIVE);
		let req = req.into_inner();

		add_tracing_attributes(vec![
			KeyValue::new("payment_hash", format!("{:?}", req.payment_hash)),
			KeyValue::new("amount_sats", format!("{:?}", req.amount_sat)),
		]);

		let payment_hash = PaymentHash::try_from(req.payment_hash)
			.expect("payment hash must be 32 bytes");
		let amount = Amount::from_sat(req.amount_sat);

		let resp = self.start_lightning_receive(payment_hash, amount).await.to_status()?;

		Ok(tonic::Response::new(resp))
	}

	async fn subscribe_lightning_receive(
		&self,
		req: tonic::Request<protos::SubscribeLightningReceiveRequest>,
	) -> Result<tonic::Response<protos::SubscribeLightningReceiveResponse>, tonic::Status> {
		let _ = RpcMethodDetails::grpc_ark(RPC_SERVICE_ARK_SUBSCRIBE_LIGHTNING_RECEIVE);
		let req = req.into_inner();

		let invoice = &req.bolt11;
		add_tracing_attributes(vec![
			KeyValue::new("bolt11", format!("{:?}", invoice)),
		]);

		let invoice = Bolt11Invoice::from_str(invoice).badarg("invalid invoice")?;

		let update = self.subscribe_lightning_receive(invoice).await.to_status()?;

		Ok(tonic::Response::new(update))
	}

	async fn claim_lightning_receive(
		&self,
		req: tonic::Request<protos::ClaimLightningReceiveRequest>
	) -> Result<tonic::Response<protos::ArkoorCosignResponse>, tonic::Status> {
		let _ = RpcMethodDetails::grpc_ark(RPC_SERVICE_ARK_CLAIM_LIGHTNING_RECEIVE);
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

		let payment_preimage: Preimage = req.payment_preimage.as_slice()
			.try_into().badarg("invalid preimage, not 32 bytes")?;

		let cosign_resp = self.claim_bolt11_htlc(
			input_id,
			pay_req,
			user_nonce,
			payment_preimage,
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

		let stream = self.rounds.events();
		Ok(tonic::Response::new(Box::new(stream.map(|e| Ok(e.as_ref().into())))))
	}

	async fn last_round_event(
		&self,
		_req: tonic::Request<protos::Empty>,
	) -> Result<tonic::Response<protos::RoundEvent>, tonic::Status> {
		let _ = RpcMethodDetails::grpc_ark(RPC_SERVICE_ARK_LAST_ROUND_EVENT);

		if let Some(event) = self.rounds.last_event() {
			Ok(tonic::Response::new(event.as_ref().into()))
		} else {
			not_found!([""], "no round event yet");
		}
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
impl rpc::server::WalletAdminService for Server {
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
}

#[tonic::async_trait]
impl rpc::server::RoundAdminService for Server {
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
}

#[tonic::async_trait]
impl rpc::server::LightningAdminService for Server {
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
}

#[tonic::async_trait]
impl rpc::server::SweepAdminService for Server {
	async fn trigger_sweep(
		&self,
		_req: tonic::Request<protos::Empty>,
	) -> Result<tonic::Response<protos::Empty>, tonic::Status> {
		let _ = RpcMethodDetails::grpc_admin(RPC_SERVICE_ADMIN_TRIGGER_SWEEP);
		self.vtxo_sweeper.trigger_sweep()
			.context("VtxoSweeper down")?;
		Ok(tonic::Response::new(protos::Empty{}))
	}
}

/// Run the public gRPC endpoint.
pub async fn run_public_rpc_server(srv: Arc<Server>) -> anyhow::Result<()> {
	RPC_RICH_ERRORS.store(srv.config.rpc_rich_errors, atomic::Ordering::Relaxed);

	let _worker = srv.rtmgr.spawn_critical("PublicRpcServer");

	let addr = srv.config.rpc.public_address;
	info!("Starting public gRPC service on address {}", addr);

	let routes = tonic::service::Routes::default()
		.add_service(rpc::server::ArkServiceServer::from_arc(srv.clone()));

	if srv.config.otel_collector_endpoint.is_some() {
		tonic::transport::Server::builder()
			.layer(middleware::TelemetryMetricsLayer)
			.add_routes(routes)
			.serve_with_shutdown(addr, srv.rtmgr.shutdown_signal()).await?;
	} else {
		tonic::transport::Server::builder()
			.add_routes(routes)
			.serve_with_shutdown(addr, srv.rtmgr.shutdown_signal()).await?;
	}

	info!("Terminated public gRPC service on address {}", addr);

	Ok(())
}

/// Run the public gRPC endpoint.
pub async fn run_admin_rpc_server(srv: Arc<Server>) -> anyhow::Result<()> {
	RPC_RICH_ERRORS.store(srv.config.rpc_rich_errors, atomic::Ordering::Relaxed);

	let _worker = srv.rtmgr.spawn_critical("AdminRpcServer");

	let addr = srv.config.rpc.admin_address.expect("shouldn't call this method otherwise");
	info!("Starting admin gRPC service on address {}", addr);

	let routes = tonic::service::Routes::default()
		.add_service(rpc::server::WalletAdminServiceServer::from_arc(srv.clone()))
		.add_service(rpc::server::RoundAdminServiceServer::from_arc(srv.clone()))
		.add_service(rpc::server::LightningAdminServiceServer::from_arc(srv.clone()))
		.add_service(rpc::server::SweepAdminServiceServer::from_arc(srv.clone()));

	if srv.config.otel_collector_endpoint.is_some() {
		tonic::transport::Server::builder()
			.layer(middleware::TelemetryMetricsLayer)
			.add_routes(routes)
			.serve_with_shutdown(addr, srv.rtmgr.shutdown_signal()).await?;
	} else {
		tonic::transport::Server::builder()
			.add_routes(routes)
			.serve_with_shutdown(addr, srv.rtmgr.shutdown_signal()).await?;
	}

	info!("Terminated admin gRPC service on address {}", addr);

	Ok(())
}

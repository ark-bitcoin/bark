
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic;
use std::time::Duration;

use bip39::rand::Rng;
use bitcoin::{Amount, OutPoint, ScriptBuf};
use bitcoin::hashes::Hash;
use bitcoin::hex::DisplayHex;
use bitcoin::secp256k1::{rand, schnorr, PublicKey};
use log::info;
use opentelemetry::KeyValue;
use tokio::sync::oneshot;
use tokio_stream::{Stream, StreamExt};

use ark::{musig, OffboardRequest, ProtocolEncoding, Vtxo, VtxoId, VtxoIdInput, VtxoPolicy, VtxoRequest};
use ark::lightning::{Bolt12InvoiceExt, Invoice, Offer, OfferAmount, PaymentHash, Preimage};
use ark::rounds::RoundId;
use bitcoin_ext::{AmountExt, BlockDelta, BlockHeight};
use server_rpc::{self as rpc, protos, TryFromBytes};

use crate::Server;
use crate::rpcserver::{
	middleware,
	ReceiverExt,
	StatusContext,
	ToStatusResult,
	MAX_PROTOCOL_VERSION,
	MIN_PROTOCOL_VERSION,
	RPC_RICH_ERRORS,
};
use crate::round::RoundInput;
use crate::rpcserver::middleware::RpcMethodDetails;
use crate::telemetry;


macro_rules! badarg {
	($($arg:tt)*) => { return $crate::error::badarg!($($arg)*).to_status(); };
}

#[allow(unused)]
macro_rules! not_found {
	($($arg:tt)*) => { return $crate::error::not_found!($($arg)*).to_status(); };
}

#[tonic::async_trait]
impl rpc::server::ArkService for Server {
	async fn handshake(
		&self,
		req: tonic::Request<protos::HandshakeRequest>,
	) -> Result<tonic::Response<protos::HandshakeResponse>, tonic::Status> {
		let _ = RpcMethodDetails::grpc_ark(middleware::RPC_SERVICE_ARK_HANDSHAKE);
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
		let _ = RpcMethodDetails::grpc_ark(middleware::RPC_SERVICE_ARK_GET_ARK_INFO);

		Ok(tonic::Response::new(self.ark_info().into()))
	}

	async fn get_fresh_rounds(
		&self,
		req: tonic::Request<protos::FreshRoundsRequest>,
	) -> Result<tonic::Response<protos::FreshRounds>, tonic::Status> {
		let _ = RpcMethodDetails::grpc_ark(middleware::RPC_SERVICE_ARK_GET_FRESH_ROUNDS);
		let req = req.into_inner();

		crate::rpcserver::add_tracing_attributes(vec![
			KeyValue::new("last_round_txid", req.last_round_txid.clone().unwrap_or_default()),
		]);

		let txid = match req.last_round_txid {
			Some(t) => Some(RoundId::from_str(&t).badarg("invalid last_round_txid")?),
			None => None,
		};
		let lifetime = Duration::from_secs(10 * 60 * self.config.vtxo_lifetime as u64);
		let ids = self.db.get_fresh_round_ids(txid, Some(lifetime)).await
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
		let _ = RpcMethodDetails::grpc_ark(middleware::RPC_SERVICE_ARK_GET_ROUND);
		let req = req.into_inner();

		crate::rpcserver::add_tracing_attributes(vec![KeyValue::new("txid", format!("{:?}", req.txid))]);

		let id = RoundId::from_bytes(req.txid.as_slice())?;

		let ret = self.db.get_round(id).await
			.context("db error")?
			.not_found([id], "round with txid {} not found")?;

		let response = protos::RoundInfo {
			funding_tx: bitcoin::consensus::serialize(&ret.funding_tx),
			signed_vtxos: ret.signed_tree.serialize(),
		};

		Ok(tonic::Response::new(response))
	}

	// boarding

	async fn request_board_cosign(
		&self,
		req: tonic::Request<protos::BoardCosignRequest>,
	) -> Result<tonic::Response<protos::BoardCosignResponse>, tonic::Status> {
		let _ = RpcMethodDetails::grpc_ark(middleware::RPC_SERVICE_ARK_REQUEST_BOARD_COSIGN);
		let req = req.into_inner();

		crate::rpcserver::add_tracing_attributes(vec![KeyValue::new("amount", req.amount.to_string())]);
		crate::rpcserver::add_tracing_attributes(vec![KeyValue::new("user_pubkey", req.user_pubkey.as_hex().to_string())]);
		crate::rpcserver::add_tracing_attributes(vec![KeyValue::new("expiry_height", req.expiry_height.to_string())]);
		crate::rpcserver::add_tracing_attributes(vec![KeyValue::new("utxo", req.utxo.as_hex().to_string())]);

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
		let _ = RpcMethodDetails::grpc_ark(middleware::RPC_SERVICE_ARK_REGISTER_BOARD_VTXOS);
		let req = req.into_inner();

		crate::rpcserver::add_tracing_attributes(vec![
			KeyValue::new("board_vtxo", format!("{:?}", req.board_vtxo.as_hex())),
		]);

		let vtxo = Vtxo::from_bytes(&req.board_vtxo)?;
		self.register_board(vtxo).await.to_status()?;

		Ok(tonic::Response::new(protos::Empty {}))
	}

	// oor
	async fn request_arkoor_package_cosign(
		&self,
		req: tonic::Request<protos::ArkoorPackageCosignRequest>,
	) -> Result<tonic::Response<protos::ArkoorPackageCosignResponse>, tonic::Status> {
		let _ = RpcMethodDetails::grpc_ark(middleware::RPC_SERVICE_ARK_REQUEST_ARKOOR_PACKAGE_COSIGN);
		let req = req.into_inner();

		crate::rpcserver::add_tracing_attributes(vec![
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
		let _ = RpcMethodDetails::grpc_ark(middleware::RPC_SERVICE_ARK_POST_ARKOOR_PACKAGE_MAILBOX);
		let req = req.into_inner();

		crate::rpcserver::add_tracing_attributes(vec![
			KeyValue::new("arkoors", format!("{:?}", req.arkoors)),
		]);


		let arkoor_package_id = rand::thread_rng().r#gen::<[u8; 32]>();

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
		let _ = RpcMethodDetails::grpc_ark(middleware::RPC_SERVICE_ARK_EMPTY_ARKOOR_MAILBOX);
		let req = req.into_inner();

		crate::rpcserver::add_tracing_attributes(vec![
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
		req: tonic::Request<protos::StartLightningPaymentRequest>,
	) -> Result<tonic::Response<protos::StartLightningPaymentResponse>, tonic::Status> {
		let _ = RpcMethodDetails::grpc_ark(middleware::RPC_SERVICE_ARK_START_LIGHTNING_PAYMENT);
		let req = req.into_inner();

		crate::rpcserver::add_tracing_attributes(
			vec![
				KeyValue::new("invoice", format!("{:?}", req.invoice)),
				KeyValue::new("amount_sats", format!("{:?}", req.user_amount_sat)),
				KeyValue::new("input_vtxo_ids", format!("{:?}", req.input_vtxo_ids)),
				KeyValue::new("user_nonces", format!("{:?}", req.user_nonces)),
			]);

		let invoice = Invoice::from_str(&req.invoice).badarg("invalid invoice")?;
		invoice.check_signature().badarg("invalid invoice signature")?;

		let inv_amount = invoice.amount_msat()
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

		let resp = self.start_lightning_payment(
			invoice, amount, user_pubkey, input_vtxos, user_nonces
		).await.context("error making payment")?;

		Ok(tonic::Response::new(resp))
	}

	async fn finish_lightning_payment(
		&self,
		req: tonic::Request<protos::SignedLightningPaymentDetails>,
	) -> Result<tonic::Response<protos::LightningPaymentResult>, tonic::Status> {
		let _ = RpcMethodDetails::grpc_ark(middleware::RPC_SERVICE_ARK_FINISH_LIGHTNING_PAYMENT);
		let req = req.into_inner();

		let htlc_vtxo_ids = req.htlc_vtxo_ids.iter()
			.map(VtxoId::from_bytes)
			.collect::<Result<Vec<_>, _>>()?;

		crate::rpcserver::add_tracing_attributes(vec![
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
		let _ = RpcMethodDetails::grpc_ark(middleware::RPC_SERVICE_ARK_CHECK_LIGHTNING_PAYMENT);
		let req = req.into_inner();

		crate::rpcserver::add_tracing_attributes(vec![
			KeyValue::new("payment_hash", req.hash.as_hex().to_string()),
		]);

		let payment_hash = PaymentHash::from_bytes(req.hash)?;
		let res = self.check_lightning_payment(payment_hash, req.wait).await.to_status()?;
		Ok(tonic::Response::new(res))
	}

	async fn revoke_lightning_payment(
		&self,
		req: tonic::Request<protos::RevokeLightningPaymentRequest>
	) -> Result<tonic::Response<protos::ArkoorPackageCosignResponse>, tonic::Status> {
		let _ = RpcMethodDetails::grpc_ark(middleware::RPC_SERVICE_ARK_REVOKE_LIGHTNING_PAYMENT);
		let req = req.into_inner();

		crate::rpcserver::add_tracing_attributes(vec![
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
		let _ = RpcMethodDetails::grpc_ark(middleware::RPC_SERVICE_ARK_FETCH_BOLT12_INVOICE);
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
		let _ = RpcMethodDetails::grpc_ark(middleware::RPC_SERVICE_ARK_START_LIGHTNING_RECEIVE);
		let req = req.into_inner();

		crate::rpcserver::add_tracing_attributes(vec![
			KeyValue::new("payment_hash", format!("{:?}", req.payment_hash)),
			KeyValue::new("amount_sats", format!("{:?}", req.amount_sat)),
		]);

		let payment_hash = PaymentHash::from_bytes(req.payment_hash)?;
		let amount = Amount::from_sat(req.amount_sat);

		let resp = self.start_lightning_receive(
			payment_hash,
			amount,
			req.min_cltv_delta as BlockDelta
		).await.to_status()?;

		Ok(tonic::Response::new(resp))
	}

	async fn check_lightning_receive(
		&self,
		req: tonic::Request<protos::CheckLightningReceiveRequest>,
	) -> Result<tonic::Response<protos::CheckLightningReceiveResponse>, tonic::Status> {
		let _ = RpcMethodDetails::grpc_ark(middleware::RPC_SERVICE_ARK_CHECK_LIGHTNING_RECEIVE);
		let req = req.into_inner();

		let payment_hash = PaymentHash::from_bytes(req.hash)?;
		crate::rpcserver::add_tracing_attributes(vec![
			KeyValue::new("payment_hash", payment_hash.to_string()),
		]);

		let sub = self.check_lightning_receive(payment_hash, req.wait).await.to_status()?;
		Ok(tonic::Response::new(sub.into()))
	}

	async fn prepare_lightning_receive_claim(
		&self,
		req: tonic::Request<protos::PrepareLightningReceiveClaimRequest>
	) -> Result<tonic::Response<protos::PrepareLightningReceiveClaimResponse>, tonic::Status> {
		let _ = RpcMethodDetails::grpc_ark(middleware::RPC_SERVICE_ARK_CLAIM_LIGHTNING_RECEIVE);
		let req = req.into_inner();

		let payment_hash = PaymentHash::from_bytes(req.payment_hash)?;
		crate::rpcserver::add_tracing_attributes(vec![
			KeyValue::new("payment_hash", payment_hash.to_string()),
		]);

		let user_pubkey = PublicKey::from_bytes(&req.user_pubkey)?;
		let htlc_recv_expiry = req.htlc_recv_expiry as BlockHeight;

		let (sub, htlcs) = self.prepare_lightning_claim(
			payment_hash, user_pubkey, htlc_recv_expiry,
		).await.to_status()?;

		Ok(tonic::Response::new(protos::PrepareLightningReceiveClaimResponse {
			receive: Some(sub.into()),
			htlc_vtxos: htlcs.into_iter().map(|v| v.serialize()).collect(),
		}))
	}

	async fn claim_lightning_receive(
		&self,
		req: tonic::Request<protos::ClaimLightningReceiveRequest>
	) -> Result<tonic::Response<protos::ArkoorPackageCosignResponse>, tonic::Status> {
		let _ = RpcMethodDetails::grpc_ark(middleware::RPC_SERVICE_ARK_CLAIM_LIGHTNING_RECEIVE);
		let req = req.into_inner();

		let payment_hash = PaymentHash::from_bytes(req.payment_hash)?;
		crate::rpcserver::add_tracing_attributes(vec![
			KeyValue::new("payment_hash", payment_hash.to_string()),
		]);

		let payment_preimage = Preimage::from_bytes(req.payment_preimage)?;

		let vtxo_policy = VtxoPolicy::from_bytes(req.vtxo_policy)?;
		let user_nonces = req.user_pub_nonces.iter()
			.map(musig::PublicNonce::from_bytes)
			.collect::<Result<Vec<_>, _>>()?;

		let cosign_resp = self.claim_lightning_receive(
			payment_hash,
			vtxo_policy,
			user_nonces,
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
		let _ = RpcMethodDetails::grpc_ark(middleware::RPC_SERVICE_ARK_SUBSCRIBE_ROUNDS);

		let stream = self.rounds.events();
		Ok(tonic::Response::new(Box::new(stream.map(|e| Ok(e.as_ref().into())))))
	}

	async fn last_round_event(
		&self,
		_req: tonic::Request<protos::Empty>,
	) -> Result<tonic::Response<protos::RoundEvent>, tonic::Status> {
		let _ = RpcMethodDetails::grpc_ark(middleware::RPC_SERVICE_ARK_LAST_ROUND_EVENT);

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
		let _ = RpcMethodDetails::grpc_ark(middleware::RPC_SERVICE_ARK_SUBMIT_PAYMENT);
		let req = req.into_inner();

		crate::rpcserver::add_tracing_attributes(vec![
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
		let _ = RpcMethodDetails::grpc_ark(middleware::RPC_SERVICE_ARK_PROVIDE_VTXO_SIGNATURES);
		let req = req.into_inner();

		crate::rpcserver::add_tracing_attributes(vec![
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
		let _ = RpcMethodDetails::grpc_ark(middleware::RPC_SERVICE_ARK_PROVIDE_FORFEIT_SIGNATURES);
		let req = req.into_inner();

		crate::rpcserver::add_tracing_attributes(vec![
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

/// Run the public gRPC endpoint.
pub async fn run_rpc_server(srv: Arc<Server>) -> anyhow::Result<()> {
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

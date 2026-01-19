
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic;
use std::time::Duration;

use bip39::rand::Rng;
use bitcoin::consensus::serialize;
use bitcoin::Txid;
use bitcoin::{Amount, OutPoint};
use bitcoin::hashes::Hash;
use bitcoin::hex::DisplayHex;
use bitcoin::secp256k1::{rand, schnorr, PublicKey};
use opentelemetry::KeyValue;
use tokio::sync::oneshot;
use tokio_stream::{Stream, StreamExt};
use tonic_tracing_opentelemetry::middleware::server::OtelGrpcLayer;
use tracing::info;

use ark::{
	musig, ProtocolEncoding, Vtxo, VtxoId, VtxoIdInput, VtxoPolicy,
};
use ark::arkoor::package::ArkoorPackageCosignRequest;
use ark::forfeit::HashLockedForfeitBundle;
use ark::lightning::{Bolt12InvoiceExt, Invoice, Offer, OfferAmount, PaymentHash, Preimage};
use ark::tree::signed::{LeafVtxoCosignRequest, UnlockHash, UnlockPreimage};
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
use crate::rpcserver::macros;
use crate::telemetry;


#[async_trait]
impl rpc::server::ArkService for Server {
	async fn handshake(
		&self,
		req: tonic::Request<protos::HandshakeRequest>,
	) -> Result<tonic::Response<protos::HandshakeResponse>, tonic::Status> {
		let _ = RpcMethodDetails::grpc_ark(middleware::rpc_names::ark::HANDSHAKE);
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
		let _ = RpcMethodDetails::grpc_ark(middleware::rpc_names::ark::GET_ARK_INFO);

		Ok(tonic::Response::new(self.ark_info().into()))
	}

	async fn get_fresh_rounds(
		&self,
		req: tonic::Request<protos::FreshRoundsRequest>,
	) -> Result<tonic::Response<protos::FreshRounds>, tonic::Status> {
		let _ = RpcMethodDetails::grpc_ark(middleware::rpc_names::ark::GET_FRESH_ROUNDS);
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
		let _ = RpcMethodDetails::grpc_ark(middleware::rpc_names::ark::GET_ROUND);
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
		let _ = RpcMethodDetails::grpc_ark(middleware::rpc_names::ark::REQUEST_BOARD_COSIGN);
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
		let _ = RpcMethodDetails::grpc_ark(middleware::rpc_names::ark::REGISTER_BOARD_VTXO);
		let req = req.into_inner();

		crate::rpcserver::add_tracing_attributes(vec![
			KeyValue::new("board_vtxo", format!("{:?}", req.board_vtxo.as_hex())),
		]);

		let vtxo = Vtxo::from_bytes(&req.board_vtxo)?;
		self.register_board(vtxo).await.to_status()?;

		Ok(tonic::Response::new(protos::Empty {}))
	}

	// arkoor

	/// Handles an arkoor cosign request.
	async fn request_arkoor_cosign(
		&self,
		req: tonic::Request<protos::ArkoorPackageCosignRequest>,
	) -> Result<tonic::Response<protos::ArkoorPackageCosignResponse>, tonic::Status> {
		let _ = RpcMethodDetails::grpc_ark(middleware::rpc_names::ark::REQUEST_ARKOOR_COSIGN);
		let req = req.into_inner();

		let request = ArkoorPackageCosignRequest::try_from(req)
			.context("Failed to parse request")?;

		let response = self.cosign_oor(request).await.to_status()?;
		Ok(tonic::Response::new(response.into()))
	}

	// mailbox
	// deprecated
	async fn post_arkoor_package_mailbox(
		&self,
		req: tonic::Request<protos::ArkoorPackage>,
	) -> Result<tonic::Response<protos::Empty>, tonic::Status> {
		let _ = RpcMethodDetails::grpc_ark(middleware::rpc_names::ark::POST_ARKOOR_PACKAGE_MAILBOX);
		let req = req.into_inner();

		crate::rpcserver::add_tracing_attributes(vec![
			KeyValue::new("arkoors", format!("{:?}", req.arkoors)),
		]);

		let arkoor_package_id = rand::thread_rng().r#gen::<[u8; 32]>();

		for arkoor in req.arkoors {
			let pubkey = PublicKey::from_bytes(&arkoor.pubkey)?;
			let vtxo = Vtxo::from_bytes(&arkoor.vtxo)?;
			#[allow(deprecated)]
			self.db.store_arkoor_by_vtxo_pubkey(pubkey, &arkoor_package_id, vtxo).await.to_status()?;
		}

		Ok(tonic::Response::new(protos::Empty{}))
	}

	// deprecated
	async fn empty_arkoor_mailbox(
		&self,
		req: tonic::Request<protos::ArkoorVtxosRequest>,
	) -> Result<tonic::Response<protos::ArkoorVtxosResponse>, tonic::Status> {
		let _ = RpcMethodDetails::grpc_ark(middleware::rpc_names::ark::EMPTY_ARKOOR_MAILBOX);
		let req = req.into_inner();

		crate::rpcserver::add_tracing_attributes(vec![
			KeyValue::new("pubkeys", format!("{:?}", req.pubkeys)),
		]);

		if req.pubkeys.len() > rpc::MAX_NB_MAILBOX_PUBKEYS {
			macros::badarg!("too many pubkeys: max {}", rpc::MAX_NB_MAILBOX_PUBKEYS);
		}

		let pubkeys = req.pubkeys.iter()
			.map(PublicKey::from_bytes)
			.collect::<Result<Vec<_>, _>>()?;
		#[allow(deprecated)]
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

	async fn request_lightning_pay_htlc_cosign(
		&self,
		req: tonic::Request<protos::LightningPayHtlcCosignRequest>,
	) -> Result<tonic::Response<protos::ArkoorPackageCosignResponse>, tonic::Status> {
		let _ = RpcMethodDetails::grpc_ark(middleware::rpc_names::ark::REQUEST_LIGHTNING_PAY_HTLC_COSIGN);
		let req = req.into_inner();

		let cosign_requests = ArkoorPackageCosignRequest::try_from(req.clone())
			.context("Failed to parse request")?;

		crate::rpcserver::add_tracing_attributes(
			vec![
				KeyValue::new("invoice", format!("{:?}", req.invoice)),
				KeyValue::new("cosign_requests", format!("{:?}", req.parts)),
			]);

		let invoice = Invoice::from_str(&req.invoice).badarg("invalid invoice")?;
		invoice.check_signature().badarg("invalid invoice signature")?;

		let resp = self.request_lightning_pay_htlc_cosign(
			invoice, cosign_requests
		).await.context("error making payment")?;

		Ok(tonic::Response::new(resp.into()))
	}

	async fn initiate_lightning_payment(
		&self,
		req: tonic::Request<protos::InitiateLightningPaymentRequest>,
	) -> Result<tonic::Response<protos::Empty>, tonic::Status> {
		let _ = RpcMethodDetails::grpc_ark(middleware::rpc_names::ark::INITIATE_LIGHTNING_PAYMENT);
		let req = req.into_inner();

		let htlc_vtxo_ids = req.htlc_vtxo_ids.iter()
			.map(VtxoId::from_bytes)
			.collect::<Result<Vec<_>, _>>()?;

		crate::rpcserver::add_tracing_attributes(vec![
			KeyValue::new("invoice", format!("{:?}", req.invoice)),
			KeyValue::new("htlc_vtxo_ids", format!("{:?}", htlc_vtxo_ids)),
		]);

		let invoice = Invoice::from_str(&req.invoice).badarg("invalid invoice")?;

		self.initiate_lightning_payment(invoice, htlc_vtxo_ids).await.to_status()?;
		Ok(tonic::Response::new(protos::Empty {}))
	}

	async fn check_lightning_payment(
		&self,
		req: tonic::Request<protos::CheckLightningPaymentRequest>,
	) -> Result<tonic::Response<protos::LightningPaymentStatus>, tonic::Status> {
		let _ = RpcMethodDetails::grpc_ark(middleware::rpc_names::ark::CHECK_LIGHTNING_PAYMENT);
		let req = req.into_inner();

		crate::rpcserver::add_tracing_attributes(vec![
			KeyValue::new("payment_hash", req.hash.as_hex().to_string()),
			KeyValue::new("wait", req.wait.to_string()),
		]);

		let payment_hash = PaymentHash::from_bytes(req.hash)?;
		let res = self.check_lightning_payment(payment_hash, req.wait).await.to_status()?;
		Ok(tonic::Response::new(protos::LightningPaymentStatus { payment_status: Some(res) }))
	}

	async fn request_lightning_pay_htlc_revocation(
		&self,
		req: tonic::Request<protos::ArkoorPackageCosignRequest>
	) -> Result<tonic::Response<protos::ArkoorPackageCosignResponse>, tonic::Status> {
		let _ = RpcMethodDetails::grpc_ark(middleware::rpc_names::ark::REQUEST_LIGHTNING_PAY_HTLC_REVOCATION);
		let req = req.into_inner();

		let cosign_requests = ArkoorPackageCosignRequest::try_from(req.clone())
			.context("Failed to parse request")?;

		crate::rpcserver::add_tracing_attributes(vec![
			KeyValue::new("cosign_requests", format!("{:?}", cosign_requests)),
		]);

		let cosign_resp = self.revoke_lightning_pay_htlcs(cosign_requests).await
			.to_status()?;

		Ok(tonic::Response::new(cosign_resp.into()))
	}

	async fn fetch_bolt12_invoice(
		&self,
		req: tonic::Request<protos::FetchBolt12InvoiceRequest>,
	) -> Result<tonic::Response<protos::FetchBolt12InvoiceResponse>, tonic::Status> {
		let _ = RpcMethodDetails::grpc_ark(middleware::rpc_names::ark::FETCH_BOLT12_INVOICE);
		let req = req.into_inner();

		let offer = match Offer::try_from(req.offer.to_vec()) {
			Ok(offer) => offer,
			Err(_) => {
				macros::badarg!("invalid offer");
			},
		};

		let amount = match req.amount_sat {
			Some(a) => { Amount::from_sat(a) },
			None if offer.amount().is_some() => {
				match offer.amount().unwrap() {
					OfferAmount::Bitcoin { amount_msats } => { Amount::from_msat_ceil(amount_msats) },
					_ => { macros::badarg!("unsupported offer currency"); }
				}
			},
			None => {
				macros::badarg!("amount_sat is required for bolt12 offers with no amount specified");
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
		let _ = RpcMethodDetails::grpc_ark(middleware::rpc_names::ark::START_LIGHTNING_RECEIVE);
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
		let _ = RpcMethodDetails::grpc_ark(middleware::rpc_names::ark::CHECK_LIGHTNING_RECEIVE);
		let req = req.into_inner();

		let payment_hash = PaymentHash::from_bytes(req.hash)?;
		crate::rpcserver::add_tracing_attributes(vec![
			KeyValue::new("payment_hash", payment_hash.to_string()),
		]);

		let sub = self.check_lightning_receive(payment_hash, req.wait).await.to_status()?;
		Ok(tonic::Response::new(sub.into()))
	}

	#[tracing::instrument(skip(self))]
	async fn prepare_lightning_receive_claim(
		&self,
		req: tonic::Request<protos::PrepareLightningReceiveClaimRequest>
	) -> Result<tonic::Response<protos::PrepareLightningReceiveClaimResponse>, tonic::Status> {
		let _ = RpcMethodDetails::grpc_ark(middleware::rpc_names::ark::PREPARE_LIGHTNING_RECEIVE_CLAIM);
		let req = req.into_inner();

		let payment_hash = PaymentHash::from_bytes(req.payment_hash)?;
		crate::rpcserver::add_tracing_attributes(vec![
			KeyValue::new("payment_hash", payment_hash.to_string()),
		]);

		let user_pubkey = PublicKey::from_bytes(&req.user_pubkey)?;
		let htlc_recv_expiry = req.htlc_recv_expiry as BlockHeight;

		let (sub, htlcs) = self.prepare_lightning_claim(
			payment_hash, user_pubkey, htlc_recv_expiry, req.lightning_receive_anti_dos,
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
		let _ = RpcMethodDetails::grpc_ark(middleware::rpc_names::ark::CLAIM_LIGHTNING_RECEIVE);
		let req = req.into_inner();

		let payment_hash = PaymentHash::from_bytes(req.payment_hash)?;
		crate::rpcserver::add_tracing_attributes(vec![
			KeyValue::new("payment_hash", payment_hash.to_string()),
		]);

		let payment_preimage = Preimage::from_bytes(req.payment_preimage)?;
		let vtxo_policy = VtxoPolicy::from_bytes(req.vtxo_policy)?;
		let cosign_request = ArkoorPackageCosignRequest::try_from(
			req.cosign_request.badarg("cosign request missing")?,
		).badarg("invalid cosign request")?;

		let cosign_resp = self.claim_lightning_receive(
			payment_hash,
			vtxo_policy,
			payment_preimage,
			cosign_request,
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
		let _ = RpcMethodDetails::grpc_ark(middleware::rpc_names::ark::SUBSCRIBE_ROUNDS);

		let stream = self.rounds.events();
		Ok(tonic::Response::new(Box::new(stream.map(|e| Ok(e.as_ref().into())))))
	}

	async fn last_round_event(
		&self,
		_req: tonic::Request<protos::Empty>,
	) -> Result<tonic::Response<protos::RoundEvent>, tonic::Status> {
		let _ = RpcMethodDetails::grpc_ark(middleware::rpc_names::ark::LAST_ROUND_EVENT);

		if let Some(event) = self.rounds.last_event() {
			Ok(tonic::Response::new(event.as_ref().into()))
		} else {
			macros::not_found!([""], "no round event yet");
		}
	}

	async fn submit_payment(
		&self,
		req: tonic::Request<protos::SubmitPaymentRequest>,
	) -> Result<tonic::Response<protos::SubmitPaymentResponse>, tonic::Status> {
		let _ = RpcMethodDetails::grpc_ark(middleware::rpc_names::ark::SUBMIT_PAYMENT);
		let req = req.into_inner();

		crate::rpcserver::add_tracing_attributes(vec![
			KeyValue::new("input_vtxos_count", format!("{:?}", req.input_vtxos.len())),
			KeyValue::new("vtxo_requests_count", format!("{:?}", req.vtxo_requests.len())),
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
				macros::badarg!("need exactly {} public nonces", self.config.nb_round_nonces);
			}
			vtxo_requests.push(r.try_into().badarg("invalid signed vtxo request")?);
		}

		#[allow(deprecated)]
		if !req.offboard_requests.is_empty() {
			return Err(tonic::Status::unimplemented("offboards in rounds are no longer supported"));
		}

		let unlock_preimage = rand::random::<UnlockPreimage>();
		let unlock_hash = UnlockHash::hash(&unlock_preimage);

		let (tx, rx) = oneshot::channel();
		let inp = RoundInput::RegisterPayment { inputs, vtxo_requests, unlock_preimage };

		self.rounds.round_input_tx.send((inp, tx))
			.expect("input channel closed");
		rx.wait_for_status().await?;

		Ok(tonic::Response::new(protos::SubmitPaymentResponse {
			unlock_hash: unlock_hash.to_byte_array().to_vec(),
		}))
	}

	async fn provide_vtxo_signatures(
		&self,
		req: tonic::Request<protos::VtxoSignaturesRequest>,
	) -> Result<tonic::Response<protos::Empty>, tonic::Status> {
		let _ = RpcMethodDetails::grpc_ark(middleware::rpc_names::ark::PROVIDE_VTXO_SIGNATURES);
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

	// hArk

	async fn submit_round_participation(
		&self,
		req: tonic::Request<protos::RoundParticipationRequest>,
	) -> Result<tonic::Response<protos::RoundParticipationResponse>, tonic::Status> {
		let _ = RpcMethodDetails::grpc_ark(middleware::rpc_names::ark::SUBMIT_ROUND_PARTICIPATION);
		let req = req.into_inner();

		crate::rpcserver::add_tracing_attributes(vec![
			KeyValue::new("input_vtxos_count", format!("{:?}", req.input_vtxos.len())),
			KeyValue::new("vtxo_requests_count", format!("{:?}", req.vtxo_requests.len())),
		]);

		let inputs =  req.input_vtxos.iter().map(|input| {
			let vtxo_id = VtxoId::from_bytes(&input.vtxo_id)?;
			let ownership_proof = schnorr::Signature::from_bytes(&input.ownership_proof)?;
			Ok(VtxoIdInput { vtxo_id, ownership_proof })
		}).collect::<Result<_, tonic::Status>>()?;

		let mut vtxo_requests = Vec::with_capacity(req.vtxo_requests.len());
		for r in req.vtxo_requests.clone() {
			vtxo_requests.push(r.try_into().badarg("invalid vtxo request")?);
		}

		let unlock_hash = self.register_non_interactive_round_participation(inputs, vtxo_requests).await
			.to_status()?;

		Ok(tonic::Response::new(protos::RoundParticipationResponse {
			unlock_hash: unlock_hash.to_byte_array().to_vec(),
		}))
	}

	async fn round_participation_status(
		&self,
		req: tonic::Request<protos::RoundParticipationStatusRequest>,
	) -> Result<tonic::Response<protos::RoundParticipationStatusResponse>, tonic::Status> {
		let _ = RpcMethodDetails::grpc_ark(middleware::rpc_names::ark::ROUND_PARTICIPATION_STATUS);
		let req = req.into_inner();

		crate::rpcserver::add_tracing_attributes(vec![
			KeyValue::new("unlock_hash", req.unlock_hash.as_hex().to_string()),
		]);

		let unlock_hash = UnlockHash::from_bytes(&req.unlock_hash)?;
		let part = self.db.get_round_participation_by_unlock_hash(unlock_hash).await.to_status()?
			.not_found([unlock_hash], "round participation not found")?;

		let res = if let Some(round_id) = part.round_id {
			//TODO(stevenroose) consider storing the new vtxos in the participation table
			// so that we don't have to create the entire cached tree here each time

			let round = self.db.get_round(round_id).await.to_status()?
				.context("our own db has unknown round")?;
			let round_funding_tx = Some(serialize(&round.funding_tx));

			let mut output_vtxos = Vec::with_capacity(part.outputs.len());
			let tree = round.signed_tree.into_cached_tree();
			for output in &part.outputs {
				let idx = tree.spec.spec.leaf_idx_of_req(output)
					.with_context(|| format!("output req {:?} not in round {}", output, round.id))?;
				output_vtxos.push(tree.build_vtxo(idx).serialize());
			}

			if part.inputs.iter().all(|i| i.is_forfeited()) {
				protos::RoundParticipationStatusResponse {
					status: protos::RoundParticipationStatus::RoundPartReleased.into(),
					unlock_preimage: Some(part.unlock_preimage.leak_ref().to_vec()),
					round_funding_tx, output_vtxos,
				}
			} else {
				protos::RoundParticipationStatusResponse {
					status: protos::RoundParticipationStatus::RoundPartIssued.into(),
					unlock_preimage: None,
					round_funding_tx, output_vtxos,
				}
			}
		} else {
			protos::RoundParticipationStatusResponse {
				status: protos::RoundParticipationStatus::RoundPartPending.into(),
				round_funding_tx: None,
				unlock_preimage: None,
				output_vtxos: vec![],
			}
		};

		Ok(tonic::Response::new(res))
	}

	async fn request_leaf_vtxo_cosign(
		&self,
		req: tonic::Request<protos::LeafVtxoCosignRequest>,
	) -> Result<tonic::Response<protos::LeafVtxoCosignResponse>, tonic::Status> {
		let _ = RpcMethodDetails::grpc_ark(middleware::rpc_names::ark::REQUEST_LEAF_VTXO_COSIGN);
		let req = req.into_inner();

		let vtxo_id = VtxoId::from_bytes(req.vtxo_id)?;
		crate::rpcserver::add_tracing_attributes(vec![
			KeyValue::new("vtxo_id", format!("{:?}", vtxo_id)),
		]);

		let pub_nonce = musig::PublicNonce::from_bytes(req.public_nonce)?;
		let req = LeafVtxoCosignRequest { vtxo_id, pub_nonce };

		let resp = self.cosign_hashlocked_leaf_round(&req).await.to_status()?;
		Ok(tonic::Response::new(resp.into()))
	}

	async fn request_forfeit_nonces(
		&self,
		req: tonic::Request<protos::ForfeitNoncesRequest>,
	) -> Result<tonic::Response<protos::ForfeitNoncesResponse>, tonic::Status> {
		let _ = RpcMethodDetails::grpc_ark(middleware::rpc_names::ark::REQUEST_FORFEIT_NONCES);
		let req = req.into_inner();

		let unlock_hash = UnlockHash::from_bytes(req.unlock_hash)?;
		let vtxos = req.vtxo_ids.iter().map(|v| VtxoId::from_bytes(v))
			.collect::<Result<Vec<_>, _>>()?;
		crate::rpcserver::add_tracing_attributes(vec![
			KeyValue::new("unlock_hash", unlock_hash.to_string()),
			KeyValue::new("vtxo_ids", format!("{:?}", vtxos)),
		]);

		let res = self.generate_forfeit_nonces(unlock_hash, &vtxos).await.to_status()?;
		Ok(tonic::Response::new(protos::ForfeitNoncesResponse {
			public_nonces: res.into_iter().map(|n| n.serialize()).collect(),
		}))
	}

	async fn forfeit_vtxos(
		&self,
		req: tonic::Request<protos::ForfeitVtxosRequest>,
	) -> Result<tonic::Response<protos::ForfeitVtxosResponse>, tonic::Status> {
		let _ = RpcMethodDetails::grpc_ark(middleware::rpc_names::ark::FORFEIT_VTXOS);
		let req = req.into_inner();

		let forfeits = req.forfeit_bundles.iter()
			.map(|v| HashLockedForfeitBundle::from_bytes(v))
			.collect::<Result<Vec<_>, _>>()?;

		let preimage = self.register_vtxo_forfeit(&forfeits).await.to_status()?;

		Ok(tonic::Response::new(protos::ForfeitVtxosResponse {
			unlock_preimage: preimage.to_vec(),
		}))
	}

	async fn prepare_offboard(
		&self,
		req: tonic::Request<protos::PrepareOffboardRequest>,
	) -> Result<tonic::Response<protos::PrepareOffboardResponse>, tonic::Status> {
		let _ = RpcMethodDetails::grpc_ark(middleware::rpc_names::ark::PREPARE_OFFBOARD);
		let req = req.into_inner();

		let request = req.offboard.badarg("missing offboard field")?.try_into()
			.badarg("invalid offboard request")?;
		let input_vtxos = req.input_vtxo_ids.iter().map(|v| VtxoId::from_bytes(v))
			.collect::<Result<Vec<_>, _>>()?;
		let ownership_proofs = req.input_vtxo_ownership_proofs.iter()
			.map(|v| schnorr::Signature::from_bytes(v))
			.collect::<Result<Vec<_>, _>>()?;
		let resp = self.prepare_offboard(request, input_vtxos, ownership_proofs).await.to_status()?;

		Ok(tonic::Response::new(protos::PrepareOffboardResponse {
			offboard_tx: serialize(&resp.offboard_tx),
			forfeit_cosign_nonces: resp.forfeit_cosign_nonces.into_iter()
				.map(|n| n.serialize().to_vec())
				.collect(),
		}))
	}

	async fn finish_offboard(
		&self,
		req: tonic::Request<protos::FinishOffboardRequest>,
	) -> Result<tonic::Response<protos::FinishOffboardResponse>, tonic::Status> {
		let _ = RpcMethodDetails::grpc_ark(middleware::rpc_names::ark::FINISH_OFFBOARD);
		let req = req.into_inner();

		let offboard_txid = Txid::from_bytes(req.offboard_txid)?;
		let pub_nonces = req.user_nonces.iter()
			.map(musig::PublicNonce::from_bytes)
			.collect::<Result<Vec<_>, _>>()?;
		let partial_sigs = req.partial_signatures.iter()
			.map(musig::PartialSignature::from_bytes)
			.collect::<Result<Vec<_>, _>>()?;

		let tx = self.finish_offboard(offboard_txid, &pub_nonces, &partial_sigs).await.to_status()?;

		Ok(tonic::Response::new(protos::FinishOffboardResponse {
			signed_offboard_tx: serialize(&tx),
		}))
	}
}

/// Run the public gRPC endpoint.
pub async fn run_rpc_server(srv: Arc<Server>) -> anyhow::Result<()> {
	RPC_RICH_ERRORS.store(srv.config.rpc_rich_errors, atomic::Ordering::Relaxed);

	let _worker = srv.rtmgr.spawn_critical("PublicRpcServer");

	let addr = srv.config.rpc.public_address;
	info!("Starting public gRPC service on address {}", addr);

	let routes = tonic::service::Routes::default()
		.add_service(rpc::server::ArkServiceServer::from_arc(srv.clone()))
		.add_service(rpc::server::MailboxServiceServer::from_arc(srv.clone()));

	tonic::transport::Server::builder()
		.layer(OtelGrpcLayer::default())
		.layer(middleware::TelemetryMetricsLayer)
		.add_routes(routes)
		.serve_with_shutdown(addr, srv.rtmgr.shutdown_signal()).await?;

	info!("Terminated public gRPC service on address {}", addr);

	Ok(())
}

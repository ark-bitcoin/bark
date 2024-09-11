
use std::str::FromStr;
use std::sync::Arc;

use ark::lightning::SignedBolt11Payment;
use bitcoin::hex::DisplayHex;
use bitcoin::{Amount, ScriptBuf, Txid};
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::PublicKey;
use lightning_invoice::Bolt11Invoice;
use tokio_stream::{Stream, StreamExt};
use tokio_stream::wrappers::BroadcastStream;

use ark::{musig, OffboardRequest, VtxoRequest, Vtxo, VtxoId};

use crate::App;
use crate::rpc;
use crate::round::RoundInput;
use crate::lightning::pay_bolt11;

macro_rules! badarg {
	($($arg:tt)*) => {{
		tonic::Status::invalid_argument(format!($($arg)*))
	}};
}

macro_rules! internal {
	($($arg:tt)*) => {{
		tonic::Status::internal(format!($($arg)*))
	}};
}

macro_rules! not_found {
	($($arg:tt)*) => {{
		tonic::Status::not_found(format!($($arg)*))
	}};
}

/// Just a trait to easily convert some kind of errors to tonic things.
trait ToStatus<T> {
	fn to_status(self) -> Result<T, tonic::Status>;
}

impl<T> ToStatus<T> for anyhow::Result<T> {
	fn to_status(self) -> Result<T, tonic::Status> {
		self.map_err(|e| tonic::Status::internal(format!("internal error: {}", e)))
	}
}

#[tonic::async_trait]
impl rpc::ArkService for Arc<App> {
	async fn get_ark_info(
		&self,
		_req: tonic::Request<rpc::Empty>,
	) -> Result<tonic::Response<rpc::ArkInfo>, tonic::Status> {
		let ret = rpc::ArkInfo {
			network: self.config.network.to_string(),
			pubkey: self.master_key.public_key().serialize().to_vec(),
			xonly_pubkey: self.master_key.x_only_public_key().0.serialize().to_vec(),
			nb_round_nonces: self.config.nb_round_nonces as u32,
			vtxo_exit_delta: self.config.vtxo_exit_delta as u32,
			vtxo_expiry_delta: self.config.vtxo_expiry_delta as u32,
		};
		Ok(tonic::Response::new(ret))
	}

	async fn get_fresh_rounds(
		&self,
		req: tonic::Request<rpc::FreshRoundsRequest>,
	) -> Result<tonic::Response<rpc::FreshRounds>, tonic::Status> {
		let ids = self.db.get_fresh_round_ids(req.into_inner().start_height)
			.map_err(|e| internal!("db error: {}", e))?;
		Ok(tonic::Response::new(rpc::FreshRounds {
			txids: ids.into_iter().map(|t| t.to_byte_array().to_vec()).collect(),
		}))
	}

	async fn get_round(
		&self,
		req: tonic::Request<rpc::RoundId>,
	) -> Result<tonic::Response<rpc::RoundInfo>, tonic::Status> {
		let txid = Txid::from_slice(&req.into_inner().txid)
			.map_err(|e| badarg!("invalid txid: {}", e))?;
		let ret = self.db.get_round(txid)
			.map_err(|e| internal!("db error: {}", e))?
			.ok_or_else(|| not_found!("round with txid {} not found", txid))?;
		Ok(tonic::Response::new(rpc::RoundInfo {
			round_tx: bitcoin::consensus::serialize(&ret.tx),
			signed_vtxos: ret.signed_tree.encode(),
		}))
	}

	// onboard

	async fn request_onboard_cosign(
		&self,
		req: tonic::Request<rpc::OnboardCosignRequest>,
	) -> Result<tonic::Response<rpc::OnboardCosignResponse>, tonic::Status> {
		let req = req.into_inner();
		let user_part = ciborium::from_reader::<ark::onboard::UserPart, _>(&req.user_part[..])
			.map_err(|e| badarg!("invalid user part: {}", e))?;
		if user_part.spec.asp_pubkey != self.master_key.public_key() {
			return Err(badarg!("ASP public key is incorrect!"));
		}

		if let Some(max) = self.config.max_onboard_value {
			if user_part.spec.amount > max {
				return Err(badarg!("onboard amount exceeds limit of {}", max));
			}
		}

		let asp_part = self.cosign_onboard(user_part);
		Ok(tonic::Response::new(rpc::OnboardCosignResponse {
			asp_part: {
				let mut buf = Vec::new();
				ciborium::into_writer(&asp_part, &mut buf).unwrap();
				buf
			},
		}))
	}

	// oor

	async fn request_oor_cosign(
		&self,
		req: tonic::Request<rpc::OorCosignRequest>,
	) -> Result<tonic::Response<rpc::OorCosignResponse>, tonic::Status> {
		let req = req.into_inner();
		let payment = ark::oor::OorPayment::decode(&req.payment)
			.map_err(|e| badarg!("invalid oor payment request: {}", e))?;
		let user_nonces = req.pub_nonces.into_iter().map(|b| {
			musig::MusigPubNonce::from_slice(&b)
				.map_err(|e| badarg!("invalid public nonce: {}", e))
		}).collect::<Result<Vec<_>, tonic::Status>>()?;

		if payment.inputs.len() != user_nonces.len() {
			return Err(badarg!("wrong number of user nonces"));
		}

		let (nonces, sigs) = self.cosign_oor(&payment, &user_nonces).to_status()?;
		Ok(tonic::Response::new(rpc::OorCosignResponse {
			pub_nonces: nonces.into_iter().map(|n| n.serialize().to_vec()).collect(),
			partial_sigs: sigs.into_iter().map(|s| s.serialize().to_vec()).collect(),
		}))
	}

	async fn post_oor_mailbox(
		&self,
		req: tonic::Request<rpc::OorVtxo>,
	) -> Result<tonic::Response<rpc::Empty>, tonic::Status> {
		let req = req.into_inner();
		let pubkey = PublicKey::from_slice(&req.pubkey)
			.map_err(|e| badarg!("invalid pubkey: {}", e))?;
		let vtxo = Vtxo::decode(&req.vtxo)
			.map_err(|e| badarg!("invalid vtxo: {}", e))?;
		self.db.store_oor(pubkey, vtxo).to_status()?;
		Ok(tonic::Response::new(rpc::Empty {}))
	}

	async fn empty_oor_mailbox(
		&self,
		req: tonic::Request<rpc::OorVtxosRequest>,
	) -> Result<tonic::Response<rpc::OorVtxosResponse>, tonic::Status> {
		let req = req.into_inner();
		let pubkey = PublicKey::from_slice(&req.pubkey)
			.map_err(|e| badarg!("invalid pubkey: {}", e))?;
		let vtxos = self.db.pull_oors(pubkey).to_status()?;
		Ok(tonic::Response::new(rpc::OorVtxosResponse {
			vtxos: vtxos.into_iter().map(|v| v.encode()).collect(),
		}))
	}

	// lightning

	async fn start_bolt11_payment(
		&self,
		req: tonic::Request<rpc::Bolt11PaymentRequest>,
	) -> Result<tonic::Response<rpc::Bolt11PaymentDetails>, tonic::Status> {
		let req = req.into_inner();
		let invoice = Bolt11Invoice::from_str(&req.invoice)
			.map_err(|e| badarg!("invalid invoice: {}", e))?;
		invoice.check_signature().map_err(|_| badarg!("invalid invoice signature"))?;

		let inv_amount = invoice.amount_milli_satoshis()
			.map(|v| Amount::from_sat(v.div_ceil(1000)));
		if let (Some(_), Some(inv)) = (req.amount_sats, inv_amount) {
			return Err(badarg!("Invoice has amount of {} encoded. Please omit amount field", inv));
		}
		let amount = req.amount_sats.map(|v| Amount::from_sat(v)).or(inv_amount)
			.ok_or(badarg!("amount field required for invoice without amount"))?;

		let input_vtxos = req.input_vtxos.into_iter().map(|v| Vtxo::decode(&v))
			.collect::<Result<Vec<_>, _>>()
			.map_err(|e| badarg!("invalid vtxo: {}", e))?;
		let user_pubkey = PublicKey::from_slice(&req.user_pubkey)
			.map_err(|e| badarg!("invalid user pubkey: {}", e))?;
		let user_nonces = req.user_nonces.into_iter().map(|b| {
			musig::MusigPubNonce::from_slice(&b)
				.map_err(|e| badarg!("invalid public nonce: {}", e))
		}).collect::<Result<Vec<_>, tonic::Status>>()?;

		let (details, asp_nonces, part_sigs) = self.start_bolt11(
			invoice, amount, input_vtxos, user_pubkey, &user_nonces,
		).map_err(|e| internal!("error making payment: {}", e))?;

		Ok(tonic::Response::new(rpc::Bolt11PaymentDetails {
			details: details.encode(),
			pub_nonces: asp_nonces.into_iter().map(|n| n.serialize().to_vec()).collect(),
			partial_sigs: part_sigs.into_iter().map(|s| s.serialize().to_vec()).collect(),
		}))
	}

	async fn finish_bolt11_payment(
		&self,
		req: tonic::Request<rpc::SignedBolt11PaymentDetails>,
	) -> Result<tonic::Response<rpc::Bolt11PaymentResult>, tonic::Status> {
		let req = req.into_inner();
		let signed = SignedBolt11Payment::decode(&req.signed_payment)
			.map_err(|e| badarg!("invalid payment encoding: {}", e))?;
		if let Err(e) = signed.validate_signatures(&crate::SECP) {
			return Err(badarg!("bad signatures on payment: {}", e));
		}

		// Connecting to the grpc-client
		let cln_config = self.config.cln_config.as_ref()
			.ok_or(not_found!("This asp does not support lightning"))?;
		let cln_client = cln_config.grpc_client().await
			.map_err(|_| internal!("Failed to connect to lightning"))?;
		let sendpay_rx = self.sendpay_updates.as_ref().unwrap().sendpay_rx.resubscribe();

		trace!("Trying to deliver bolt11 invoice...");
		let preimage = pay_bolt11(cln_client, signed, sendpay_rx).await
			.map_err(|e| internal!("failed to make bolt11 payment: {}", e))?;
		trace!("Done! preimage: {}", preimage.as_hex());

		Ok(tonic::Response::new(rpc::Bolt11PaymentResult {
			payment_preimage: preimage,
		}))
	}

	// round

	type SubscribeRoundsStream = Box<
		dyn Stream<Item = Result<rpc::RoundEvent, tonic::Status>> + Unpin + Send + 'static
	>;

	async fn subscribe_rounds(
		&self,
		_req: tonic::Request<rpc::Empty>,
	) -> Result<tonic::Response<Self::SubscribeRoundsStream>, tonic::Status> {
		let chan = self.try_rounds().to_status()?.round_event_tx.subscribe();
		let stream = BroadcastStream::new(chan);

		Ok(tonic::Response::new(Box::new(stream.map(|e| {
			let e = e.map_err(|e| internal!("broken stream: {}", e))?;
			Ok(e.into())
		}))))
	}

	async fn submit_payment(
		&self,
		req: tonic::Request<rpc::SubmitPaymentRequest>,
	) -> Result<tonic::Response<rpc::Empty>, tonic::Status> {
		let req = req.into_inner();

		let inputs =  req.input_vtxos.into_iter().map(|vtxo| {
			Ok(Vtxo::decode(&vtxo).map_err(|e| badarg!("invalid vtxo: {}", e))?)
		}).collect::<Result<_, tonic::Status>>()?;

		let mut outputs = Vec::with_capacity(req.payments.len());
		let mut offboards = Vec::with_capacity(req.payments.len() / 2);
		for payment in req.payments {
			let amount = Amount::from_sat(payment.amount);
			match payment.destination.ok_or_else(|| badarg!("missing destination"))? {
				rpc::payment::Destination::VtxoPublicKey(pk) => {
					let pubkey= PublicKey::from_slice(&pk)
						.map_err(|e| badarg!("malformed pubkey {:?}: {}", pk, e))?;
					outputs.push(VtxoRequest { amount, pubkey });
				},
				rpc::payment::Destination::OffboardSpk(s) => {
					let script_pubkey = ScriptBuf::from_bytes(s);
					let offb = OffboardRequest { script_pubkey, amount };
					offb.validate().map_err(|e| badarg!("invalid offboard request: {}", e))?;
					offboards.push(offb);
				},
			}
		}

		let cosign_pubkey = PublicKey::from_slice(&req.cosign_pubkey)
			.map_err(|e| badarg!("invalid cosign pubkey: {}", e))?;

		// Make sure we have at least enough nonces, but just drop
		// leftover if user provided too many.
		if req.public_nonces.len() < self.config.nb_round_nonces {
			return Err(badarg!(
				"need at least {} public nonces", self.config.nb_round_nonces,
			));
		}
		let public_nonces = req.public_nonces.into_iter()
		.take(self.config.nb_round_nonces)
		.map(|n| {
			musig::MusigPubNonce::from_slice(&n)
				.map_err(|e| badarg!("invalid public nonce: {}", e))
		}).collect::<Result<_, tonic::Status>>()?;

		let inp = RoundInput::RegisterPayment {
			inputs, outputs, offboards, cosign_pubkey, public_nonces,
		};
		self.try_rounds().to_status()?.round_input_tx.send(inp).expect("input channel closed");
		Ok(tonic::Response::new(rpc::Empty {}))
	}

	async fn provide_vtxo_signatures(
		&self,
		req: tonic::Request<rpc::VtxoSignaturesRequest>,
	) -> Result<tonic::Response<rpc::Empty>, tonic::Status> {
		let req = req.into_inner();

		let inp = RoundInput::VtxoSignatures {
			pubkey: PublicKey::from_slice(&req.pubkey)
				.map_err(|e| badarg!("invalid pubkey: {}", e))?,
			signatures: req.signatures.into_iter().map(|s| {
				musig::MusigPartialSignature::from_slice(&s)
					.map_err(|e| badarg!("invalid signature: {}", e))
			}).collect::<Result<_, tonic::Status>>()?,
		};
		self.try_rounds().to_status()?.round_input_tx.send(inp).expect("input channel closed");
		Ok(tonic::Response::new(rpc::Empty {}))
	}

	async fn provide_forfeit_signatures(
		&self,
		req: tonic::Request<rpc::ForfeitSignaturesRequest>,
	) -> Result<tonic::Response<rpc::Empty>, tonic::Status> {
		let inp = RoundInput::ForfeitSignatures {
			signatures: req.into_inner().signatures.into_iter().map(|ff| {
				let id = VtxoId::from_slice(&ff.input_vtxo_id)
					.map_err(|e| badarg!("invalid vtxo id: {}", e))?;
				let nonces = ff.pub_nonces.into_iter().map(|n| {
					musig::MusigPubNonce::from_slice(&n)
						.map_err(|e| badarg!("invalid forfeit nonce: {}", e))
				}).collect::<Result<_, tonic::Status>>()?;
				let signatures = ff.signatures.into_iter().map(|s| {
					musig::MusigPartialSignature::from_slice(&s)
						.map_err(|e| badarg!("invalid forfeit sig: {}", e))
				}).collect::<Result<_, tonic::Status>>()?;
				Ok((id, nonces, signatures))
			}).collect::<Result<_, tonic::Status>>()?
		};
		self.try_rounds().to_status()?.round_input_tx.send(inp).expect("input channel closed");
		Ok(tonic::Response::new(rpc::Empty {}))
	}
}

#[tonic::async_trait]
impl rpc::AdminService for Arc<App> {
	async fn wallet_status(
		&self,
		_req: tonic::Request<rpc::Empty>,
	) -> Result<tonic::Response<rpc::WalletStatusResponse>, tonic::Status> {
		Ok(tonic::Response::new(rpc::WalletStatusResponse {
			address: self.onchain_address().await.to_status()?.to_string(),
			balance: self.sync_onchain_wallet().await.to_status()?.to_sat(),
		}))
	}

	async fn trigger_round(
		&self,
		_req: tonic::Request<rpc::Empty>,
	) -> Result<tonic::Response<rpc::Empty>, tonic::Status> {
		match self.try_rounds().to_status()?.round_trigger_tx.try_send(()) {
			Err(tokio::sync::mpsc::error::TrySendError::Closed(())) => {
				Err(internal!("round scheduler closed"))
			},
			_ => Ok(tonic::Response::new(rpc::Empty {})),
		}
	}

	async fn stop(
		&self,
		_req: tonic::Request<rpc::Empty>,
	) -> Result<tonic::Response<rpc::Empty>, tonic::Status> {
		//TODO(stevenroose) implement graceful shutdown
		std::process::exit(0);
	}
}

/// Run the public gRPC endpoint.
pub async fn run_public_rpc_server(app: Arc<App>) -> anyhow::Result<()> {
	let addr = app.config.public_rpc_address;
	info!("Starting public gRPC service on address {}", addr);
	let ark_server = rpc::ArkServiceServer::new(app.clone());
	tonic::transport::Server::builder()
		.add_service(ark_server)
		.serve(addr)
		.await?;
	info!("Started public gRPC service on address {}", addr);
	Ok(())
}

/// Run the public gRPC endpoint.
pub async fn run_admin_rpc_server(app: Arc<App>) -> anyhow::Result<()> {
	let addr = app.config.admin_rpc_address.expect("shouldn't call this method otherwise");
	info!("Starting admin gRPC service on address {}", addr);
	let admin_server = rpc::AdminServiceServer::new(app.clone());
	tonic::transport::Server::builder()
		.add_service(admin_server)
		.serve(addr)
		.await?;
	info!("Started admin gRPC service on address {}", addr);
	Ok(())
}

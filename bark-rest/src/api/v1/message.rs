use std::str::FromStr;

use axum::extract::State;
use axum::routing::post;
use axum::{Json, Router, debug_handler};

use bitcoin::secp256k1::{schnorr, PublicKey};
use utoipa::OpenApi;

use crate::{ServerState, error};
use crate::error::{ContextExt, HandlerResult, badarg};

#[derive(OpenApi)]
#[openapi(
	paths(
		sign_message,
		verify_message,
	),
	components(schemas(
		bark_json::web::SignMessageRequest,
		bark_json::web::VerifyMessageRequest,
		bark_json::cli::SignedMessage,
		bark_json::cli::MessageVerification,
		error::InternalServerError,
		error::BadRequestError,
	)),
	tags((name = "message", description = "Sign arbitrary messages with the wallet's keys and verify signed messages."))
)]
pub struct MessageApiDoc;

pub fn router() -> Router<ServerState> {
	Router::new()
		.route("/sign", post(sign_message))
		.route("/verify", post(verify_message))
}

#[utoipa::path(
	post,
	path = "/sign",
	summary = "Sign a message",
	request_body = bark_json::web::SignMessageRequest,
	responses(
		(status = 200, description = "Returns the signature over the message", body = bark_json::cli::SignedMessage),
		(status = 400, description = "Invalid ark address or address not owned by this wallet", body = error::BadRequestError),
		(status = 500, description = "Internal server error", body = error::InternalServerError)
	),
	description = "Signs an arbitrary message with a BIP-340 Schnorr signature over a \
		prefixed hash (`SHA256(\"bark/message\" || message)`) of the UTF-8 message \
		bytes. The message is signed with the key of the given Ark address, which \
		must be one of the wallet's own addresses; addresses that do not belong to \
		the wallet are rejected. The resulting signature can be checked with the \
		`/message/verify` endpoint.",
	tag = "message"
)]
#[debug_handler]
pub async fn sign_message(
	State(state): State<ServerState>,
	Json(body): Json<bark_json::web::SignMessageRequest>,
) -> HandlerResult<Json<bark_json::cli::SignedMessage>> {
	let wallet = state.require_wallet()?;

	let address = ark::Address::from_str(&body.address)
		.badarg("invalid ark address")?;
	let signature = wallet.sign_message(body.message.as_bytes(), &address).await?
		.badarg("address does not belong to this wallet or its key has not been derived")?;

	Ok(axum::Json(bark_json::cli::SignedMessage { signature }))
}

#[utoipa::path(
	post,
	path = "/verify",
	summary = "Verify a signed message",
	request_body = bark_json::web::VerifyMessageRequest,
	responses(
		(status = 200, description = "Returns whether the signature is valid", body = bark_json::cli::MessageVerification),
		(status = 400, description = "Invalid signature, pubkey or address encoding, or not exactly one of pubkey and address set", body = error::BadRequestError),
		(status = 500, description = "Internal server error", body = error::InternalServerError)
	),
	description = "Verifies a BIP-340 Schnorr signature over a prefixed hash \
		(`SHA256(\"bark/message\" || message)`) of the UTF-8 message bytes, as created by the \
		`/message/sign` endpoint. The signature is checked against a public key \
		(`pubkey`) or against the user public key of an Ark address (`address`); \
		exactly one of the two must be set. Verification is stateless and works \
		for signatures made by any wallet, not just this one.",
	tag = "message"
)]
#[debug_handler]
pub async fn verify_message(
	Json(body): Json<bark_json::web::VerifyMessageRequest>,
) -> HandlerResult<Json<bark_json::cli::MessageVerification>> {
	let signature = schnorr::Signature::from_str(&body.signature)
		.badarg("invalid signature")?;

	let pubkey = match (&body.pubkey, &body.address) {
		(Some(pubkey), None) => PublicKey::from_str(pubkey).badarg("invalid pubkey")?,
		(None, Some(address)) => {
			ark::Address::from_str(address).badarg("invalid ark address")?
				.policy().user_pubkey()
		},
		_ => badarg!("exactly one of pubkey and address must be set"),
	};

	let valid = ark::message::verify(pubkey, body.message.as_bytes(), &signature);
	Ok(axum::Json(bark_json::cli::MessageVerification { valid }))
}

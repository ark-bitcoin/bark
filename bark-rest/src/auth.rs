
use std::fmt;

use axum::body::Body;
use axum::extract::State;
use axum::http::Request;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

use crate::ServerState;
use crate::error::{ErrorResponse, unauthorized};

/// A bearer token that is the 32-byte secret itself.
///
/// The token grants full access when it matches any registered secret.
#[derive(Clone, PartialEq, Eq)]
pub struct AuthToken {
	secret: [u8; 32],
}

#[derive(Debug)]
pub struct TokenDecodeError(String);

impl fmt::Display for TokenDecodeError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}", self.0)
	}
}

impl std::error::Error for TokenDecodeError {}

impl AuthToken {
	// One byte for the version, 32 bytes for the secret.
	pub const ENCODED_SIZE: usize = 33;

	/// Create an auth token from a 32-byte secret.
	pub fn new(secret: [u8; 32]) -> Self {
		AuthToken { secret }
	}

	/// Base64url-encode the token for transmission.
	///
	/// Wire format: `<version byte><32-byte secret>`
	pub fn encode(&self) -> String {
		let mut buf = Vec::with_capacity(AuthToken::ENCODED_SIZE);
		buf.push(0); // version byte
		buf.extend_from_slice(&self.secret);
		URL_SAFE_NO_PAD.encode(&buf)
	}

	/// Decode a base64url-encoded auth token.
	pub fn decode(encoded: &str) -> Result<Self, TokenDecodeError> {
		let bytes = URL_SAFE_NO_PAD.decode(encoded.trim())
			.map_err(|e| TokenDecodeError(format!("invalid base64: {}", e)))?;

		if bytes.is_empty() {
			return Err(TokenDecodeError("invalid format".into()));
		}

		let version = bytes[0];
		if version == 0 {
			if bytes.len() != AuthToken::ENCODED_SIZE {
				return Err(TokenDecodeError("invalid format".into()));
			}

			let secret = &bytes[1..];
			let secret = secret.try_into()
				.map_err(|e| TokenDecodeError(format!("invalid secret: {}", e)))?;

			return Ok(AuthToken { secret });
		}

		return Err(TokenDecodeError("unknown version".into()));
	}
}

/// Extract the auth token from the `Authorization: Bearer <token>` header
/// per RFC 6750.
///
/// Returns `Ok(Some(token))` when a valid token string is found,
/// `Ok(None)` when no auth header is present, or `Err(msg)` when
/// a header is present but malformed.
fn extract_auth_token(req: &Request<Body>) -> Result<Option<String>, &'static str> {
	if let Some(val) = req.headers().get("authorization") {
		let s = val.to_str().map_err(|_| "authorization header is not valid UTF-8")?;
		let s = s.trim();
		if let Some(token) = s.strip_prefix("Bearer ") {
			return Ok(Some(token.trim().to_string()));
		}
		return Err("unsupported authorization scheme; expected 'Bearer <token>'");
	}

	Ok(None)
}

fn inner_guard_auth(
	State(state): State<ServerState>,
	req: &Request<Body>,
) -> Result<(), ErrorResponse> {
	// If no auth token is configured, allow unauthenticated access.
	let expected = match state.auth_token() {
		Some(t) => t,
		None => return Ok(()),
	};

	let token_str = match extract_auth_token(req) {
		Ok(Some(t)) => t,
		Ok(None) => unauthorized!("missing auth token"),
		Err(msg) => unauthorized!("{}", msg),
	};

	let token = match AuthToken::decode(&token_str) {
		Ok(r) => r,
		Err(e) => unauthorized!("{}", e.to_string()),
	};

	if token != *expected {
		unauthorized!("invalid auth token");
	}

	Ok(())
}

pub(crate) async fn guard_auth(
	state: State<ServerState>,
	req: Request<Body>,
	next: Next,
) -> Response {
	match inner_guard_auth(state, &req) {
		Ok(()) => next.run(req).await,
		Err(e) => e.into_response(),
	}
}

#[cfg(test)]
mod tests {
	use std::sync::Arc;

	use super::*;

	fn test_token() -> AuthToken {
		AuthToken::new([42u8; 32])
	}

	fn make_state(token: AuthToken) -> State<ServerState> {
		State(ServerState {
			wallet: Arc::new(parking_lot::RwLock::new(None)),
			on_wallet_create: None,
			auth_token: Some(token),
			on_wallet_delete: None,
		})
	}

	#[test]
	fn roundtrip_and_whitespace() {
		let token = test_token();
		let encoded = token.encode();

		let decoded = AuthToken::decode(&encoded).unwrap();
		assert_eq!(token.secret, decoded.secret);

		// decode trims surrounding whitespace (important for file-loaded tokens)
		let padded = format!("  {} \n", encoded);
		assert_eq!(AuthToken::decode(&padded).unwrap().secret, token.secret);
	}

	#[test]
	fn decode_rejects_malformed_input() {
		assert!(AuthToken::decode("").is_err(), "empty string");
		assert!(AuthToken::decode("not!valid!base64").is_err(), "invalid base64");
		assert!(AuthToken::decode("AAAAAA").is_err(), "wrong length");

		// unknown version byte
		let mut raw = URL_SAFE_NO_PAD.decode(test_token().encode()).unwrap();
		raw[0] = 1;
		assert!(AuthToken::decode(&URL_SAFE_NO_PAD.encode(&raw)).is_err(), "unknown version");
	}

	#[test]
	fn extract_auth_token_from_headers() {
		let req = |name: &str, val: &str| Request::builder()
			.header(name, val).body(Body::empty()).unwrap();

		// Authorization: Bearer header (RFC 6750)
		assert_eq!(extract_auth_token(&req("authorization", "Bearer tok")).unwrap(), Some("tok".into()));

		// no auth headers
		let empty = Request::builder().body(Body::empty()).unwrap();
		assert_eq!(extract_auth_token(&empty).unwrap(), None);

		// unsupported scheme
		assert!(extract_auth_token(&req("authorization", "Basic dXNlcjpwYXNz")).is_err());
	}

	#[test]
	fn guard_auth_accepts_and_rejects() {
		let token = test_token();
		let req = |hdr: Option<&str>| {
			let mut b = Request::builder();
			if let Some(v) = hdr { b = b.header("authorization", format!("Bearer {}", v)); }
			b.body(Body::empty()).unwrap()
		};

		// valid token passes
		assert!(inner_guard_auth(make_state(token.clone()), &req(Some(&token.encode()))).is_ok());

		// missing, wrong, and garbage tokens all fail
		let state = make_state(token);
		let no_hdr = Request::builder().body(Body::empty()).unwrap();
		assert!(inner_guard_auth(state.clone(), &no_hdr).is_err());
		assert!(inner_guard_auth(state.clone(), &req(Some(&AuthToken::new([0u8; 32]).encode()))).is_err());
		assert!(inner_guard_auth(state, &req(Some("not-a-valid-token"))).is_err());
	}
}

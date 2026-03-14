//! A SOCKS5 proxy transport for jsonrpc using ureq.
//!
//! This implements the [`jsonrpc::Transport`] trait by routing connections
//! through a SOCKS5 proxy via ureq. This exists because the jsonrpc crate's
//! `proxy` feature flag changes `simple_http::fresh_socket` to **always** route
//! through a SOCKS5 proxy (defaulting to 127.0.0.1:9050), breaking all
//! non-proxied connections. By implementing the transport ourselves, we can
//! use proxy support only when explicitly configured.
//!
//! We use ureq rather than reqwest::blocking because ureq is a pure sync HTTP
//! client with no internal tokio runtime, which avoids panics when the
//! transport is used from within an async context (as bark does).

use std::fmt;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use ureq::{Agent, Proxy};

use crate::rpc::jsonrpc::{self, Request, Response};

/// A SOCKS5-proxied HTTP transport for JSON-RPC backed by ureq.
pub struct Socks5Transport {
	url: String,
	agent: Agent,
	basic_auth: Option<String>,
}

impl fmt::Debug for Socks5Transport {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		f.debug_struct("Socks5Transport")
			.field("url", &self.url)
			.field("has_auth", &self.basic_auth.is_some())
			.finish()
	}
}

impl Socks5Transport {
	/// Creates a new SOCKS5 transport.
	///
	/// * `url` — the target bitcoind RPC URL (e.g. `http://127.0.0.1:8332`)
	/// * `proxy_url` — the SOCKS5 proxy URL (e.g. `socks5h://127.0.0.1:9050`)
	/// * `auth` — optional (user, password) for HTTP Basic authentication
	pub fn new(
		url: &str,
		proxy_url: &str,
		auth: Option<(String, Option<String>)>,
	) -> Result<Self, Error> {
		let proxy = Proxy::new(proxy_url)
			.map_err(|e| Error::Proxy(e.to_string()))?;

		let agent = Agent::config_builder()
			.proxy(Some(proxy))
			.timeout_global(Some(Duration::from_secs(60)))
			.build()
			.new_agent();

		let basic_auth = auth.map(|(user, pass)| {
			let credentials = format!("{}:{}", user, pass.unwrap_or_default());
			format!("Basic {}", BASE64.encode(&credentials))
		});

		Ok(Socks5Transport { url: url.to_owned(), agent, basic_auth })
	}

	fn request<R>(&self, req: impl serde::Serialize) -> Result<R, jsonrpc::Error>
	where
		R: for<'a> serde::de::Deserialize<'a>,
	{
		let body = serde_json::to_vec(&req)
			.map_err(|e| jsonrpc::Error::Transport(e.into()))?;

		let mut request = self.agent.post(&self.url)
			.header("Content-Type", "application/json");
		if let Some(ref auth) = self.basic_auth {
			request = request.header("Authorization", auth);
		}

		let resp = request
			.send(&body[..])
			.map_err(|e| jsonrpc::Error::Transport(e.into()))?;

		let status = resp.status().as_u16();
		if status < 200 || status >= 300 {
			return Err(jsonrpc::Error::Transport(
				Box::new(Error::Http(status)),
			));
		}

		let resp_body = resp.into_body().read_to_string()
			.map_err(|e| jsonrpc::Error::Transport(e.into()))?;

		serde_json::from_str(&resp_body)
			.map_err(|e| jsonrpc::Error::Transport(e.into()))
	}
}

impl jsonrpc::client::Transport for Socks5Transport {
	fn send_request(&self, req: Request) -> Result<Response, jsonrpc::Error> {
		self.request(req)
	}

	fn send_batch(&self, reqs: &[Request]) -> Result<Vec<Response>, jsonrpc::Error> {
		self.request(reqs)
	}

	fn fmt_target(&self, f: &mut fmt::Formatter) -> fmt::Result {
		write!(f, "{} (via socks5 proxy)", self.url)
	}
}

#[derive(Debug)]
pub enum Error {
	Proxy(String),
	Http(u16),
}

impl fmt::Display for Error {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match self {
			Error::Proxy(e) => write!(f, "invalid proxy URL: {}", e),
			Error::Http(code) => write!(f, "HTTP error {}", code),
		}
	}
}

impl std::error::Error for Error {}

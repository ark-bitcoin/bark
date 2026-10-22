//! Construction of the REST client configuration: the datadir's bearer
//! token attached to either barkd's default listen address or an
//! explicit --url.

use std::path::Path;

use anyhow::Context;

use bark_cli::connection;
use bark_cli::wallet::AUTH_TOKEN_FILE;
use bark_rest_client::apis::configuration::Configuration;

/// The URL wallet commands use when no --url is given: the listen address
/// recorded by the barkd on this datadir, or barkd's default listen address.
pub fn base_url_for_datadir(datadir: &Path) -> anyhow::Result<String> {
	Ok(match connection::barkd_url(datadir)? {
		Some(url) => url,
		None => format!("http://{}", bark_rest::Config::default().socket_addr()),
	})
}

/// Read the bearer token from the datadir.
pub fn load_token(datadir: &Path) -> anyhow::Result<Option<String>> {
	let path = datadir.join(AUTH_TOKEN_FILE);
	if !path.exists() {
		return Ok(None);
	}
	let token = std::fs::read_to_string(&path)
		.with_context(|| format!("failed to read auth token at {}", path.display()))?;
	let token = token.trim();
	if token.is_empty() {
		return Ok(None);
	}
	Ok(Some(token.to_string()))
}

/// Build the client configuration for a base URL and optional bearer token.
pub fn configuration(base_url: &str, token: Option<String>) -> anyhow::Result<Configuration> {
	Ok(Configuration {
		base_path: base_url.trim_end_matches('/').to_string(),
		bearer_access_token: token,
		user_agent: Some(crate::USER_AGENT.to_string()),
		client: reqwest::Client::builder().build().context("failed to build HTTP client")?,
		..Configuration::default()
	})
}

/// Extension for results of generated client calls: their error Display
/// only carries the HTTP status, so surface the error message barkd put in
/// the response body.
pub trait RestResultExt<V> {
	fn rest(self) -> anyhow::Result<V>;
}

impl<V, T> RestResultExt<V> for Result<V, bark_rest_client::apis::Error<T>> {
	fn rest(self) -> anyhow::Result<V> {
		use bark_rest_client::apis::Error;
		self.map_err(|e| match e {
			Error::ResponseError(resp) => {
				let message = serde_json::from_str::<serde_json::Value>(&resp.content)
					.ok()
					.and_then(|v| {
						v.get("message").and_then(|m| m.as_str()).map(str::to_string)
					})
					.unwrap_or(resp.content);
				anyhow::anyhow!("barkd returned {}: {}", resp.status, message)
			},
			other => anyhow::anyhow!("{}", other),
		})
	}
}

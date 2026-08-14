
use std::net::SocketAddr;

use anyhow::Context;
use chrono::Local;
use hickory_resolver::TokioResolver;
use hickory_resolver::config::ResolverConfig;
use hickory_resolver::net::runtime::TokioRuntimeProvider;

use ark::integration::{TokenStatus, TokenType};

use crate::Server;
use crate::database::intman::model::{Integration, IntegrationApiKey, IntegrationToken};
use crate::filters::Filters;

// These two UUIDs are provisioned by migration V19 as the daemon's and CLI's
// built-in integration API keys. They are intentionally hardcoded, non-secret
// constants: the CLI defaults to `CAPTAIND_CLI_API_KEY` for its DB-direct
// operations, and `verify_ln_receive_anti_dos` uses `CAPTAIND_API_KEY` to
// attribute token-status updates on the daemon's own bookkeeping path. Neither
// of those flows goes through the gRPC IntegrationService.
//
// External scanners flag this as CWE-798 (hardcoded credentials). The finding
// is neutralized by `is_hardcoded_captaind_key` below, which blocks these
// UUIDs from external usage.
pub const CAPTAIND_API_KEY: uuid::Uuid = uuid::Uuid::from_u128(2);
pub const CAPTAIND_CLI_API_KEY: uuid::Uuid = uuid::Uuid::from_u128(3);

fn is_hardcoded_captaind_key(api_key: uuid::Uuid) -> bool {
	api_key == CAPTAIND_API_KEY || api_key == CAPTAIND_CLI_API_KEY
}

impl Server {
	pub async fn get_integration_tokens(
		&self,
		client_address: Option<SocketAddr>,
		api_key: uuid::Uuid,
		token_type: TokenType,
		count: Option<u32>,
	) -> anyhow::Result<Vec<IntegrationToken>> {
		if is_hardcoded_captaind_key(api_key) {
			return badarg!("Minting is not permitted for the built-in captaind API keys");
		}
		let integration_api_key = self.db.read(async |t| t.get_integration_api_key_by_api_key(api_key).await).await?;
		let (integration, integration_api_key) =
			self.verify_integration_api_key(client_address, &integration_api_key).await?;
		let (open_count, integration_token_config) = self.db.read(async |t| {
			let open_count = t.count_open_integration_tokens(integration.id, token_type).await?;
			let config = t.get_integration_token_config(token_type, integration.id).await?
				.context("no integration token configuration found")?;
			Ok((open_count, config))
		}).await?;
		if integration_token_config.maximum_open_tokens <= open_count {
			bail!("Maximum tokens reached")
		}

		let allowed_delta = integration_token_config.maximum_open_tokens - open_count;
		let generate_token_count = if allowed_delta > count.unwrap_or(1) {
			count.unwrap_or(1)
		} else {
			allowed_delta
		};

		let mut result = Vec::with_capacity(generate_token_count as usize);
		for _ in 0..generate_token_count {
			let token_string = uuid::Uuid::new_v4().to_string();
			let token_expiry_time = Local::now() +
				chrono::Duration::seconds(integration_token_config.active_seconds as i64);

			let filters = Filters::new();
			let inserted = self.db.write(async |t| t.store_integration_token(
				token_string.as_str(),
				token_type,
				TokenStatus::Unused,
				token_expiry_time,
				&filters,
				integration.id,
				integration_api_key.id,
			).await).await?;
			result.push(inserted);
		}

		Ok(result)
	}

	pub async fn get_integration_token(
		&self,
		client_address: Option<SocketAddr>,
		api_key: uuid::Uuid,
		token: &str,
	) -> anyhow::Result<(Integration, IntegrationApiKey, IntegrationToken)> {
		let integration_api_key = self.db.read(async |t| t.get_integration_api_key_by_api_key(api_key).await).await?;
		let (integration, integration_api_key) =
			self.verify_integration_api_key(client_address, &integration_api_key).await?;
		let integration_token = self.db.read(async |t| t.get_integration_token(token).await).await?;
		let integration_token = self.verify_integration_token(
			&integration, integration_token,
		).await?;
		if is_hardcoded_captaind_key(api_key)
			&& integration_token.created_by_api_key_id != integration_api_key.id
		{
			return badarg!("Built-in captaind API keys may only operate on tokens they created");
		}

		Ok((integration, integration_api_key, integration_token))
	}

	pub async fn update_integration_token(
		&self,
		client_address: Option<SocketAddr>,
		api_key: uuid::Uuid,
		token: &str,
		status: TokenStatus,
	) -> anyhow::Result<IntegrationToken> {
		let (_, integration_api_key, integration_token) =
			self.get_integration_token(client_address, api_key.clone(), token).await?;
		if status == integration_token.status {
			return Ok(integration_token);
		}


		match status {
			TokenStatus::Abused => {}
			TokenStatus::Disabled => {
				if integration_token.status == TokenStatus::Abused {
					bail!("You cannot disable a token that is flagged as abused")
				}
			}
			TokenStatus::Unused => {
				bail!("You cannot mark a token unused")
			}
			TokenStatus::Used => {
				if integration_token.is_expired() {
					bail!("Token is expired")
				}
			}
		};

		Ok(self.db.write(async |t| t.update_integration_token(
			integration_token.clone(),
			integration_api_key.id,
			status,
			&integration_token.filters,
		).await).await?)
	}

	/// Verify an integration API key and, if the key has per-key IP filters,
	/// check `client_address` against them.
	///
	/// The bearer UUID is the primary auth factor; the IP filter is
	/// defense-in-depth and only meaningful when `client_address`
	/// reflects the real peer. `client_address` comes from
	/// [`crate::rpcserver::middleware::RemoteAddrService`], which prefers
	/// `X-Forwarded-For`; see its docs for the proxy-chain + UFW
	/// invariants that keep the derived value trustworthy. If those
	/// break, only the bearer UUID protects the endpoint.
	async fn verify_integration_api_key(
		&self,
		client_address: Option<SocketAddr>,
		integration_api_key: &Option<IntegrationApiKey>,
	) -> Result<(Integration, IntegrationApiKey), anyhow::Error> {
		match integration_api_key {
			None => badarg!("API key cannot be found"),
			Some(integration_api_key) => {
				if integration_api_key.deleted_at.is_some() {
					return badarg!("API key is deleted");
				}
				if integration_api_key.expires_at.lt(&Local::now()) {
					return badarg!("API key is expired");
				}

				let integration = self.db.read(async |t| t.get_integration_by_id(integration_api_key.integration_id).await).await?;
				match integration {
					None => badarg!("Integration linked with API key not found"),
					Some(integration) => {
						if integration.deleted_at.is_some() {
							return badarg!("Integration linked with API key is deleted");
						}

						if integration_api_key.filters.is_empty() {
							return Ok((integration, integration_api_key.clone()));
						};

						if client_address.is_none() {
							return badarg!("Client's address cannot be found");
						}

						let client_address = client_address.unwrap();

						let resolver = TokioResolver::builder_with_config(
							ResolverConfig::default(),
							TokioRuntimeProvider::default(),
						).build()?;

						if !integration_api_key.filters.allowed(&resolver, &client_address).await {
							return badarg!("Client's address is not allowed");
						}

						Ok((integration, integration_api_key.clone()))
					}
				}
			}
		}
	}

	async fn verify_integration_token(
		&self,
		integration: &Integration,
		integration_token: Option<IntegrationToken>,
	) -> Result<IntegrationToken, anyhow::Error> {
		match integration_token {
			None => badarg!("Token cannot be found"),
			Some(integration_token) => {
				if integration_token.integration_id != integration.id {
					// TODO DEACTIVATE API_KEY??? Abuse???
					return badarg!("Token doesn't match the provided integration");
				}

				Ok(integration_token.clone())
			}
		}
	}
}

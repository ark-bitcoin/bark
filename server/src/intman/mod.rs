
use std::net::SocketAddr;

use chrono::Local;
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::TokioAsyncResolver;

use ark::integration::{TokenStatus, TokenType};

use crate::Server;
use crate::database::intman::model::{Integration, IntegrationApiKey, IntegrationToken};
use crate::filters::Filters;

impl Server {
	pub async fn get_integration_tokens(
		&self,
		client_address: Option<SocketAddr>,
		api_key: uuid::Uuid,
		token_type: TokenType,
		count: Option<u32>,
	) -> anyhow::Result<Vec<IntegrationToken>> {
		let integration_api_key = self.db.get_integration_api_key_by_api_key(api_key).await?;
		let (integration, integration_api_key) =
			self.verify_integration_api_key(client_address, &integration_api_key).await?;
		let open_count = self.db.count_open_integration_tokens(integration.integration_id, token_type).await?;
		let integration_token_config = self.db.get_integration_token_config(token_type, integration.integration_id)
			.await?.expect("no integration token configuration found");
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
			let inserted = self.db.store_integration_token(
				token_string.as_str(),
				token_type,
				TokenStatus::Unused,
				token_expiry_time,
				&filters,
				integration.integration_id,
				integration_api_key.integration_api_key_id,
			).await?;
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
		let integration_api_key = self.db.get_integration_api_key_by_api_key(api_key).await?;
		let (integration, integration_api_key) =
			self.verify_integration_api_key(client_address, &integration_api_key).await?;
		let integration_token = self.db.get_integration_token(token).await?;
		let integration_token = self.verify_integration_token(
			&integration, integration_token,
		).await?;

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

		Ok(self.db.update_integration_token(
			integration_token.clone(),
			integration_api_key.integration_api_key_id,
			status,
			&integration_token.filters,
		).await?)
	}

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

				let integration = self.db.get_integration_by_id(integration_api_key.integration_id).await?;
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

						let resolver = TokioAsyncResolver::tokio(
							ResolverConfig::default(),
							ResolverOpts::default(),
						);

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
				if integration_token.integration_id != integration.integration_id {
					// TODO DEACTIVATE API_KEY??? Abuse???
					return badarg!("Token doesn't match the provided integration");
				}

				Ok(integration_token.clone())
			}
		}
	}
}

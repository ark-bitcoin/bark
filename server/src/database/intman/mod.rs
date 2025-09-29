use chrono::{DateTime, Local};

use ark::integration::{TokenStatus, TokenType};

use crate::database::Db;
use crate::database::intman::model::{
	EncodedFilters, Integration, IntegrationApiKey, IntegrationToken, IntegrationTokenConfig,
};
use crate::filters;

pub mod model;

impl Db {
	pub async fn store_integration(
		&self,
		name: &str,
	) -> anyhow::Result<Integration> {
		let conn = self.pool.get().await?;
		let statement = conn.prepare("
			INSERT INTO integration (name, created_at) VALUES ($1, NOW())
			RETURNING id, name, created_at, deleted_at
		").await?;

		let row = conn.query_one(&statement, &[
			&name,
		]).await?;

		Ok(Integration::from(row))
	}

	pub async fn delete_integration(
		&self,
		id: i64,
	) -> anyhow::Result<Integration> {
		let conn = self.pool.get().await?;
		let statement = conn.prepare("
			UPDATE integration
			SET deleted_at = NOW()
			WHERE id = $1
			RETURNING id, name, created_at, deleted_at
		").await?;

		let row = conn.query_one(&statement, &[
			&id,
		]).await?;

		Ok(Integration::from(row))
	}

	pub async fn get_integration_by_name(
		&self,
		name: &str,
	) -> anyhow::Result<Option<Integration>> {
		let conn = self.pool.get().await?;
		let statement = conn.prepare("
			SELECT id, name, created_at, deleted_at
			FROM integration
			WHERE name = $1
		").await?;

		let row = conn.query_opt(&statement, &[
			&name,
		]).await?;

		Ok(row.map(Integration::from))
	}

	pub async fn get_integration_by_id(
		&self,
		id: i64,
	) -> anyhow::Result<Option<Integration>> {
		let conn = self.pool.get().await?;
		let statement = conn.prepare("
			SELECT id, name, created_at, deleted_at
			FROM integration
			WHERE id = $1
		").await?;

		let row = conn.query_opt(&statement, &[
			&id,
		]).await?;

		Ok(row.map(Integration::from))
	}

	pub async fn store_integration_api_key(
		&self,
		name: &str,
		api_key: uuid::Uuid,
		filters: &filters::Filters,
		integration_id: i64,
		expires_at: DateTime<Local>,
	) -> anyhow::Result<IntegrationApiKey> {
		let conn = self.pool.get().await?;
		let statement = conn.prepare("
			INSERT INTO integration_api_key (
				name, api_key, filters, integration_id, expires_at,
				created_at, updated_at
			) VALUES ($1, $2, $3, $4, $5, NOW(), NOW())
			RETURNING id,
				name, api_key, filters, integration_id, expires_at,
				created_at, updated_at, deleted_at
		").await?;

		let api_key = api_key.to_string();
		let filters = EncodedFilters::from(filters);

		let row = conn.query_one(&statement, &[
			&name,
			&api_key,
			&filters.encode(),
			&integration_id,
			&expires_at,
		]).await?;

		Ok(IntegrationApiKey::try_from(row)?)
	}

	pub async fn get_integration_api_key_by_api_key(
		&self,
		api_key: uuid::Uuid,
	) -> anyhow::Result<Option<IntegrationApiKey>> {
		let conn = self.pool.get().await?;
		let statement = conn.prepare("
			SELECT id,
				name, api_key, filters, integration_id, expires_at,
				created_at, updated_at, deleted_at
			FROM integration_api_key
			WHERE api_key=$1
		").await?;

		let row = conn.query_opt(&statement, &[
			&api_key.to_string(),
		]).await?;

		Ok(row.map(IntegrationApiKey::try_from).transpose()?)
	}

	pub async fn get_integration_api_key_by_name(
		&self,
		integration_name: &str,
		api_key_name: &str,
	) -> anyhow::Result<Option<IntegrationApiKey>> {
		let conn = self.pool.get().await?;
		let statement = conn.prepare("
			SELECT iak.id,
				iak.name, iak.api_key, iak.filters, iak.integration_id, iak.expires_at,
				iak.created_at, iak.updated_at, iak.deleted_at
			FROM integration_api_key AS iak
			JOIN integration AS i ON i.id = iak.integration_id
			WHERE i.name = $1 AND iak.name = $2
		").await?;

		let row = conn.query_opt(&statement, &[
			&integration_name,
			&api_key_name,
		]).await?;

		Ok(row.map(IntegrationApiKey::try_from).transpose()?)
	}

	pub async fn update_integration_api_key(
		&self,
		old_integration_api_key: IntegrationApiKey,
		new_filters: &filters::Filters,
	) -> anyhow::Result<IntegrationApiKey> {
		let conn = self.pool.get().await?;
		let statement = conn.prepare("
			UPDATE integration_api_key
			SET filters = $1, updated_at = NOW()
			WHERE id = $2 AND updated_at = $3
			RETURNING id,
				name, api_key, filters, integration_id, expires_at,
				created_at, updated_at, deleted_at
		").await?;

		let filters = EncodedFilters::from(new_filters);

		let row = conn.query_one(&statement, &[
			&filters.encode(),
			&old_integration_api_key.id,
			&old_integration_api_key.updated_at,
		]).await?;

		Ok(IntegrationApiKey::try_from(row)?)
	}

	pub async fn delete_integration_api_key(
		&self,
		id: i64,
		old_updated_at: DateTime<Local>,
	) -> anyhow::Result<IntegrationApiKey> {
		let conn = self.pool.get().await?;
		let statement = conn.prepare("
			UPDATE integration_api_key
			SET deleted_at = NOW(), updated_at = NOW()
			WHERE id = $1 AND updated_at = $2
			RETURNING id,
				name, api_key, filters, integration_id, expires_at,
				created_at, updated_at, deleted_at
		").await?;

		let row = conn.query_one(&statement, &[
			&id,
			&old_updated_at,
		]).await?;

		Ok(IntegrationApiKey::try_from(row)?)
	}

	pub async fn store_integration_token_config(
		&self,
		token_type: TokenType,
		maximum_open_tokens: u32,
		active_seconds: u32,
		integration_id: i64,
	) -> anyhow::Result<IntegrationTokenConfig> {
		let conn = self.pool.get().await?;
		let statement = conn.prepare("
			INSERT INTO integration_token_config (
				type, maximum_open_tokens, active_seconds, integration_id,
				created_at, updated_at
			) VALUES ($1::TEXT::token_type, $2, $3, $4,
				NOW(), NOW())
			RETURNING id,
				type::TEXT, maximum_open_tokens, active_seconds,
				integration_id,
				created_at, updated_at, deleted_at
		").await?;

		let token_type = token_type.to_string();
		let maximum_open_tokens = maximum_open_tokens as i32;
		let active_seconds = active_seconds as i32;

		let row = conn.query_one(&statement, &[
			&token_type,
			&maximum_open_tokens,
			&active_seconds,
			&integration_id,
		]).await?;

		Ok(IntegrationTokenConfig::from(row))
	}

	pub async fn get_integration_token_config(
		&self,
		token_type: TokenType,
		integration_id: i64,
	) -> anyhow::Result<Option<IntegrationTokenConfig>> {
		let conn = self.pool.get().await?;
		let statement = conn.prepare("
			SELECT id,
				type::TEXT, maximum_open_tokens, active_seconds,
				integration_id,
				created_at, updated_at, deleted_at
			FROM integration_token_config
			WHERE integration_id = $1 AND type = $2::TEXT::token_type
		").await?;

		let token_type = token_type.to_string();
		let row = conn.query_opt(&statement, &[
			&integration_id,
			&token_type,
		]).await?;

		Ok(row.map(IntegrationTokenConfig::from))
	}

	pub async fn update_integration_token_config(
		&self,
		old_integration_token_config: IntegrationTokenConfig,
		new_maximum_open_tokens: u32,
		new_active_seconds: u32,
	) -> anyhow::Result<IntegrationTokenConfig> {
		let conn = self.pool.get().await?;
		let statement = conn.prepare("
			UPDATE integration_token_config
			SET maximum_open_tokens = $1, active_seconds = $2, updated_at = NOW()
			WHERE id = $3 AND updated_at = $4
			RETURNING id,
				type::TEXT, maximum_open_tokens, active_seconds,
				integration_id,
				created_at, updated_at, deleted_at
		").await?;

		let maximum_open_tokens = new_maximum_open_tokens as i32;
		let active_seconds = new_active_seconds as i32;

		let row = conn.query_one(&statement, &[
			&maximum_open_tokens,
			&active_seconds,
			&old_integration_token_config.id,
			&old_integration_token_config.updated_at,
		]).await?;

		Ok(IntegrationTokenConfig::from(row))
	}

	pub async fn delete_integration_token_config(
		&self,
		id: i64,
		old_updated_at: DateTime<Local>,
	) -> anyhow::Result<IntegrationTokenConfig> {
		let conn = self.pool.get().await?;
		let statement = conn.prepare("
			UPDATE integration_token_config
			SET deleted_at = NOW(), updated_at = NOW()
			WHERE id = $1 AND updated_at = $2
			RETURNING id,
				type::TEXT, maximum_open_tokens, active_seconds,
				integration_id,
				created_at, updated_at, deleted_at
		").await?;

		let row = conn.query_one(&statement, &[
			&id,
			&old_updated_at,
		]).await?;

		Ok(IntegrationTokenConfig::from(row))
	}

	pub async fn get_integration_token(
		&self,
		token: &str,
	) -> anyhow::Result<Option<IntegrationToken>> {
		let conn = self.pool.get().await?;
		let statement = conn.prepare("
			SELECT id, token, type::TEXT, status::TEXT, filters,
				integration_id, expires_at,
				created_at, created_by_api_key_id, updated_at, updated_by_api_key_id
			FROM integration_token
			WHERE token = $1
		").await?;

		let row = conn.query_opt(&statement, &[
			&token,
		]).await?;

		Ok(row.map(IntegrationToken::try_from).transpose()?)
	}

	pub async fn count_open_integration_tokens(
		&self,
		integration_id: i64,
		token_type: TokenType,
	) -> anyhow::Result<u32> {
		let conn = self.pool.get().await?;
		let statement = conn.prepare("
			SELECT COUNT(*) AS open_count
			FROM integration_token it
			WHERE it.status = $1::TEXT::token_status AND
				it.type = $2::TEXT::token_type AND
				it.integration_id = $3 AND
				it.expires_at IS NOT NULL AND
				it.expires_at > NOW()
		").await?;
		let unused = TokenStatus::Unused.to_string();
		let token_type = token_type.to_string();

		let row = conn.query_one(&statement, &[
			&unused,
			&token_type,
			&integration_id,
		]).await?;

		Ok(row.get::<_, i64>("open_count") as u32)
	}

	pub async fn store_integration_token(
		&self,
		token_string: &str,
		token_type: TokenType,
		status: TokenStatus,
		expiry_time: DateTime<Local>,
		filters: &filters::Filters,
		integration_id: i64,
		api_key_id: i64,
	) -> anyhow::Result<IntegrationToken> {
		let conn = self.pool.get().await?;
		let statement = conn.prepare("
			INSERT INTO integration_token (
				token, type, status, filters, expires_at, integration_id,
				created_at, created_by_api_key_id, updated_at, updated_by_api_key_id
			) VALUES (
				$1, $2::TEXT::token_type, $3::TEXT::token_status, $4, $5, $6, NOW(), $7, NOW(), $7
			)
			RETURNING id,
				token, type::TEXT, status::TEXT, filters, expires_at, integration_id,
				created_at, created_by_api_key_id, updated_at, updated_by_api_key_id
		").await?;
		let token_type = token_type.to_string();
		let token_status = status.to_string();
		let filters = EncodedFilters::from(filters);

		let row = conn.query_one(&statement, &[
			&token_string,
			&token_type,
			&token_status,
			&filters.encode(),
			&expiry_time,
			&integration_id,
			&api_key_id,
		]).await?;

		Ok(IntegrationToken::try_from(row)?)
	}

	pub async fn update_integration_token(
		&self,
		old_integration_token: IntegrationToken,
		updated_by_api_key_id: i64,
		new_status: TokenStatus,
		new_filters: &filters::Filters,
	) -> anyhow::Result<IntegrationToken> {
		let conn = self.pool.get().await?;
		let statement = conn.prepare("
			UPDATE integration_token
			SET status = $1::TEXT::token_status, filters = $2,
				updated_at = NOW(), updated_by_api_key_id = $3
			WHERE id = $4 AND updated_at = $5
			RETURNING id, token, type::TEXT, status::TEXT, filters,
				integration_id, expires_at,
				created_at, created_by_api_key_id, updated_at, updated_by_api_key_id
		").await?;
		let status = new_status.to_string();
		let filters = EncodedFilters::from(new_filters);

		let row = conn.query_one(&statement, &[
			&status,
			&filters.encode(),
			&updated_by_api_key_id,
			&old_integration_token.id,
			&old_integration_token.updated_at,
		]).await?;

		Ok(IntegrationToken::try_from(row)?)
	}
}

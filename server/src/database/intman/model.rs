
use chrono::{DateTime, Local};
use serde_json::to_string_pretty;
use tokio_postgres::Row;
use ark::integration::{TokenStatus, TokenType};

use crate::filters;

pub type EncodedFilters = Option<String>;

// Define a trait for the functionality
pub trait EncodedFiltersExt {
	fn to_filters(&self) -> filters::Filters;
	fn from_filters(filters: &filters::Filters) -> EncodedFilters;
}

impl EncodedFiltersExt for EncodedFilters {
	fn to_filters(&self) -> filters::Filters {
		self.as_ref()
			.and_then(|s| serde_json::from_str(s).ok())
			.unwrap_or_else(filters::Filters::new)
	}

	fn from_filters(filters: &filters::Filters) -> EncodedFilters {
		if filters.is_empty() {
			None
		} else {
			to_string_pretty(filters).ok()
		}
	}
}

#[derive(Debug, Clone)]
pub struct Integration {
	pub integration_id: i64,
	pub name: String,
	pub created_at: DateTime<Local>,
	pub deleted_at: Option<DateTime<Local>>,
}

impl From<Row> for Integration {
	fn from(row: Row) -> Self {
		Integration {
			integration_id: row.get("integration_id"),
			name: row.get("name"),
			created_at: row.get("created_at"),
			deleted_at: row.get("deleted_at"),
		}
	}
}

#[derive(Debug, Clone)]
pub struct IntegrationApiKey {
	pub integration_api_key_id: i64,
	pub name: String,
	pub api_key: uuid::Uuid,
	pub filters: EncodedFilters,
	pub integration_id: i64,
	pub created_at: DateTime<Local>,
	pub expires_at: DateTime<Local>,
	pub updated_at: DateTime<Local>,
	pub deleted_at: Option<DateTime<Local>>,
}

impl IntegrationApiKey {
	pub fn is_expired(&self) -> bool {
		self.expires_at < Local::now()
	}
}

impl From<Row> for IntegrationApiKey {
	fn from(row: Row) -> Self {
		IntegrationApiKey {
			integration_api_key_id: row.get("integration_api_key_id"),
			name: row.get("name"),
			api_key: uuid::Uuid::try_from(row.get::<_, &str>("api_key")).unwrap(),
			filters: row.get("filters"),
			integration_id: row.get("integration_id"),
			created_at: row.get("created_at"),
			expires_at: row.get("expires_at"),
			updated_at: row.get("updated_at"),
			deleted_at: row.get("deleted_at"),
		}
	}
}

#[derive(Debug, Clone)]
pub struct IntegrationTokenConfig {
	pub integration_token_config_id: i64,
	pub token_type: TokenType,
	pub maximum_open_tokens: u32,
	pub active_seconds: u32,
	pub integration_id: i64,
	pub created_at: DateTime<Local>,
	pub updated_at: DateTime<Local>,
	pub deleted_at: Option<DateTime<Local>>,
}

impl From<Row> for IntegrationTokenConfig {
	fn from(row: Row) -> Self {
		IntegrationTokenConfig {
			integration_token_config_id: row.get("integration_token_config_id"),
			token_type: row.get::<_, &str>("type").parse::<TokenType>().unwrap(),
			maximum_open_tokens: u32::try_from(row.get::<_, i32>("maximum_open_tokens")).unwrap(),
			active_seconds: row.get::<_, i32>("active_seconds") as u32,
			integration_id: row.get("integration_id"),
			created_at: row.get("created_at"),
			updated_at: row.get("updated_at"),
			deleted_at: row.get("deleted_at"),
		}
	}
}

#[derive(Debug, Clone)]
pub struct IntegrationToken {
	pub integration_token_id: i64,
	pub token: String,
	pub token_type: TokenType,
	pub status: TokenStatus,
	pub filters: EncodedFilters,
	pub integration_id: i64,
	pub created_at: DateTime<Local>,
	pub created_by_api_key_id: i64,
	pub expires_at: DateTime<Local>,
	pub updated_at: DateTime<Local>,
	pub updated_by_api_key_id: i64,
}

impl IntegrationToken {
	pub fn is_expired(&self) -> bool {
		if self.status != TokenStatus::Unused {
			return false;
		}

		self.expires_at < Local::now()
	}
}

impl From<Row> for IntegrationToken {
	fn from(row: Row) -> Self {
		IntegrationToken {
			integration_token_id: row.get("integration_token_id"),
			token: row.get("token"),
			token_type: row.get::<_, &str>("type").parse::<TokenType>().unwrap(),
			status: row.get::<_, &str>("status").parse::<TokenStatus>().unwrap(),
			filters: row.get("filters"),
			integration_id: row.get("integration_id"),
			created_at: row.get("created_at"),
			created_by_api_key_id: row.get("created_by_api_key_id"),
			expires_at: row.get("expires_at"),
			updated_at: row.get("updated_at"),
			updated_by_api_key_id: row.get("updated_by_api_key_id"),
		}
	}
}


#[cfg(test)]
mod test {
	use crate::filters::Filters;
	use super::*;

	#[test]
	fn test_encoded_filters() {
		let f = Filters::new();
		let ef = EncodedFilters::from_filters(&f);
		assert_eq!(ef, None);

		let f = Filters::init(
			vec!["127.0.0.1".to_string(), "10.0.0.1/8".to_string()],
			vec![],
		);
		let ef = EncodedFilters::from_filters(&f);
		assert_eq!(ef.unwrap(), "{\n  \"ip\": [\n    \"127.0.0.1\",\n    \"10.0.0.1/8\"\n  ],\n  \"dns\": []\n}");

		let f = Filters::init(
			vec![],
			vec!["localhost".to_string(), "host".to_string()],
		);
		let ef = EncodedFilters::from_filters(&f);
		assert_eq!(ef.unwrap(), "{\n  \"ip\": [],\n  \"dns\": [\n    \"localhost\",\n    \"host\"\n  ]\n}");

		let f = Filters::init(
			vec!["127.0.0.1".to_string(), "10.0.0.1/8".to_string()],
			vec!["localhost".to_string(), "host".to_string()],
		);
		let ef = EncodedFilters::from_filters(&f);
		assert_eq!(ef.unwrap(), "{\n  \"ip\": [\n    \"127.0.0.1\",\n    \"10.0.0.1/8\"\n  ],\n  \"dns\": [\n    \"localhost\",\n    \"host\"\n  ]\n}");

		let ef: EncodedFilters = None;
		let f = EncodedFilters::to_filters(&ef);
		assert_eq!(f.is_empty(), true);

		let ef: EncodedFilters = Some("{\"ip\":[\"127.0.0.1\",\"10.0.0.1/8\"]}".to_string());
		let f = EncodedFilters::to_filters(&ef);
		assert_eq!(f.is_empty(), false);
		assert_eq!(f.ip(), vec!["127.0.0.1".to_string(), "10.0.0.1/8".to_string()]);
		assert_eq!(f.dns().is_empty(), true);

		let ef: EncodedFilters = Some("{\"dns\":[\"localhost\",\"host\"]}".to_string());
		let f = EncodedFilters::to_filters(&ef);
		assert_eq!(f.is_empty(), false);
		assert_eq!(f.ip().is_empty(), true);
		assert_eq!(f.dns(), vec!["localhost".to_string(), "host".to_string()]);

		let ef: EncodedFilters = Some("{\"ip\":[\"127.0.0.1\",\"10.0.0.1/8\"],\"dns\":[\"localhost\",\"host\"]}".to_string());
		let f = EncodedFilters::to_filters(&ef);
		assert_eq!(f.is_empty(), false);
		assert_eq!(f.ip(), vec!["127.0.0.1".to_string(), "10.0.0.1/8".to_string()]);
		assert_eq!(f.dns(), vec!["localhost".to_string(), "host".to_string()]);
	}
}

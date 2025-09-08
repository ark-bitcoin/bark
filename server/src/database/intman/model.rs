
use anyhow::Context;
use chrono::{DateTime, Local};
use tokio_postgres::Row;
use ark::integration::{TokenStatus, TokenType};

use crate::filters::Filters;

#[derive(Clone, Debug, Deserialize, Serialize, Default)]
pub(super) struct EncodedFilters {
	#[serde(default)]
	ip: Vec<String>,
	#[serde(default)]
	dns: Vec<String>,
}

impl EncodedFilters {
	pub fn encode(&self) -> String {
		serde_json::to_string(self).expect("serializer shouldn't fail")
	}

	pub fn decode(encoded: &str) -> Result<Self, serde_json::Error> {
		serde_json::from_str(encoded)
	}
}

impl From<&Filters> for EncodedFilters {
	fn from(v: &Filters) -> Self {
		EncodedFilters {
			ip: v.ip().to_vec(),
			dns: v.dns().to_vec(),
		}
	}
}

impl From<EncodedFilters> for Filters {
	fn from(v: EncodedFilters) -> Self {
		Filters::init(v.ip, v.dns)
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
	pub filters: Filters,
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

impl TryFrom<Row> for IntegrationApiKey {
	type Error = anyhow::Error;

	fn try_from(row: Row) -> anyhow::Result<Self> {
		Ok(IntegrationApiKey {
			integration_api_key_id: row.get("integration_api_key_id"),
			name: row.get("name"),
			api_key: uuid::Uuid::try_from(row.get::<_, &str>("api_key")).expect("invalid UUID"),
			filters: row.get::<_, Option<&str>>("filters")
				.map(EncodedFilters::decode)
				.transpose().context("failed to decode fitlers")?
				.unwrap_or_default()
				.into(),
			integration_id: row.get("integration_id"),
			created_at: row.get("created_at"),
			expires_at: row.get("expires_at"),
			updated_at: row.get("updated_at"),
			deleted_at: row.get("deleted_at"),
		})
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
	pub filters: Filters,
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

impl TryFrom<Row> for IntegrationToken {
	type Error = anyhow::Error;

	fn try_from(row: Row) -> anyhow::Result<Self> {
		Ok(IntegrationToken {
			integration_token_id: row.get("integration_token_id"),
			token: row.get("token"),
			token_type: row.get::<_, &str>("type").parse::<TokenType>()
				.context("unknown TokenType")?,
			status: row.get::<_, &str>("status").parse::<TokenStatus>()
				.context("unknown TokenStatus")?,
			filters: row.get::<_, Option<&str>>("filters")
				.map(EncodedFilters::decode)
				.transpose().context("failed to decode fitlers")?
				.unwrap_or_default()
				.into(),
			integration_id: row.get("integration_id"),
			created_at: row.get("created_at"),
			created_by_api_key_id: row.get("created_by_api_key_id"),
			expires_at: row.get("expires_at"),
			updated_at: row.get("updated_at"),
			updated_by_api_key_id: row.get("updated_by_api_key_id"),
		})
	}
}


#[cfg(test)]
mod test {
	use crate::filters::Filters;
	use super::*;

	#[test]
	fn test_encoded_filters() {
		let f = Filters::new();
		let ef = EncodedFilters::from(&f);
		assert_eq!(ef.encode(), "{\"ip\":[],\"dns\":[]}");

		let f = Filters::init(
			vec!["127.0.0.1".to_string(), "10.0.0.1/8".to_string()],
			vec![],
		);
		let ef = EncodedFilters::from(&f);
		assert_eq!(ef.encode(), "{\"ip\":[\"127.0.0.1\",\"10.0.0.1/8\"],\"dns\":[]}");

		let f = Filters::init(
			vec![],
			vec!["localhost".to_string(), "host".to_string()],
		);
		let ef = EncodedFilters::from(&f);
		assert_eq!(ef.encode(), "{\"ip\":[],\"dns\":[\"localhost\",\"host\"]}");

		let f = Filters::init(
			vec!["127.0.0.1".to_string(), "10.0.0.1/8".to_string()],
			vec!["localhost".to_string(), "host".to_string()],
		);
		let ef = EncodedFilters::from(&f);
		assert_eq!(ef.encode(), "{\"ip\":[\"127.0.0.1\",\"10.0.0.1/8\"],\"dns\":[\"localhost\",\"host\"]}");

		let ef = EncodedFilters::decode("{}").unwrap();
		let f = Filters::from(ef);
		assert_eq!(f.is_empty(), true);

		let ef = EncodedFilters::decode("{\"ip\":[\"127.0.0.1\",\"10.0.0.1/8\"]}").unwrap();
		let f = Filters::from(ef);
		assert_eq!(f.is_empty(), false);
		assert_eq!(f.ip(), vec!["127.0.0.1".to_string(), "10.0.0.1/8".to_string()]);
		assert_eq!(f.dns().is_empty(), true);

		let ef = EncodedFilters::decode("{\"dns\":[\"localhost\",\"host\"]}").unwrap();
		let f = Filters::from(ef);
		assert_eq!(f.is_empty(), false);
		assert_eq!(f.ip().is_empty(), true);
		assert_eq!(f.dns(), vec!["localhost".to_string(), "host".to_string()]);

		let ef = EncodedFilters::decode("{\"ip\":[\"127.0.0.1\",\"10.0.0.1/8\"],\"dns\":[\"localhost\",\"host\"]}").unwrap();
		let f = Filters::from(ef);
		assert_eq!(f.is_empty(), false);
		assert_eq!(f.ip(), vec!["127.0.0.1".to_string(), "10.0.0.1/8".to_string()]);
		assert_eq!(f.dns(), vec!["localhost".to_string(), "host".to_string()]);
	}
}

use std::env::{self, VarError};

use tokio_postgres::{Client, Config, NoTls};

use crate::postgres::query::drop_and_create_database;
use crate::constants::env::TEST_POSTGRES_HOST;

/// The hostname of the external postgres database
pub fn postgres_host() -> Option<String> {
	match env::var(TEST_POSTGRES_HOST) {
		Ok(host) => Some(host),
		Err(VarError::NotPresent) => None,
		Err(VarError::NotUnicode(_)) => panic!("{} is not unicode", TEST_POSTGRES_HOST),
	}
}

pub struct ExternallyManagedPostgres {
	host: String,
	port: u16,
	name: String,
	user: Option<String>,
	password: Option<String>,
}

impl ExternallyManagedPostgres {

	pub async fn init() -> Self {
		Self {
			host: postgres_host().expect("Postgres host is configured"),
			port: 5432,
			name: String::from("postgres"),
			user: Some(String::from("postgres")),
			password: Some(String::from("postgres")),
		}
	}

	pub async fn request_database(&self, db_name: &str) -> aspd::config::Postgres {
		let client = self.global_client().await;
		drop_and_create_database(&client, db_name).await;
		aspd::config::Postgres {
			host: self.host.clone(),
			port: self.port,
			name: db_name.to_string(),
			user: self.user.clone(),
			password: self.password.clone(),
		}
	}

	async fn global_client(&self) -> Client {
		let mut config = Config::new();
		config.host(self.host.clone());
		config.port(5432);

		config.dbname(self.name.clone());

		if self.user.is_some() {
			config.user(self.user.clone().unwrap());
		}
		if self.password.is_some() {
			config.password(self.password.clone().unwrap());
		}

		let (client, connection) = config.connect(NoTls).await
			.expect("failed to connect to global postgres client");
		tokio::spawn(async move {
			if let Err(e) = connection.await {
				panic!("postgres daemon connection error: {}", e);
			}
		});

		client
	}
}

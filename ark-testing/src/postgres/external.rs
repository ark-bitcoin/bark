use std::env::{self, VarError};

use tokio_postgres::{Client, Config, NoTls};


use crate::constants::env::TEST_POSTGRES_HOST;

/// The hostname of the external postgres database
pub fn postgres_host() -> Option<String> {
	match env::var(TEST_POSTGRES_HOST) {
		Ok(host) => Some(host),
		Err(VarError::NotPresent) => None,
		Err(VarError::NotUnicode(_)) => panic!("{} is not unicode", TEST_POSTGRES_HOST),
	}
}

/// The global client is used to drop
/// and create databases on the external host.
pub async fn global_client() -> Client {
	let mut config = Config::new();

	// we use default database and user to connect and create testing ones
	config.dbname("postgres");
	config.user("postgres");
	config.password("postgres");

	config.host(postgres_host().unwrap());
	config.port(5432);

	let (client, connection) = config.connect(NoTls).await
		.expect("failed to connect to global postgres client");
	tokio::spawn(async move {
		if let Err(e) = connection.await {
			panic!("postgres daemon connection error: {}", e);
		}
	});

	client
}

use std::path::PathBuf;

use tokio_postgres::Client;

use crate::daemon::postgres::Postgres;
use crate::postgres::query::drop_and_create_database;

pub struct TestManagedPostgres {
	postgresd: Postgres,
}

impl TestManagedPostgres {

	pub async fn init(datadir: PathBuf) -> Self {
		let mut postgresd = Postgres::new("postgres", datadir);
		postgresd.start().await.unwrap();
		Self { postgresd }
	}

	pub async fn request_database(
		&self, db_name: &str
	) -> aspd::config::Postgres {
		let client = self.global_client().await;
		drop_and_create_database(&client, db_name).await;
		self.postgresd.helper().into_config(db_name)
	}

	async fn global_client(&self) -> Client {
		self.postgresd
			.helper()
			.try_connect().await
			.expect("Failed to connect to postgres host")
	}
}

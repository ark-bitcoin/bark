use std::env;
use std::path::PathBuf;
use std::str::FromStr;

use log::{debug, error, trace};
use tokio::fs;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tokio_postgres::{Client, Config, NoTls};

use server::config;
use server::secret::Secret;

use crate::constants::env::POSTGRES_BINS;
use crate::daemon::{Daemon, DaemonHelper};
use crate::util::resolve_path;


const LOCK_DIR: &str = "/tmp/ark-testing-postgres-locks";

pub fn host_base_config() -> config::Postgres {
	config::Postgres {
		name: String::new(), // left empty to be filled
		host: env::var("TEST_POSTGRES_HOST").unwrap_or(String::from("localhost")),
		port: 5432,
		user: Some("postgres".into()),
		password: Some(Secret::new("postgres".into())),
		max_connections: 10,
	}
}


pub type Postgres = Daemon<PostgresHelper>;

impl Postgres {
	fn initdb() -> PathBuf {
		if let Ok(e) = std::env::var(&POSTGRES_BINS) {
			resolve_path(&PathBuf::from_str(&e).unwrap().join("initdb"))
				.expect("failed to resolve $POSTGRES_BINS/initdb")
		} else if let Ok(e) = which::which("initdb") {
			e
		} else {
			panic!("POSTGRES_BINS env not set")
		}
	}

	fn postgres() -> PathBuf {
		if let Ok(e) = std::env::var(&POSTGRES_BINS) {
			resolve_path(format!("{}/postgres", e)).expect("failed to resolve $POSTGRES_BINS/postgres")
		} else if let Ok(e) = which::which("postgres") {
			e.into()
		} else {
			panic!("POSTGRES_BINS env not set")
		}
	}

	pub fn new(name: impl AsRef<str>, datadir: PathBuf) -> Self {
		let inner = PostgresHelper::new(name, datadir);
		Daemon::wrap(inner)
	}

	pub fn helper(&self) -> &PostgresHelper {
		&self.inner
	}
}

#[derive(Clone)]
pub struct PostgresHelper {
	pub name: String,
	pub datadir: PathBuf,
	pub port: Option<u16>
}

impl PostgresHelper {
	pub fn new(name: impl AsRef<str>, datadir: PathBuf) -> PostgresHelper {
		PostgresHelper {
			name: name.as_ref().to_string(),
			datadir: datadir,
			port: None
		}
	}

	pub fn port(&self) -> u16 {
		self.port.expect("port should be set")
	}

	pub fn into_config(&self, dbname: &str) -> config::Postgres {
		config::Postgres {
			name: dbname.to_owned(),
			host: String::from("localhost"),
			port: self.port(),
			user: None,
			password: None,
			max_connections: 10,
		}
	}

	pub async fn try_connect(&self, dbname: Option<&str>) -> anyhow::Result<Client> {
		let mut config = Config::new();

		if let Some(dbname) = dbname {
			// user can define a specific database to connect to for testing
			config.dbname(dbname);
		} else {
			// we use default database to connect and create testing ones
			config.dbname("postgres");
		}

		config.host("localhost");
		config.port(self.port());

		let (client, connection) = config.connect(NoTls).await?;
		tokio::spawn(async move {
			if let Err(e) = connection.await {
				panic!("postgres daemon connection error: {}", e);
			}
		});

		Ok(client)
	}

	pub async fn is_ready(&self) -> bool {
		self.try_connect(None).await.is_ok()
	}

	pub fn pgdata(&self) -> PathBuf {
		self.datadir.join("pg_data")
	}
}

#[tonic::async_trait]
impl DaemonHelper for PostgresHelper {
	fn name(&self) -> &str {
		&self.name
	}

	fn datadir(&self) -> PathBuf {
		self.datadir.clone()
	}

	async fn make_reservations(&mut self) -> anyhow::Result<()> {
		let db_port = portpicker::pick_unused_port().expect("No ports free");

		trace!("Reserved postgres port = {}", db_port);
		self.port = Some(db_port);

		Ok(())
	}

	async fn prepare(&self) -> anyhow::Result<()> {
		fs::create_dir_all(LOCK_DIR).await.expect("failed to create postgres lock dir");

		if self.datadir.exists() {
			fs::remove_dir_all(&self.datadir).await.expect("failed to clear postgres datadir");
		}
		fs::create_dir_all(&self.datadir()).await.expect("failed to create postgres datadir");

		// also create dedicated dir for pgdata
		fs::create_dir_all(&self.pgdata()).await.expect("failed to create pgdata dir");

		let output = Command::new(Postgres::initdb())
			.args(["-D", &self.pgdata().display().to_string(),
				"--encoding=UTF8",
				"--locale=C.UTF-8",
			])
			.output()
			.await
			.expect("cannot init postgres");


		if !output.status.success() {
			let stderr = String::from_utf8(output.clone().stderr)?;
			error!("stderr: {}", stderr);
			bail!("Failed to init postgres db: {:?}", output);
		}

		let conf_path = self.pgdata().join("postgresql.conf");
		let shared_buffers = "\n# Custom shared memory settings\nshared_buffers = 256MB\n";
		fs::OpenOptions::new()
			.append(true)
			.open(&conf_path)
			.await?
			.write_all(shared_buffers.as_bytes())
			.await?;

		Ok(())
	}

	async fn get_command(&self) -> anyhow::Result<Command> {
		let mut cmd = Command::new(Postgres::postgres());
		cmd.args([
			"-k", LOCK_DIR,
			"-D", &self.pgdata().display().to_string(),
			"-p", &self.port.expect("a port should be configured").to_string(),
		]);

		debug!("postgresql command: {:?}", cmd);

		return Ok(cmd)
	}

	async fn wait_for_init(&self) -> anyhow::Result<()> {
		loop {
			if self.is_ready().await {
				return Ok(());
			}
			tokio::time::sleep(std::time::Duration::from_millis(100)).await;
		}
	}
}


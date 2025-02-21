use std::env;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::{Duration, Instant};

use aspd::config;
use tokio::fs;
use tokio::process::{Child, Command};
use tokio_postgres::{Client, Config, NoTls};

use crate::constants::env::POSTGRES_BINS;
use crate::daemon::{Daemon, DaemonHelper};
use crate::util::resolve_path;

pub type Postgres = Daemon<PostgresHelper>;

pub fn use_global_database() -> bool {
	env::var("USE_GLOBAL_DATABASE").unwrap_or_default() == "true".to_string()
}

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
	pub datadir: Option<PathBuf>,
	pub auth: Option<(String, String)>,
	pub port: Option<u16>
}

impl PostgresHelper {
	pub fn new(name: impl AsRef<str>, datadir: PathBuf) -> PostgresHelper {
		PostgresHelper {
			name: name.as_ref().to_string(),
			datadir: Some(datadir.join("pg_data")),
			auth: None,
			port: None
		}
	}

	pub fn new_global(name: impl AsRef<str>) -> PostgresHelper {
		PostgresHelper {
			name: name.as_ref().to_string(),
			datadir: None,
			auth: Some(("postgres".to_string(), "postgres".to_string())),
			port: Some(5432)
		}
	}

	pub fn port(&self) -> u16 {
		self.port.expect("port should be set")
	}

	pub fn as_base_config(&self) -> config::Postgres {
		let (user, password) = self.auth.as_ref()
			.map(|(u, p)| (Some(u.clone()), Some(p.clone())))
			.unwrap_or((None, None));

		config::Postgres {
			host: String::from("localhost"),
			port: self.port(),
			name: String::new(),
			user: user,
			password: password,
		}
	}

	async fn connect(&self) -> anyhow::Result<Client> {
		let mut config = Config::new();

		// we use default database and user to connect and create testing ones
		config.dbname("postgres");
		if let Some((user, pwd)) = &self.auth {
			config.user(user.clone());
			config.password(pwd.clone());
		}

		config.host("localhost");
		config.port(self.port());

		let (client, connection) = config.connect(NoTls).await?;
		tokio::spawn(async move {
			if let Err(e) = connection.await {
				println!("daemon connection error: {}", e);
			}
		});

		Ok(client)
	}

	pub async fn cleanup_dbs(&self, name: &str) -> anyhow::Result<()> {
		let client = self.connect().await?;

		let rows = client
			.query(
				"SELECT datname FROM pg_database WHERE datname LIKE $1",
				&[&format!("{}%", name)],
			).await?;

		for row in rows {
			let db_name = row.get::<_, &str>(0);
			client.execute(&format!("DROP DATABASE \"{}\"", db_name), &[]).await?;
		}

		Ok(())
	}

	pub async fn is_ready(&self) -> bool {
		self.connect().await.is_ok()
	}
}

impl DaemonHelper for PostgresHelper {
	fn name(&self) -> &str {
		&self.name
	}

	fn datadir(&self) -> PathBuf {
		self.datadir.clone().expect("datadir should be set when helper used as daemon").clone()
	}

	async fn make_reservations(&mut self) -> anyhow::Result<()> {
		let db_port = portpicker::pick_unused_port().expect("No ports free");

		trace!("Reserved postgres port = {}", db_port);
		self.port = Some(db_port);

		Ok(())
	}

	async fn prepare(&self) -> anyhow::Result<()> {
		fs::create_dir_all(&self.datadir()).await?;
		let pgdata = &self.datadir().display().to_string();

		let output = Command::new(Postgres::initdb()).args(["-D", &pgdata])
			.output()
			.await
			.expect("cannot init postgres");


		if !output.status.success() {
			let stderr = String::from_utf8(output.clone().stderr)?;
			error!("stderr: {}", stderr);
			bail!("Failed to init postgres db: {:?}", output);
		}

		Ok(())
	}

	async fn get_command(&self) -> anyhow::Result<Command> {
		let mut cmd = Command::new(Postgres::postgres());
		cmd.args([
			"-D", &self.datadir().display().to_string(),
			"-p", &self.port.expect("a port should be configured").to_string()
			]);

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

	fn prepare_kill(&mut self, child: &mut Child) {
		let pid = child.id().expect("child without pid");
		let pid = nix::unistd::Pid::from_raw(pid as i32);
		nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGTERM)
			.expect("error sending SIGTERM to postgres");

		let start = Instant::now();
		while start.elapsed() < Duration::from_secs(5) {
			std::thread::sleep(Duration::from_millis(500));
			if child.try_wait().is_ok() {
				break;
			}
		}
	}
}


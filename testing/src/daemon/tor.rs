use std::fs::{create_dir_all, write};
use std::path::PathBuf;
use std::time::Duration;

use log::{debug, info};
use tokio::fs::read_to_string;
use tokio::process::Command;
use tokio::sync::mpsc::Sender;
use tokio::time::sleep;

use crate::constants::env::TOR_EXEC;
use crate::daemon::{Daemon, DaemonHelper};
use crate::util::resolve_path;

pub struct HiddenService {
	pub name: String,
	pub onion_address: Option<String>,
	pub virtual_port: u16,
	pub target_port: u16,
}

pub struct TorConfig {
	pub datadir: PathBuf,
	pub hidden_services: Vec<HiddenServiceConfig>,
}

pub struct HiddenServiceConfig {
	pub name: String,
	pub virtual_port: u16,
	pub target_port: u16,
}

pub struct TorHelper {
	name: String,
	exec: PathBuf,
	config: TorConfig,
	socks_port: Option<u16>,
	hidden_services: Vec<HiddenService>,
}

pub type Tor = Daemon<TorHelper>;

impl Tor {
	fn exec() -> PathBuf {
		if let Ok(e) = std::env::var(TOR_EXEC) {
			resolve_path(e).expect("failed to resolve TOR_EXEC")
		} else if let Ok(e) = which::which("tor") {
			e.into()
		} else {
			panic!("TOR_EXEC env not set and tor not found in PATH")
		}
	}

	pub fn new(name: impl AsRef<str>, config: TorConfig) -> Self {
		let exec = Self::exec();
		let hidden_services = config.hidden_services.iter().map(|hs| {
			HiddenService {
				name: hs.name.clone(),
				onion_address: None,
				virtual_port: hs.virtual_port,
				target_port: hs.target_port,
			}
		}).collect();

		Daemon::wrap(TorHelper {
			name: name.as_ref().to_owned(),
			exec,
			config,
			socks_port: None,
			hidden_services,
		})
	}

	pub fn socks_port(&self) -> u16 {
		self.inner.socks_port.expect("socks port not assigned yet; is tor running?")
	}

	pub fn socks_address(&self) -> String {
		format!("socks5h://127.0.0.1:{}", self.socks_port())
	}

	pub fn onion_address(&self, name: &str) -> &str {
		self.inner.hidden_services
			.iter()
			.find(|hs| hs.name == name)
			.unwrap_or_else(|| panic!("no hidden service named '{}'", name))
			.onion_address
			.as_deref()
			.expect("onion address not available yet; is tor running?")
	}
}

#[async_trait]
impl DaemonHelper for TorHelper {
	fn name(&self) -> &str {
		&self.name
	}

	fn datadir(&self) -> PathBuf {
		self.config.datadir.clone()
	}

	async fn make_reservations(&mut self) -> anyhow::Result<()> {
		self.socks_port = Some(portpicker::pick_unused_port().expect("free port available"));
		Ok(())
	}

	async fn prepare(&self) -> anyhow::Result<()> {
		debug!("Creating tor datadir in {:?}", self.config.datadir);
		create_dir_all(&self.config.datadir)?;

		let data_dir = self.config.datadir.join("data");
		create_dir_all(&data_dir)?;

		// Build torrc
		let mut torrc = format!(
			"SocksPort {}\n\
			 DataDirectory {}\n\
			 Log notice file {}\n",
			self.socks_port.expect("port reserved"),
			data_dir.display(),
			self.config.datadir.join("tor.log").display(),
		);

		for service in &self.hidden_services {
			let service_dir = self.config.datadir.join(format!("hs_{}", service.name));
			create_dir_all(&service_dir)?;
			// Tor requires hidden service directories to have mode 0700 on unix
			#[cfg(unix)]
			{
				use std::fs::{set_permissions, Permissions};
				use std::os::unix::fs::PermissionsExt;

				set_permissions(&service_dir, Permissions::from_mode(0o700))?;
			}
			torrc.push_str(&format!(
				"HiddenServiceDir {}\n\
				 HiddenServicePort {} 127.0.0.1:{}\n",
				service_dir.display(),
				service.virtual_port,
				service.target_port,
			));
		}

		write(self.config.datadir.join("torrc"), &torrc)?;
		Ok(())
	}

	async fn get_command(&self) -> anyhow::Result<Command> {
		let mut cmd = Command::new(&self.exec);
		cmd.arg("-f").arg(self.config.datadir.join("torrc"));
		Ok(cmd)
	}

	async fn wait_for_init(&self) -> anyhow::Result<()> {
		// Tor is ready once all hidden service hostname files are written
		for service in &self.hidden_services {
			let hostname_path = self.config.datadir
				.join(format!("hs_{}", service.name))
				.join("hostname");

			loop {
				if let Ok(contents) = read_to_string(&hostname_path).await {
					let addr = contents.trim().to_string();
					if !addr.is_empty() {
						info!("Tor hidden service '{}' available at {}", service.name, addr);
						break;
					}
				}
				sleep(Duration::from_millis(500)).await;
			}
		}

		let log_path = self.config.datadir.join("tor.log");
		loop {
			if let Ok(contents) = read_to_string(&log_path).await {
				if contents.contains("Bootstrapped 100%") {
					info!("Tor fully bootstrapped");
					break;
				}
			}
			sleep(Duration::from_millis(500)).await;
		}

		Ok(())
	}

	async fn post_start(
		&mut self,
		_log_handler_tx: &Sender<Box<dyn super::LogHandler>>,
	) -> anyhow::Result<()> {
		// Read all onion addresses now that tor is initialized.
		for service in &mut self.hidden_services {
			let hostname_path = self.config.datadir
				.join(format!("hs_{}", service.name))
				.join("hostname");

			let contents = read_to_string(&hostname_path).await?;
			service.onion_address = Some(contents.trim().to_string());
		}
		Ok(())
	}
}

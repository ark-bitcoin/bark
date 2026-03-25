use std::net::{IpAddr, SocketAddr};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
	pub port: u16,
	pub host: IpAddr,
	pub allowed_origins: Vec<String>,
}

impl Default for Config {
	fn default() -> Self {
		Self {
			port: 3000,
			host: "127.0.0.1".parse().expect("Invalid ip address"),
			allowed_origins: Vec::new(),
		}
	}
}

impl Config {
	pub fn socket_addr(&self) -> SocketAddr {
		SocketAddr::from((self.host, self.port))
	}
}
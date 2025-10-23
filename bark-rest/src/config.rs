use std::net::{IpAddr, SocketAddr};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
	pub port: u16,
	pub host: IpAddr,
}

impl Default for Config {
	fn default() -> Self {
		Self {
			port: 3000,
			host: "0.0.0.0".parse().expect("Invalid ip address"),
		}
	}
}

impl Config {
	pub fn socket_addr(&self) -> SocketAddr {
		SocketAddr::from((self.host, self.port))
	}
}
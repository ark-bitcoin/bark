use std::net::{IpAddr, SocketAddr};
use clap::Args;
use ipnet::IpNet;
use log::trace;
use serde::Deserialize;
use trust_dns_resolver::TokioAsyncResolver;

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq, Args)]
pub struct Filters {
	#[arg(long, num_args = 0..)]
	#[serde(default)]
	ip: Vec<String>,
	#[arg(long, num_args = 0..)]
	#[serde(default)]
	dns: Vec<String>,
}

impl Filters {
	pub fn new() -> Filters {
		Filters {
			ip: Vec::new(),
			dns: Vec::new(),
		}
	}

	pub fn init(ip: Vec<String>, dns: Vec<String>) -> Filters {
		Filters { ip, dns }
	}

	pub fn dns(&self) -> &[String] {
		&self.dns
	}

	pub fn ip(&self) -> &[String] {
		&self.ip
	}

	pub fn is_empty(&self) -> bool {
		self.ip.is_empty() && self.dns.is_empty()
	}

	pub async fn allowed(
		&self,
		resolver: &TokioAsyncResolver,
		addr: &SocketAddr,
	) -> bool {
		let ip = addr.ip();
		trace!("Filters check for allowing {:?}", addr);

		for entry in &self.ip {
			if let Ok(net) = entry.parse::<IpNet>() {
				if net.contains(&ip) {
					trace!("Filters check allowed via IP network {:?}", net);
					return true;
				}

				continue;
			}

			if let Ok(single) = entry.parse::<IpAddr>() {
				if single == ip {
					trace!("Filters check allowed via IP {:?}", single);
					return true;
				}
			}
		}

		for host in &self.dns {
			if let Ok(lookup) = resolver.lookup_ip(host).await {
				if lookup.iter().any(|resolved| resolved == ip) {
					trace!("Filters check allowed via dns {:?}", host);
					return true;
				}
			}
		}

		false
	}
}

use std::net::{IpAddr, SocketAddr};

use clap::Args;
use ipnet::IpNet;
use tracing::trace;
use hickory_resolver::TokioResolver;
use hickory_resolver::config::ResolverConfig;
use hickory_resolver::net::runtime::TokioRuntimeProvider;

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

	/// Refuses `client` unless it passes these filters. Empty filters allow
	/// any client, also one whose address is unknown.
	pub async fn check_client(&self, client: Option<SocketAddr>) -> anyhow::Result<()> {
		if self.is_empty() {
			return Ok(());
		}
		let Some(client) = client else {
			return badarg!("client's address cannot be found");
		};
		let resolver = TokioResolver::builder_with_config(
			ResolverConfig::default(),
			TokioRuntimeProvider::default(),
		).build()?;
		if !self.allowed(&resolver, &client).await {
			return badarg!("client's address is not allowed");
		}
		Ok(())
	}

	pub async fn allowed(
		&self,
		resolver: &TokioResolver,
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

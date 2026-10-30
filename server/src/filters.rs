use std::net::{IpAddr, SocketAddr};
use std::sync::OnceLock;

use clap::Args;
use ipnet::IpNet;
use tracing::trace;
use hickory_resolver::TokioResolver;

/// A resolver using the system's DNS configuration, for the DNS filters.
///
/// Shared so its cache of lookups, which honours their TTLs, outlives a
/// request. A failure to build it is retried on the next call.
pub fn system_resolver() -> anyhow::Result<&'static TokioResolver> {
	static RESOLVER: OnceLock<TokioResolver> = OnceLock::new();
	if let Some(resolver) = RESOLVER.get() {
		return Ok(resolver);
	}
	let resolver = TokioResolver::builder_tokio()?.build()?;
	Ok(RESOLVER.get_or_init(|| resolver))
}

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
		if !self.allowed(system_resolver()?, &client).await {
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


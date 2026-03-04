use std::net::IpAddr;

use anyhow::Context;
use http::Uri;

/// Returns the proxy URL only if the target is non-local.
/// Localhost addresses (127.0.0.0/8, ::1, 0.0.0.0) bypass the proxy.
pub(crate) fn proxy_for_url(
	proxy: &Option<String>,
	url: &str,
) -> anyhow::Result<Option<String>> {
	let proxy = match proxy.as_ref() {
		Some(p) => p,
		None => return Ok(None),
	};

	let uri = url.parse::<Uri>().context("invalid URL")?;
	if let Some(host) = uri.host() {
		if is_local(host) {
			return Ok(None);
		}
	}
	// Validate the proxy URL is socks5h before returning successfully.
	let proxy_uri : Uri = proxy.parse().context("invalid proxy url")?;
	if proxy_uri.scheme_str() != Some("socks5h") {
		bail!("socks5-proxy must use socks5h");
	}
	Ok(Some(proxy.clone()))
}

fn is_local(host: &str) -> bool {
	if host == "localhost" {
		return true;
	}
	// Uri::host() keeps brackets around IPv6 addresses, strip them.
	let host = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')).unwrap_or(host);
	if let Ok(ip) = host.parse::<IpAddr>() {
		return ip.is_loopback() || ip.is_unspecified();
	}
	false
}

#[cfg(test)]
mod test {
	use super::*;

	const PROXY: &str = "socks5h://127.0.0.1:9050";

	fn proxy_some() -> Option<String> {
		Some(PROXY.to_string())
	}

	#[test]
	fn no_proxy_configured() {
		assert_eq!(proxy_for_url(&None, "http://example.com:3535").unwrap(), None);
	}

	#[test]
	fn remote_host() {
		assert_eq!(
			proxy_for_url(&proxy_some(), "http://example.com:3535").unwrap(),
			Some(PROXY.to_string()),
		);
	}

	#[test]
	fn onion_address() {
		assert_eq!(
			proxy_for_url(&proxy_some(), "http://abc.onion:3535").unwrap(),
			Some(PROXY.to_string()),
		);
	}

	#[test]
	fn localhost_127_0_0_1() {
		assert_eq!(proxy_for_url(&proxy_some(), "http://127.0.0.1:18443").unwrap(), None);
	}

	#[test]
	fn localhost_127_x_y_z() {
		assert_eq!(proxy_for_url(&proxy_some(), "http://127.0.0.2:18443").unwrap(), None);
	}

	#[test]
	fn localhost_name() {
		assert_eq!(proxy_for_url(&proxy_some(), "http://localhost:3535").unwrap(), None);
	}

	#[test]
	fn localhost_ipv6() {
		assert_eq!(proxy_for_url(&proxy_some(), "http://[::1]:3535").unwrap(), None);
	}

	#[test]
	fn localhost_0_0_0_0() {
		assert_eq!(proxy_for_url(&proxy_some(), "http://0.0.0.0:3535").unwrap(), None);
	}

	#[test]
	fn unparseable_url_is_error() {
		assert!(proxy_for_url(&proxy_some(), "not a url").is_err());
	}

	#[test]
	fn unparseable_url_without_proxy_is_ok() {
		assert_eq!(proxy_for_url(&None, "not a url").unwrap(), None);
	}
}

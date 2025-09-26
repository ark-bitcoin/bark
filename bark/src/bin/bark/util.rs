
use std::io::{self, Write};
use std::str::FromStr;

use anyhow::Context;
use serde::Serialize;
use serde_json;
use tonic::transport::Uri;

/// Parse the URL and add `https` scheme if no scheme is given.
pub fn https_default_scheme(url: String) -> anyhow::Result<String> {
	// default scheme to https if unset
	let mut uri_parts = Uri::from_str(&url).context("invalid url")?.into_parts();
	if uri_parts.authority.is_none() {
		bail!("invalid url '{}': missing authority", url);
	}
	if uri_parts.scheme.is_none() {
		uri_parts.scheme = Some("https".parse().unwrap());
		// because from_parts errors for missing PathAndQuery, set it
		uri_parts.path_and_query = Some(uri_parts.path_and_query
			.unwrap_or_else(|| "".parse().unwrap())
		);
		let new = Uri::from_parts(uri_parts).unwrap();
		Ok(new.to_string())
	} else {
		Ok(url)
	}
}

/// Writes a [`Serializable`] value to stdout
pub fn output_json<T>(value: &T)
where
	T: ?Sized + Serialize,
{
	serde_json::to_writer_pretty(io::stdout(), value).expect("value is serializable");
	write!(io::stdout(), "\n").expect("Failed to write newline to stdout");
}

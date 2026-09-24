//! Nostr Wallet Connect (NIP-47) protocol and transport.
//!
//! Lets a third-party app drive a wallet through a nostr relay. The wallet
//! dials out to the relay and listens there, so it needs no inbound port, no
//! TLS of its own, and works behind NAT.
//!
//! The protocol wire format, the NIP-44 encryption and the event signing all
//! come from the [nostr] crate. What lives here is everything above that which
//! is not specific to any one wallet: what a connection is, what it is allowed
//! to do, and the service that carries requests to and from a relay.
//!
//! Nothing here knows how to answer a request. A host supplies that by
//! implementing [handler::RequestHandler], which is the only seam between this
//! crate and a wallet; bark does so in its own `nwc` module.
//!
//! Note that [nostr] carries its own secp256k1 and bitcoin_hashes versions,
//! which do not match the ones bark uses. Keys therefore cross between the two
//! as raw bytes. This costs nothing in practice, because NWC connection keys
//! are deliberately unrelated to wallet keys.

pub mod amount;
pub mod connection;
pub mod persist;

pub use self::connection::{Connection, ConnectionStore};
pub use self::persist::ConnectionPersister;

/// Parse the configured relay urls.
///
/// Done up front so a typo fails when NWC is registered, rather than leaving
/// the wallet serving on fewer relays than asked for, which looks like the
/// feature working.
pub fn parse_relays(relays: &[String]) -> anyhow::Result<Vec<nostr::types::RelayUrl>> {
	use anyhow::Context;

	relays.iter()
		.map(|r| nostr::types::RelayUrl::parse(r)
			.with_context(|| format!("invalid NWC relay url: {r}")))
		.collect()
}


#[cfg(test)]
mod relay_test {
	use super::parse_relays;

	/// No relays means NWC is off, which is the default.
	#[test]
	fn no_relays_parses_to_nothing() {
		assert!(parse_relays(&[]).unwrap().is_empty());
	}

	#[test]
	fn relay_urls_are_parsed() {
		let relays = parse_relays(&[
			"wss://relay.example.com".to_string(),
			"ws://127.0.0.1:7000".to_string(),
		]).unwrap();
		assert_eq!(relays.len(), 2);
	}

	/// A typo has to fail when NWC is registered. Silently serving on fewer
	/// relays than asked for would look like the feature working.
	#[test]
	fn an_invalid_relay_url_is_rejected() {
		let err = parse_relays(&["not a url".to_string()]).unwrap_err();
		assert!(err.to_string().contains("invalid NWC relay url"), "{err:#}");
	}
}

#[cfg(test)]
mod test {
	use std::str::FromStr;

	use nostr::key::{Keys, PublicKey, SecretKey};
	use nostr::nips::nip44::{self, Version};
	use nostr::nips::nip47::{Method, NostrWalletConnectUri, Request, RequestParams};
	use nostr::types::RelayUrl;

	/// Assert that the pieces we depend on from the nostr crate behave the way
	/// the wallet service needs: a connection URI round-trips, and a request
	/// encrypted by a client decrypts to the same request on the wallet side.
	#[test]
	fn nip47_request_survives_a_nip44_round_trip() {
		let wallet = Keys::generate();
		let client = Keys::generate();

		let uri = NostrWalletConnectUri::new(
			wallet.public_key(),
			vec![RelayUrl::parse("wss://relay.example.com").unwrap()],
			client.secret_key().clone(),
			None,
		);
		let parsed = NostrWalletConnectUri::from_str(&uri.to_string()).unwrap();
		assert_eq!(parsed.public_key, wallet.public_key());
		assert_eq!(parsed.secret, *client.secret_key());

		let request = Request {
			method: Method::GetBalance,
			params: RequestParams::GetBalance,
		};

		// The client encrypts to the wallet service pubkey, and the wallet
		// decrypts using the client pubkey it has on file for the connection.
		let ciphertext = nip44::encrypt(
			client.secret_key(), &wallet.public_key(), request.as_json(), Version::V2,
		).unwrap();
		let plaintext = nip44::decrypt(
			wallet.secret_key(), &client.public_key(), &ciphertext,
		).unwrap();

		assert_eq!(Request::from_json(&plaintext).unwrap(), request);
	}

	/// Keys cross between nostr and bark as raw bytes, so confirm that a
	/// secret key survives the trip.
	#[test]
	fn keys_round_trip_through_raw_bytes() {
		let keys = Keys::generate();

		let secret_bytes = keys.secret_key().to_secret_bytes();
		let restored = SecretKey::from_slice(&secret_bytes).unwrap();
		assert_eq!(restored, *keys.secret_key());

		let public_bytes = keys.public_key().to_bytes();
		assert_eq!(PublicKey::from_slice(&public_bytes).unwrap(), keys.public_key());
	}
}

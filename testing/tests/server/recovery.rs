use std::time::Duration;

use bitcoin::NetworkKind;
use bitcoin::bip32::{Xpriv, Xpub};
use bitcoin::secp256k1::{Keypair, PublicKey};

use ark::{ProtocolEncoding, SECP};
use ark::recovery::XpubRecoveryAuthorization;
use server_rpc::protos;

use ark_testing::TestContext;

fn dummy_xpriv(network: NetworkKind) -> Xpriv {
	Xpriv::new_master(network, &[42u8; 32]).unwrap()
}

fn auth(xpriv: &Xpriv, server_pubkey: PublicKey) -> Vec<u8> {
	let expiry = chrono::Local::now() + Duration::from_secs(60);
	XpubRecoveryAuthorization::new(xpriv, server_pubkey, expiry).serialize()
}

fn xpub_request(
	xpriv: &Xpriv,
	server_pubkey: PublicKey,
	start_index: u32,
) -> protos::RecoverVtxosByXpubRequest {
	protos::RecoverVtxosByXpubRequest {
		xpub: Xpub::from_priv(&SECP, xpriv).encode().to_vec(),
		start_index,
		authorization: auth(xpriv, server_pubkey),
	}
}

/// The server scans exactly the configured number of keys from the requested
/// start index, cut short at the last non-hardened index.
#[tokio::test]
async fn recover_vtxos_by_xpub_scans_configured_keys() {
	let ctx = TestContext::new("server/recover_vtxos_by_xpub_scans_configured_keys").await;
	let srv = ctx.captaind("server").cfg(|c| c.recovery_xpub_nb_keys = 1_000).create().await;
	let server_pubkey = srv.ark_info().await.server_pubkey;
	let mut client = srv.get_public_rpc().await;
	let xpriv = dummy_xpriv(NetworkKind::Test);

	let resp = client.recover_vtxos_by_xpub(xpub_request(&xpriv, server_pubkey, 0)).await
		.expect("a valid xpub is accepted").into_inner();
	assert!(resp.vtxos.is_empty());
	assert_eq!(resp.nb_keys_scanned, 1_000);
	assert!(!resp.have_more, "nothing found, so nothing more to look for");

	let resp = client.recover_vtxos_by_xpub(xpub_request(&xpriv, server_pubkey, 5_000)).await
		.expect("a start index is accepted").into_inner();
	assert_eq!(resp.nb_keys_scanned, 1_000);

	let last_range = (1 << 31) - 400;
	let resp = client.recover_vtxos_by_xpub(xpub_request(&xpriv, server_pubkey, last_range)).await
		.expect("a start index near the end is accepted").into_inner();
	assert_eq!(resp.nb_keys_scanned, 400);
}

/// An xpub without any VTXOs costs the server a single chunk of keys.
#[tokio::test]
async fn recover_vtxos_by_xpub_stops_after_an_empty_chunk() {
	let ctx = TestContext::new("server/recover_vtxos_by_xpub_stops_after_an_empty_chunk").await;
	let srv = ctx.captaind("server").cfg(|c| c.recovery_xpub_nb_keys = 100_000).create().await;
	let server_pubkey = srv.ark_info().await.server_pubkey;
	let mut client = srv.get_public_rpc().await;
	let xpriv = dummy_xpriv(NetworkKind::Test);

	let resp = client.recover_vtxos_by_xpub(xpub_request(&xpriv, server_pubkey, 0)).await
		.expect("a valid xpub is accepted").into_inner();
	assert!(resp.vtxos.is_empty());
	assert_eq!(resp.nb_keys_scanned, server_rpc::RECOVERY_XPUB_CHUNK_SIZE);
	assert!(!resp.have_more);
}

#[tokio::test]
async fn recover_vtxos_by_xpub_rejects_bad_requests() {
	let ctx = TestContext::new("server/recover_vtxos_by_xpub_rejects_bad_requests").await;
	let srv = ctx.captaind("server").cfg(|c| c.recovery_xpub_nb_keys = 1_000).create().await;
	let server_pubkey = srv.ark_info().await.server_pubkey;
	let mut client = srv.get_public_rpc().await;
	let xpriv = dummy_xpriv(NetworkKind::Test);

	let err = client.recover_vtxos_by_xpub(protos::RecoverVtxosByXpubRequest {
		xpub: vec![1, 2, 3],
		..xpub_request(&xpriv, server_pubkey, 0)
	}).await.expect_err("garbage is not an xpub");
	assert_eq!(err.code(), tonic::Code::InvalidArgument, "{err:?}");

	let mainnet = dummy_xpriv(NetworkKind::Main);
	let err = client.recover_vtxos_by_xpub(xpub_request(&mainnet, server_pubkey, 0)).await
		.expect_err("a mainnet xpub is refused on regtest");
	assert_eq!(err.code(), tonic::Code::InvalidArgument, "{err:?}");

	let err = client.recover_vtxos_by_xpub(xpub_request(&xpriv, server_pubkey, 1 << 31)).await
		.expect_err("hardened indices can't be derived from an xpub");
	assert_eq!(err.code(), tonic::Code::InvalidArgument, "{err:?}");

	let err = client.recover_vtxos_by_xpub(protos::RecoverVtxosByXpubRequest {
		authorization: vec![],
		..xpub_request(&xpriv, server_pubkey, 0)
	}).await.expect_err("an authorization is required");
	assert_eq!(err.code(), tonic::Code::InvalidArgument, "{err:?}");

	let other = Xpriv::new_master(NetworkKind::Test, &[43u8; 32]).unwrap();
	let err = client.recover_vtxos_by_xpub(protos::RecoverVtxosByXpubRequest {
		authorization: auth(&other, server_pubkey),
		..xpub_request(&xpriv, server_pubkey, 0)
	}).await.expect_err("the authorization must be signed by the xpub");
	assert_eq!(err.code(), tonic::Code::InvalidArgument, "{err:?}");

	let other_server = Keypair::from_seckey_slice(&SECP, &[7u8; 32]).unwrap().public_key();
	let err = client.recover_vtxos_by_xpub(xpub_request(&xpriv, other_server, 0)).await
		.expect_err("the authorization must be for this server");
	assert_eq!(err.code(), tonic::Code::InvalidArgument, "{err:?}");

	let expired = XpubRecoveryAuthorization::new(&xpriv, server_pubkey,
		chrono::Local::now() - Duration::from_secs(60));
	let err = client.recover_vtxos_by_xpub(protos::RecoverVtxosByXpubRequest {
		authorization: expired.serialize(),
		..xpub_request(&xpriv, server_pubkey, 0)
	}).await.expect_err("an expired authorization is refused");
	assert_eq!(err.code(), tonic::Code::InvalidArgument, "{err:?}");

	client.recover_vtxos_by_xpub(xpub_request(&xpriv, server_pubkey, 0)).await
		.expect("a valid request is accepted");
}

#[tokio::test]
async fn recover_vtxos_by_xpub_disabled() {
	let ctx = TestContext::new("server/recover_vtxos_by_xpub_disabled").await;
	let srv = ctx.captaind("server").cfg(|c| c.recovery_xpub_nb_keys = 0).create().await;
	let server_pubkey = srv.ark_info().await.server_pubkey;
	let mut client = srv.get_public_rpc().await;

	let req = xpub_request(&dummy_xpriv(NetworkKind::Test), server_pubkey, 0);
	let err = client.recover_vtxos_by_xpub(req).await.expect_err("the rpc is disabled");
	assert_eq!(err.code(), tonic::Code::Unimplemented, "{err:?}");
}

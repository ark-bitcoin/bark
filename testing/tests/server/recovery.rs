use std::collections::HashSet;
use std::time::Duration;

use bitcoin::{Amount, NetworkKind};
use bitcoin::bip32::{Xpriv, Xpub};
use bitcoin::secp256k1::{Keypair, PublicKey};

use ark::{ProtocolEncoding, ServerVtxo, Vtxo, VtxoId, SECP};
use ark::recovery::XpubRecoveryAuthorization;
use ark::test_util::dummy::DummyTestVtxoSpec;
use ark::vtxo::Full;
use server::database::Db;
use server::recovery::{MAX_RECOVERY_RESPONSE_VTXO_BYTES, RECOVERY_VTXO_PAGE_SIZE};
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
		cursor_vtxo_id: None,
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

/// A key that owns more VTXOs than fit in one response is split over several
/// calls, each one continuing after the cursor_vtxo_id of the previous one,
/// until the scan moves on to the next keys.
#[tokio::test]
async fn recover_vtxos_by_xpub_splits_a_key_over_several_calls() {
	let ctx = TestContext::new("server/recover_vtxos_by_xpub_splits_a_key_over_several_calls").await;
	let srv = ctx.captaind("server").cfg(|c| c.recovery_xpub_nb_keys = 1_000).create().await;
	let server_pubkey = srv.ark_info().await.server_pubkey;
	let mut client = srv.get_public_rpc().await;
	let xpriv = dummy_xpriv(NetworkKind::Test);

	let keypair = |idx: u32| xpriv.derive_priv(&SECP, &[idx.into()]).unwrap().to_keypair(&SECP);
	let build = |user_keypair: Keypair, i: usize| DummyTestVtxoSpec {
		amount: Amount::ONE_BTC + Amount::from_sat(i as u64),
		user_keypair,
		..Default::default()
	}.build().1;

	// Key 0 owns enough VTXOs to fill more than two responses, each of them
	// read in several database pages, and key 2 owns a few more.
	let mut key0 = Vec::new();
	let mut key0_bytes = 0;
	while key0_bytes <= 2 * MAX_RECOVERY_RESPONSE_VTXO_BYTES {
		let vtxo = build(keypair(0), key0.len());
		key0_bytes += vtxo.serialize().len();
		key0.push(vtxo);
	}
	assert!(key0.len() > 2 * RECOVERY_VTXO_PAGE_SIZE);
	let key2 = (0..3).map(|i| build(keypair(2), i)).collect::<Vec<_>>();

	let db = Db::connect(&srv.config().postgres).await.expect("connect to captaind's postgres");
	for batch in key0.chunks(RECOVERY_VTXO_PAGE_SIZE).chain([&key2[..]]) {
		db.write(async |t| t.upsert_vtxos(batch.iter().map(|v| ServerVtxo::from(v.clone()))).await)
			.await.expect("upsert vtxos");
	}

	let mut returned = Vec::<(u32, VtxoId)>::new();
	let mut nb_splits = 0;
	let mut nb_calls = 0;
	let mut start_index = 0;
	let mut cursor_vtxo_id = None;
	loop {
		assert!(nb_calls < 10, "the scan should end after a handful of calls");
		nb_calls += 1;
		let resp = client.recover_vtxos_by_xpub(protos::RecoverVtxosByXpubRequest {
			cursor_vtxo_id: cursor_vtxo_id.clone(),
			..xpub_request(&xpriv, server_pubkey, start_index)
		}).await.expect("a valid request is accepted").into_inner();

		let nb_bytes = resp.vtxos.iter().map(|v| v.vtxo.len()).sum::<usize>();
		assert!(nb_bytes <= MAX_RECOVERY_RESPONSE_VTXO_BYTES, "response holds {nb_bytes} bytes of vtxos");
		returned.extend(resp.vtxos.iter().map(|v| {
			(v.derivation_index, Vtxo::<Full>::deserialize(&v.vtxo).unwrap().id())
		}));

		start_index += resp.nb_keys_scanned;
		if let Some(ref cursor) = resp.cursor_vtxo_id {
			assert_eq!(start_index, 0, "only key 0 has too many vtxos for one response");
			assert_eq!(Some(cursor), returned.last().map(|(_, id)| id.to_bytes().to_vec()).as_ref(),
				"the cursor is the last vtxo returned",
			);
			nb_splits += 1;
		}
		cursor_vtxo_id = resp.cursor_vtxo_id;
		if !resp.have_more {
			break;
		}
	}
	assert_eq!(nb_splits, 2, "key 0 fills two responses and ends in the third");

	assert!(returned.is_sorted_by_key(|(idx, _)| *idx), "keys are returned in derivation order");
	let unique = returned.iter().copied().collect::<HashSet<_>>();
	assert_eq!(unique.len(), returned.len(), "no vtxo is returned twice");
	let expected = key0.iter().map(|v| (0, v.id()))
		.chain(key2.iter().map(|v| (2, v.id())))
		.collect::<HashSet<_>>();
	assert_eq!(unique, expected);
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

	let err = client.recover_vtxos_by_xpub(protos::RecoverVtxosByXpubRequest {
		cursor_vtxo_id: Some(vec![1, 2, 3]),
		..xpub_request(&xpriv, server_pubkey, 0)
	}).await.expect_err("garbage is not a vtxo id");
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

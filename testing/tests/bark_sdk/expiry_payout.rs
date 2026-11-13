use bitcoin::Network;
use bitcoin::secp256k1::{Keypair, PublicKey};

use ark::{ProtocolEncoding, SECP};
use ark::address::VtxoDelivery;
use ark::attestations::{LightningReceiveClaimAttestation, VtxoStatusAttestation};
use ark::lightning::PaymentHash;
use ark::mailbox::{BlindedMailboxIdentifier, MailboxIdentifier};
use bark::actions::lightning::receive::LightningReceiveState;
use bark::persist::BarkPersister;
use bark::persist::sqlite::SqliteClient;
use server::database::Db;
use server_rpc::protos;

use ark_testing::{btc, sat, TestContext};
use ark_testing::util::{poll_interval, FutureExt};

/// An application supplies the mailbox keypair. Its key routes delivery
/// and sets the payout script, and the wallet refuses to open without it.
#[tokio::test]
async fn expiry_payout_mailbox_keypair_is_checked_on_open() {
	let ctx = TestContext::new("bark_sdk/expiry_payout_mailbox_keypair_is_checked_on_open").await;
	let srv = ctx.captaind("server").cfg(|cfg| cfg.expiry_payouts = true).create().await;
	let mnemonic = bip39::Mnemonic::generate(12).unwrap();
	let key = Keypair::from_seckey_slice(&SECP, &[41; 32]).unwrap();
	let wallet = ctx.bark_sdk("external", &srv).mnemonic(mnemonic.clone())
		.external_mailbox_keypair(key).cfg(|c| c.daemon_manual_sync = true).create().await;
	wallet.stop_daemon_wait().await.unwrap();
	assert_eq!(wallet.mailbox_identifier().as_pubkey(), key.public_key());
	assert_eq!(wallet.payout_script(), ark::expiry_payout::payout_script(key.public_key()));
	let address = wallet.new_address().await.unwrap();
	let [VtxoDelivery::ServerMailbox { blinded_id }] = address.delivery() else {
		panic!("the address must have one server mailbox");
	};
	assert_eq!(MailboxIdentifier::from_blinded(*blinded_id, address.policy().user_pubkey(), &srv.mailbox_keypair())
		.unwrap(), wallet.mailbox_identifier());
	let properties = SqliteClient::open(ctx.datadir.join("external/db.sqlite")).unwrap()
		.read_properties().await.unwrap().unwrap();
	assert_eq!(properties.mailbox_pubkey, Some(key.public_key()));
	let sender = ctx.bark_sdk("sender", &srv).boarded(sat(100_000)).create().await;
	sender.send_arkoor_payment(&address, sat(10_000)).await.unwrap();
	wallet.sync().await;
	assert_eq!(wallet.balance().await.unwrap().spendable, sat(10_000));
	let config = wallet.config().clone();
	drop(wallet);

	let open = async |seed: bark::WalletSeed| bark::Wallet::open(Network::Regtest, seed, config.clone(),
		bark::OpenWalletArgs { datadir: Some(ctx.datadir.join("external")), run_daemon: false, ..Default::default() },
	).await;
	let seed = || bark::WalletSeed::new_from_mnemonic(Network::Regtest, &mnemonic);
	let other = Keypair::from_secret_key(&SECP, &key.secret_key().negate());
	for seed in [seed(), seed().with_mailbox_keypair(other)] {
		let error = open(seed).await.err().expect("a missing or other mailbox key is refused");
		assert!(error.to_string().contains("mailbox key"), "{error:#}");
	}
	let reopened = open(seed().with_mailbox_keypair(key)).await.unwrap();
	assert_eq!(reopened.payout_script(), ark::expiry_payout::payout_script(key.public_key()));
	assert_eq!(reopened.balance().await.unwrap().spendable, sat(10_000));
}

/// An address altered to bind the recipient's VTXO key to the payer's
/// mailbox is valid, and the server binds the VTXO to the payer. The
/// recipient refuses that VTXO, even when it recovers it by id.
#[tokio::test]
async fn expiry_payout_recipient_refuses_another_mailbox() {
	let ctx = TestContext::new("bark_sdk/expiry_payout_recipient_refuses_another_mailbox").await;
	let srv = ctx.captaind("server").cfg(|cfg| cfg.expiry_payouts = true).create().await;
	let sender = ctx.bark_sdk("sender", &srv).boarded(sat(400_000))
		.cfg(|cfg| cfg.daemon_manual_sync = true).create().await;
	let recipient = ctx.bark_sdk("recipient", &srv)
		.cfg(|cfg| cfg.daemon_manual_sync = true).create().await;
	sender.stop_daemon_wait().await.unwrap();
	recipient.stop_daemon_wait().await.unwrap();
	let address = recipient.new_address().await.unwrap();
	let [VtxoDelivery::ServerMailbox { blinded_id }] = address.delivery() else {
		panic!("the address must have one server mailbox");
	};
	let changed = PublicKey::combine_keys(&[
		&blinded_id.as_pubkey(), &sender.mailbox_identifier().as_pubkey(),
		&recipient.mailbox_identifier().as_pubkey().negate(&SECP),
	]).unwrap();
	let altered = ark::Address::new(address.is_testnet(), address.ark_id(), address.policy().clone(),
		vec![VtxoDelivery::ServerMailbox { blinded_id: BlindedMailboxIdentifier::from_pubkey(changed) }]);
	sender.send_arkoor_payment(&altered, sat(100_000)).await.unwrap();
	let db = Db::connect(&srv.config().postgres).await.unwrap();
	let [id] = db.read(async |t| t.get_vtxos_by_policy_page(address.policy(), None, 2).await).await.unwrap()
		.into_iter().map(|row| row.vtxo_id).collect::<Vec<_>>().try_into().unwrap();
	let (_, key) = recipient.pubkey_keypair(&address.policy().user_pubkey()).await.unwrap().unwrap();
	let status = srv.get_public_rpc().await.get_vtxo_status(protos::GetVtxoStatusRequest {
		vtxo_id: id.to_bytes().to_vec(),
		attestation: VtxoStatusAttestation::new(id, &key).serialize(),
	}).await.unwrap().into_inner();
	assert_eq!(status.owner_mailbox, sender.mailbox_identifier().serialize());
	recipient.sync_mailbox().await.unwrap();
	assert!(recipient.spendable_vtxos().await.unwrap().is_empty());
	let report = recipient.recover_vtxos([id], None).await.unwrap();
	assert!(report.recovered().is_empty(), "{report:?}");
	assert_eq!(report.foreign().ids().collect::<Vec<_>>(), [id]);
	let body = db.read(async |t| t.get_user_vtxos_by_id(&[id]).await).await.unwrap().remove(0).vtxo;
	recipient.import_vtxo(&body, Default::default()).await.expect_err("a VTXO of another mailbox is refused");
	assert!(recipient.spendable_vtxos().await.unwrap().is_empty());
}

/// A wallet that receives for itself binds the receive to its claim key.
/// No other key gets the grant, and the wallet claims it.
#[tokio::test]
async fn expiry_payout_receive_is_bound_to_the_claim_key() {
	let ctx = TestContext::new("bark_sdk/expiry_payout_receive_is_bound_to_the_claim_key").await;
	let lightning = ctx.new_lightning_setup("lightningd").await;
	let srv = ctx.captaind("server").lightningd(&lightning.internal).funded(btc(10))
		.cfg(|cfg| cfg.expiry_payouts = true).create().await;
	srv.wait_for_vtxopool(&ctx).await;
	let wallet = ctx.bark_sdk("wallet", &srv).cfg(|cfg| cfg.daemon_manual_sync = true).create().await;
	let invoice = wallet.bolt11_invoice(sat(50_000), None, None).await.unwrap();
	let hash = PaymentHash::from(&invoice);
	let db = Db::connect(&srv.config().postgres).await.unwrap();
	let sub = db.read(async |t| t.get_htlc_subscription_by_payment_hash(hash).await).await.unwrap().unwrap();
	let claim_key = sub.claim_pubkey.expect("the wallet binds its receive to a claim key");
	lightning.sync().await;
	let claim = async {
		let lowest = loop {
			let sub = db.read(async |t| t.get_htlc_subscription_by_payment_hash(hash).await).await.unwrap().unwrap();
			if let Some(lowest) = sub.lowest_incoming_htlc_expiry {
				break lowest;
			}
			tokio::time::sleep(poll_interval()).await;
		};
		let other = Keypair::from_seckey_slice(&SECP, &[75; 32]).unwrap();
		let expiry = lowest.saturating_sub(srv.config().htlc_expiry_delta);
		let refused = srv.get_public_rpc().await.prepare_lightning_receive_claim(protos::PrepareLightningReceiveClaimRequest {
			payment_hash: hash.to_vec(),
			user_pubkey: other.public_key().serialize().to_vec(),
			htlc_recv_expiry: expiry.into(),
			lightning_receive_anti_dos: None,
			claim_attestation: Some(LightningReceiveClaimAttestation::new(hash, expiry, &other).serialize()),
		}).await.expect_err("another key cannot take the grant");
		assert_eq!(refused.code(), tonic::Code::InvalidArgument);
		wallet.try_claim_lightning_receive(hash, true).await
	};
	let (paid, claimed) = async { tokio::join!(lightning.external.try_pay_bolt11(invoice.to_string()), claim) }
		.wait_millis(60_000).await;
	paid.unwrap();
	assert!(matches!(claimed.unwrap(), LightningReceiveState::Settled(_)));
	wallet.sync().await;
	assert!(wallet.spendable_vtxos().await.unwrap().iter().any(|vtxo| vtxo.user_pubkey() == claim_key));
}

/// A server in payout mode accepts only its protocol version. A wallet
/// that requires expiry payouts opens on it, and refuses to open on a
/// server without them.
#[tokio::test]
async fn expiry_payout_required_is_checked_on_open() {
	let ctx = TestContext::new("bark_sdk/expiry_payout_required_is_checked_on_open").await;
	let payout = ctx.captaind("payout").cfg(|cfg| cfg.expiry_payouts = true).create().await;
	let version = server_rpc::pver::PROTOCOL_VERSION_SCUTTLE_EXPIRY_PAYOUT;
	let handshake = payout.get_public_rpc().await
		.handshake(protos::HandshakeRequest { bark_version: None }).await.unwrap().into_inner();
	assert_eq!((handshake.min_protocol_version, handshake.max_protocol_version), (version, version));
	let connect = |url: String| async move {
		server_rpc::ServerConnection::builder().address(url).network(Network::Regtest).connect().await.unwrap()
	};
	assert!(connect(payout.ark_url()).await.expiry_payouts().await);

	// A client that uses an upstream version gets the upstream too-old error.
	let mut client = server_rpc::ArkServiceClient::connect(payout.ark_url()).await.unwrap();
	let mut request = tonic::Request::new(protos::Empty {});
	server_rpc::RequestExt::set_pver(&mut request, server_rpc::MAX_PROTOCOL_VERSION);
	let error = client.get_ark_info(request).await.expect_err("an upstream version is refused");
	assert_eq!(error.code(), tonic::Code::InvalidArgument);

	ctx.bark_sdk("required", &payout).cfg(|cfg| cfg.require_expiry_payouts = true).create().await
		.refresh_server().await.unwrap();
	let ordinary = ctx.captaind("ordinary").create().await;
	assert!(!connect(ordinary.ark_url()).await.expiry_payouts().await);
	let error = ctx.bark_sdk("refused", &ordinary).cfg(|cfg| cfg.require_expiry_payouts = true)
		.try_create().await.err().expect("a wallet that requires expiry payouts refuses an ordinary server");
	assert!(format!("{error:#}").contains("does not offer expiry payouts"), "{error:#}");
	ctx.bark_sdk("upstream", &ordinary).create().await;
}

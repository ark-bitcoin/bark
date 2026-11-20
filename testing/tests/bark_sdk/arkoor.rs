use std::future::Future;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use bitcoin::{Amount, SignedAmount};
use bitcoin::secp256k1::PublicKey;

use ark::{VtxoId, VtxoPolicy};
use ark::address::VtxoDelivery;
use bark::Wallet;
use bark::movement::MovementStatus;
use bark::vtxo::VtxoState;

use ark_testing::{TestContext, btc, sat};
use ark_testing::balance::assert_balance_consistent;
use ark_testing::daemon::captaind::{self, ArkClient};
use server_rpc::protos;

/// An address that lists no delivery mechanism this bark can use is refused
/// before the arkoor is built, so the sender keeps its funds.
#[tokio::test]
async fn send_to_unsupported_delivery_is_refused() {
	let ctx = TestContext::new("bark_sdk/send_to_unsupported_delivery_is_refused").await;
	let srv = ctx.captaind("server").create().await;

	let sender = ctx.bark_sdk("bark", &srv)
		.boarded(sat(400_000))
		.create().await;
	let receiver = ctx.bark_sdk("bark2", &srv).create().await;

	// Same server and policy as a payable address, but the only way it offers
	// to hand over the VTXO is a mechanism this bark doesn't know.
	let address = receiver.new_address().await.expect("new address");
	let address = ark::Address::new(
		address.is_testnet(),
		address.ark_id(),
		address.policy().clone(),
		vec![VtxoDelivery::Unknown { delivery_type: 0xff, data: vec![1, 2, 3] }],
	);

	let err = sender.send_arkoor_payment(&address, sat(100_000)).await
		.expect_err("send to an undeliverable address must fail");
	assert!(format!("{:#}", err).contains("Unknown delivery mechanism"), "err: {err:#}");

	// The send never started: no action is pending and no VTXO was spent.
	assert!(sender.pending_arkoor_sends().await.unwrap().is_empty());
	assert_eq!(assert_balance_consistent(&sender, false).await.spendable, sat(400_000));
}

/// An address that lists no delivery mechanism at all is the receiver's
/// choice to pick up the VTXO out-of-band: the payment succeeds and bark
/// never attempts a delivery.
#[tokio::test]
async fn send_to_address_without_delivery_succeeds() {
	let ctx = TestContext::new("bark_sdk/send_to_address_without_delivery_succeeds").await;
	let srv = ctx.captaind("server").create().await;

	let sender = ctx.bark_sdk("bark", &srv)
		.boarded(sat(400_000))
		.create().await;

	// A hard-coded recipient key on an address that opts out of delivery.
	let recipient_pubkey = PublicKey::from_str(
		"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
	).unwrap();
	let own = sender.new_address().await.expect("new address");
	let address = ark::Address::new(
		own.is_testnet(),
		own.ark_id(),
		VtxoPolicy::new_pubkey(recipient_pubkey),
		vec![],
	);

	sender.send_arkoor_payment(&address, sat(100_000)).await
		.expect("send to a delivery-less address must succeed");

	// The send ran to completion and only the change remains spendable.
	assert!(sender.pending_arkoor_sends().await.unwrap().is_empty());
	assert_eq!(assert_balance_consistent(&sender, false).await.spendable, sat(300_000));
}

/// Each arkoor send returns the movement that records it, also when two
/// payments have the same amount and destination.
#[tokio::test]
async fn send_returns_its_movement_id() {
	let ctx = TestContext::new("bark_sdk/send_returns_its_movement_id").await;
	let srv = ctx.captaind("server").create().await;

	let sender = ctx.bark_sdk("bark", &srv)
		.boarded(sat(400_000))
		.create().await;
	let receiver = ctx.bark_sdk("bark2", &srv).create().await;

	let address = receiver.new_address().await.expect("new address");
	let first = sender.send_arkoor_payment(&address, sat(10_000)).await.expect("first send");
	let second = sender.send_arkoor_payment(&address, sat(10_000)).await.expect("second send");
	assert_ne!(first, second);

	let history = sender.history().await.expect("history");
	let mut arkoor_ids = history.iter()
		.filter(|m| m.subsystem.name == "bark.arkoor")
		.map(|m| m.id)
		.collect::<Vec<_>>();
	arkoor_ids.sort();
	assert_eq!(arkoor_ids, vec![first, second]);
	for id in [first, second] {
		let movement = history.iter().find(|m| m.id == id).unwrap();
		assert_eq!(movement.status, MovementStatus::Successful);
	}
}

/// Refuses VTXO registrations while set, as the server refuses a chain spending an exited input.
#[derive(Clone)]
struct RefuseRegistration(Arc<AtomicBool>);

#[async_trait::async_trait]
impl captaind::proxy::ArkRpcProxy for RefuseRegistration {
	async fn register_vtxo_transactions(
		&self, upstream: &mut ArkClient, req: protos::RegisterVtxoTransactionsRequest,
	) -> Result<protos::Empty, tonic::Status> {
		if self.0.load(Ordering::Relaxed) {
			return Err(tonic::Status::invalid_argument("proxy: registration refused"));
		}
		Ok(upstream.register_vtxo_transactions(req).await?.into_inner())
	}
}

/// Acknowledges VTXO registrations without forwarding them.
#[derive(Clone)]
struct DropRegistration;

#[async_trait::async_trait]
impl captaind::proxy::ArkRpcProxy for DropRegistration {
	async fn register_vtxo_transactions(
		&self, _upstream: &mut ArkClient, _req: protos::RegisterVtxoTransactionsRequest,
	) -> Result<protos::Empty, tonic::Status> {
		Ok(protos::Empty {})
	}
}

/// Syncs `wallet`, boxed so the large future stays out of the frame of the test.
fn sync(wallet: &Wallet) -> Pin<Box<dyn Future<Output = ()> + '_>> {
	Box::pin(wallet.sync())
}

/// Checks that `wallet` has a single pending receive of `amount`, its VTXO locked out of the
/// balance, and returns that VTXO.
async fn assert_receive_pending(wallet: &Wallet, amount: Amount) -> VtxoId {
	let [recv] = wallet.pending_arkoor_receives().await.unwrap().try_into().expect("one receive");
	let [vtxo] = recv.vtxos.try_into().expect("one received VTXO");
	let state = wallet.get_vtxo_by_id(vtxo.id()).await.unwrap().state;
	assert!(matches!(state, VtxoState::Locked { .. }), "state: {state:?}");
	assert_eq!(assert_balance_consistent(wallet, false).await.spendable, Amount::ZERO);
	let [movement] = wallet.history().await.unwrap().try_into().expect("one movement");
	assert_eq!(movement.status, MovementStatus::Pending);
	assert_eq!(movement.intended_balance, amount.to_signed().unwrap());
	vtxo.id()
}

/// A received arkoor the server refuses to register stays locked until the server registers it.
#[tokio::test]
async fn arkoor_receive_is_credited_once_registered() {
	let ctx = TestContext::new("bark_sdk/arkoor_receive_is_credited_once_registered").await;
	let srv = ctx.captaind("server").create().await;
	let refuse = Arc::new(AtomicBool::new(true));
	let proxy = srv.start_proxy_no_mailbox(RefuseRegistration(refuse.clone())).await;
	let sender = ctx.bark_sdk("sender", &srv).boarded(sat(400_000)).create().await;
	let receiver = ctx.bark_sdk("receiver", &proxy).create().await;
	receiver.stop_daemon_wait().await.expect("stop daemon");

	let address = receiver.new_address().await.expect("new address");
	sender.send_arkoor_payment(&address, sat(100_000)).await.expect("arkoor send");
	sync(&receiver).await;
	let vtxo = assert_receive_pending(&receiver, sat(100_000)).await;

	refuse.store(false, Ordering::Relaxed);
	sync(&receiver).await;
	assert!(receiver.pending_arkoor_receives().await.unwrap().is_empty());
	assert_eq!(receiver.get_vtxo_by_id(vtxo).await.unwrap().state, VtxoState::Spendable);
	assert_eq!(assert_balance_consistent(&receiver, false).await.spendable, sat(100_000));
	assert_eq!(receiver.history().await.unwrap()[0].status, MovementStatus::Successful);
}

/// A sender skips registration and exits its input on-chain, so the server refuses the received
/// VTXO. Once the sender claims its exit, the receiver marks the VTXO spent and the receive failed.
#[tokio::test]
async fn arkoor_receive_whose_input_exit_is_claimed_fails() {
	let ctx = TestContext::new("bark_sdk/arkoor_receive_whose_input_exit_is_claimed_fails").await;
	let srv = ctx.captaind("server").funded(btc(10)).no_vtxo_pool().watchmand().create().await;
	let receiver = ctx.bark_sdk("receiver", &srv).create().await;
	receiver.stop_daemon_wait().await.expect("stop daemon");
	let sender_proxy = srv.start_proxy_no_mailbox(DropRegistration).await;
	let sender = ctx.bark_sdk("sender", &sender_proxy).boarded(sat(200_000)).create().await;
	sender.stop_daemon_wait().await.expect("stop daemon");
	let [input] = sender.vtxos().await.unwrap().try_into().expect("one boarded VTXO");
	let input = sender.get_full_vtxo(input.id()).await.expect("full input VTXO");

	let address = receiver.new_address().await.expect("new address");
	sender.send_arkoor_payment(&address, sat(50_000)).await.expect("arkoor send");
	let tip = ctx.mine(&input.transactions().map(|item| item.tx).collect::<Vec<_>>()).await;
	srv.watchmand().wait_for_sync_height(tip).await;
	sync(&receiver).await;
	let vtxo = assert_receive_pending(&receiver, sat(50_000)).await;

	// The sender claims the exit of the input that the arkoor spent.
	sender.set_vtxo_states([input.id()], &VtxoState::Spendable, &[]).await.unwrap();
	sender.exit_mgr().start_exit_for_vtxos(&[input.to_bare()]).await.expect("start exit");
	let mut claimable = Vec::new();
	for _ in 0..(srv.config().vtxo_exit_delta.to_u32() * 2) {
		sender.progress_exits().await.expect("progress exits");
		claimable = sender.exit_mgr().list_claimable().await;
		if !claimable.is_empty() {
			break;
		}
		ctx.generate_blocks(1).await;
	}
	let claim = sender.exit_mgr()
		.drain_exits(&claimable, &sender, ctx.bitcoind().get_new_address(), None).await
		.expect("drain exits")
		.extract_tx().expect("claim tx");
	ctx.mine([&claim]).await;

	sync(&receiver).await;
	assert!(receiver.pending_arkoor_receives().await.unwrap().is_empty());
	assert_eq!(receiver.get_vtxo_by_id(vtxo).await.unwrap().state, VtxoState::Spent);
	assert_eq!(assert_balance_consistent(&receiver, false).await.spendable, Amount::ZERO);
	let [movement] = receiver.history().await.unwrap().try_into().expect("one movement");
	assert_eq!(movement.status, MovementStatus::Failed);
	assert_eq!(movement.effective_balance, SignedAmount::ZERO);
}

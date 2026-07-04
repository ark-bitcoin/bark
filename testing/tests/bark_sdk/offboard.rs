
use bitcoin::Amount;

use bark::movement::{Movement, MovementStatus, PaymentMethod};
use server_rpc::protos;

use ark_testing::{btc, sat, TestContext};
use ark_testing::daemon::captaind::{self, ArkClient};

/// Sends every prepare_offboard request to the server twice, like a
/// client that lost the first response and retries. The server must
/// replay the same session instead of rejecting the retry because
/// the vtxos are locked by the first request's session.
#[derive(Clone)]
struct ReplayPrepareOffboardProxy;

#[async_trait::async_trait]
impl captaind::proxy::ArkRpcProxy for ReplayPrepareOffboardProxy {
	async fn prepare_offboard(
		&self, upstream: &mut ArkClient, req: protos::PrepareOffboardRequest,
	) -> Result<protos::PrepareOffboardResponse, tonic::Status> {
		let first = upstream.prepare_offboard(req.clone()).await?.into_inner();
		let retry = upstream.prepare_offboard(req).await?.into_inner();
		if first != retry {
			return Err(tonic::Status::internal(format!(
				"prepare_offboard retry got a different response: {:?} vs {:?}",
				first, retry,
			)));
		}
		Ok(retry)
	}
}

/// The offboard movement of the given wallet.
async fn offboard_movement(wallet: &bark::Wallet) -> Movement {
	let movements = wallet.history().await.expect("list movements").into_iter()
		.filter(|m| m.subsystem.name == "bark.offboard" && m.subsystem.kind == "offboard")
		.collect::<Vec<_>>();
	assert_eq!(movements.len(), 1);
	movements[0].clone()
}

#[tokio::test]
async fn offboard_replays_identical_prepare_request() {
	const OFFBOARD_CONFIRMATIONS: u32 = 2;

	let ctx = TestContext::new("bark_sdk/offboard_replays_identical_prepare_request").await;
	let srv = ctx.captaind("server").funded(btc(10)).create().await;
	let proxy = srv.start_proxy_no_mailbox(ReplayPrepareOffboardProxy).await;

	let wallet = ctx.bark_sdk("bark", &proxy)
		.cfg(|c| c.offboard_required_confirmations = OFFBOARD_CONFIRMATIONS)
		.boarded(sat(800_000))
		.create().await;

	let address = ctx.bitcoind().get_new_address();
	wallet.offboard_all(address.clone()).await.expect("offboard should succeed");

	assert_eq!(wallet.balance().await.expect("balance").spendable, Amount::ZERO);

	// The offboard went through the replayed session; its movement stays
	// pending until the offboard tx confirms.
	assert_eq!(offboard_movement(&wallet).await.status, MovementStatus::Pending);

	// Confirm the offboard tx and sync so the movement settles.
	ctx.generate_blocks(OFFBOARD_CONFIRMATIONS).await;
	wallet.sync().await;

	let movement = offboard_movement(&wallet).await;
	assert_eq!(movement.status, MovementStatus::Successful);
	let sent = movement.sent_to.first().expect("offboard has a destination");
	assert_eq!(sent.destination, PaymentMethod::Bitcoin(address.clone().into_unchecked()));

	// And the destination address received the funds onchain.
	assert_eq!(ctx.bitcoind().get_received_by_address(&address), sent.amount);
}

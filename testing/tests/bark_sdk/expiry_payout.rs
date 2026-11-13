use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use bitcoin::{Amount, Network, ScriptBuf, SignedAmount, Transaction};
use bitcoin::secp256k1::{Keypair, PublicKey};
use bitcoin_ext::BlockDelta;
use bitcoin_ext::rpc::RpcApi;
use cln_rpc::plugins::hold;

use ark::{ProtocolEncoding, SECP};
use ark::address::VtxoDelivery;
use ark::attestations::{LightningReceiveClaimAttestation, VtxoStatusAttestation};
use ark::lightning::{PaymentHash, Preimage};
use ark::mailbox::{BlindedMailboxIdentifier, MailboxIdentifier};
use bark::Wallet;
use bark::actions::offboard;
use bark::actions::lightning::pay;
use bark::actions::lightning::receive::{self, LightningReceiveState};
use bark::exit::ExitState;
use bark::movement::{Movement, MovementStatus};
use bark::persist::BarkPersister;
use bark::persist::sqlite::SqliteClient;
use bark::vtxo::{ExpiryPayoutState, VtxoLockHolder, VtxoState};
use server::database::Db;
use server_rpc::protos;

use ark_testing::{btc, sat, Captaind, TestContext};
use ark_testing::constants::{BOARD_CONFIRMATIONS, ROUND_CONFIRMATIONS};
use ark_testing::daemon::captaind::{ArkClient, MailboxClient};
use ark_testing::daemon::captaind::proxy::{ArkRpcProxy, ArkRpcProxyServer, MailboxRpcProxy};
use ark_testing::util::{poll_interval, FutureExt};

// A wallet action that holds a VTXO the server pays out at expiry ends once
// the wallet sees that payout. The proxy refuses the request each action
// waits on, and reports the status a server gives once it paid out a VTXO.

#[derive(Clone, Default)]
struct PayoutProxy {
	/// Set once the server co-signed an arkoor or Lightning send.
	cosigned: Arc<AtomicBool>,
	/// Hold every registration after a co-sign until the request is dropped.
	hold_registration: Arc<AtomicBool>,
	held: Arc<tokio::sync::Notify>,
	/// Refuse every registration after a co-sign.
	refuse_registration: Arc<AtomicBool>,
	/// Simulate an input registration rejected by an expiry decision.
	decided_input_registration: Arc<AtomicBool>,
	/// Refuse a fresh Lightning co-sign as decided for payout.
	decided_lightning_cosign: Arc<AtomicBool>,
	/// Commit one Lightning co-sign but lose its reply, then refuse input registration.
	lose_lightning_cosign_reply_once: Arc<AtomicBool>,
	/// Keep the action at HTLC received while testing a recovered co-sign.
	stall_lightning_initiation: Arc<AtomicBool>,
	/// A round's forfeit was accepted; hold its subsequent output registration.
	forfeit_accepted: Arc<AtomicBool>,
	/// Refuse Lightning payments, revocations and receive claims.
	refuse_lightning: Arc<AtomicBool>,
	/// Refuse every round participation as spending a VTXO that is decided
	/// for an expiry payout.
	refuse_participation: Arc<AtomicBool>,
	/// Report every VTXO as paid out to `owner`.
	decide: Arc<AtomicBool>,
	/// Make the batch status request fail while recovery stages VTXOs.
	status_down: Arc<AtomicBool>,
	owner: Arc<Mutex<Vec<u8>>>,
	/// Report a spend state that the wallet does not know for a VTXO, or
	/// the owner mailbox given for it.
	bad_status: Arc<Mutex<HashMap<Vec<u8>, Option<Vec<u8>>>>>,
}

const PAYOUT: protos::ExpiryPayout = protos::ExpiryPayout {
	state: protos::ExpiryPayoutState::Paid as i32, gross_sat: 10_000, fee_sat: 2_000, payout_sat: 8_000,
};

fn refusal() -> tonic::Status {
	tonic::Status::invalid_argument("refused by the test proxy")
}

fn payout_decision_refusal() -> tonic::Status {
	let mut status = tonic::Status::invalid_argument("input is decided for an expiry payout");
	status.metadata_mut().insert("expiry-payout-reason", "decided_for_payout".parse().unwrap());
	status
}

#[async_trait::async_trait]
impl ArkRpcProxy for PayoutProxy {
	async fn request_arkoor_cosign(&self, upstream: &mut ArkClient, req: protos::ArkoorPackageCosignRequest)
		-> Result<protos::ArkoorPackageCosignResponse, tonic::Status>
	{
		let res = upstream.request_arkoor_cosign(req).await?.into_inner();
		self.cosigned.store(true, Ordering::SeqCst);
		Ok(res)
	}

	async fn request_lightning_pay_htlc_cosign(&self, upstream: &mut ArkClient, req: protos::LightningPayHtlcCosignRequest)
		-> Result<protos::ArkoorPackageCosignResponse, tonic::Status>
	{
		if self.decided_lightning_cosign.load(Ordering::SeqCst) {
			return Err(payout_decision_refusal());
		}
		let res = upstream.request_lightning_pay_htlc_cosign(req).await?.into_inner();
		self.cosigned.store(true, Ordering::SeqCst);
		if self.lose_lightning_cosign_reply_once.swap(false, Ordering::SeqCst) {
			self.decided_input_registration.store(true, Ordering::SeqCst);
			return Err(tonic::Status::unavailable("cosign reply lost"));
		}
		Ok(res)
	}

	async fn register_vtxo_transactions(&self, upstream: &mut ArkClient, req: protos::RegisterVtxoTransactionsRequest)
		-> Result<protos::Empty, tonic::Status>
	{
		if self.forfeit_accepted.load(Ordering::SeqCst) && self.hold_registration.load(Ordering::SeqCst) {
			self.held.notify_one();
			std::future::pending::<()>().await;
		}
		if self.decided_input_registration.load(Ordering::SeqCst) {
			return Err(payout_decision_refusal());
		}
		if self.cosigned.load(Ordering::SeqCst) {
			if self.hold_registration.load(Ordering::SeqCst) {
				self.held.notify_one();
				std::future::pending::<()>().await;
			}
			if self.refuse_registration.load(Ordering::SeqCst) {
				return Err(refusal());
			}
		}
		Ok(upstream.register_vtxo_transactions(req).await?.into_inner())
	}

	async fn forfeit_vtxos(&self, upstream: &mut ArkClient, req: protos::ForfeitVtxosRequest)
		-> Result<protos::ForfeitVtxosResponse, tonic::Status>
	{
		let response = upstream.forfeit_vtxos(req).await?.into_inner();
		self.forfeit_accepted.store(true, Ordering::SeqCst);
		Ok(response)
	}

	async fn initiate_lightning_payment(&self, upstream: &mut ArkClient, req: protos::InitiateLightningPaymentRequest)
		-> Result<protos::Empty, tonic::Status>
	{
		if self.stall_lightning_initiation.load(Ordering::SeqCst) {
			return Err(tonic::Status::unavailable("payment initiation deferred"));
		}
		if self.refuse_lightning.load(Ordering::SeqCst) {
			return Err(refusal());
		}
		Ok(upstream.initiate_lightning_payment(req).await?.into_inner())
	}

	async fn request_lightning_pay_htlc_revocation(&self, upstream: &mut ArkClient, req: protos::ArkoorPackageCosignRequest)
		-> Result<protos::ArkoorPackageCosignResponse, tonic::Status>
	{
		if self.refuse_lightning.load(Ordering::SeqCst) {
			return Err(refusal());
		}
		Ok(upstream.request_lightning_pay_htlc_revocation(req).await?.into_inner())
	}

	async fn claim_lightning_receive(&self, upstream: &mut ArkClient, req: protos::ClaimLightningReceiveRequest)
		-> Result<protos::ArkoorPackageCosignResponse, tonic::Status>
	{
		if self.refuse_lightning.load(Ordering::SeqCst) {
			return Err(refusal());
		}
		Ok(upstream.claim_lightning_receive(req).await?.into_inner())
	}

	async fn submit_round_participation(&self, upstream: &mut ArkClient, req: protos::RoundParticipationRequest)
		-> Result<protos::RoundParticipationResponse, tonic::Status>
	{
		if self.refuse_participation.load(Ordering::SeqCst) {
			let ids = req.input_vtxos.iter()
				.map(|input| ark::VtxoId::from_slice(&input.vtxo_id).unwrap().to_string())
				.collect::<Vec<_>>().join(",");
			let mut status = tonic::Status::invalid_argument("the input is decided for an expiry payout");
			status.metadata_mut().insert("identifiers", ids.parse().unwrap());
			return Err(status);
		}
		Ok(upstream.submit_round_participation(req).await?.into_inner())
	}

	async fn get_vtxo_status(&self, upstream: &mut ArkClient, req: protos::GetVtxoStatusRequest)
		-> Result<protos::GetVtxoStatusResponse, tonic::Status>
	{
		let mut res = upstream.get_vtxo_status(req).await?.into_inner();
		if self.decide.load(Ordering::SeqCst) {
			res.spend_state = protos::VtxoSpendState::Spent as i32;
			res.owner_mailbox = self.owner.lock().unwrap().clone();
			res.expiry_payout = Some(PAYOUT);
		}
		Ok(res)
	}

	async fn get_vtxos_status_by_ids(&self, upstream: &mut ArkClient, req: protos::GetVtxosStatusByIdsRequest)
		-> Result<protos::GetVtxosStatusByIdsResponse, tonic::Status>
	{
		if self.status_down.load(Ordering::SeqCst) {
			return Err(tonic::Status::unavailable("status down during recovery"));
		}
		let mut res = upstream.get_vtxos_status_by_ids(req).await?.into_inner();
		if self.decide.load(Ordering::SeqCst) {
			for status in &mut res.vtxos {
				status.spend_state = protos::VtxoSpendState::Spent as i32;
				status.owner_mailbox = self.owner.lock().unwrap().clone();
				status.expiry_payout = Some(PAYOUT);
			}
		}
		let bad_status = self.bad_status.lock().unwrap();
		for status in &mut res.vtxos {
			match bad_status.get(&status.vtxo_id) {
				Some(Some(owner)) => status.owner_mailbox = owner.clone(),
				Some(None) => status.spend_state = i32::MAX,
				None => {},
			}
		}
		Ok(res)
	}
}

impl PayoutProxy {
	/// Report every VTXO as paid out to `wallet`.
	fn decide_for(&self, wallet: &Wallet) {
		*self.owner.lock().unwrap() = wallet.mailbox_identifier().as_pubkey().serialize().to_vec();
		self.decide.store(true, Ordering::SeqCst);
	}
}

async fn payout_server(ctx: &TestContext) -> (Arc<Captaind>, PayoutProxy, ArkRpcProxyServer) {
	let srv = ctx.captaind("server").no_vtxo_pool().cfg(|cfg| {
		cfg.expiry_payouts = true;
		cfg.vtxo_lifetime = BlockDelta::new(24);
	}).create().await;
	let proxy = PayoutProxy::default();
	let server = srv.start_proxy_no_mailbox(proxy.clone()).await;
	(srv, proxy, server)
}

async fn movement(wallet: &Wallet, subsystem: &str) -> Movement {
	let mut movements = wallet.history().await.unwrap().into_iter()
		.filter(|m| m.subsystem.name == subsystem).collect::<Vec<_>>();
	assert_eq!(movements.len(), 1, "{movements:?}");
	movements.remove(0)
}

async fn mine_past(ctx: &TestContext, srv: &Captaind, wallet: &Wallet, height: bitcoin_ext::BlockHeight) {
	let tip = ctx.bitcoind().get_block_count().await as u32;
	let tip = ctx.generate_blocks(height.to_u32() + 1 - tip).await;
	srv.wait_for_sync_height(tip).await;
	wallet.chain().invalidate_caches().await;
}

/// An arkoor send stopped after the co-sign, whose outputs expired before
/// they were registered. The server refunds them to the sender, so the send
/// fails and nothing is delivered.
#[tokio::test]
async fn expiry_payout_fails_send_of_unregistered_outputs() {
	let ctx = TestContext::new("bark_sdk/expiry_payout_fails_send_of_unregistered_outputs").await;
	let (srv, proxy, server) = payout_server(&ctx).await;
	let sender = ctx.bark_sdk("sender", &server).boarded(sat(100_000))
		.cfg(|cfg| cfg.daemon_manual_sync = true).create().await;
	let recipient = ctx.bark_sdk("recipient", &srv)
		.cfg(|cfg| cfg.daemon_manual_sync = true).create().await;
	let input = sender.spendable_vtxos().await.unwrap().remove(0);

	// The sender stops while it registers the co-signed outputs.
	proxy.hold_registration.store(true, Ordering::SeqCst);
	let address = recipient.new_address().await.unwrap();
	tokio::select! {
		res = sender.send_arkoor_payment(&address, sat(10_000)) => panic!("send finished: {res:?}"),
		_ = proxy.held.notified() => {},
	}
	assert_eq!(sender.pending_arkoor_sends().await.unwrap().len(), 1);

	// It comes back after the outputs expired; the server refuses them.
	mine_past(&ctx, &srv, &sender, input.expiry_height()).await;
	proxy.hold_registration.store(false, Ordering::SeqCst);
	proxy.refuse_registration.store(true, Ordering::SeqCst);
	sender.sync_pending_arkoor_sends().await.unwrap();

	assert!(sender.pending_arkoor_sends().await.unwrap().is_empty());
	assert_eq!(movement(&sender, "bark.arkoor").await.status, MovementStatus::Failed);
	assert_eq!(sender.get_vtxo_by_id(input.id()).await.unwrap().state, VtxoState::Spent);
	recipient.sync_mailbox().await.unwrap();
	assert!(recipient.history().await.unwrap().is_empty(), "the recipient was never paid");
}

/// A Lightning send whose HTLCs the server refuses to revoke ends once
/// they are paid out at expiry.
#[tokio::test]
async fn expiry_payout_ends_lightning_send_of_paid_htlcs() {
	let ctx = TestContext::new("bark_sdk/expiry_payout_ends_lightning_send_of_paid_htlcs").await;
	let lightning = ctx.new_lightning_setup("lightningd").await;
	let srv = ctx.captaind("server").lightningd(&lightning.internal).funded(btc(10))
		.cfg(|cfg| cfg.expiry_payouts = true).create().await;
	let proxy = PayoutProxy::default();
	let server = srv.start_proxy_no_mailbox(proxy.clone()).await;
	let wallet = ctx.bark_sdk("bark", &server).boarded(btc(1))
		.cfg(|cfg| cfg.daemon_manual_sync = true).create().await;
	lightning.sync().await;

	let payment_hash = Preimage::random().compute_payment_hash();
	let invoice = lightning.external.hold_client().await.invoice(hold::InvoiceRequest {
		payment_hash: payment_hash.as_ref().to_vec(),
		amount_msat: 10_000_000,
		description: Some(hold::invoice_request::Description::Memo("payout".into())),
		min_final_cltv_expiry: Some(18),
		expiry: Some(3600),
		routing_hints: vec![],
	}).await.unwrap().into_inner().bolt11;

	// The server refuses to pay and then to revoke the HTLCs.
	proxy.refuse_lightning.store(true, Ordering::SeqCst);
	let _ = wallet.pay_lightning_invoice(invoice, None, false).await;
	let stuck = wallet.stuck_failed_lightning_sends().await.unwrap();
	assert_eq!(stuck.len(), 1);
	let pay::Progress::RevocationStuck { htlcs, .. } = &stuck[0].progress else {
		panic!("unexpected {:?}", stuck[0].progress);
	};
	let htlcs = htlcs.vtxo_ids.clone();

	// The HTLCs expired and were paid out to this wallet.
	proxy.decide_for(&wallet);
	let _ = wallet.check_lightning_payment(payment_hash, false).await;

	assert!(wallet.pending_lightning_sends().await.unwrap().is_empty());
	let send = movement(&wallet, "bark.lightning_send").await;
	assert_eq!((send.status, send.effective_balance), (MovementStatus::Failed, SignedAmount::ZERO));
	for id in htlcs {
		let htlc = wallet.get_vtxo_by_id(id).await.unwrap();
		assert_eq!((htlc.state, htlc.expiry_payout_state), (VtxoState::Spent, Some(ExpiryPayoutState::Paid)));
	}
	let balance = ark_testing::balance::assert_balance_consistent(&wallet, false).await;
	assert_eq!(balance.pending_lightning_send, Amount::ZERO);
}

/// A payout decision before a fresh Lightning co-sign ends the action.
/// The other selected inputs are unlocked and the server pays nothing.
#[tokio::test]
async fn expiry_payout_refused_lightning_input_registration_ends_send() {
	let ctx = TestContext::new("bark_sdk/expiry_payout_refused_lightning_input_registration_ends_send").await;
	let lightning = ctx.new_lightning_setup("lightningd").await;
	let srv = ctx.captaind("server").lightningd(&lightning.internal).funded(btc(1))
		.cfg(|cfg| cfg.expiry_payouts = true).create().await;
	let proxy = PayoutProxy::default();
	let server = srv.start_proxy_no_mailbox(proxy.clone()).await;
	let wallet = ctx.bark_sdk("sender", &server).boarded(sat(100_000)).boarded(sat(100_000))
		.cfg(|cfg| cfg.daemon_manual_sync = true).create().await;
	let inputs = wallet.spendable_vtxos().await.unwrap();
	assert_eq!(inputs.len(), 2);
	proxy.decided_input_registration.store(true, Ordering::SeqCst);
	proxy.decided_lightning_cosign.store(true, Ordering::SeqCst);
	let invoice = lightning.external.invoice(Some(sat(150_000)), "decided-input", "decided input").await;
	wallet.pay_lightning_invoice(invoice, None, false).await.expect_err("fresh spend must be refused");
	assert!(wallet.pending_lightning_sends().await.unwrap().is_empty());
	for input in inputs {
		assert_eq!(wallet.get_vtxo_by_id(input.id()).await.unwrap().state, VtxoState::Spendable);
	}
	assert_eq!(movement(&wallet, "bark.lightning_send").await.status, MovementStatus::Failed);
	let db = Db::connect(&srv.config().postgres).await.unwrap();
	let attempts: i64 = db.read(async |t| Ok(t.query_one(
		"SELECT count(*) FROM lightning_payment_attempt", &[],
	).await?.get(0))).await.unwrap();
	assert_eq!(attempts, 0);
	assert!(!proxy.cosigned.load(Ordering::SeqCst));
}

/// A lost co-sign reply can leave the action at InputsLocked. A later
/// registration refusal must still let the committed co-sign replay.
#[tokio::test]
async fn expiry_payout_lightning_cosign_replay_survives_registration_refusal() {
	let ctx = TestContext::new("bark_sdk/expiry_payout_lightning_cosign_replay_survives_registration_refusal").await;
	let lightning = ctx.new_lightning_setup("lightningd").await;
	let srv = ctx.captaind("server").lightningd(&lightning.internal).funded(btc(1))
		.cfg(|cfg| cfg.expiry_payouts = true).create().await;
	let proxy = PayoutProxy::default();
	let server = srv.start_proxy_no_mailbox(proxy.clone()).await;
	let wallet = ctx.bark_sdk("sender", &server).boarded(sat(100_000))
		.cfg(|cfg| cfg.daemon_manual_sync = true).create().await;
	let input = wallet.spendable_vtxos().await.unwrap().remove(0);
	proxy.lose_lightning_cosign_reply_once.store(true, Ordering::SeqCst);
	proxy.stall_lightning_initiation.store(true, Ordering::SeqCst);
	let invoice = lightning.external.invoice(Some(sat(50_000)), "lost-cosign", "lost cosign").await;
	wallet.pay_lightning_invoice(invoice, None, false).await.expect_err("the first reply was lost");
	assert!(proxy.cosigned.load(Ordering::SeqCst));
	let send = wallet.pending_lightning_sends().await.unwrap().remove(0);
	assert!(matches!(send.progress, pay::Progress::InputsLocked { .. }));
	let _ = wallet.check_lightning_payment(send.invoice.payment_hash(), false).await;
	let send = wallet.pending_lightning_sends().await.unwrap().remove(0);
	assert!(matches!(send.progress, pay::Progress::HtlcReceived(_)), "{:?}", send.progress);
	let db = Db::connect(&srv.config().postgres).await.unwrap();
	let state = db.read(async |t| t.get_user_vtxo_by_id(input.id()).await).await.unwrap().spend_state;
	assert_eq!(state, server::database::SpendState::Spent);
	assert_ne!(movement(&wallet, "bark.lightning_send").await.status, MovementStatus::Failed);
}

/// A Lightning receive whose claim the server refuses ends once its grants
/// are paid out at expiry, to this wallet or, for a forwarded receive, to
/// the recipient.
#[tokio::test]
async fn expiry_payout_ends_lightning_receive_of_paid_grants() {
	let ctx = TestContext::new("bark_sdk/expiry_payout_ends_lightning_receive_of_paid_grants").await;
	let lightning = Arc::new(ctx.new_lightning_setup("lightningd").await);
	let srv = ctx.captaind("server").lightningd(&lightning.internal).funded(btc(10))
		.cfg(|cfg| cfg.expiry_payouts = true).create().await;
	srv.wait_for_vtxopool(&ctx).await;
	let proxy = PayoutProxy::default();
	let server = srv.start_proxy_no_mailbox(proxy.clone()).await;
	let wallet = ctx.bark_sdk("receiver", &server).cfg(|cfg| cfg.daemon_manual_sync = true).create().await;
	let recipient = ctx.bark_sdk("recipient", &srv).create().await;
	lightning.sync().await;
	proxy.refuse_lightning.store(true, Ordering::SeqCst);

	for forwarded in [false, true] {
		proxy.decide.store(false, Ordering::SeqCst);
		let destination = if forwarded { Some(recipient.new_address().await.unwrap()) } else { None };
		let invoice = wallet.bolt11_invoice_builder().amount(sat(50_000)).claim_destination(destination)
			.build().await.unwrap();
		let hash = PaymentHash::from(&invoice);
		let (payer, bolt11) = (lightning.clone(), invoice.to_string());
		// The refused claim never settles the hold invoice.
		tokio::spawn(async move { payer.external.try_pay_bolt11(bolt11).await });
		srv.wait_for_lightning_receive_accepted(hash).await;

		// Refused claims leave the receive pending.
		let _ = wallet.try_claim_lightning_receive(hash, false).await;
		let LightningReceiveState::InProgress(receive) = wallet.lightning_receive_state(hash).await.unwrap() else {
			panic!("the refused claim ended the receive");
		};
		let receive::Progress::PreimageRevealed(htlcs) = receive.progress else {
			panic!("unexpected {:?}", receive.progress);
		};

		// The grants are paid out: to this wallet, or to the recipient.
		if forwarded {
			*proxy.owner.lock().unwrap() = recipient.mailbox_identifier().as_pubkey().serialize().to_vec();
			proxy.decide.store(true, Ordering::SeqCst);
		} else {
			proxy.decide_for(&wallet);
		}
		let state = wallet.try_claim_lightning_receive(hash, false).await.unwrap();
		assert!(matches!(state, LightningReceiveState::Settled(_)), "{state:?}");
		let receive = wallet.history().await.unwrap().into_iter()
			.find(|m| m.id == htlcs.movement_id).unwrap();
		assert_eq!((receive.status, receive.effective_balance), (MovementStatus::Successful, SignedAmount::ZERO));
		for id in htlcs.vtxo_ids {
			let grant = wallet.get_vtxo_by_id(id).await.unwrap();
			let expected = if forwarded { None } else { Some(ExpiryPayoutState::Paid) };
			assert_eq!((grant.state, grant.expiry_payout_state), (VtxoState::Spent, expected));
		}
	}
}

/// An offboard whose arkoor outputs the server refuses to register ends
/// once they are paid out at expiry.
#[tokio::test]
async fn expiry_payout_ends_offboard_of_paid_vtxos() {
	let ctx = TestContext::new("bark_sdk/expiry_payout_ends_offboard_of_paid_vtxos").await;
	let (_srv, proxy, server) = payout_server(&ctx).await;
	let wallet = ctx.bark_sdk("bark", &server).boarded(sat(800_000))
		.cfg(|cfg| cfg.daemon_manual_sync = true).create().await;

	proxy.refuse_registration.store(true, Ordering::SeqCst);
	let _ = wallet.send_onchain(ctx.bitcoind().get_new_address(), sat(100_000)).await;
	let pending = wallet.pending_offboards().await.unwrap();
	assert_eq!(pending.len(), 1);
	let offboard::Progress::ArkoorRegistrationRequired { offboard_vtxo_ids, change_vtxo_ids } = &pending[0].progress else {
		panic!("unexpected {:?}", pending[0].progress);
	};
	let vtxos = offboard_vtxo_ids.iter().chain(change_vtxo_ids).copied().collect::<Vec<_>>();

	proxy.decide_for(&wallet);
	wallet.sync_pending_offboards().await.unwrap();

	assert!(wallet.pending_offboards().await.unwrap().is_empty());
	let offboard = movement(&wallet, "bark.offboard").await;
	assert_eq!((offboard.status, offboard.effective_balance), (MovementStatus::Failed, SignedAmount::ZERO));
	for id in vtxos {
		assert_eq!(wallet.get_vtxo_by_id(id).await.unwrap().state, VtxoState::Spent);
	}
	assert_eq!(ark_testing::balance::assert_balance_consistent(&wallet, false).await.total(), Amount::ZERO);
}

/// A delegated refresh is cancelled when the server pays out its input at
/// expiry.
#[tokio::test]
async fn expiry_payout_cancels_delegated_refresh_of_paid_vtxo() {
	let ctx = TestContext::new("bark_sdk/expiry_payout_cancels_delegated_refresh_of_paid_vtxo").await;
	let (srv, proxy, server) = payout_server(&ctx).await;
	let wallet = ctx.bark_sdk("bark", &server).boarded(sat(100_000))
		.cfg(|cfg| cfg.daemon_manual_sync = true).create().await;
	let input = wallet.spendable_vtxos().await.unwrap().remove(0);
	wallet.refresh_vtxos_delegated(vec![input.id()]).await.unwrap().expect("refresh joined");

	mine_past(&ctx, &srv, &wallet, input.expiry_height()).await;
	proxy.decide_for(&wallet);
	wallet.sync().wait_millis(60_000).await;

	assert!(wallet.pending_round_states().await.unwrap().is_empty());
	assert_eq!(movement(&wallet, "bark.round").await.status, MovementStatus::Failed);
	let paid = wallet.get_vtxo_by_id(input.id()).await.unwrap();
	assert_eq!((paid.state, paid.expiry_payout_state), (VtxoState::Spent, Some(ExpiryPayoutState::Paid)));
	let payout = wallet.expiry_payout(input.id()).await.unwrap().unwrap();
	assert_eq!((payout.gross, payout.fee, payout.payout), (sat(10_000), sat(2_000), sat(8_000)));
	assert_eq!(payout.address.script_pubkey(), wallet.payout_script());
	assert_eq!(ark_testing::balance::assert_balance_consistent(&wallet, false).await.total(), Amount::ZERO);
}

/// A ban added after a delegated refresh is stored does not prevent expiry
/// payout from retiring that input and cancelling the participation.
#[tokio::test]
async fn expiry_payout_cancels_banned_delegated_refresh() {
	let ctx = TestContext::new("bark_sdk/expiry_payout_cancels_banned_delegated_refresh").await;
	let (srv, proxy, server) = payout_server(&ctx).await;
	let wallet = ctx.bark_sdk("bark", &server).boarded(sat(100_000))
		.cfg(|cfg| cfg.daemon_manual_sync = true).create().await;
	let input = wallet.spendable_vtxos().await.unwrap().remove(0);
	wallet.refresh_vtxos_delegated(vec![input.id()]).await.unwrap().expect("refresh joined");
	srv.ban_vtxo(input.id(), 100).await;

	mine_past(&ctx, &srv, &wallet, input.expiry_height()).await;
	proxy.decide_for(&wallet);
	wallet.sync().wait_millis(60_000).await;

	assert!(wallet.pending_round_states().await.unwrap().is_empty());
	assert_eq!(movement(&wallet, "bark.round").await.status, MovementStatus::Failed);
	let paid = wallet.get_vtxo_by_id(input.id()).await.unwrap();
	assert_eq!((paid.state, paid.expiry_payout_state),
		(VtxoState::Spent, Some(ExpiryPayoutState::Paid)));
	assert_eq!(ark_testing::balance::assert_balance_consistent(&wallet, false).await.total(), Amount::ZERO);
}

/// A maintenance refresh that the server refuses because its input is
/// decided for an expiry payout marks that input paid out.
#[tokio::test]
async fn expiry_payout_retires_input_of_refused_refresh() {
	let ctx = TestContext::new("bark_sdk/expiry_payout_retires_input_of_refused_refresh").await;
	let (srv, proxy, server) = payout_server(&ctx).await;
	let wallet = ctx.bark_sdk("bark", &server).boarded(sat(100_000))
		.cfg(|cfg| cfg.daemon_manual_sync = true).create().await;
	let input = wallet.spendable_vtxos().await.unwrap().remove(0);

	mine_past(&ctx, &srv, &wallet, input.expiry_height()).await;
	proxy.refuse_participation.store(true, Ordering::SeqCst);
	proxy.decide_for(&wallet);
	wallet.maybe_schedule_maintenance_refresh_delegated().await.unwrap_err();

	let paid = wallet.get_vtxo_by_id(input.id()).await.unwrap();
	assert_eq!((paid.state, paid.expiry_payout_state), (VtxoState::Spent, Some(ExpiryPayoutState::Paid)));
	assert!(wallet.get_vtxos_to_refresh().await.unwrap().is_empty());
}

/// After the server accepts a round's forfeits, a restart must recover its
/// output even when the old input is locally marked paid out.
#[tokio::test]
async fn expiry_payout_released_round_recovers_output_after_restart() {
	let ctx = TestContext::new("bark_sdk/expiry_payout_released_round_recovers_output_after_restart").await;
	let srv = ctx.captaind("server").no_vtxo_pool().cfg(|cfg| {
		cfg.expiry_payouts = true;
		cfg.vtxo_lifetime = BlockDelta::new(288);
	}).create().await;
	ctx.fund_captaind(&srv, btc(1)).await;
	let proxy = PayoutProxy::default();
	let server = srv.start_proxy_no_mailbox(proxy.clone()).await;
	let mnemonic = bip39::Mnemonic::generate(12).unwrap();
	let wallet = ctx.bark_sdk("sender", &server).mnemonic(mnemonic.clone()).boarded(sat(200_000))
		.cfg(|cfg| cfg.daemon_manual_sync = true).create().await;
	let input = wallet.spendable_vtxos().await.unwrap().remove(0);
	let round = wallet.refresh_vtxos_delegated(vec![input.id()]).await.unwrap().unwrap();
	let mut finished = srv.subscribe_log::<server_log::RoundFinished>();
	srv.trigger_round().await;
	finished.recv().wait(Duration::from_secs(60)).await.expect("round completed");
	let tip = ctx.generate_blocks(ROUND_CONFIRMATIONS).await;
	srv.wait_for_sync_height(tip).await;
	proxy.hold_registration.store(true, Ordering::SeqCst);
	tokio::time::timeout(Duration::from_secs(60), async {
		let sync = wallet.sync_pending_rounds();
		tokio::pin!(sync);
		tokio::select! {
			_ = proxy.held.notified() => {},
			result = &mut sync => panic!("sync finished before output registration: {result:?}"),
		}
	}).await.expect("output registration reached");
	assert!(proxy.forfeit_accepted.load(Ordering::SeqCst));
	let config = wallet.config().clone();
	wallet.stop_daemon_wait().await.unwrap();
	drop(wallet);
	let db = SqliteClient::open(ctx.datadir.join("sender/db.sqlite")).unwrap();
	db.set_vtxo_expiry_payout_state(input.id(), ExpiryPayoutState::Paid).await.unwrap();
	proxy.hold_registration.store(false, Ordering::SeqCst);
	let wallet = Wallet::open(Network::Regtest,
		bark::WalletSeed::new_from_mnemonic(Network::Regtest, &mnemonic), config,
		bark::OpenWalletArgs { datadir: Some(ctx.datadir.join("sender")), run_daemon: false, ..Default::default() },
	).await.unwrap();
	let status = wallet.sync_pending_rounds().await.unwrap();
	assert!(status.get(&round.id()).is_some_and(|s| s.is_success()), "{status:?}");
	let outputs = wallet.spendable_vtxos().await.unwrap();
	assert_eq!(outputs.len(), 1, "released round's output must be stored once");
	assert_ne!(outputs[0].id(), input.id());
	wallet.sync_pending_rounds().await.unwrap();
	assert_eq!(wallet.spendable_vtxos().await.unwrap().len(), 1);
	assert_eq!(movement(&wallet, "bark.round").await.status, MovementStatus::Successful);
}

/// The wallet daemon marks a VTXO it holds paid out once the server pays
/// it out at expiry.
#[tokio::test]
async fn expiry_payout_daemon_retires_paid_held_vtxo() {
	let ctx = TestContext::new("bark_sdk/expiry_payout_daemon_retires_paid_held_vtxo").await;
	let (srv, proxy, server) = payout_server(&ctx).await;
	let wallet = ctx.bark_sdk("bark", &server).boarded(sat(100_000))
		.cfg(|cfg| cfg.daemon_sync_interval_secs = 1).create().await;
	let input = wallet.spendable_vtxos().await.unwrap().remove(0);

	mine_past(&ctx, &srv, &wallet, input.expiry_height()).await;
	proxy.decide_for(&wallet);

	let paid = async {
		loop {
			let vtxo = wallet.get_vtxo_by_id(input.id()).await.unwrap();
			if vtxo.state == VtxoState::Spent {
				break vtxo;
			}
			tokio::time::sleep(poll_interval()).await;
		}
	}.wait_millis(60_000).await;
	assert_eq!(paid.expiry_payout_state, Some(ExpiryPayoutState::Paid));
}

/// A payment on a server in expiry payout mode leaves out a VTXO at or past
/// its expiry and spends a VTXO that expires later instead.
#[tokio::test]
async fn expiry_payout_payment_skips_expired_vtxo() {
	let ctx = TestContext::new("bark_sdk/expiry_payout_payment_skips_expired_vtxo").await;
	let (srv, _proxy, server) = payout_server(&ctx).await;
	ctx.fund_captaind(&srv, sat(1_000_000)).await;
	let wallet = ctx.bark_sdk("bark", &server).funded(sat(1_000_000)).boarded(sat(100_000))
		.cfg(|cfg| cfg.daemon_manual_sync = true).create().await;
	let expired = wallet.spendable_vtxos().await.unwrap().remove(0);

	// A later board expires after the first one.
	ctx.generate_blocks(12).await;
	let board = wallet.board_amount(sat(400_000)).await.unwrap();
	ctx.await_transaction(board.funding_tx.compute_txid()).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
	wallet.sync().await;
	mine_past(&ctx, &srv, &wallet, expired.expiry_height()).await;

	wallet.send_onchain(ctx.bitcoind().get_new_address(), sat(50_000)).await.unwrap();

	assert_eq!(wallet.get_vtxo_by_id(expired.id()).await.unwrap().state, VtxoState::Spendable);
}

/// The transaction in the mempool that pays `script`, if any.
fn mempool_payout(ctx: &TestContext, script: &ScriptBuf) -> Option<Transaction> {
	let core = ctx.bitcoind().sync_client();
	core.get_raw_mempool().unwrap().into_iter()
		.filter_map(|txid| core.get_raw_transaction(&txid, None).ok())
		.find(|tx| tx.output.iter().any(|output| output.script_pubkey == *script))
}

/// The value the blocks of the current chain from height `from` on pay to `script`.
fn paid_to(ctx: &TestContext, script: &ScriptBuf, from: u64) -> Vec<Amount> {
	let core = ctx.bitcoind().sync_client();
	(from..=core.get_block_count().unwrap()).flat_map(|height| {
		core.get_block(&core.get_block_hash(height).unwrap()).unwrap().txdata
	}).flat_map(|tx| tx.output).filter(|output| output.script_pubkey == *script).map(|output| output.value).collect()
}

/// The watchman pays out an expired board while its owner is away. When
/// the owner comes back and exits, the exit ends with the VTXO spent and
/// never becomes claimable. The wallet reports the payout, pending until it
/// is six blocks deep, and refuses to refresh the VTXO.
#[tokio::test]
async fn expiry_payout_ends_the_exit_of_a_paid_vtxo() {
	let ctx = TestContext::new("bark_sdk/expiry_payout_ends_the_exit_of_a_paid_vtxo").await;
	let srv = ctx.captaind("server").funded(btc(10)).cfg(|cfg| {
		cfg.expiry_payouts = true;
		cfg.vtxopool.vtxo_targets = vec![];
	}).watchmand_cfg(|cfg| {
		cfg.watchman.reaction_interval = Duration::from_secs(15 * 60);
		cfg.watchman.sweep_interval = Duration::from_secs(15 * 60);
	}).create().await;
	let wm = srv.watchmand();
	ctx.bitcoind().fund_addr(wm.wait_wallet_address().await, sat(1_000_000)).await;
	let wallet = ctx.bark_sdk("bark", &srv).cfg(|c| c.daemon_manual_sync = true)
		.funded(sat(1_000_000)).boarded(sat(400_000)).create().await;
	let start = ctx.bitcoind().get_block_count().await;
	let vtxo = wallet.vtxos().await.unwrap().remove(0);
	let anchor = vtxo.vtxo.chain_anchor();
	let script = wallet.payout_script();
	// The fee is 1% of 400,000 sats.
	let amount = sat(396_000);

	// The owner is away, so the watchman pays out the board before the exit
	// starts.
	let tip = ctx.bitcoind().get_block_count().await as u32;
	let expired = ctx.generate_blocks(vtxo.vtxo.expiry_height().to_u32() + 1 - tip).await;
	wm.wait_for_sync_height(expired).await;
	let payout = async {
		loop {
			wm.trigger_sweep().await;
			if let Some(tx) = mempool_payout(&ctx, &script) {
				break tx;
			}
			tokio::time::sleep(poll_interval()).await;
		}
	}.wait_millis(30_000).await;
	assert!(payout.input.iter().any(|input| input.previous_output == anchor));
	let output = payout.output.iter().position(|output| output.script_pubkey == script).unwrap() as u32;
	assert_eq!(payout.output[output as usize].value, amount);
	// The 0.9.0 force-exit scan checks each spendable VTXO's own funding tx.
	// A payout spends its root without putting this board VTXO's exit tx on-chain.
	wallet.sync_force_exited_vtxos().await.unwrap();
	assert!(!wallet.exit_mgr().get_exit_vtxo_ids().await.contains(&vtxo.id()),
		"an expiry payout is not a forced exit");

	wallet.exit_mgr().start_exit_for_entire_wallet().await.unwrap();
	ctx.generate_blocks(1).await;
	wallet.chain().invalidate_caches().await;
	wallet.sync_onchain().await.unwrap();
	let _ = wallet.progress_exits().await;
	let exit = wallet.exit_mgr().get_exit_vtxo(vtxo.id()).await.map(|exit| exit.state().clone());
	assert!(matches!(exit, Some(ExitState::Processing(_))), "one confirmation does not end the exit: {exit:?}");
	wallet.sync_expiry_payouts().await.unwrap();
	let state = wallet.get_vtxo_by_id(vtxo.id()).await.unwrap();
	assert_eq!((state.state, state.expiry_payout_state), (VtxoState::Spent, Some(ExpiryPayoutState::Pending)));

	// The exit cannot claim an output that is gone.
	let mut claimable = false;
	let mut exit = None;
	for _ in 0..15 {
		wallet.chain().invalidate_caches().await;
		wallet.sync_onchain().await.unwrap();
		let _ = wallet.progress_exits().await;
		exit = wallet.exit_mgr().get_exit_vtxo(vtxo.id()).await.map(|exit| exit.state().clone());
		claimable |= matches!(exit, Some(ExitState::Claimable(_) | ExitState::Claimed(_)));
		ctx.generate_blocks(1).await;
	}
	assert!(matches!(exit, Some(ExitState::VtxoAlreadySpent(_))), "{exit:?}");
	assert!(!claimable, "the exit of a paid VTXO is never claimable");

	let output = ctx.bitcoind().sync_client().get_tx_out(&payout.compute_txid(), output, Some(true)).unwrap().unwrap();
	assert!(output.confirmations >= 6);
	let history = wallet.history().await.unwrap();
	wallet.chain().invalidate_caches().await;
	wallet.sync_expiry_payouts().await.unwrap();
	let state = wallet.get_vtxo_by_id(vtxo.id()).await.unwrap();
	assert_eq!((state.state, state.expiry_payout_state), (VtxoState::Spent, Some(ExpiryPayoutState::Paid)));
	let reported = wallet.expiry_payout(vtxo.id()).await.unwrap().unwrap();
	assert_eq!((reported.status, reported.gross, reported.fee, reported.payout),
		(ExpiryPayoutState::Paid, sat(400_000), sat(4_000), amount));
	assert_eq!(reported.address.script_pubkey(), script);
	assert!(wallet.vtxos().await.unwrap().is_empty());
	let error = wallet.refresh_vtxos([vtxo.id()]).await.expect_err("a paid VTXO cannot be refreshed");
	assert_eq!(error.to_string(), format!("input VTXO {} is not spendable (state: Spent)", vtxo.id()));
	assert_eq!(wallet.history().await.unwrap(), history, "a payout is not an Ark movement");
	assert_eq!(paid_to(&ctx, &script, start), [amount], "the owner is paid once");
}

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

/// A wallet that was away while it received two arkoor payments, which
/// were then paid out at expiry, learns of both on its next sync. It
/// records them as paid out, with no Ark receive.
#[tokio::test]
async fn expiry_payout_of_unseen_receives_is_recorded_on_sync() {
	let ctx = TestContext::new("bark_sdk/expiry_payout_of_unseen_receives_is_recorded_on_sync").await;
	let srv = ctx.captaind("server").no_vtxo_pool().cfg(|cfg| {
		cfg.expiry_payouts = true;
		cfg.vtxo_lifetime = BlockDelta::new(24);
		cfg.vtxo_exit_delta = BlockDelta::new(3);
	}).watchmand().create().await;
	let config = |cfg: &mut bark::Config| {
		cfg.daemon_manual_sync = true;
		cfg.vtxo_refresh_expiry_threshold = BlockDelta::new(4);
		cfg.vtxo_exit_margin = BlockDelta::new(2);
	};
	let sender = ctx.bark_sdk("sender", &srv).cfg(config).boarded(sat(100_000)).create().await;
	sender.stop_daemon_wait().await.unwrap();
	let mnemonic = bip39::Mnemonic::generate(12).unwrap();
	let recipient = ctx.bark_sdk("recipient", &srv).mnemonic(mnemonic.clone()).cfg(config).create().await;
	recipient.stop_daemon_wait().await.unwrap();
	let source = sender.spendable_vtxos().await.unwrap().remove(0);
	let address = recipient.new_address().await.unwrap();
	let script = recipient.payout_script();
	drop(recipient);
	let start = ctx.bitcoind().get_block_count().await;
	for _ in 0..2 {
		sender.send_arkoor_payment(&address, sat(10_000)).await.unwrap();
	}
	let db = Db::connect(&srv.config().postgres).await.unwrap();
	let received = db.read(async |t| t.get_vtxos_by_policy_page(address.policy(), None, 3).await).await.unwrap()
		.into_iter().map(|row| row.vtxo_id).collect::<Vec<_>>();
	assert_eq!(received.len(), 2);
	let mut exit_path = BTreeSet::new();
	for vtxo in db.read(async |t| t.get_user_vtxos_by_id(&received).await).await.unwrap() {
		exit_path.extend(vtxo.vtxo.transactions().map(|step| step.tx.compute_txid()));
	}
	ctx.bitcoind().fund_addr(srv.watchmand().wait_wallet_address().await, sat(100_000)).await;
	ctx.generate_blocks(2).await;
	let tip = ctx.bitcoind().get_block_count().await as u32;
	let expired = ctx.generate_blocks(source.expiry_height().to_u32() + 1 - tip).await;
	srv.wait_for_sync_height(expired).await;
	srv.watchmand().wait_for_sync_height(expired).await;

	// The watchman puts the exit path on chain, then pays out both receives.
	let grace = srv.watchmand().config().watchman.progress_grace_period.to_u32() + 1;
	let core = ctx.bitcoind().sync_client();
	async {
		loop {
			if mempool_payout(&ctx, &script).is_some() {
				break;
			}
			if let Some(txid) = core.get_raw_mempool().unwrap().into_iter().find(|id| exit_path.contains(id)) {
				exit_path.remove(&txid);
				let tip = ctx.generate_blocks(grace).await;
				srv.wait_for_sync_height(tip).await;
				srv.watchmand().wait_for_sync_height(tip).await;
			}
			tokio::time::sleep(poll_interval()).await;
		}
	}.wait_millis(30_000).await;
	let tip = ctx.generate_blocks(6).await;
	srv.wait_for_sync_height(tip).await;
	srv.watchmand().wait_for_sync_height(tip).await;
	assert_eq!(paid_to(&ctx, &script, start).into_iter().sum::<Amount>(), sat(18_000),
		"the two receives are charged one fee");

	let returned = ctx.bark_sdk("recipient", &srv).mnemonic(mnemonic).cfg(config).create().await;
	returned.sync().await;
	for id in &received {
		let state = returned.get_vtxo_by_id(*id).await.unwrap();
		assert_eq!((state.state, state.expiry_payout_state), (VtxoState::Spent, Some(ExpiryPayoutState::Paid)));
		let payout = returned.expiry_payout(*id).await.unwrap().unwrap();
		assert_eq!((payout.gross, payout.address.script_pubkey()), (sat(10_000), script.clone()));
	}
	assert_eq!(returned.balance().await.unwrap().total(), Amount::ZERO);
	assert!(returned.history().await.unwrap().is_empty(), "a paid out receive is not an Ark receive");
	returned.sync().await;
	assert!(returned.history().await.unwrap().is_empty());
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
	let recipient_seed = bip39::Mnemonic::generate(12).unwrap();
	let recipient = ctx.bark_sdk("recipient", &srv)
		.mnemonic(recipient_seed.clone())
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
	let restored = ctx.bark_sdk("restored", &srv).mnemonic(recipient_seed)
		.cfg(|cfg| cfg.daemon_manual_sync = true).create().await;
	assert!(restored.pending_recovery().await.unwrap().is_none(), "seed recovery must finish");
	assert!(restored.all_vtxos().await.unwrap().iter().all(|vtxo| vtxo.id() != id),
		"seed recovery must not keep a VTXO bound to another mailbox");
	let report = restored.recover_vtxos([id], None).await.unwrap();
	assert_eq!(report.foreign().ids().collect::<Vec<_>>(), [id]);
}

/// The server reports a spend state that the recipient does not know for one
/// received VTXO, and another owner mailbox for a second one. The recipient
/// keeps both locked and credits the VTXO that follows them in its mailbox.
/// It credits the locked ones once the server reports them spendable and
/// bound to its mailbox.
#[tokio::test]
async fn expiry_payout_recipient_holds_a_receive_with_a_bad_status() {
	let ctx = TestContext::new("bark_sdk/expiry_payout_recipient_holds_a_receive_with_a_bad_status").await;
	let (srv, proxy, server) = payout_server(&ctx).await;
	let sender = ctx.bark_sdk("sender", &srv).boarded(sat(100_000))
		.cfg(|cfg| cfg.daemon_manual_sync = true).create().await;
	let recipient = ctx.bark_sdk("recipient", &server)
		.cfg(|cfg| cfg.daemon_manual_sync = true).create().await;
	recipient.stop_daemon_wait().await.unwrap();
	let db = Db::connect(&srv.config().postgres).await.unwrap();
	let pay = async |amount| {
		let address = recipient.new_address().await.unwrap();
		sender.send_arkoor_payment(&address, sat(amount)).await.unwrap();
		db.read(async |t| t.get_vtxos_by_policy_page(address.policy(), None, 10).await).await.unwrap()
			.into_iter().map(|row| row.vtxo_id.to_bytes().to_vec()).collect::<Vec<_>>()
	};
	let unknown_state = pay(10_000).await;
	let other_mailbox = pay(20_000).await;
	pay(30_000).await;
	let owner = sender.mailbox_identifier().as_pubkey().serialize().to_vec();
	proxy.bad_status.lock().unwrap().extend(
		unknown_state.into_iter().map(|id| (id, None))
			.chain(other_mailbox.into_iter().map(|id| (id, Some(owner.clone())))),
	);

	recipient.sync_mailbox().await.unwrap();
	assert_eq!(recipient.balance().await.unwrap().spendable, sat(30_000));
	let held = VtxoState::Locked { holder: Some(VtxoLockHolder::MailboxReceive) };
	let locked = recipient.vtxos().await.unwrap().into_iter()
		.filter(|vtxo| vtxo.state == held).map(|vtxo| vtxo.amount()).sum::<Amount>();
	assert_eq!(locked, sat(30_000));

	proxy.bad_status.lock().unwrap().clear();
	recipient.sync_mailbox().await.unwrap();
	assert_eq!(recipient.balance().await.unwrap().spendable, sat(60_000));
}

/// Counts the recovery posts and chain registrations of a wallet, and the
/// recovery posts that the server refuses.
#[derive(Clone, Default)]
struct RecoveryCounts {
	posts: Arc<AtomicUsize>,
	refused: Arc<AtomicUsize>,
	registrations: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl ArkRpcProxy for RecoveryCounts {
	async fn register_vtxo_transactions(&self, upstream: &mut ArkClient, req: protos::RegisterVtxoTransactionsRequest)
		-> Result<protos::Empty, tonic::Status>
	{
		self.registrations.fetch_add(1, Ordering::SeqCst);
		Ok(upstream.register_vtxo_transactions(req).await?.into_inner())
	}
}

#[async_trait::async_trait]
impl MailboxRpcProxy for RecoveryCounts {
	async fn post_recovery_vtxo_ids(&self, upstream: &mut MailboxClient,
		req: protos::mailbox_server::PostRecoveryVtxoIdsRequest,
	) -> Result<protos::core::Empty, tonic::Status> {
		self.posts.fetch_add(1, Ordering::SeqCst);
		let res = upstream.post_recovery_vtxo_ids(req).await;
		if res.is_err() {
			self.refused.fetch_add(1, Ordering::SeqCst);
		}
		Ok(res?.into_inner())
	}
}

/// A wallet on a server in payout mode backs up its board in the recovery
/// mailbox. The server accepts the post, the wallet marks the VTXO
/// registered and does not post or register it again, and a wallet
/// restored from the same seed recovers the VTXO before it expires.
#[tokio::test]
async fn expiry_payout_board_is_backed_up_for_recovery() {
	let ctx = TestContext::new("bark_sdk/expiry_payout_board_is_backed_up_for_recovery").await;
	// The xpub lookup finds a VTXO without a backup, so it is turned off to
	// recover through the recovery mailbox.
	let srv = ctx.captaind("server").cfg(|cfg| {
		cfg.expiry_payouts = true;
		cfg.recovery_xpub_nb_keys = 0;
	}).create().await;
	let counts = RecoveryCounts::default();
	let proxy = srv.start_proxy_with_mailbox(counts.clone(), counts.clone()).await;
	let mnemonic = bip39::Mnemonic::generate(12).unwrap();
	let wallet = ctx.bark_sdk("owner", &proxy).mnemonic(mnemonic.clone()).boarded(sat(100_000))
		.cfg(|cfg| cfg.daemon_manual_sync = true).create().await;
	let vtxo = wallet.spendable_vtxos().await.unwrap().remove(0);

	wallet.sync().await;
	assert!(counts.posts.load(Ordering::SeqCst) > 0);
	assert_eq!(counts.refused.load(Ordering::SeqCst), 0, "the server accepts every recovery post");
	assert!(wallet.get_vtxo_by_id(vtxo.id()).await.unwrap().registered);

	counts.posts.store(0, Ordering::SeqCst);
	counts.registrations.store(0, Ordering::SeqCst);
	wallet.sync().await;
	assert_eq!(counts.posts.load(Ordering::SeqCst), 0, "a registered VTXO is not posted again");
	assert_eq!(counts.registrations.load(Ordering::SeqCst), 0, "a registered VTXO is not registered again");

	let restored = ctx.bark_sdk("restored", &srv).mnemonic(mnemonic)
		.cfg(|cfg| cfg.daemon_manual_sync = true).create().await;
	assert!(restored.pending_recovery().await.unwrap().is_none(), "board recovery must finish");
	assert!((ctx.bitcoind().get_block_count().await as u32) < vtxo.expiry_height().to_u32());
	let ids = restored.spendable_vtxos().await.unwrap().iter().map(|v| v.id()).collect::<Vec<_>>();
	assert_eq!(ids, [vtxo.id()]);
}

/// A seed recovery that staged an expired board learns its payout when status
/// requests resume. An expiry payout sync can also observe that payout while
/// recovery is pending, without crediting the board as spendable.
#[tokio::test]
async fn expiry_payout_of_staged_recovery_board_is_recorded() {
	let ctx = TestContext::new("bark_sdk/expiry_payout_of_staged_recovery_board_is_recorded").await;
	let srv = ctx.captaind("server").cfg(|cfg| {
		cfg.expiry_payouts = true;
		cfg.recovery_xpub_nb_keys = 0;
		cfg.vtxo_lifetime = BlockDelta::new(24);
	}).create().await;
	let mnemonic = bip39::Mnemonic::generate(12).unwrap();
	let owner = ctx.bark_sdk("owner", &srv).mnemonic(mnemonic.clone()).boarded(sat(100_000))
		.cfg(|cfg| cfg.daemon_manual_sync = true).create().await;
	owner.sync().await;
	let board = owner.spendable_vtxos().await.unwrap().remove(0);
	mine_past(&ctx, &srv, &owner, board.expiry_height()).await;

	let proxy = PayoutProxy::default();
	proxy.status_down.store(true, Ordering::SeqCst);
	let server = srv.start_proxy_no_mailbox(proxy.clone()).await;
	let restored = ctx.bark_sdk("restored", &server).mnemonic(mnemonic.clone())
		.cfg(|cfg| cfg.daemon_manual_sync = true).create().await;
	assert!(restored.pending_recovery().await.unwrap().is_some());
	assert!(matches!(restored.get_vtxo_by_id(board.id()).await.unwrap().state, VtxoState::Locked { .. }));
	assert!(restored.spendable_vtxos().await.unwrap().is_empty());

	proxy.decide_for(&restored);
	proxy.status_down.store(false, Ordering::SeqCst);
	restored.sync_pending_recovery().await.unwrap();
	assert!(restored.pending_recovery().await.unwrap().is_none());
	let paid = restored.get_vtxo_by_id(board.id()).await.unwrap();
	assert_eq!((paid.state, paid.expiry_payout_state), (VtxoState::Spent, Some(ExpiryPayoutState::Paid)));
	assert!(restored.spendable_vtxos().await.unwrap().is_empty());

	proxy.status_down.store(true, Ordering::SeqCst);
	let concurrent = ctx.bark_sdk("concurrent", &server).mnemonic(mnemonic)
		.cfg(|cfg| cfg.daemon_manual_sync = true).create().await;
	assert!(concurrent.pending_recovery().await.unwrap().is_some());
	proxy.status_down.store(false, Ordering::SeqCst);
	concurrent.sync_expiry_payouts().await.unwrap();
	assert!(concurrent.pending_recovery().await.unwrap().is_some(),
		"the payout check must leave the recovery action in progress");
	concurrent.sync_pending_recovery().await.unwrap();
	assert!(concurrent.pending_recovery().await.unwrap().is_none());
	let paid = concurrent.get_vtxo_by_id(board.id()).await.unwrap();
	assert_eq!((paid.state, paid.expiry_payout_state), (VtxoState::Spent, Some(ExpiryPayoutState::Paid)));
	assert!(concurrent.spendable_vtxos().await.unwrap().is_empty());
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

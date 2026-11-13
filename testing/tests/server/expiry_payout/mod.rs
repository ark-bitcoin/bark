mod binding;
mod fees;
#[cfg(feature = "slow_test")]
mod large_tree;
mod payout;
mod races;
mod reorg;

use std::collections::BTreeMap;
use std::sync::OnceLock;

use bitcoin::{Amount, BlockHash, Network, OutPoint, ScriptBuf, Transaction, Txid};
use bitcoin::bip32::{ChildNumber, Xpriv};
use bitcoin::consensus::deserialize;
use bitcoin::secp256k1::Keypair;
use bitcoin_ext::{BlockDelta, BlockHeight, BlockRef};
use bitcoin_ext::rpc::{BitcoinRpcExt, RpcApi};

use ark::{ProtocolEncoding, Vtxo, VtxoId, VtxoPolicy};
use ark::arkoor::package::{ArkoorPackageBuilder, ArkoorPackageCosignResponse};
use ark::lightning::PaymentHash;
use ark::mailbox::MailboxIdentifier;
use ark::vtxo::Full;
use bark::Wallet;
use server::database::{BlockTable, Db, Tx};
use server_rpc::protos;

use ark_testing::{Captaind, TestContext};
use ark_testing::util::{poll_interval, FutureExt};

/// The mailbox key the database tests bind their VTXOs to.
pub(crate) fn test_server_mailbox_key() -> &'static Keypair {
	static KEY: OnceLock<Keypair> = OnceLock::new();
	KEY.get_or_init(|| Keypair::from_seckey_slice(&ark::SECP, &[251; 32]).unwrap())
}

/// An owner whose VTXO keys and mailbox come from one seed, so a test can
/// sign for its VTXOs without a wallet.
struct Owner {
	account: Xpriv,
	mailbox: Keypair,
	script: ScriptBuf,
}

impl Owner {
	fn new(seed: &[u8]) -> Self {
		let account = Xpriv::new_master(Network::Regtest, seed).unwrap();
		let mailbox = account.to_keypair(&ark::SECP);
		let script = ark::expiry_payout::payout_script(mailbox.public_key());
		Owner { account, mailbox, script }
	}

	fn key(&self, index: u32) -> Keypair {
		self.account.derive_priv(&ark::SECP, &[ChildNumber::from_normal_idx(index).unwrap()]).unwrap()
			.to_keypair(&ark::SECP)
	}

	fn mailbox_id(&self) -> MailboxIdentifier {
		MailboxIdentifier::from_pubkey(self.mailbox.public_key())
	}
}

/// The blinded id of `mailbox` for an output whose key is `key`.
async fn blinded_mailbox(srv: &Captaind, key: &Keypair, mailbox: MailboxIdentifier) -> Vec<u8> {
	let server_mailbox = srv.ark_info().await.mailbox_pubkey;
	mailbox.to_blinded(server_mailbox, key).unwrap().as_ref().to_vec()
}

/// Bind every output of `package` to `mailbox`.
async fn bind_outputs(
	srv: &Captaind, package: &mut protos::ArkoorPackageCosignRequest, key: &Keypair, mailbox: MailboxIdentifier,
) {
	let blinded = blinded_mailbox(srv, key, mailbox).await;
	for output in package.parts.iter_mut().flat_map(|p| p.outputs.iter_mut().chain(&mut p.isolated_outputs)) {
		output.blinded_mailbox_id = blinded.clone();
	}
}

/// Bind each unbound output of `package` to the mailbox of the wallet that
/// holds its key.
async fn bind_to_wallets(
	srv: &Captaind, wallets: &[&Wallet], mut package: protos::ArkoorPackageCosignRequest,
) -> protos::ArkoorPackageCosignRequest {
	for output in package.parts.iter_mut().flat_map(|p| p.outputs.iter_mut().chain(&mut p.isolated_outputs)) {
		if !output.blinded_mailbox_id.is_empty() {
			continue;
		}
		let key = VtxoPolicy::deserialize(&output.policy).unwrap().user_pubkey();
		let mut owner = None;
		for wallet in wallets {
			if let Some((_, keypair)) = wallet.pubkey_keypair(&key).await.unwrap() {
				owner = Some((keypair, wallet.mailbox_identifier()));
				break;
			}
		}
		let (keypair, mailbox) = owner.unwrap_or_else(|| panic!("no wallet holds the key of output {key}"));
		output.blinded_mailbox_id = blinded_mailbox(srv, &keypair, mailbox).await;
	}
	package
}

/// Co-sign `input` into one output with `policy`, bound to the wallet's
/// mailbox, and register it.
async fn signed_leaf(srv: &Captaind, wallet: &Wallet, input: Vtxo<Full>, policy: VtxoPolicy) -> Vtxo<Full> {
	let key = wallet.get_vtxo_key(&input).await.unwrap();
	let builder = ArkoorPackageBuilder::new_claim_all_with_checkpoints([input], policy.clone()).unwrap()
		.generate_user_nonces(&[key]).unwrap();
	let request = bind_to_wallets(srv, &[wallet],
		protos::ArkoorPackageCosignRequest::from(builder.cosign_request())).await;
	let mut rpc = srv.get_public_rpc().await;
	let response = if matches!(policy, VtxoPolicy::ServerHtlcSend(_)) {
		rpc.request_lightning_pay_htlc_cosign(protos::LightningPayHtlcCosignRequest { parts: request.parts })
			.await.unwrap().into_inner()
	} else {
		rpc.request_arkoor_cosign(request).await.unwrap().into_inner()
	};
	let mut outputs = builder.user_cosign(&[key], ArkoorPackageCosignResponse::try_from(response).unwrap())
		.unwrap().build_signed_vtxos();
	assert_eq!(outputs.len(), 1);
	wallet.register_vtxo_transactions_with_server(&outputs).await.unwrap();
	outputs.remove(0)
}

/// Turn `input` into a registered HTLC-send VTXO for `hash`, owned by the
/// key of `input`, and return it with that key.
async fn htlc_send(
	ctx: &TestContext, srv: &Captaind, wallet: &Wallet, input: Vtxo<Full>, hash: PaymentHash,
) -> (Vtxo<Full>, Keypair) {
	let key = wallet.get_vtxo_key(&input).await.unwrap();
	let tip = BlockHeight::new(ctx.bitcoind().get_block_count().await as u32);
	let deadline = tip + srv.config().htlc_send_expiry_delta + BlockDelta::new(2);
	let policy = VtxoPolicy::new_server_htlc_send(key.public_key(), hash, deadline);
	(signed_leaf(srv, wallet, input, policy).await, key)
}

/// A board of `amount` whose wallet then goes away, the payout script of
/// that wallet, and the wallet's mailbox.
async fn idle_board(
	ctx: &TestContext, srv: &Captaind, name: &str, amount: Amount,
) -> (Vtxo<Full>, ScriptBuf, MailboxIdentifier) {
	let wallet = ctx.bark_sdk(name, srv).boarded(amount)
		.cfg(|cfg| cfg.daemon_manual_sync = true).create().await;
	wallet.stop_daemon_wait().await.unwrap();
	let vtxo = wallet.spendable_vtxos().await.unwrap().pop().unwrap();
	let vtxo = wallet.get_full_vtxo(vtxo.id()).await.unwrap();
	(vtxo, wallet.payout_script(), wallet.mailbox_identifier())
}

/// The spendable VTXOs of `wallet`.
async fn full_vtxos(wallet: &Wallet) -> Vec<Vtxo<Full>> {
	let mut vtxos = Vec::new();
	for vtxo in wallet.spendable_vtxos().await.unwrap() {
		vtxos.push(wallet.get_full_vtxo(vtxo.id()).await.unwrap());
	}
	vtxos
}

/// Wait until both daemons reached `tip`.
async fn sync(srv: &Captaind, tip: BlockHeight) {
	srv.wait_for_sync_height(tip).await;
	srv.watchmand().wait_for_sync_height(tip).await;
}

/// Mine `blocks` blocks and wait for both daemons.
async fn mine(ctx: &TestContext, srv: &Captaind, blocks: u32) -> BlockHeight {
	let tip = ctx.generate_blocks(blocks).await;
	sync(srv, tip).await;
	tip
}

/// Mine up to one block past `height` and wait for both daemons.
async fn mine_past(ctx: &TestContext, srv: &Captaind, height: BlockHeight) -> BlockHeight {
	let tip = ctx.bitcoind().get_block_count().await as u32;
	assert!(tip <= height.to_u32(), "already past {height}");
	mine(ctx, srv, height.to_u32() + 1 - tip).await
}

/// Send `amount` to the watchman's wallet and confirm it twice.
async fn fund_watchman(ctx: &TestContext, srv: &Captaind, amount: Amount) -> OutPoint {
	let address = srv.watchmand().wait_wallet_address().await;
	let txid = ctx.bitcoind().fund_addr(&address, amount).await;
	let tx = ctx.bitcoind().await_transaction(txid).await;
	let vout = tx.output.iter().position(|out| out.script_pubkey == address.script_pubkey()).unwrap();
	ctx.generate_blocks(2).await;
	OutPoint::new(txid, vout as u32)
}

/// The script of the operator's sweep address.
fn operator_script(srv: &Captaind) -> ScriptBuf {
	let config = srv.watchmand().config();
	config.sweep_address.clone().unwrap().require_network(config.network).unwrap().script_pubkey()
}

/// The fee `tx` pays to miners.
async fn miner_fee(ctx: &TestContext, tx: &Transaction) -> Amount {
	let mut total = Amount::ZERO;
	for input in &tx.input {
		let previous = ctx.bitcoind().await_transaction(input.previous_output.txid).await;
		total += previous.output[input.previous_output.vout as usize].value;
	}
	total.checked_sub(tx.output.iter().map(|output| output.value).sum::<Amount>()).unwrap()
}

/// Assert that `tx` has one output paying `amount` to `script` and return it.
fn payout_output(tx: &Transaction, script: &ScriptBuf, amount: Amount) -> OutPoint {
	let outputs = tx.output.iter().enumerate()
		.filter(|(_, output)| output.script_pubkey == *script).collect::<Vec<_>>();
	assert_eq!(outputs.len(), 1, "one output pays {script}");
	assert_eq!(outputs[0].1.value, amount);
	OutPoint::new(tx.compute_txid(), outputs[0].0 as u32)
}

/// Mine six blocks on `tx` and assert that its output to `script` pays
/// `amount` and is unspent.
async fn assert_paid(ctx: &TestContext, srv: &Captaind, tx: &Transaction, script: &ScriptBuf, amount: Amount) {
	let point = payout_output(tx, script, amount);
	assert_eq!(ctx.bitcoind().await_transaction(point.txid).await, *tx);
	mine(ctx, srv, 6).await;
	let output = ctx.bitcoind().sync_client().get_tx_out(&point.txid, point.vout, Some(true)).unwrap()
		.expect("the payout output is unspent");
	assert!(output.confirmations >= 6);
	assert_eq!(output.value, amount);
}

/// Assert that `tx` is six blocks deep on the current chain, and return its block.
fn assert_six_deep(ctx: &TestContext, tx: &Transaction) -> BlockRef {
	let core = ctx.bitcoind().sync_client();
	let info = core.custom_get_raw_transaction_info(tx.compute_txid(), None).unwrap().unwrap();
	assert!(info.confirmations.unwrap_or(0) >= 6);
	let hash = info.blockhash.unwrap();
	let height = core.get_block_header_info(&hash).unwrap().height;
	assert_eq!(core.get_block_hash(height as u64).unwrap(), hash);
	BlockRef { height: BlockHeight::new(height as u32), hash }
}

/// Wait until the highest block the watchman stored is `point`.
async fn wait_watchman_tip(db: &Db, point: BlockRef) {
	async {
		while db.read(async |t| t.get_highest_block(BlockTable::Watchmand).await).await.unwrap() != Some(point) {
			tokio::time::sleep(poll_interval()).await;
		}
	}.wait_millis(30_000).await
}

/// Wait until both daemons reached Core's tip and the watchman stored it.
async fn wait_synced(ctx: &TestContext, srv: &Captaind, db: &Db) {
	let tip = server::bitcoind::tip(&ctx.bitcoind().async_client()).await.unwrap();
	sync(srv, tip.height).await;
	wait_watchman_tip(db, tip).await;
}

/// The payout share of one VTXO in one allocation.
#[derive(Debug, Clone, PartialEq, Eq)]
struct PayoutShare {
	allocation: i64,
	status: String,
	owner: Option<String>,
	gross: Amount,
	fee: Amount,
	payout: Amount,
	tx: Option<Transaction>,
	published: bool,
}

/// Every payout share of `vtxo`, in allocation order. The owner is `None`
/// for a share that goes to the operator.
async fn payout_shares(db: &Db, vtxo: VtxoId) -> Vec<PayoutShare> {
	let rows = db.read(async |t| Ok(t.query("
		SELECT a.id, a.status, a.payout_tx, a.broadcast_at IS NOT NULL AS published,
			c.disposition, c.owner_mailbox, c.gross_sat, c.fee_sat, c.payout_sat
		FROM v_expiry_payout_state a
		JOIN expiry_payout_vtxo c ON c.expiry_payout_id = a.id
		WHERE c.vtxo_id = $1
		ORDER BY a.id
	", &[&vtxo.to_string()]).await?)).await.unwrap();
	rows.into_iter().map(|row| {
		let owner = row.get::<_, &str>("disposition") == "owner";
		PayoutShare {
			allocation: row.get("id"),
			status: row.get("status"),
			owner: if owner { row.get("owner_mailbox") } else { None },
			gross: Amount::from_sat(row.get::<_, i64>("gross_sat") as u64),
			fee: Amount::from_sat(row.get::<_, i64>("fee_sat") as u64),
			payout: Amount::from_sat(row.get::<_, i64>("payout_sat") as u64),
			tx: row.get::<_, Option<&[u8]>>("payout_tx").map(|raw| deserialize(raw).unwrap()),
			published: row.get("published"),
		}
	}).collect()
}

/// The payout share of `vtxo` in its allocation that is not conflicted.
async fn current_share(db: &Db, vtxo: VtxoId) -> Option<PayoutShare> {
	let mut shares = payout_shares(db, vtxo).await;
	shares.retain(|share| share.status != "conflicted");
	assert!(shares.len() <= 1, "{vtxo} has more than one current payout");
	shares.pop()
}

/// The published payout of `vtxo`, if any.
async fn published_payout(db: &Db, vtxo: VtxoId) -> Option<(i64, Transaction)> {
	current_share(db, vtxo).await.filter(|share| share.published)
		.map(|share| (share.allocation, share.tx.unwrap()))
}

/// Wait for the published payout of `vtxo`.
async fn wait_payout(db: &Db, vtxo: VtxoId) -> (i64, Transaction) {
	async {
		loop {
			if let Some(payout) = published_payout(db, vtxo).await {
				break payout;
			}
			tokio::time::sleep(poll_interval()).await;
		}
	}.wait_millis(30_000).await
}

/// Wait for the published payout of `vtxo` while mining a block on every
/// pass, for payouts that wait for exit transactions to confirm.
async fn mine_until_payout(ctx: &TestContext, srv: &Captaind, db: &Db, vtxo: VtxoId) -> Transaction {
	for _ in 0..30 {
		if let Some((_, tx)) = published_payout(db, vtxo).await {
			return tx;
		}
		srv.watchmand().trigger_sweep().await;
		mine(ctx, srv, 1).await;
	}
	panic!("{vtxo} was not paid out");
}

/// Wait until `vtxo` has a payout share.
async fn wait_decided(db: &Db, vtxo: VtxoId) -> PayoutShare {
	async {
		loop {
			if let Some(share) = current_share(db, vtxo).await {
				break share;
			}
			tokio::time::sleep(poll_interval()).await;
		}
	}.wait_millis(30_000).await
}

/// The signed transactions of `allocation` and the fee each pays.
async fn payout_attempts(db: &Db, allocation: i64) -> BTreeMap<Txid, Amount> {
	db.read(async |t| Ok(t.query("
		SELECT txid, fee_sat FROM expiry_payout_attempt WHERE expiry_payout_id = $1
	", &[&allocation]).await?)).await.unwrap().into_iter().map(|row| (
		row.get::<_, &str>("txid").parse().unwrap(),
		Amount::from_sat(row.get::<_, i64>("fee_sat") as u64),
	)).collect()
}

/// The allocations that spend `vtxo` as an input of their payout.
async fn input_allocations(db: &Db, vtxo: VtxoId) -> Vec<i64> {
	db.read(async |t| Ok(t.query("
		SELECT expiry_payout_id FROM expiry_payout_input WHERE vtxo_id = $1
	", &[&vtxo.to_string()]).await?)).await.unwrap().into_iter().map(|row| row.get(0)).collect()
}

/// The number of allocations the server stored.
async fn allocation_count(db: &Db) -> i64 {
	db.read(async |t| Ok(t.query_one("SELECT COUNT(*) FROM expiry_payout", &[]).await?.get(0)))
		.await.unwrap()
}

/// Record VTXOs as decided for an expiry payout: one operator share each in
/// a new allocation.
pub(crate) async fn decide_for_payout(t: &tokio_postgres::Transaction<'_>, ids: &[String]) -> anyhow::Result<()> {
	let id: i64 = t.query_one("INSERT INTO expiry_payout(expiry_height) VALUES(0) RETURNING id", &[])
		.await?.get(0);
	t.execute("
		INSERT INTO expiry_payout_vtxo(expiry_payout_id, vtxo_id, disposition, gross_sat, fee_sat, payout_sat, replannable)
		SELECT $1, UNNEST($2::TEXT[]), 'operator', 1, 0, 0, FALSE
	", &[&id, &ids]).await?;
	Ok(())
}

/// Wait until `allocation` is confirmed in `hash` and both daemons reached `point`.
async fn wait_for_confirmation(db: &Db, allocation: i64, point: BlockRef, hash: BlockHash) {
	async {
		loop {
			let ready = db.read(async |t| {
				let row = t.query_one("
					SELECT status, (SELECT hash FROM watchmand_block WHERE height = confirmed_height) AS hash
					FROM v_expiry_payout_state WHERE id = $1
				", &[&allocation]).await?;
				Ok(t.get_highest_block(BlockTable::Captaind).await? == Some(point)
					&& t.get_highest_block(BlockTable::Watchmand).await? == Some(point)
					&& row.get::<_, &str>("status") == "confirmed"
					&& row.get::<_, Option<String>>("hash") == Some(hash.to_string()))
			}).await.unwrap();
			if ready {
				break;
			}
			tokio::time::sleep(poll_interval()).await;
		}
	}.wait_millis(30_000).await
}

/// Wait until another connection waits on a lock to run `prefix`.
async fn wait_for_query_lock(tx: &Tx<'_>, prefix: &str) -> anyhow::Result<()> {
	async {
		loop {
			tx.query_one("SELECT pg_stat_clear_snapshot()", &[]).await?;
			let waiting = tx.query_one("
				SELECT EXISTS(
					SELECT 1
					FROM pg_stat_activity
					WHERE datname = current_database()
					AND wait_event_type = 'Lock'
					AND ltrim(query, chr(9) || chr(10) || chr(13) || ' ') LIKE $1)
			", &[&prefix]).await?.get::<_, bool>(0);
			if waiting {
				return Ok::<_, anyhow::Error>(());
			}
			tokio::time::sleep(poll_interval()).await;
		}
	}.wait_millis(15_000).await
}

/// The transaction that spent `vtxo` on chain, as the server saw it.
async fn onchain_spend(db: &Db, vtxo: VtxoId) -> Option<Txid> {
	db.read(async |t| Ok(t.query_one("SELECT onchain_spent_txid FROM vtxo WHERE vtxo_id = $1",
		&[&vtxo.to_string()]).await?.get::<_, Option<String>>(0))).await.unwrap()
		.map(|txid| txid.parse().unwrap())
}

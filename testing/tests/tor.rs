
use bitcoincore_rpc::Auth;

use ark_testing::{btc, sat, Bark, Captaind, TestContext, Tor, TorConfig, HiddenServiceConfig};
use ark_testing::constants::{BOARD_CONFIRMATIONS};
use ark_testing::context::LightningPaymentSetup;
use ark_testing::util::FutureExt;

const SERVER_VIRTUAL_PORT: u16 = 3535;
const CHAIN_VIRTUAL_PORT: u16 = 8080;

async fn setup(test_name: &str) -> (TestContext, Captaind, Tor, LightningPaymentSetup) {
	let ctx = TestContext::new(test_name).await;
	let lightning = ctx.new_lightning_setup("lightningd").await;
	let srv = ctx.new_captaind_with_funds("server", Some(&lightning.sender), btc(10)).await;

	let chain_target_port = if let Some(ref electrs) = ctx.electrs {
		electrs.rest_port()
	} else {
		ctx.bitcoind().rpc_port()
	};

	let mut tor = Tor::new("tor", TorConfig {
		datadir: ctx.datadir.join("tor"),
		hidden_services: vec![
			HiddenServiceConfig {
				name: "server".into(),
				virtual_port: SERVER_VIRTUAL_PORT,
				target_port: srv.rpc_port(),
			},
			HiddenServiceConfig {
				name: "chain".into(),
				virtual_port: CHAIN_VIRTUAL_PORT,
				target_port: chain_target_port,
			},
		],
	});
	tor.start().await.expect("failed to start tor");

	(ctx, srv, tor, lightning)
}

async fn new_tor_bark(
	ctx: &TestContext,
	name: &str,
	srv: &Captaind,
	tor: &Tor,
	onion_server: bool,
	onion_chain: bool,
) -> Bark {
	let socks = tor.socks_address();
	let server_onion = format!(
		"http://{}:{}", tor.onion_address("server"), SERVER_VIRTUAL_PORT,
	);
	let chain_onion = format!(
		"http://{}:{}", tor.onion_address("chain"), CHAIN_VIRTUAL_PORT,
	);
	ctx.try_new_bark_with_cfg(name, srv, |cfg| {
		if onion_server {
			cfg.server_address = server_onion.clone();
		}
		if onion_chain {
			if cfg.esplora_address.is_some() {
				cfg.esplora_address = Some(chain_onion.clone());
			} else {
				cfg.bitcoind_address = Some(chain_onion.clone());
				match ctx.bitcoind().auth() {
					Auth::UserPass(u, p) => {
						cfg.bitcoind_user = Some(u.clone());
						cfg.bitcoind_pass = Some(p.clone());
					}
					Auth::CookieFile(path) => {
						cfg.bitcoind_cookiefile = Some(path.clone());
					}
					a => panic!("unexpected bitcoind auth: {:?}", a),
				}
			}
		}
		if onion_server || onion_chain {
			cfg.socks5_proxy = Some(socks.clone());
		}
	}).await.expect("failed to create bark")
}

async fn smoke_test(
	ctx: &TestContext,
	srv: &Captaind,
	lightning: LightningPaymentSetup,
	bark1: Bark,
	bark2: Bark,
) {
	let fund_amount = sat(1_000_000);
	let board_amount = sat(900_000);

	// Fund and board both barks
	ctx.fund_bark(&bark1, fund_amount).await;
	ctx.fund_bark(&bark2, fund_amount).await;

	bark1.board(board_amount).await;
	bark2.board(board_amount).await;

	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	assert_eq!(bark1.spendable_balance().await, board_amount);
	assert_eq!(bark2.spendable_balance().await, board_amount);

	// Refresh round — give bark time to connect over Tor before triggering
	bark1.send_onchain(bark1.get_onchain_address().await, sat(400_000)).await;
	ctx.generate_blocks(1).await;
	assert_eq!(bark1.onchain_balance().await, sat(499_228));
	assert_eq!(bark1.spendable_balance().await, sat(499_062));

	// OOR send: bark1 -> bark2
	bark1.send_oor(bark2.address().await, sat(50_000)).await;
	assert_eq!(bark1.spendable_balance().await, sat(449_062));
	assert_eq!(bark2.spendable_balance().await, sat(950_000));

	// OOR send: bark2 -> bark1
	bark2.send_oor(bark1.address().await, sat(50_000)).await;
	assert_eq!(bark1.spendable_balance().await, sat(499_062));
	assert_eq!(bark2.spendable_balance().await, sat(900_000));

	// LN send to external node
	lightning.sync().await;
	srv.wait_for_vtxopool(&ctx).await;
	let invoice = lightning.receiver.invoice(Some(sat(10_000)), "ln_send_ext", "test").await;
	bark1.pay_lightning_wait(&invoice, None).await;
	assert_eq!(bark1.spendable_balance().await, sat(489_062));

	// LN send bark1 -> bark2
	let invoice_info = bark2.bolt11_invoice(sat(10_000)).await;
	tokio::join!(
		bark1.pay_lightning_wait(&invoice_info.invoice, None),
		bark2.lightning_receive(&invoice_info.invoice).wait_millis(60_000),
	);
	assert_eq!(bark1.spendable_balance().await, sat(479_062));
	assert_eq!(bark2.spendable_balance().await, sat(910_000));

	// LN send bark2 -> bark1
	let invoice_info = bark1.bolt11_invoice(sat(10_000)).await;
	tokio::join!(
		bark2.pay_lightning_wait(&invoice_info.invoice, None),
		bark1.lightning_receive(&invoice_info.invoice).wait_millis(60_000),
	);
	assert_eq!(bark1.spendable_balance().await, sat(489_062));
	assert_eq!(bark2.spendable_balance().await, sat(900_000));
}

#[tokio::test]
async fn tor_onion_server_clearnet_chain() {
	let (ctx, srv, tor, lightning) = setup("tor/onion_server_clearnet_chain").await;
	let bark1 = new_tor_bark(&ctx, "bark1", &srv, &tor, true, false).await;
	let bark2 = new_tor_bark(&ctx, "bark2", &srv, &tor, false, false).await;
	smoke_test(&ctx, &srv, lightning, bark1, bark2).await;
}

#[tokio::test]
async fn tor_clearnet_server_onion_chain() {
	let (ctx, srv, tor, lightning) = setup("tor/clearnet_server_onion_chain").await;
	let bark1 = new_tor_bark(&ctx, "bark1", &srv, &tor, false, true).await;
	let bark2 = new_tor_bark(&ctx, "bark2", &srv, &tor, false, false).await;
	smoke_test(&ctx, &srv, lightning, bark1, bark2).await;
}

#[tokio::test]
async fn tor_onion_server_onion_chain() {
	let (ctx, srv, tor, lightning) = setup("tor/onion_server_onion_chain").await;
	let bark1 = new_tor_bark(&ctx, "bark1", &srv, &tor, true, true).await;
	let bark2 = new_tor_bark(&ctx, "bark2", &srv, &tor, false, false).await;
	smoke_test(&ctx, &srv, lightning, bark1, bark2).await;
}

#[tokio::test]
async fn tor_double_onion_server_onion_chain() {
	let (ctx, srv, tor, lightning) = setup("tor/tor_double_onion_server_onion_chain").await;
	let bark1 = new_tor_bark(&ctx, "bark1", &srv, &tor, true, true).await;
	let bark2 = new_tor_bark(&ctx, "bark2", &srv, &tor, true, true).await;
	smoke_test(&ctx, &srv, lightning, bark1, bark2).await;
}

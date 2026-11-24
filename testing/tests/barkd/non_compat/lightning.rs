use ark_testing::TestContext;

/// An unavailable wallet database cannot establish that a receive is missing.
#[tokio::test]
async fn lightning_receive_status_checks_wallet_before_returning_not_found() {
	let ctx = TestContext::new("barkd/lightning_receive_status_checks_wallet_before_returning_not_found").await;
	let srv = ctx.captaind("server").create().await;
	let barkd = ctx.barkd("barkd", &srv).cfg(|cfg| cfg.daemon_manual_sync = true).create().await;
	let config = barkd.client_config();
	let hash = "0000000000000000000000000000000000000000000000000000000000000000";
	let url = format!("{}/api/v1/lightning/receives/{hash}", barkd.base_url());

	let datadir = barkd.datadir();
	let offline = ctx.datadir.join("wallet-offline");
	std::fs::rename(&datadir, &offline).unwrap();
	let unavailable = config.client.get(&url).send().await;
	std::fs::rename(&offline, &datadir).unwrap();
	assert_eq!(unavailable.unwrap().status(), reqwest::StatusCode::INTERNAL_SERVER_ERROR);

	let missing = config.client.get(&url).send().await.unwrap();
	assert_eq!(missing.status(), reqwest::StatusCode::NOT_FOUND);
	assert_eq!(missing.json::<serde_json::Value>().await.unwrap(), serde_json::json!({
		"resources": [hash],
		"message": format!("not found [resources={hash}]: Lightning receive not found: no pending lightning receive found for this payment hash"),
	}));
}

use ark_testing::TestContext;

#[tokio::test]
async fn bark_version() {
	let ctx = TestContext::new("bark/bark_version").await;
	let srv = ctx.new_captaind("server", None).await;
	let bark1 = ctx.new_bark("bark1", &srv).await;
	let result = bark1.run(&[&"--version"]).await;
	assert!(result.starts_with("bark "));
}

#[tokio::test]
async fn bark_ark_info() {
	let ctx = TestContext::new("bark/bark_ark_info").await;
	let srv = ctx.new_captaind("server", None).await;
	let bark1 = ctx.new_bark("bark1", &srv).await;
	let result = bark1.run(&[&"ark-info"]).await;
	serde_json::from_str::<bark_json::cli::ArkInfo>(&result).expect("should deserialise");
}

#[tokio::test]
async fn bark_config_json() {
	let ctx = TestContext::new("bark/bark_config_json").await;
	let srv = ctx.new_captaind("server", None).await;
	let bark1 = ctx.new_bark("bark1", &srv).await;
	let result = bark1.run(&[&"config"]).await;
	serde_json::from_str::<bark::Config>(&result).expect("should deserialise");
}

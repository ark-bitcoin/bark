
use server_rpc::client::ACCESS_TOKEN_HEADER;

use ark_testing::{require_bark_version, TestContext};
use ark_testing::daemon::captaind;


#[tokio::test]
async fn access_token_is_sent() {
	require_bark_version!(> "0.1.2");

	let ctx = TestContext::new("bark/access_token_is_sent").await;
	let srv = ctx.captaind("server").create().await;

	const TOKEN: &str = "super-duper-secret";

	#[derive(Clone)]
	struct TokenProxy;

	#[async_trait::async_trait]
	impl captaind::proxy::ArkRpcProxy for TokenProxy {
		async fn on_request(
			&self, metadata: &tonic::metadata::MetadataMap,
		) -> Result<(), tonic::Status> {
			let token = metadata.get(ACCESS_TOKEN_HEADER).expect("token not set")
				.to_str().unwrap();
			assert_eq!(token, TOKEN);
			Ok(())
		}
	}

	#[async_trait::async_trait]
	impl captaind::proxy::MailboxRpcProxy for TokenProxy {
		async fn on_request(
			&self, metadata: &tonic::metadata::MetadataMap,
		) -> Result<(), tonic::Status> {
			let token = metadata.get(ACCESS_TOKEN_HEADER).expect("token not set")
				.to_str().unwrap();
			assert_eq!(token, TOKEN);
			Ok(())
		}
	}

	let proxy = srv.start_proxy_no_mailbox(TokenProxy).await;

	let bark = ctx.bark("bark", &proxy.address)
		.cfg(|cfg| cfg.server_access_token = Some(TOKEN.to_string()))
		.create().await;

	bark.offchain_balance().await;
}

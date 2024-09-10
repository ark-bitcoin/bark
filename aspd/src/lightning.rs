use std::fs;

use anyhow::Context;
use std::sync::Arc;

use tonic::transport::{Channel, ClientTlsConfig, Certificate, Identity};

use tokio::sync::broadcast;

use bark_cln::grpc;
use bark_cln::grpc::node_client::NodeClient;
use bark_cln::subscribe_sendpay::{SubscribeSendpay, SendpaySubscriptionItem};

use crate::ClnConfig;

impl ClnConfig {

	pub async fn grpc_client(&self) ->  anyhow::Result<NodeClient<tonic::transport::Channel>> {
		// Client doesn't support grpc over http
		// We need to use https using m-TLS authentication
		let ca_pem = fs::read_to_string(&self.grpc_server_cert_path)?;
		let id_pem = fs::read_to_string(&self.grpc_client_cert_path)?;
		let id_key = fs::read_to_string(&self.grpc_client_key_path)?;

		let channel = Channel::builder(self.grpc_uri.clone().into())
			.tls_config(ClientTlsConfig::new()
				.ca_certificate(Certificate::from_pem(ca_pem))
				.identity(Identity::from_pem(&id_pem, &id_key))
				)?
			.connect()
			.await?;

		let client = NodeClient::new(channel);
		Ok(client)
	}

	/// Verifies if the configuration is valid
	pub async fn check_connection(&self) -> anyhow::Result<()> {
		let mut grpc_client = self.grpc_client().await?;
		let _ = grpc_client.getinfo(grpc::GetinfoRequest{}).await?.into_inner();
		Ok(())
	}
}

pub async fn run_process_sendpay_updates(
	cln_config: &ClnConfig,
	tx: broadcast::Sender<SendpaySubscriptionItem>,
) -> anyhow::Result<()> {
	// Get the grpc-client
	let mut client = cln_config.grpc_client().await.context("Failed to connect to lightningd over grpc")?;

	// TODO: I now request the latest start-index from cln
	// However, it is nicer to store the start-indcies somewhere in the database
	// This would allow us to replay all send-pays if aspd crashes and cln keeps running
	let updated_index = client.wait(grpc::WaitRequest {
		subsystem: grpc::wait_request::WaitSubsystem::Sendpays as i32,
		indexname: grpc::wait_request::WaitIndexname::Updated as i32,
		nextvalue: 0
	}).await?.into_inner().updated() + 1;
	let created_index = client.wait(grpc::WaitRequest {
		subsystem: grpc::wait_request::WaitSubsystem::Sendpays as i32,
		indexname: grpc::wait_request::WaitIndexname::Created as i32,
		nextvalue: 0
	}).await?.into_inner().created() + 1;

	info!("Start listening for sendpays for created_index={}, updated_index={}",
		created_index, updated_index,
	);

	let subscribe_send_pay = SubscribeSendpay {
		client: client.clone(),
		created_index: created_index,
		update_index: updated_index,
	};

	subscribe_send_pay.run(tx).await.context("sendpay processor shut ")?;
	Ok(())
}

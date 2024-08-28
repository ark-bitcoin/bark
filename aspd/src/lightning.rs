use std::fs;

use tonic::transport::{Channel, ClientTlsConfig, Certificate, Identity};

use bark_cln::grpc;
use bark_cln::grpc::node_client::NodeClient;

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

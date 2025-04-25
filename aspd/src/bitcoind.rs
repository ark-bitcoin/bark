

pub use bdk_bitcoind_rpc::bitcoincore_rpc::RpcApi;

use bdk_bitcoind_rpc::bitcoincore_rpc::{Auth, Client, Error};


/// Clonable bitcoind rpc client.
#[derive(Debug)]
pub struct BitcoinRpcClient {
	client: Client,
	url: String,
	auth: Auth,
}

impl BitcoinRpcClient {
	pub fn new(url: &str, auth: Auth) -> anyhow::Result<Self> {
		Ok(BitcoinRpcClient {
			client: Client::new(url, auth.clone())?,
			url: url.to_owned(),
			auth: auth,
		})
	}
}

impl RpcApi for BitcoinRpcClient {
	fn call<T: for<'a> serde::de::Deserialize<'a>>(
		&self, cmd: &str, args: &[serde_json::Value],
	) -> Result<T, Error> {
		self.client.call(cmd, args)
	}
}

impl Clone for BitcoinRpcClient {
	fn clone(&self) -> Self {
		BitcoinRpcClient {
			client: Client::new(&self.url, self.auth.clone()).expect("we did it before"),
			url: self.url.clone(),
			auth: self.auth.clone(),
		}
	}
}
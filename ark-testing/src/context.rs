use std::path::PathBuf;
use std::time::Duration;

use bitcoin::{Amount, FeeRate, Network, Txid};
use bitcoincore_rpc::RpcApi;
use tokio::fs;

use crate::util::test_data_directory;
use crate::{
	Aspd, AspdConfig, Bitcoind, BitcoindConfig, Bark, BarkConfig, Lightningd, LightningdConfig,
};

pub trait ToAspUrl {
	fn asp_url(&self) -> String;
}
impl ToAspUrl for Aspd {
	fn asp_url(&self) -> String { self.asp_url() }
}
impl ToAspUrl for String {
	fn asp_url(&self) -> String { self.clone() }
}
impl ToAspUrl for str {
	fn asp_url(&self) -> String { self.to_owned() }
}

pub struct TestContext {
	#[allow(dead_code)]
	pub name: String,
	pub datadir: PathBuf,

	pub bitcoind: Bitcoind,
}

impl TestContext {
	pub async fn new(name: impl AsRef<str>) -> Self {
		crate::util::init_logging().expect("Logging can be initialized");

		let name = name.as_ref();
		let datadir = test_data_directory().await.join(name);

		if datadir.exists() {
			fs::remove_dir_all(&datadir).await.unwrap();
		}
		fs::create_dir_all(&datadir).await.unwrap();

		let bitcoind = {
			let mut bitcoind = Bitcoind::new(
				"bitcoind".to_string(),
				BitcoindConfig {
					datadir: datadir.join("bitcoind"),
					txindex: true,
					network: Network::Regtest,
					fallback_fee: FeeRate::from_sat_per_vb(1).unwrap(),
					relay_fee: None,
				},
				None
			);
			bitcoind.start().await.unwrap();
			bitcoind
		};

		bitcoind.prepare_funds().await;

		TestContext {
			name: name.to_string(),
			datadir,
			bitcoind
		}
	}

	pub fn bitcoind_default_cfg(&self, name: impl AsRef<str>) -> BitcoindConfig {
		let datadir = self.datadir.join(name.as_ref());
		BitcoindConfig {
			datadir,
			txindex: true,
			network: Network::Regtest,
			fallback_fee: FeeRate::from_sat_per_vb(1).unwrap(),
			relay_fee: None,
		}
	}

	pub async fn bitcoind(&mut self, name: impl AsRef<str>) -> Bitcoind {
		self.bitcoind_with_cfg(name.as_ref(), self.bitcoind_default_cfg(name.as_ref())).await
	}

	pub async fn bitcoind_with_cfg(&self, name: impl AsRef<str>, cfg: BitcoindConfig) -> Bitcoind {
		let mut bitcoind = Bitcoind::new(name.as_ref().to_string(), cfg, Some(self.bitcoind.p2p_url()));
		bitcoind.start().await.unwrap();
		bitcoind.init_wallet().await;
		bitcoind
	}

	pub async fn aspd_with_cfg(&mut self, name: impl AsRef<str>, cfg: AspdConfig) -> Aspd {
		let bitcoind = self.bitcoind(format!("{}_bitcoind", name.as_ref())).await;
		let mut ret = Aspd::new(name, bitcoind, cfg);
		ret.start().await.unwrap();
		ret
	}

	pub async fn aspd_default_cfg(
		&self,
		name: impl AsRef<str>,
		lightningd: Option<&Lightningd>,
	) -> AspdConfig {
		let datadir = self.datadir.join(name.as_ref());
		let mut aspd_config = AspdConfig {
			datadir: datadir.clone(),
			round_interval: Duration::from_millis(500),
			round_submit_time: Duration::from_millis(500),
			round_sign_time: Duration::from_millis(500),
			vtxo_expiry_delta: 1 * 24 * 6,
			vtxo_exit_delta: 2 * 6,
			sweep_threshold: Amount::from_sat(1_000_000),
			nb_round_nonces: 100,
			use_bitcoind_auth_pass: false,
			cln_grpc_uri: None,
			cln_grpc_server_cert_path: None,
			cln_grpc_client_cert_path: None,
			cln_grpc_client_key_path: None,
		};

		if lightningd.is_some() {
			aspd_config.configure_lighting(lightningd.unwrap()).await;
		};

		aspd_config
	}

	pub async fn fund_asp(&self, asp: &Aspd, amount: Amount) -> Txid {
		info!("Fund {} {}", asp.name(), amount);
		let address = asp.get_funding_address().await;
		let txid = self.bitcoind.fund_addr(address, amount).await;

		// wait for funding transaction to appear in mempool
		let client = asp.bitcoind().sync_client();
		while client.get_raw_transaction(&txid, None).is_err() {
			tokio::time::sleep(Duration::from_millis(200)).await;
		}

		asp.get_admin_client().await.wallet_status(aspd_rpc::Empty {}).await
			.expect("error calling wallet status after funding apsd");
		txid
	}

	/// Send `amount` to an onchain address of this Bark client.
	pub async fn fund_bark(&self, bark: &Bark, amount: Amount) -> Txid {
		info!("Fund {} {}", bark.name(), amount);
		let address = bark.get_onchain_address().await;
		let txid = self.bitcoind.fund_addr(address, amount).await;

		// wait for funding transaction to appear in mempool
		let client = bark.bitcoind().sync_client();
		while client.get_raw_transaction(&txid, None).is_err() {
			tokio::time::sleep(Duration::from_millis(200)).await;
		}

		txid
	}

	pub async fn fund_lightning(&self, lightning: &Lightningd, amount: Amount) -> Txid {
		info!("Fund {} {}", lightning.name(), amount);
		let address = lightning.get_onchain_address().await;

		let client = self.bitcoind.sync_client();
		client.send_to_address(
			&address, amount, None, None, None, None, None, None,
		).unwrap()
	}
	
	/// Creates new aspd without any funds.
	pub async fn aspd(
		&mut self,
		name: impl AsRef<str>,
		lightningd: Option<&Lightningd>,
	) -> Aspd {
		let name = name.as_ref();
		self.aspd_with_cfg(name, self.aspd_default_cfg(name, lightningd).await).await
	}

	/// Creates new aspd and immediately funds it. Waits until the aspd's bitcoind
	/// receives funding transaction.
	pub async fn aspd_with_funds(
		&mut self,
		name: impl AsRef<str>,
		lightningd: Option<&Lightningd>,
		amount: Amount
	) -> Aspd {
		let asp = self.aspd(name, lightningd).await;
		let _txid = self.fund_asp(&asp, amount).await;
		asp
	}
	
	pub async fn try_bark(
		&mut self,
		name: impl AsRef<str>,
		aspd: &dyn ToAspUrl,
	) -> anyhow::Result<Bark> {
		let datadir = self.datadir.join(name.as_ref());

		let bitcoind = self.bitcoind(format!("{}_bitcoind", name.as_ref())).await;

		let cfg = BarkConfig {
			datadir,
			asp_url: aspd.asp_url(),
			network: String::from("regtest"),
		};
		Bark::try_new(name, bitcoind, cfg).await
	}

	/// Creates new bark without any funds.
	pub async fn bark(&mut self, name: impl AsRef<str>, aspd: &dyn ToAspUrl) -> Bark {
		self.try_bark(name, aspd).await.unwrap()
	}

	/// Creates new bark and immediately funds it. Waits until the bark's bitcoind
	/// receives funding transaction.
	pub async fn bark_with_funds(&mut self, name: impl AsRef<str>, aspd: &dyn ToAspUrl, amount: Amount) -> Bark {
		let bark = self.try_bark(name, aspd).await.unwrap();
		let _txid = self.fund_bark(&bark, amount).await;
		bark
	}

	pub async fn lightningd(&mut self, name: impl AsRef<str>) -> Lightningd {
		let datadir = self.datadir.join(name.as_ref());

		let bitcoind = self.bitcoind(format!("{}_bitcoind", name.as_ref())).await;

		let cfg = LightningdConfig {
			network: String::from("regtest"),
			bitcoin_dir: bitcoind.datadir(),
			bitcoin_rpcport: bitcoind.rpc_port(),
			lightning_dir: datadir.clone()
		};

		let mut ret = Lightningd::new(name, bitcoind, cfg);
		ret.start().await.unwrap();
		ret
	}
}

impl Drop for TestContext {
	fn drop(&mut self) {
		log::info!("Textcontext: Datadir is located at {:?}", self.datadir);
	}
}

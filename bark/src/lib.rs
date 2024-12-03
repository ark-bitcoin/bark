
pub extern crate lightning_invoice;
pub extern crate lnurl as lnurllib;

#[macro_use] extern crate anyhow;
#[macro_use] extern crate log;
#[macro_use] extern crate serde;

mod db;
mod exit;
use ark::musig::{MusigPubNonce, MusigSecNonce};
use bitcoin::hex::DisplayHex;
pub use exit::ExitStatus;
mod lnurl;
mod onchain;
mod psbtext;
mod vtxo_state;


use std::time::Duration;
use std::{fs, iter};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::str::FromStr;

use anyhow::{bail, Context};
use bitcoin::{bip32, secp256k1, Address, Amount, FeeRate, Network, OutPoint, Psbt, Transaction, Txid, Weight};
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{rand, schnorr, Keypair, PublicKey};
use lnurllib::lightning_address::LightningAddress;
use lightning_invoice::Bolt11Invoice;
use serde::Serialize;
use tokio_stream::StreamExt;

use ark::{musig, BaseVtxo, OffboardRequest, PaymentRequest, VtxoRequest, Vtxo, VtxoId, VtxoSpec};
use ark::connectors::ConnectorChain;
use ark::tree::signed::{SignedVtxoTree, VtxoTreeSpec};
use aspd_rpc_client as rpc;

use crate::vtxo_state::VtxoState;

/// The file name of the config file.
const CONFIG_FILE: &str = "config.json";

/// File name of the database file.
const DB_FILE: &str = "db.sqlite";

lazy_static::lazy_static! {
	/// Global secp context.
	static ref SECP: secp256k1::Secp256k1<secp256k1::All> = secp256k1::Secp256k1::new();
}

#[derive(Clone)]
pub struct ArkInfo {
	pub asp_pubkey: PublicKey,
	pub nb_round_nonces: usize,
	pub vtxo_expiry_delta: u16,
	pub vtxo_exit_delta: u16,
}

/// Configuration of the Bark wallet.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct Config {
	/// The Bitcoin network to run Bark on.
	///
	/// Default value: signet.
	pub network: Network,

	/// The address of your ASP.
	pub asp_address: String,

	/// The address of the Esplora HTTP server to use.
	///
	/// Either this or the `bitcoind_address` field has to be provided.
	pub esplora_address: Option<String>,

	/// The address of the bitcoind RPC server to use.
	///
	/// Either this or the `esplora_address` field has to be provided.
	pub bitcoind_address: Option<String>,

	/// The path to the bitcoind rpc cookie file.
	///
	/// Only used with `bitcoind_address`.
	pub bitcoind_cookiefile: Option<PathBuf>,

	/// The bitcoind RPC username.
	///
	/// Only used with `bitcoind_address`.
	pub bitcoind_user: Option<String>,

	/// The bitcoind RPC password.
	///
	/// Only used with `bitcoind_address`.
	pub bitcoind_pass: Option<String>,

	/// The number of blocks before expiration to refresh vtxos.
	///
	/// Default value: 288 (48 hrs)
	pub vtxo_refresh_threshold: u32
}

impl Default for Config {
	fn default() -> Config {
		Config {
			network: Network::Signet,
			asp_address: "http://127.0.0.1:3535".to_owned(),
			esplora_address: None,
			bitcoind_address: None,
			bitcoind_cookiefile: None,
			bitcoind_user: None,
			bitcoind_pass: None,
			vtxo_refresh_threshold: 288,
		}
	}
}

#[derive(Clone)]
struct AspConnection {
	pub info: ArkInfo,
	pub client: rpc::ArkServiceClient<tonic::transport::Channel>,
}

pub struct Wallet {
	config: Config,
	datadir: PathBuf,
	db: db::Db,
	onchain: onchain::Wallet,
	vtxo_seed: bip32::Xpriv,
	asp: Option<AspConnection>,
}

impl Wallet {
	/// Write the config file into the data directory.
	fn write_config(cfg: &Config, datadir: &Path) -> anyhow::Result<()> {
		let config_str = serde_json::to_string_pretty(cfg)
			.expect("serialization can't error");
		let path = datadir.join(CONFIG_FILE);
		fs::write(&path, config_str.as_bytes())
			.with_context(|| format!("failed to write config file {}", path.display()))?;
		Ok(())
	}

	/// Create new wallet.
	pub async fn create(
		datadir: &Path,
		config: Config,
	) -> anyhow::Result<Wallet> {
		info!("Creating new bark Wallet at {}", datadir.display());
		trace!("Config: {:?}", config);

		// create dir if not exit, but check that it's empty
		fs::create_dir_all(&datadir).context("can't create dir")?;
		if fs::read_dir(&datadir).context("can't read dir")?.next().is_some() {
			bail!("dir is not empty");
		}

		// write the config to disk
		Self::write_config(&config, datadir).context("failed to write config file")?;

		// generate seed
		let mnemonic = bip39::Mnemonic::generate(12).expect("12 is valid");

		// write it to file
		fs::write(datadir.join("mnemonic"), mnemonic.to_string().as_bytes())
			.context("failed to write mnemonic")?;

		// from then on we can open the wallet
		let wallet = Wallet::open(&datadir).await.context("failed to open")?;
		wallet.require_chainsource_version()?;

		if wallet.asp.is_none() {
			bail!("Cannot create bark if asp is not available");
		}

		Ok(wallet)
	}

	/// Open existing wallet.
	pub async fn open(datadir: &Path) -> anyhow::Result<Wallet> {
		info!("Opening bark Wallet at {}", datadir.display());

		let config = {
			let path = datadir.join(CONFIG_FILE);
			let bytes = fs::read(&path)
				.with_context(|| format!("failed to read config file: {}", path.display()))?;
			serde_json::from_slice::<Config>(&bytes).context("invalid config file")?
		};
		trace!("Config: {:?}", config);

		// read mnemonic file
		let mnemonic_path = datadir.join("mnemonic");
		let mnemonic_str = fs::read_to_string(&mnemonic_path)
			.with_context(|| format!("failed to read mnemonic file at {}", mnemonic_path.display()))?;
		let mnemonic = bip39::Mnemonic::from_str(&mnemonic_str).context("broken mnemonic")?;
		let seed = mnemonic.to_seed("");

		// create on-chain wallet
		let chain_source = if let Some(ref url) = config.esplora_address {
			onchain::ChainSource::Esplora {
				url: url.clone(),
			}
		} else if let Some(ref url) = config.bitcoind_address {
			let auth = if let Some(ref c) = config.bitcoind_cookiefile {
				bdk_bitcoind_rpc::bitcoincore_rpc::Auth::CookieFile(c.clone())
			} else {
				bdk_bitcoind_rpc::bitcoincore_rpc::Auth::UserPass(
					config.bitcoind_user.clone().context("need bitcoind auth config")?,
					config.bitcoind_pass.clone().context("need bitcoind auth config")?,
				)
			};
			onchain::ChainSource::Bitcoind {
				url: url.clone(),
				auth: auth,
			}
		} else {
			bail!("Need to either provide esplora or bitcoind info");
		};

		let connection_string = datadir.join(DB_FILE);
		let db = db::Db::open(connection_string)?;

		let onchain = onchain::Wallet::create(config.network, seed, db.clone(), chain_source)
			.context("failed to create onchain wallet")?;


		let vtxo_seed = {
			let master = bip32::Xpriv::new_master(config.network, &seed).unwrap();
			master.derive_priv(&SECP, &[350.into()]).unwrap()
		};

		let asp_uri = tonic::transport::Uri::from_str(&config.asp_address)
			.context("invalid asp addr")?;
		let scheme = asp_uri.scheme_str().expect("no scheme?");
		if scheme != "http" && scheme != "https" {
			bail!("ASP scheme must be either http or https");
		}

		let mut endpoint = tonic::transport::Channel::builder(asp_uri.clone())
			.keep_alive_timeout(Duration::from_secs(600))
			.timeout(Duration::from_secs(600));

		if scheme == "https" {
			info!("Connecting to ASP using SSL...");
			let uri_auth = asp_uri.clone().into_parts().authority.expect("need authority");
			let domain = uri_auth.host();

			let tls_config = tonic::transport::ClientTlsConfig::new()
				.domain_name(domain);
			endpoint = endpoint.tls_config(tls_config)?
		} else {
			info!("Connecting to ASP without TLS...");
		};

		let asp = match rpc::ArkServiceClient::connect(endpoint).await {
			Ok(mut client) => {
				let res = client.get_ark_info(rpc::Empty{})
					.await.context("ark info request failed")?.into_inner();

				if config.network != res.network.parse().context("invalid network from asp")? {
					bail!("ASP is for net {} while we are on net {}", res.network, config.network);
				}

				let info = ArkInfo {
					asp_pubkey: PublicKey::from_slice(&res.pubkey).context("asp pubkey")?,
					nb_round_nonces: res.nb_round_nonces as usize,
					vtxo_expiry_delta: res.vtxo_expiry_delta as u16,
					vtxo_exit_delta: res.vtxo_exit_delta as u16,
				};

				Some(AspConnection { info, client })
			},
			_ => None
		};

		let datadir = datadir.to_path_buf();

		Ok(Wallet { config, datadir, db, onchain, vtxo_seed, asp })
	}

	pub fn config(&self) -> &Config {
		&self.config
	}

	/// Change the config of this wallet.
	///
	/// In order for these changes to be persistent, call [Wallet::persist_config].
	pub fn set_config(&mut self, config: Config) {
		self.config = config;
	}

	pub fn persist_config(&self) -> anyhow::Result<()> {
		Self::write_config(&self.config, &self.datadir)
	}

	fn require_asp(&self) -> anyhow::Result<AspConnection> {
		self.asp.clone().context("You should be connected to ASP to perform this action")
	}

	pub fn require_chainsource_version(&self) -> anyhow::Result<()> {
		self.onchain.require_chainsource_version()
	}

	pub async fn chain_tip_height(&self) -> anyhow::Result<u32> {
		self.onchain.tip().await
	}

	pub fn get_new_onchain_address(&mut self) -> anyhow::Result<Address> {
		self.onchain.new_address()
	}

	/// Sync the onchain wallet, returns the balance.
	pub async fn sync_onchain(&mut self) -> anyhow::Result<Amount> {
		self.onchain.sync().await
	}

	/// Return the balance of the onchain wallet.
	///
	/// Make sure you sync before calling this method.
	pub fn onchain_balance(&self) -> Amount {
		self.onchain.balance()
	}

	pub fn onchain_utxos(&self) -> Vec<OutPoint> {
		self.onchain.utxos()
	}

	pub async fn send_onchain(&mut self, addr: Address, amount: Amount) -> anyhow::Result<Txid> {
		Ok(self.onchain.send_money(addr, amount).await?)
	}

	/// Retrieve the off-chain balance of the wallet.
	///
	/// Make sure you sync before calling this method.
	pub async fn offchain_balance(&self) -> anyhow::Result<Amount> {
		let mut sum = Amount::ZERO;
		for vtxo in self.db.get_all_vtxos()? {
			sum += vtxo.spec().amount;
			debug!("Vtxo {}: {}", vtxo.id(), vtxo.spec().amount);
		}
		Ok(sum)
	}

	pub fn get_vtxo_by_id(&self, vtxo_id: VtxoId) -> anyhow::Result<Vtxo> {
		let vtxo = self.db.get_vtxo(vtxo_id)
			.with_context(|| format!("Error when querying vtxo {} in database", vtxo_id))?
			.with_context(|| format!("The VTXO with id {} cannot be found", vtxo_id))?;
		Ok(vtxo)
	}

	/// Returns all unspent vtxos
	pub fn vtxos(&self) -> anyhow::Result<Vec<Vtxo>> {
		Ok(self.db.get_all_vtxos()?)
	}

	/// Returns all vtxos that will expire within
	// [threshold_blocks] blocks
	pub async fn get_expiring_vtxos(&mut self, threshold_blocks: u32) -> anyhow::Result<Vec<Vtxo>> {
		let height = self.onchain.tip().await?;
		let mut ret = self.db.get_all_vtxos()?;
		ret.retain(|v| height + threshold_blocks > v.spec().expiry_height);
		Ok(ret)
	}

	/// Sync both the onchain and offchain wallet.
	pub async fn sync(&mut self) -> anyhow::Result<()> {
		self.onchain.sync().await?;
		self.sync_ark().await?;
		Ok(())
	}

	//TODO(stevenroose) improve the way we expose dangerous methods
	pub async fn drop_vtxos(&self) -> anyhow::Result<()> {
		warn!("Dropping all vtxos from the db...");
		for vtxo in self.db.get_all_vtxos()? {
			self.db.remove_vtxo(vtxo.id())?;
		}
		self.db.store_exit(&exit::Exit::default())?;
		Ok(())
	}

	pub fn vtxo_pubkey(&self) -> PublicKey {
		self.vtxo_seed.to_keypair(&SECP).public_key()
	}

	// Onboard a vtxo with the given vtxo amount.
	//
	// NB we will spend a little more on-chain to cover minrelayfee.
	pub async fn onboard_amount(&mut self, amount: Amount) -> anyhow::Result<()> {
		let asp = self.require_asp()?;

		//TODO(stevenroose) impl key derivation
		let user_keypair = self.vtxo_seed.to_keypair(&SECP);
		let current_height = self.onchain.tip().await?;
		let spec = ark::VtxoSpec {
			user_pubkey: user_keypair.public_key(),
			asp_pubkey: asp.info.asp_pubkey,
			expiry_height: current_height + asp.info.vtxo_expiry_delta as u32,
			exit_delta: asp.info.vtxo_exit_delta,
			amount: amount,
		};

		let onboard_amount = amount + ark::onboard::onboard_surplus();
		let addr = Address::from_script(&ark::onboard::onboard_spk(&spec), self.config.network).unwrap();

		// We create the onboard tx template, but don't sign it yet.
		let onboard_tx = self.onchain.prepare_tx(addr, onboard_amount)?;

		self.onboard(spec, user_keypair, onboard_tx).await
	}

	pub async fn onboard_all(&mut self) -> anyhow::Result<()> {
		let asp = self.require_asp()?;

		//TODO(stevenroose) impl key derivation
		let user_keypair = self.vtxo_seed.to_keypair(&SECP);
		let current_height = self.onchain.tip().await?;
		let mut spec = ark::VtxoSpec {
			user_pubkey: user_keypair.public_key(),
			asp_pubkey: asp.info.asp_pubkey,
			expiry_height: current_height + asp.info.vtxo_expiry_delta as u32,
			exit_delta: asp.info.vtxo_exit_delta,
			// amount is temporarily set to total balance but will
			// have fees deducted after psbt construction
			amount: self.onchain_balance()
		};

		let addr = Address::from_script(&ark::onboard::onboard_spk(&spec), self.config.network).unwrap();
		let onboard_all_tx = self.onchain.prepare_send_all_tx(addr)?;

		// Deduct fee from vtxo spec
		let fee = onboard_all_tx.fee().context("Unable to calculate fee")?;
		spec.amount = spec.amount.checked_sub(fee + ark::onboard::onboard_surplus()).unwrap();

		assert_eq!(onboard_all_tx.outputs.len(), 1);
		assert_eq!(onboard_all_tx.unsigned_tx.tx_out(0).unwrap().value, spec.amount + ark::onboard::onboard_surplus());

		self.onboard(spec, user_keypair, onboard_all_tx).await
	}

	async fn onboard(&mut self, spec: VtxoSpec, user_keypair: Keypair, onboard_tx: Psbt) -> anyhow::Result<()> {
		let mut asp = self.require_asp()?;

		// This is manually enforced in prepare_tx
		const VTXO_VOUT: u32 = 0;

		let utxo = OutPoint::new(onboard_tx.unsigned_tx.compute_txid(), VTXO_VOUT);
		// We ask the ASP to cosign our onboard vtxo reveal tx.
		let (user_part, priv_user_part) = ark::onboard::new_user(spec, utxo);
		let asp_part = {
			let res = asp.client.request_onboard_cosign(aspd_rpc_client::OnboardCosignRequest {
				user_part: {
					let mut buf = Vec::new();
					ciborium::into_writer(&user_part, &mut buf).unwrap();
					buf
				},
			}).await.context("error requesting onboard cosign")?;
			ciborium::from_reader::<ark::onboard::AspPart, _>(&res.into_inner().asp_part[..])
				.context("invalid ASP part in response")?
		};

		// Store vtxo first before we actually make the on-chain tx.
		let vtxo = ark::onboard::finish(user_part, asp_part, priv_user_part, &user_keypair);
		self.db.store_vtxo(&vtxo).context("db error storing vtxo")?;

		let tx = self.onchain.finish_tx(onboard_tx)?;
		trace!("Broadcasting onboard tx: {}", bitcoin::consensus::encode::serialize_hex(&tx));
		self.onchain.broadcast_tx(&tx).await?;

		info!("Onboard successful");

		Ok(())
	}

	fn add_new_vtxo(&self, vtxos: &SignedVtxoTree, leaf_idx: usize) -> anyhow::Result<()> {
		let exit_branch = vtxos.exit_branch(leaf_idx).unwrap();
		let dest = &vtxos.spec.vtxos[leaf_idx];
		let vtxo = Vtxo::Round {
			base: BaseVtxo {
				spec: VtxoSpec {
					user_pubkey: dest.pubkey,
					asp_pubkey: vtxos.spec.asp_pk,
					expiry_height: vtxos.spec.expiry_height,
					exit_delta: vtxos.spec.exit_delta,
					amount: dest.amount,
				},
				utxo: vtxos.utxo,
			},
			leaf_idx: leaf_idx,
			exit_branch: exit_branch,
		};

		if self.db.has_spent_vtxo(vtxo.id())? {
			debug!("Not adding vtxo {} because it is considered spent", vtxo.id());
			return Ok(());
		}

		if self.db.get_vtxo(vtxo.id())?.is_none() {
			debug!("Storing new vtxo {} with value {}", vtxo.id(), vtxo.spec().amount);
			self.db.store_vtxo(&vtxo).context("failed to store vtxo")?;
		}
		Ok(())
	}

	/// Sync with the Ark and look for received vtxos.
	pub async fn sync_ark(&self) -> anyhow::Result<()> {
		let mut asp = self.require_asp()?;

		//TODO(stevenroose) impl key derivation
		let vtxo_key = self.vtxo_seed.to_keypair(&SECP);


		//TODO(stevenroose) we won't do reorg handling here
		let current_height = self.onchain.tip().await?;
		let last_sync_height = self.db.get_last_ark_sync_height()?;
		let req = rpc::FreshRoundsRequest { start_height: last_sync_height };
		let fresh_rounds = asp.client.get_fresh_rounds(req).await?.into_inner();

		for txid in fresh_rounds.txids {
			let txid = Txid::from_slice(&txid).context("invalid txid from asp")?;
			let req = rpc::RoundId { txid: txid.to_byte_array().to_vec() };
			let round = asp.client.get_round(req).await?.into_inner();

			let tree = SignedVtxoTree::decode(&round.signed_vtxos)
				.context("invalid signed vtxo tree from asp")?;

			for (idx, dest) in tree.spec.vtxos.iter().enumerate() {
				if dest.pubkey == vtxo_key.public_key() {
					self.add_new_vtxo(&tree, idx)?;
				}
			}
		}

		//TODO(stevenroose) we currently actually could accidentally be syncing
		// a round multiple times because new blocks could have come in since we
		// took current height

		self.db.store_last_ark_sync_height(current_height)?;

		// Then sync OOR vtxos.
		debug!("Emptying OOR mailbox at ASP...");
		let req = rpc::OorVtxosRequest { pubkey: vtxo_key.public_key().serialize().to_vec() };
		let resp = asp.client.empty_oor_mailbox(req).await.context("error fetching oors")?;
		let oors = resp.into_inner().vtxos.into_iter()
			.map(|b| Vtxo::decode(&b).context("invalid vtxo from asp"))
			.collect::<Result<Vec<_>, _>>()?;
		debug!("ASP has {} OOR vtxos for us", oors.len());
		for vtxo in oors {
			//TODO(stevenroose) verify oor signatures

			// Not sure if this can happen, but well.
			if self.db.has_spent_vtxo(vtxo.id())? {
				debug!("Not adding OOR vtxo {} because it is considered spent", vtxo.id());
			}

			if self.db.get_vtxo(vtxo.id())?.is_none() {
				debug!("Storing new OOR vtxo {} with value {}", vtxo.id(), vtxo.spec().amount);
				self.db.store_vtxo(&vtxo).context("failed to store OOR vtxo")?;
			}
		}

		Ok(())
	}

	async fn offboard(&mut self, vtxos: Vec<Vtxo>, address: Option<Address>) -> anyhow::Result<()> {
		let vtxo_sum = vtxos.iter().map(|v| v.amount()).sum::<Amount>();

		let addr = match address {
			Some(addr) => addr,
			None => self.onchain.new_address()?,
		};

		self.participate_round(move |_id, offb_fr| {
			let fee = OffboardRequest::calculate_fee(&addr.script_pubkey(), offb_fr)
				.expect("bdk created invalid scriptPubkey");

			let offb = OffboardRequest {
				amount: vtxo_sum - fee,
				script_pubkey: addr.script_pubkey(),
			};

			Ok((vtxos.clone(), Vec::new(), vec![offb]))
		}).await.context("round failed")?;

		Ok(())
	}

	/// Offboard all vtxos to a given address or default to bark onchain address
	pub async fn offboard_all(&mut self, address: Option<Address>) -> anyhow::Result<()> {
		self.sync_ark().await.context("failed to sync with ark")?;

		let input_vtxos = self.db.get_all_vtxos()?;

		self.offboard(input_vtxos, address).await?;

		Ok(())
	}

	/// Offboard vtxos selection to a given address or default to bark onchain address
	pub async fn offboard_vtxos(&mut self, vtxos: Vec<VtxoId>, address: Option<Address>) -> anyhow::Result<()> {
		self.sync_ark().await.context("failed to sync with ark")?;

		let input_vtxos =  vtxos
				.into_iter()
				.map(|vtxoid| match self.db.get_vtxo(vtxoid)? {
					Some(vtxo) => Ok(vtxo),
					_ => bail!("cannot find requested vtxo: {}", vtxoid),
				})
				.collect::<anyhow::Result<_>>()?;

		self.offboard(input_vtxos, address).await?;

		Ok(())
	}

	/// Refresh vtxo's
	pub async fn refresh_vtxos(
		&mut self,
		vtxos: Vec<Vtxo>
	) -> anyhow::Result<()> {
		// Todo: Implement key-derivation
		let total_amount: bitcoin::Amount = vtxos.iter().map(|v| v.amount()).sum();
		let vtxo_key = self.vtxo_seed.to_keypair(&SECP);
		let payment_request = PaymentRequest {
			pubkey: vtxo_key.public_key(),
			amount: total_amount
		};

		self.participate_round(move |_id, _offb_fr| {
			Ok((vtxos.clone(), vec![payment_request.clone()], Vec::new()))
		}).await.context("round failed")?;
		Ok(())
	}

	pub async fn refresh_all_vtxos(&mut self) -> anyhow::Result<()> {
		let all_vtxos = self.db.get_all_vtxos()?;
		self.refresh_vtxos(all_vtxos).await
	}

	/// Refresh vtxos that are close to expiration.
	///
	/// If no threshold is given the wallet default is used
	pub async fn refresh_expiring_vtxos(&mut self, threshold_blocks: u32) -> anyhow::Result<()> {
		let expiring_vtxos = self.get_expiring_vtxos(threshold_blocks).await?;
		self.refresh_vtxos(expiring_vtxos).await
	}

	pub async fn send_oor_payment(&mut self, destination: PublicKey, amount: Amount) -> anyhow::Result<VtxoId> {
		let mut asp = self.require_asp()?;

		let fr = self.onchain.regular_feerate();
		//TODO(stevenroose) impl key derivation
		let vtxo_key = self.vtxo_seed.to_keypair(&SECP);
		let output = PaymentRequest { pubkey: destination, amount };

		// We do some kind of naive fee estimation: we try create a tx,
		// if we don't have enough fee, we add the fee we were short to
		// the desired input amount and try again.
		let mut account_for_fee = ark::oor::OOR_MIN_FEE;
		let payment = loop {
			let input_vtxos = self.db.get_expiring_vtxos(amount + account_for_fee)?;
			let change = {
				let sum = input_vtxos.iter().map(|v| v.amount()).sum::<Amount>();
				let avail = Amount::from_sat(sum.to_sat().saturating_sub(account_for_fee.to_sat()));
				if avail < output.amount {
					bail!("Balance too low: {}", sum);
				} else if avail < output.amount + ark::P2TR_DUST {
					None
				} else {
					let change_amount = avail - output.amount;
					Some(PaymentRequest {
						pubkey: vtxo_key.public_key(),
						amount: change_amount,
					})
				}
			};
			let outputs = Some(output.clone()).into_iter().chain(change).collect::<Vec<_>>();

			let payment = ark::oor::OorPayment::new(
				asp.info.asp_pubkey,
				asp.info.vtxo_exit_delta,
				input_vtxos,
				outputs,
			);

			if let Err(ark::oor::InsufficientFunds { missing, .. }) = payment.check_fee(fr) {
				account_for_fee += missing;
			} else {
				break payment;
			}
		};
		// it's a bit fragile, but if there is a second output, it's our change
		if let Some(o) = payment.outputs.get(1) {
			info!("Added change VTXO of {}", o.amount);
		}

		let (sec_nonces, pub_nonces) = {
			let mut secs = Vec::with_capacity(payment.inputs.len());
			let mut pubs = Vec::with_capacity(payment.inputs.len());
			for _ in 0..payment.inputs.len() {
				let (s, p) = musig::nonce_pair(&vtxo_key);
				secs.push(s);
				pubs.push(p);
			}
			(secs, pubs)
		};

		let req = rpc::OorCosignRequest {
			payment: payment.encode(),
			pub_nonces: pub_nonces.iter().map(|n| n.serialize().to_vec()).collect(),
		};
		let resp = asp.client.request_oor_cosign(req).await.context("cosign request failed")?.into_inner();
		let len = payment.inputs.len();
		if resp.pub_nonces.len() != len || resp.partial_sigs.len() != len {
			bail!("invalid length of asp response");
		}

		let asp_pub_nonces = resp.pub_nonces.into_iter()
			.map(|b| musig::MusigPubNonce::from_slice(&b))
			.collect::<Result<Vec<_>, _>>()
			.context("invalid asp pub nonces")?;
		let asp_part_sigs = resp.partial_sigs.into_iter()
			.map(|b| musig::MusigPartialSignature::from_slice(&b))
			.collect::<Result<Vec<_>, _>>()
			.context("invalid asp part sigs")?;

		trace!("OOR prevouts: {:?}", payment.inputs.iter().map(|i| i.txout()).collect::<Vec<_>>());
		let input_vtxos = payment.inputs.clone();
		let tx = payment.sign_finalize_user(
			&vtxo_key,
			sec_nonces,
			&pub_nonces,
			&asp_pub_nonces,
			&asp_part_sigs,
		);
		trace!("OOR tx: {}", bitcoin::consensus::encode::serialize_hex(&tx.signed_transaction()));
		let vtxos = tx.output_vtxos(asp.info.asp_pubkey, asp.info.vtxo_exit_delta);

		// The first one is of the recipient, we will post it to their mailbox.
		let user_vtxo = &vtxos[0];
		let req = rpc::OorVtxo {
			pubkey: destination.serialize().to_vec(),
			vtxo: user_vtxo.encode(),
		};
		if let Err(e) = asp.client.post_oor_mailbox(req).await {
			error!("Failed to post the OOR vtxo to the recipients mailbox: '{}'; vtxo: {}",
				e, user_vtxo.encode().as_hex(),
			);
			//NB we will continue to at least not lose our own change
		}

		if let Some(change_vtxo) = vtxos.get(1) {
			if let Err(e) = self.db.store_vtxo(change_vtxo) {
				error!("Failed to store change vtxo from OOR tx: '{}'; vtxo: {}",
					e, change_vtxo.encode().as_hex(),
				);
			}
		}

		for v in input_vtxos {
			self.db.mark_vtxo_as_spent(v.id()).context("Failed to mark vtxo as spent")?;
		}

		Ok(user_vtxo.id())
	}

	pub async fn send_bolt11_payment(
		&mut self,
		invoice: &Bolt11Invoice,
		user_amount: Option<Amount>,
	) -> anyhow::Result<Vec<u8>> {
		let mut asp = self.require_asp()?;

		let inv_amount = invoice.amount_milli_satoshis()
			.map(|v| Amount::from_sat(v.div_ceil(1000)));
		if let (Some(_), Some(inv)) = (user_amount, inv_amount) {
			bail!("Invoice has amount of {} encoded. Please omit amount argument", inv);
		}
		let amount = user_amount.or(inv_amount).context("amount required on invoice without amount")?;

		let fr = self.onchain.regular_feerate();
		//TODO(stevenroose) impl key derivation
		let vtxo_key = self.vtxo_seed.to_keypair(&SECP);

		// We do some kind of naive fee estimation: we try create a tx,
		// if we don't have enough fee, we add the fee we were short to
		// the desired input amount and try again.
		let mut account_for_fee = ark::lightning::HTLC_MIN_FEE;
		let inputs = loop {
			let input_vtxos = self.db.get_expiring_vtxos(amount + account_for_fee)?;

			//TODO(stevenroose) we need a way for the user to calculate the htlc tx feerate,
			//like in the oor way (it would be nicer if the user makes the bolt11payment info)
			// soon we might ignore this because zero relayfee

			let vb = Weight::from_vb(300 + 20 * input_vtxos.len() as u64).unwrap();
			if vb * fr > account_for_fee {
				account_for_fee = vb * fr;
			} else {
				break input_vtxos;
			}
		};

		let (sec_nonces, pub_nonces) = {
			let mut secs = Vec::with_capacity(inputs.len());
			let mut pubs = Vec::with_capacity(inputs.len());
			for _ in 0..inputs.len() {
				let (s, p) = musig::nonce_pair(&vtxo_key);
				secs.push(s);
				pubs.push(p);
			}
			(secs, pubs)
		};

		let req = rpc::Bolt11PaymentRequest {
			invoice: invoice.to_string(),
			amount_sats: user_amount.map(|a| a.to_sat()),
			input_vtxos: inputs.iter().map(|v| v.encode()).collect(),
			user_pubkey: vtxo_key.public_key().serialize().to_vec(),
			user_nonces: pub_nonces.iter().map(|n| n.serialize().to_vec()).collect(),
		};
		let resp = asp.client.start_bolt11_payment(req).await
			.context("htlc request failed")?.into_inner();
		let len = inputs.len();
		if resp.pub_nonces.len() != len || resp.partial_sigs.len() != len {
			bail!("invalid length of asp response");
		}
		let payment = ark::lightning::Bolt11Payment::decode(&resp.details)
			.context("invalid bolt11 payment details from asp")?;

		let asp_pub_nonces = resp.pub_nonces.into_iter()
			.map(|b| musig::MusigPubNonce::from_slice(&b))
			.collect::<Result<Vec<_>, _>>()
			.context("invalid asp pub nonces")?;
		let asp_part_sigs = resp.partial_sigs.into_iter()
			.map(|b| musig::MusigPartialSignature::from_slice(&b))
			.collect::<Result<Vec<_>, _>>()
			.context("invalid asp part sigs")?;

		trace!("htlc prevouts: {:?}", inputs.iter().map(|i| i.txout()).collect::<Vec<_>>());
		let input_vtxos = payment.inputs.clone();
		let signed = payment.sign_finalize_user(
			&vtxo_key,
			sec_nonces,
			&pub_nonces,
			&asp_pub_nonces,
			&asp_part_sigs,
		);
		info!("Adding change VTXO of {}", signed.change_vtxo().amount());
		trace!("htlc tx: {}", bitcoin::consensus::encode::serialize_hex(&signed.signed_transaction()));

		let req = rpc::SignedBolt11PaymentDetails {
			signed_payment: signed.encode()
		};

		let mut payment_preimage = None;
		let mut last_msg = String::from("");
		let mut stream = asp.client.finish_bolt11_payment(req).await?.into_inner();
		while let Some(msg) = stream.next().await {
			let msg = msg.context("Error reported during pay")?;
			debug!("Progress update: {}", msg.progress_message);
			last_msg = msg.progress_message.clone();
			if msg.payment_preimage().len() > 0 {
				payment_preimage = msg.payment_preimage;
				break;
			}
		}

		if payment_preimage.is_none() {
			bail!("Payment failed: {}", last_msg)
		}
		let payment_preimage = payment_preimage.unwrap();

		let change_vtxo = signed.change_vtxo();
		if let Err(e) = self.db.store_vtxo(&change_vtxo) {
			error!("Failed to store change vtxo from Bolt11 payment: '{}'; vtxo: {}",
				e, change_vtxo.encode().as_hex(),
			);
		}

		// Mark the used vtxo's as spent
		for v in input_vtxos {
			self.db.mark_vtxo_as_spent(v.id())
				.context("Failed to mark vtxo as spent")?;
		}

		info!("Bolt11 payment succeeded");
		Ok(payment_preimage)
	}

	/// Send to a lightning address.
	///
	/// Returns the invoice paid and the preimage.
	pub async fn send_lnaddr(
		&mut self,
		addr: &LightningAddress,
		amount: Amount,
		comment: Option<&str>,
	) -> anyhow::Result<(Bolt11Invoice, Vec<u8>)> {
		let invoice = lnurl::lnaddr_invoice(addr, amount, comment).await
			.context("lightning address error")?;
		info!("Attempting to pay invoice {}", invoice);
		let preimage = self.send_bolt11_payment(&invoice, None).await
			.context("bolt11 payment error")?;
		Ok((invoice, preimage))
	}

	/// Send to an off-chain address in an Ark round.
	///
	/// It is advised to sync your wallet before calling this method.
	pub async fn send_round_onchain_payment(&mut self, addr: Address, amount: Amount) -> anyhow::Result<()> {
		//TODO(stevenroose) impl key derivation
		let vtxo_key = self.vtxo_seed.to_keypair(&SECP);

		// Prepare the payment.
		let input_vtxos = self.db.get_all_vtxos()?;

		// do a quick check to fail early if we don't have enough money
		let maybe_fee = OffboardRequest::calculate_fee(
			&addr.script_pubkey(), FeeRate::from_sat_per_vb(1).unwrap(),
		).expect("script from address");
		let in_sum = input_vtxos.iter().map(|v| v.amount()).sum::<Amount>();
		if in_sum < amount + maybe_fee {
			bail!("Balance too low");
		}

		self.participate_round(move |_id, offb_fr| {
			let offb = OffboardRequest {
				script_pubkey: addr.script_pubkey(),
				amount: amount,
			};
			let out_value = amount + offb.fee(offb_fr).expect("script from address");
			let change = {
				if in_sum < out_value {
					bail!("Balance too low");
				} else if in_sum <= out_value + ark::P2TR_DUST {
					info!("No change, emptying wallet.");
					None
				} else {
					let amount = in_sum - out_value;
					info!("Adding change vtxo for {}", amount);
					Some(PaymentRequest {
						pubkey: vtxo_key.public_key(),
						amount: amount,
					})
				}
			};

			Ok((input_vtxos.clone(), change.into_iter().collect(), vec![offb]))
		}).await.context("round failed")?;
		Ok(())
	}

	/// Participate in a round.
	///
	/// NB Instead of taking the input and output data as arguments, we take a closure that is
	/// called to get these values. This is so because for offboards, the fee rate used for the
	/// offboards is only announced in the beginning of the round and can change between round
	/// attempts. Lateron this will also be useful so we can randomize destinations between failed
	/// round attempts for better privacy.
	async fn participate_round(
		&mut self,
		mut round_input: impl FnMut(u64, FeeRate) -> anyhow::Result<
			(Vec<Vtxo>, Vec<PaymentRequest>, Vec<OffboardRequest>)
		>,
	) -> anyhow::Result<()> {
		let mut asp = self.require_asp()?;

		//TODO(stevenroose) impl key derivation
		let vtxo_key = self.vtxo_seed.to_keypair(&SECP);

		info!("Waiting for a round start...");
		let mut events = asp.client.subscribe_rounds(rpc::Empty {}).await?.into_inner();

		// Wait for the next round start.
		let (mut round_id, offboard_feerate) = loop {
			match events.next().await.context("events stream broke")??.event.unwrap() {
				rpc::round_event::Event::Start(rpc::RoundStart {
					round_id, offboard_feerate_sat_vkb,
				}) => {
					let offb_fr = FeeRate::from_sat_per_kwu(offboard_feerate_sat_vkb / 4);
					break (round_id, offb_fr);
				},
				_ => {},
			}
		};
		info!("Round started");

		let (input_vtxos, pay_reqs, offb_reqs) = round_input(round_id, offboard_feerate)
			.context("error providing round input")?;
		// Assign cosign pubkeys to the payment requests.
		let cosign_keys = iter::repeat_with(|| Keypair::new(&SECP, &mut rand::thread_rng()))
			.take(pay_reqs.len())
			.collect::<Vec<_>>();
		let vtxo_reqs = pay_reqs.into_iter().zip(cosign_keys.iter()).map(|(req, ck)| {
			VtxoRequest {
				pubkey: req.pubkey,
				amount: req.amount,
				cosign_pk: ck.public_key(),
			}
		}).collect::<Vec<_>>();

		let vtxo_ids = input_vtxos.iter().map(|v| v.id()).collect::<HashSet<_>>();
		debug!("Spending vtxos: {:?}", vtxo_ids);


		'round: loop {
			// Prepare round participation info.
			// For each of our requested vtxo output, we need a set of public and secret nonces.
			let cosign_nonces = cosign_keys.iter().map(|key| {
				let mut secs = Vec::with_capacity(asp.info.nb_round_nonces);
				let mut pubs = Vec::with_capacity(asp.info.nb_round_nonces);
				for _ in 0..asp.info.nb_round_nonces {
					let (s, p) = musig::nonce_pair(key);
					secs.push(s);
					pubs.push(p);
				}
				(secs, pubs)
			})
				.take(vtxo_reqs.len())
				.collect::<Vec<(Vec<MusigSecNonce>, Vec<MusigPubNonce>)>>();

			// The round has now started. We can submit our payment.
			debug!("Submitting payment request with {} inputs, {} vtxo outputs and {} offboard outputs",
				input_vtxos.len(), vtxo_reqs.len(), offb_reqs.len(),
			);
			asp.client.submit_payment(rpc::SubmitPaymentRequest {
				input_vtxos: input_vtxos.iter().map(|v| v.encode()).collect(),
				vtxo_requests: vtxo_reqs.iter().zip(cosign_nonces.iter()).map(|(r, n)| {
					rpc::VtxoRequest {
						amount: r.amount.to_sat(),
						vtxo_public_key: r.pubkey.serialize().to_vec(),
						cosign_pubkey: r.cosign_pk.serialize().to_vec(),
						public_nonces: n.1.iter().map(|n| n.serialize().to_vec()).collect(),
					}
				}).collect(),
				offboard_requests: offb_reqs.iter().map(|r| {
					rpc::OffboardRequest {
						amount: r.amount.to_sat(),
						offboard_spk: r.script_pubkey.to_bytes(),
					}
				}).collect(),
			}).await.context("submitting payment to asp")?;


			// ****************************************************************
			// * Wait for vtxo proposal from asp.
			// ****************************************************************

			debug!("Waiting for vtxo proposal from asp...");
			let (vtxo_tree, unsigned_round_tx, vtxo_cosign_agg_nonces) = {
				match events.next().await.context("events stream broke")??.event.unwrap() {
					rpc::round_event::Event::VtxoProposal(p) => {
						assert_eq!(p.round_id, round_id, "missing messages");
						let vtxos = VtxoTreeSpec::decode(&p.vtxos_spec)
							.context("decoding vtxo spec")?;
						let tx = bitcoin::consensus::deserialize::<Transaction>(&p.unsigned_round_tx)
							.context("decoding round tx")?;
						let vtxo_nonces = p.vtxos_agg_nonces.into_iter().map(|k| {
							musig::MusigAggNonce::from_slice(&k).context("invalid agg nonce")
						}).collect::<anyhow::Result<Vec<_>>>()?;

						(vtxos, tx, vtxo_nonces)
					},
					// If a new round started meanwhile, pick up on that one.
					rpc::round_event::Event::Start(rpc::RoundStart { round_id: id, .. }) => {
						warn!("Unexpected new round started...");
						round_id = id;
						continue 'round;
					},
					//TODO(stevenroose) make this robust
					other => panic!("Unexpected message: {:?}", other),
				}
			};

			//TODO(stevenroose) remove these magic numbers
			let vtxos_utxo = OutPoint::new(unsigned_round_tx.compute_txid(), 0);
			let conns_utxo = OutPoint::new(unsigned_round_tx.compute_txid(), 1);

			// Check that the proposal contains our inputs.
			{
				let mut my_vtxos = vtxo_reqs.clone();
				for vtxo_req in vtxo_tree.iter_vtxos() {
					if let Some(i) = my_vtxos.iter().position(|v| v == vtxo_req) {
						my_vtxos.swap_remove(i);
					}
				}
				if !my_vtxos.is_empty() {
					bail!("asp didn't include all of our vtxos, missing: {:?}", my_vtxos);
				}
				let mut my_offbs = offb_reqs.clone();
				for offb in unsigned_round_tx.output.iter().skip(2) {
					if let Some(i) = my_offbs.iter().position(|o| o.to_txout() == *offb) {
						my_offbs.swap_remove(i);
					}
				}
				if !my_offbs.is_empty() {
					bail!("asp didn't include all of our offboards, missing: {:?}", my_offbs);
				}
			}

			// Make vtxo signatures from top to bottom, just like sighashes are returned.
			let unsigned_vtxos = vtxo_tree.into_unsigned_tree(vtxos_utxo);
			for ((req, key), (sec, _pub)) in vtxo_reqs.iter().zip(&cosign_keys).zip(cosign_nonces) {
				let part_sigs = unsigned_vtxos.cosign_branch(
					&vtxo_cosign_agg_nonces,
					req,
					key,
					sec,
				).context("failed to cosign branch: our request not part of tree")?;
				info!("Sending {} partial vtxo cosign signatures for pk {}",
					part_sigs.len(), key.public_key(),
				);
				asp.client.provide_vtxo_signatures(rpc::VtxoSignaturesRequest {
					pubkey: key.public_key().serialize().to_vec(),
					signatures: part_sigs.iter().map(|s| s.serialize().to_vec()).collect(),
				}).await.context("providing signatures to asp")?;
			}


			// ****************************************************************
			// * Then proceed to get a round proposal and sign forfeits
			// ****************************************************************

			debug!("Wait for round proposal from asp...");
			let (vtxo_cosign_sigs, forfeit_nonces) = {
				match events.next().await.context("events stream broke")??.event.unwrap() {
					rpc::round_event::Event::RoundProposal(p) => {
						assert_eq!(p.round_id, round_id, "missing messages");
						let vtxo_cosign_sigs = p.vtxo_cosign_signatures.iter().map(|s| {
							schnorr::Signature::from_slice(s).context("invalid vtxo sig")
						}).collect::<Result<Vec<_>, _>>()?;

						// Directly filter the forfeit nonces only for out inputs.
						let mut forfeit_nonces = HashMap::with_capacity(p.forfeit_nonces.len());
						for f in p.forfeit_nonces {
							let id = VtxoId::from_slice(&f.input_vtxo_id)
								.map_err(|e| anyhow!("invalid vtxoid from asp: {}", e))?;
							if vtxo_ids.contains(&id) {
								let nonces = f.pub_nonces.into_iter().map(|s| {
									Ok(musig::MusigPubNonce::from_slice(&s)
										.context("invalid forfeit nonce from asp")?)
								}).collect::<anyhow::Result<Vec<_>>>()?;
								forfeit_nonces.insert(id, nonces);
							}
						}

						(vtxo_cosign_sigs, forfeit_nonces)
					},
					// If a new round started meanwhile, pick up on that one.
					rpc::round_event::Event::Start(rpc::RoundStart { round_id: id, .. }) => {
						warn!("Unexpected new round started...");
						round_id = id;
						continue 'round;
					},
					//TODO(stevenroose) make this robust
					other => panic!("Unexpected message: {:?}", other),
				}
			};

			// Validate the vtxo tree.
			if let Err(e) = unsigned_vtxos.verify_cosign_sigs(&vtxo_cosign_sigs) {
				bail!("Received incorrect vtxo cosign signatures from asp: {}", e);
			}
			let signed_vtxos = unsigned_vtxos.into_signed_tree(vtxo_cosign_sigs);

			// Make forfeit signatures.
			let connectors = ConnectorChain::new(
				forfeit_nonces.values().next().unwrap().len(),
				conns_utxo,
				asp.info.asp_pubkey,
			);
			let forfeit_sigs = input_vtxos.iter().map(|v| {
				let sigs = connectors.connectors().enumerate().map(|(i, conn)| {
					let (sighash, _tx) = ark::forfeit::forfeit_sighash(v, conn);
					let asp_nonce = forfeit_nonces.get(&v.id())
						.with_context(|| format!("missing asp forfeit nonce for {}", v.id()))?
						.get(i)
						.context("asp didn't provide enough forfeit nonces")?;

					let (nonce, sig) = musig::deterministic_partial_sign(
						&vtxo_key,
						[vtxo_key.public_key(), asp.info.asp_pubkey],
						[asp_nonce.clone()],
						sighash.to_byte_array(),
						Some(v.spec().exit_taptweak().to_byte_array()),
					);
					Ok((nonce, sig))
				}).collect::<anyhow::Result<Vec<_>>>()?;
				Ok((v.id(), sigs))
			}).collect::<anyhow::Result<HashMap<_, _>>>()?;
			debug!("Sending {} sets of forfeit signatures for our inputs", forfeit_sigs.len());
			asp.client.provide_forfeit_signatures(rpc::ForfeitSignaturesRequest {
				signatures: forfeit_sigs.into_iter().map(|(id, sigs)| {
					rpc::ForfeitSignatures {
						input_vtxo_id: id.bytes().to_vec(),
						pub_nonces: sigs.iter().map(|s| s.0.serialize().to_vec()).collect(),
						signatures: sigs.iter().map(|s| s.1.serialize().to_vec()).collect(),
					}
				}).collect(),
			}).await.context("providing signatures to asp")?;


			// ****************************************************************
			// * Wait for the finishing of the round.
			// ****************************************************************

			debug!("Waiting for round to finish...");
			let signed_round_tx = match events.next().await.context("events stream broke")??.event.unwrap() {
				rpc::round_event::Event::Finished(f) => {
					if f.round_id != round_id {
						bail!("Unexpected round ID from round finished event: {} != {}",
							f.round_id, round_id);
					}
					bitcoin::consensus::deserialize::<Transaction>(&f.signed_round_tx)
						.context("invalid round tx from asp")?
				},
				// If a new round started meanwhile, pick up on that one.
				rpc::round_event::Event::Start(rpc::RoundStart { round_id: id, .. }) => {
					warn!("Unexpected new round started...");
					round_id = id;
					continue 'round;
				},
				//TODO(stevenroose) make this robust
				other => panic!("Unexpected message: {:?}", other),
			};

			if signed_round_tx.compute_txid() != unsigned_round_tx.compute_txid() {
				warn!("ASP changed the round transaction during the round!");
				warn!("unsigned tx: {}", bitcoin::consensus::encode::serialize_hex(&unsigned_round_tx));
				warn!("signed tx: {}", bitcoin::consensus::encode::serialize_hex(&signed_round_tx));
				//TODO(stevenroose) keep the unsigned tx because it might get broadcast
				// we have vtxos in it
				bail!("unsigned and signed round txids don't match");
			}

			// We also broadcast the tx, just to have it go around faster.
			info!("Broadcasting round tx {}", signed_round_tx.compute_txid());
			if let Err(e) = self.onchain.broadcast_tx(&signed_round_tx).await {
				warn!("Couldn't broadcast round tx: {}", e);
			}

			// Then add our change vtxo(s) by just checking all vtxos that might be ours.
			for (idx, dest) in signed_vtxos.spec.vtxos.iter().enumerate() {
				//TODO(stevenroose) this is broken, need to match vtxorequest exactly
				if dest.pubkey == vtxo_key.public_key() {
					self.add_new_vtxo(&signed_vtxos, idx)?;
				}
			}

			// And remove the input vtxos.
			for v in input_vtxos {
				self.db.mark_vtxo_as_spent(v.id())
					.context("Failed to mark vtxo as spent")?;
			}

			info!("Round finished");
			break;
		}

		Ok(())
	}
}

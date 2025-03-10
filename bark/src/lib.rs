
pub extern crate ark;
pub extern crate bark_json as json;

pub extern crate lightning_invoice;
pub extern crate lnurl as lnurllib;

#[macro_use] extern crate anyhow;
#[macro_use] extern crate log;
#[macro_use] extern crate serde;

pub mod persist;
use bitcoin::params::Params;
use bitcoin_ext::bdk::WalletExt;
pub use persist::sqlite::SqliteClient;
pub mod vtxo_selection;
mod exit;
mod lnurl;
pub mod onchain;
mod psbtext;
mod vtxo_state;

pub use bark_json::primitives::UtxoInfo;
pub use bark_json::cli::{Offboard, Board, SendOnchain};


use std::iter;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

use anyhow::{bail, Context};
use bdk_wallet::WalletPersister;
use bip39::Mnemonic;
use bitcoin::{secp256k1, Address, Amount, FeeRate, Network, OutPoint, Psbt, Txid};
use bitcoin::bip32::{self, Fingerprint};
use bitcoin::hashes::Hash;
use bitcoin::hex::DisplayHex;
use bitcoin::secp256k1::{rand, Keypair, PublicKey};
use lnurllib::lightning_address::LightningAddress;
use lightning_invoice::Bolt11Invoice;
use serde::ser::StdError;
use tokio_stream::StreamExt;

use ark::{
	oor, ArkInfo, ArkoorVtxo, BlockHeight, Bolt11ChangeVtxo, Movement, OffboardRequest,
	PaymentRequest, RoundVtxo, Vtxo, VtxoId, VtxoRequest, VtxoSpec,
};
use ark::connectors::ConnectorChain;
use ark::musig::{self, MusigPubNonce, MusigSecNonce};
use ark::rounds::{RoundAttempt, RoundEvent, RoundId, RoundInfo, VtxoOwnershipChallenge};
use ark::tree::signed::{CachedSignedVtxoTree, SignedVtxoTreeSpec};
use aspd_rpc as rpc;
use bitcoin_ext::P2TR_DUST;

use crate::exit::Exit;
use crate::onchain::Utxo;
use crate::persist::BarkPersister;
use crate::vtxo_selection::{FilterVtxos, VtxoFilter};
use crate::vtxo_state::VtxoState;


lazy_static::lazy_static! {
	/// Global secp context.
	static ref SECP: secp256k1::Secp256k1<secp256k1::All> = secp256k1::Secp256k1::new();
}

const OOR_PUB_KEY_INDEX: u32 = 0;
const MIN_DERIVED_INDEX: u32 = OOR_PUB_KEY_INDEX + 1;


pub struct Pagination {
	pub page_index: u16,
	pub page_size: u16,
}

impl From<Utxo> for UtxoInfo {
	fn from(value: Utxo) -> Self {
		match value {
			Utxo::Local(o) =>
				UtxoInfo {
					outpoint: o.outpoint,
					amount: o.txout.value,
					confirmation_height: o.chain_position.confirmation_height_upper_bound()
				},
			Utxo::Exit(e) =>
				UtxoInfo {
					outpoint: e.vtxo.point(),
					amount: e.vtxo.amount(),
					confirmation_height: Some(e.spendable_at_height - e.vtxo.spec().exit_delta as u32)
				}
		}
	}
}

/// Configuration of the Bark wallet.
#[derive(Debug, Clone)]
pub struct Config {
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

/// Read-only properties of the Bark wallet.
#[derive(Debug, Clone)]
pub struct WalletProperties {
	/// The Bitcoin network to run Bark on.
	///
	/// Default value: signet.
	pub network: Network,

	/// The wallet fingerpint
	///
	/// Used on wallet loading to check mnemonic correctness
	pub fingerprint: Fingerprint,
}

/// Struct representing an extended private key derived from a
/// wallet's seed, used to derived child VTXO keypairs
///
/// The VTXO seed is derived by applying a hardened derivation
/// step at index 350 from the wallet's seed.
pub struct VtxoSeed(bip32::Xpriv);

impl VtxoSeed {
	fn new(network: Network, seed: &[u8; 64]) -> Self {
		let master = bip32::Xpriv::new_master(network, seed).unwrap();

		Self(master.derive_priv(&SECP, &[350.into()]).unwrap())
	}

	fn fingerprint(&self) -> Fingerprint {
		self.0.fingerprint(&SECP)
	}

	fn derive_keypair(&self, keypair_idx: u32) -> Keypair {
		self.0.derive_priv(&SECP, &[keypair_idx.into()]).unwrap().to_keypair(&SECP)
	}
}

#[derive(Clone)]
struct AspConnection {
	pub info: ArkInfo,
	pub client: rpc::ArkServiceClient<tonic::transport::Channel>,
}

impl AspConnection {
	fn create_endpoint(asp_address: &str) -> anyhow::Result<tonic::transport::Endpoint> {
		let asp_uri = tonic::transport::Uri::from_str(asp_address)
			.context("failed to parse Ark server as a URI")?;

		let scheme = asp_uri.scheme_str().unwrap_or("");
		if scheme != "http" && scheme != "https" {
			bail!("ASP scheme must be either http or https. Found: {}", scheme);
		}

		let mut endpoint = tonic::transport::Channel::builder(asp_uri.clone())
			.keep_alive_timeout(Duration::from_secs(600))
			.timeout(Duration::from_secs(600));

		if scheme == "https" {
			info!("Connecting to ASP using TLS...");
			let uri_auth = asp_uri.clone().into_parts().authority
				.context("Ark server URI is missing an authority part")?;
			let domain = uri_auth.host();

			let tls_config = tonic::transport::ClientTlsConfig::new()
				.domain_name(domain);
			endpoint = endpoint.tls_config(tls_config)?
		} else {
			info!("Connecting to ASP without TLS...");
		};
		Ok(endpoint)
	}

	/// Try to perform the handshake with the ASP.
	async fn handshake(
		asp_address: &str,
		network: Network,
	) -> anyhow::Result<AspConnection> {
		let our_version = env!("CARGO_PKG_VERSION").into();

		let endpoint = AspConnection::create_endpoint(asp_address)?;
		let mut client = rpc::ArkServiceClient::connect(endpoint).await
			.context("couldn't connect to Ark server")?;

		let res = client.handshake(rpc::HandshakeRequest { version: our_version })
			.await.context("ark info request failed")?.into_inner();

		if let Some(ref msg) = res.message {
			warn!("Message from Ark server: \"{}\"", msg);
		}

		if let Some(info) = res.ark_info {
			let info = ArkInfo::try_from(info).context("invalid ark info from asp")?;
			if network != info.network {
				bail!("ASP is for net {} while we are on net {}", info.network, network);
			}
			Ok(AspConnection { info, client })
		} else {
			let msg = res.message.as_ref().map(|s| s.as_str()).unwrap_or("NO MESSAGE");
			bail!("Ark server handshake failed: {}", msg);
		}
	}
}

pub struct Wallet<P: BarkPersister> {
	pub onchain: onchain::Wallet<P>,
	pub exit: Exit<P>,

	config: Config,
	db: P,
	vtxo_seed: VtxoSeed,
	asp: Option<AspConnection>,
}

impl <P>Wallet<P> where
	P: BarkPersister,
	<P as WalletPersister>::Error: 'static + std::fmt::Debug + std::fmt::Display + Send + Sync + StdError
{
	/// Return a _static_ public key that can be used to send OOR payments to
	///
	/// TODO: implement key derivation for OORs also
	pub fn oor_pubkey(&self) -> PublicKey {
		self.vtxo_seed.derive_keypair(OOR_PUB_KEY_INDEX).public_key()
	}

	/// Derive and store the keypair directly after currently last revealed one
	pub fn derive_store_next_keypair(&self) -> anyhow::Result<Keypair> {
		let last_revealed = self.db.get_last_vtxo_key_index()?;

		let index = last_revealed.map(|i| i + 1).unwrap_or(MIN_DERIVED_INDEX);
		let keypair = self.vtxo_seed.derive_keypair(index);

		self.db.store_vtxo_key_index(index, keypair.public_key())?;
		Ok(keypair)
	}

	/// Create new wallet.
	pub async fn create(
		mnemonic: &Mnemonic,
		network: Network,
		config: Config,
		db: P,
		mnemonic_birthday: Option<BlockHeight>,
	) -> anyhow::Result<Wallet<P>> {
		trace!("Config: {:?}", config);
		if let Some(existing) = db.read_config()? {
			trace!("Existing config: {:?}", existing);
			bail!("cannot overwrite already existing config")
		}

		let wallet_fingerprint = VtxoSeed::new(network, &mnemonic.to_seed("")).fingerprint();
		let properties = WalletProperties {
			network: network,
			fingerprint: wallet_fingerprint,
		};

		// write the config to db
		db.init_wallet(&config, &properties).context("cannot init wallet in the database")?;

		// from then on we can open the wallet
		let mut wallet = Wallet::open(&mnemonic, db).await.context("failed to open wallet")?;
		wallet.onchain.require_chainsource_version()?;

		if wallet.asp.is_none() {
			bail!("Cannot create bark if asp is not available");
		}

		let bday = if let Some(bday) = mnemonic_birthday {
			bday
		} else {
			wallet.onchain.tip().await
				.context("failed to fetch tip from chain source")?
				as BlockHeight
		};
		let id = wallet.onchain.chain_source.block_id(bday as u32).await
			.with_context(|| format!("failed to get block height {} from chain source", bday))?;
		wallet.onchain.wallet.set_checkpoint(id);
		wallet.onchain.wallet.persist(&mut wallet.db)?;

		Ok(wallet)
	}

	/// Open existing wallet.
	pub async fn open(mnemonic: &Mnemonic, db: P) -> anyhow::Result<Wallet<P>> {
		let config = db.read_config()?.context("Wallet is not initialised")?;
		let properties = db.read_properties()?.context("Wallet is not initialised")?;
		trace!("Config: {:?}", config);

		let seed = mnemonic.to_seed("");
		let vtxo_seed = VtxoSeed::new(properties.network, &seed);

		if properties.fingerprint != vtxo_seed.fingerprint() {
			bail!("incorrect mnemonic")
		}

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

		let onchain = onchain::Wallet::create(properties.network, seed, db.clone(), chain_source.clone())
			.context("failed to create onchain wallet")?;

		let asp = match AspConnection::handshake(&config.asp_address, properties.network).await {
			Ok(asp) => Some(asp),
			Err(e) => {
				warn!("Ark server handshake failed: {}", e);
				None
			}
		};

		let exit = Exit::new(db.clone(), chain_source.clone())?;

		Ok(Wallet { config, db, onchain, vtxo_seed, exit, asp })
	}

	pub fn config(&self) -> &Config {
		&self.config
	}

	pub fn properties(&self) -> anyhow::Result<WalletProperties> {
		let properties = self.db.read_properties()?.context("Wallet is not initialised")?;
		Ok(properties)
	}

	/// Change the config of this wallet.
	///
	/// In order for these changes to be persistent, call [Wallet::persist_config].
	pub fn set_config(&mut self, config: Config) {
		self.config = config;
	}

	pub fn persist_config(&self) -> anyhow::Result<()> {
		self.db.write_config(&self.config)
	}

	fn require_asp(&self) -> anyhow::Result<AspConnection> {
		self.asp.clone().context("You should be connected to ASP to perform this action")
	}

	/// Return ArkInfo fetched on last handshake
	pub fn ark_info(&self) -> Option<&ArkInfo> {
		self.asp.as_ref().map(|a| &a.info)
	}

	/// Retrieve the off-chain balance of the wallet.
	///
	/// Make sure you sync before calling this method.
	pub async fn offchain_balance(&self) -> anyhow::Result<Amount> {
		let mut sum = Amount::ZERO;
		for vtxo in self.db.get_all_spendable_vtxos()? {
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

	pub fn movements(&self, pagination: Pagination) -> anyhow::Result<Vec<Movement>> {
		Ok(self.db.get_paginated_movements(pagination)?)
	}

	/// Returns all unspent vtxos
	pub fn vtxos(&self) -> anyhow::Result<Vec<Vtxo>> {
		Ok(self.db.get_all_spendable_vtxos()?)
	}

	/// Returns all unspent vtxos matching the provided predicate
	pub fn vtxos_with(&self, filter: impl FilterVtxos) -> anyhow::Result<Vec<Vtxo>> {
		let vtxos = self.vtxos()?;
		Ok(filter.filter(vtxos).context("error filtering vtxos")?)
	}

	/// Returns all vtxos that will expire within
	/// `threshold_blocks` blocks
	pub async fn get_expiring_vtxos(&mut self, threshold: u32) -> anyhow::Result<Vec<Vtxo>> {
		let expiry = self.onchain.tip().await? - threshold;
		let filter = VtxoFilter::new(&self).expires_before(expiry as BlockHeight);
		Ok(self.vtxos_with(filter)?)
	}

	/// Sync status of unilateral exits.
	pub async fn sync_exits(&mut self) -> anyhow::Result<()> {
		self.exit.sync_exit(&mut self.onchain).await?;
		Ok(())
	}

	/// Sync both the onchain and offchain wallet.
	pub async fn sync(&mut self) -> anyhow::Result<()> {
		self.onchain.sync().await?;
		self.exit.sync_exit(&mut self.onchain).await?;
		self.sync_ark().await?;

		Ok(())
	}

	/// Drop a specific vtxo from the database
	pub async fn drop_vtxo(&mut self, vtxo_id: VtxoId) -> anyhow::Result<()> {
		warn!("Drop vtxo {} from the database", vtxo_id);
		self.db.remove_vtxo(vtxo_id)?;
		Ok(())
	}

	//TODO(stevenroose) improve the way we expose dangerous methods
	pub async fn drop_vtxos(&mut self) -> anyhow::Result<()> {
		warn!("Dropping all vtxos from the db...");
		for vtxo in self.db.get_all_spendable_vtxos()? {
			self.db.remove_vtxo(vtxo.id())?;
		}

		self.exit.clear_exit()?;
		Ok(())
	}

	// Board a vtxo with the given vtxo amount.
	//
	// NB we will spend a little more on-chain to cover minrelayfee.
	pub async fn board_amount(&mut self, amount: Amount) -> anyhow::Result<Board> {
		let asp = self.require_asp()?;
		let properties = self.db.read_properties()?.context("Missing config")?;

		let user_keypair = self.derive_store_next_keypair()?;
		let current_height = self.onchain.tip().await?;
		let spec = ark::VtxoSpec {
			user_pubkey: user_keypair.public_key(),
			asp_pubkey: asp.info.asp_pubkey,
			expiry_height: current_height + asp.info.vtxo_expiry_delta as u32,
			exit_delta: asp.info.vtxo_exit_delta,
			amount: amount,
		};

		let board_amount = amount + ark::board::board_surplus();
		let addr = Address::from_script(&ark::board::board_spk(&spec), properties.network).unwrap();

		// We create the onboard tx template, but don't sign it yet.
		let board_tx = self.onchain.prepare_tx([(addr, board_amount)])?;

		self.board(spec, user_keypair, board_tx).await
	}

	pub async fn board_all(&mut self) -> anyhow::Result<Board> {
		let asp = self.require_asp()?;
		let properties = self.db.read_properties()?.context("Missing config")?;

		let user_keypair = self.derive_store_next_keypair()?;
		let current_height = self.onchain.tip().await?;
		let mut spec = ark::VtxoSpec {
			user_pubkey: user_keypair.public_key(),
			asp_pubkey: asp.info.asp_pubkey,
			expiry_height: current_height + asp.info.vtxo_expiry_delta as u32,
			exit_delta: asp.info.vtxo_exit_delta,
			// amount is temporarily set to total balance but will
			// have fees deducted after psbt construction
			amount: self.onchain.balance()
		};

		let addr = Address::from_script(&ark::board::board_spk(&spec), properties.network).unwrap();
		let board_all_tx = self.onchain.prepare_send_all_tx(addr)?;

		// Deduct fee from vtxo spec
		let fee = board_all_tx.fee().context("Unable to calculate fee")?;
		spec.amount = spec.amount.checked_sub(fee + ark::board::board_surplus()).unwrap();

		assert_eq!(board_all_tx.outputs.len(), 1);
		assert_eq!(board_all_tx.unsigned_tx.tx_out(0).unwrap().value, spec.amount + ark::board::board_surplus());

		self.board(spec, user_keypair, board_all_tx).await
	}

	async fn board(
		&mut self,
		spec: VtxoSpec,
		user_keypair: Keypair,
		board_tx: Psbt,
	) -> anyhow::Result<Board> {
		let mut asp = self.require_asp()?;

		// This is manually enforced in prepare_tx
		const VTXO_VOUT: u32 = 0;

		let utxo = OutPoint::new(board_tx.unsigned_tx.compute_txid(), VTXO_VOUT);
		// We ask the ASP to cosign our board vtxo exit tx.
		let (user_part, priv_user_part) = ark::board::new_user(spec, utxo);
		let asp_part = {
			let res = asp.client.request_board_cosign(rpc::BoardCosignRequest {
				user_part: {
					let mut buf = Vec::new();
					ciborium::into_writer(&user_part, &mut buf).unwrap();
					buf
				},
			}).await.context("error requesting board cosign")?;
			ciborium::from_reader::<ark::board::AspPart, _>(&res.into_inner().asp_part[..])
				.context("invalid ASP part in response")?
		};

		if !asp_part.verify_partial_sig(&user_part) {
			bail!("invalid ASP board cosignature received. user_part={:?}, asp_part={:?}",
				user_part, asp_part,
			);
		}

		// Store vtxo first before we actually make the on-chain tx.
		let vtxo = ark::board::finish(user_part, asp_part, priv_user_part, &user_keypair).into();

		self.db.register_receive(&vtxo).context("db error storing vtxo")?;
		let tx = self.onchain.finish_tx(board_tx)?;
		trace!("Broadcasting board tx: {}", bitcoin::consensus::encode::serialize_hex(&tx));
		self.onchain.broadcast_tx(&tx).await?;

		asp.client.register_board_vtxo(rpc::BoardVtxoRequest {
			board_vtxo: vtxo.encode(),
			board_tx: bitcoin::consensus::serialize(&tx),
		}).await.context("error registering board with the asp")?;

		info!("Board successful");

		Ok(
			Board {
				funding_txid: tx.compute_txid(),
				vtxos: vec![vtxo.into()],
			}
		)
	}

	fn build_vtxo(&self, vtxos: &CachedSignedVtxoTree, leaf_idx: usize) -> anyhow::Result<Option<Vtxo>> {
		let exit_branch = vtxos.exit_branch(leaf_idx).unwrap();
		let dest = &vtxos.spec.spec.vtxos[leaf_idx];
		let vtxo = Vtxo::Round(RoundVtxo {
			spec: VtxoSpec {
				user_pubkey: dest.pubkey,
				asp_pubkey: vtxos.spec.spec.asp_pk,
				expiry_height: vtxos.spec.spec.expiry_height,
				exit_delta: vtxos.spec.spec.exit_delta,
				amount: dest.amount,
			},
			leaf_idx: leaf_idx,
			exit_branch: exit_branch.into_iter().cloned().collect(),
		});

		if self.db.get_vtxo(vtxo.id())?.is_some() {
			debug!("Not adding vtxo {} because it already exists", vtxo.id());
			return Ok(None)
		}

		debug!("Built new vtxo {} with value {}", vtxo.id(), vtxo.spec().amount);
		Ok(Some(vtxo))
	}

	/// Checks if the provided VTXO has some counterparty risk in the current wallet
	///
	/// A [`Vtxo::Oor`] is considered to have some counterparty risk
	/// if it is (directly or not) based on round VTXOs that aren't owned by the wallet
	fn has_counterparty_risk(&self, vtxo: &Vtxo) -> anyhow::Result<bool> {
		let iterate_over_inputs = |inputs: &[Vtxo]| -> anyhow::Result<bool> {
			for input in inputs.iter() {
				if self.has_counterparty_risk(input)? {
					return Ok(true)
				}
			}
			Ok(false)
		};

		match vtxo {
			Vtxo::Arkoor(ArkoorVtxo { inputs, .. }) => iterate_over_inputs(inputs),
			Vtxo::Bolt11Change(Bolt11ChangeVtxo { inputs, .. }) => iterate_over_inputs(inputs),
			Vtxo::Board(_) => Ok(!self.db.check_vtxo_key_exists(&vtxo.spec().user_pubkey)?),
			Vtxo::Round(_) => Ok(!self.db.check_vtxo_key_exists(&vtxo.spec().user_pubkey)?),
		}
	}

	/// Sync with the Ark and look for received vtxos.
	pub async fn sync_ark(&self) -> anyhow::Result<()> {
		let mut asp = self.require_asp()?;

		//TODO(stevenroose) we won't do reorg handling here
		let current_height = self.onchain.tip().await?;
		let last_sync_height = self.db.get_last_ark_sync_height()?;
		debug!("Querying ark for rounds since height {}", last_sync_height);
		let req = rpc::FreshRoundsRequest { start_height: last_sync_height };
		let fresh_rounds = asp.client.get_fresh_rounds(req).await?.into_inner();
		debug!("Received {} new rounds from ark", fresh_rounds.txids.len());

		for txid in fresh_rounds.txids {
			let txid = Txid::from_slice(&txid).context("invalid txid from asp")?;
			let req = rpc::RoundId { txid: txid.to_byte_array().to_vec() };
			let round = asp.client.get_round(req).await?.into_inner();

			let tree = SignedVtxoTreeSpec::decode(&round.signed_vtxos)
				.context("invalid signed vtxo tree from asp")?
				.into_cached_tree();

			for (idx, dest) in tree.spec.spec.vtxos.iter().enumerate() {
				if self.db.check_vtxo_key_exists(&dest.pubkey)? {
					if let Some(vtxo) = self.build_vtxo(&tree, idx)? {
						self.db.register_receive(&vtxo)?;
					}
				}
			}
		}

		//TODO(stevenroose) we currently actually could accidentally be syncing
		// a round multiple times because new blocks could have come in since we
		// took current height

		self.db.store_last_ark_sync_height(current_height)?;

		// Then sync OOR vtxos.
		debug!("Emptying OOR mailbox at ASP...");
		let req = rpc::OorVtxosRequest { pubkey: self.oor_pubkey().serialize().to_vec() };
		let resp = asp.client.empty_oor_mailbox(req).await.context("error fetching oors")?;
		let oors = resp.into_inner().vtxos.into_iter()
			.map(|b| Vtxo::decode(&b).context("invalid vtxo from asp"))
			.collect::<Result<Vec<_>, _>>()?;
		debug!("ASP has {} OOR vtxos for us", oors.len());
		for vtxo in oors {
			// TODO: we need to test receiving arkoors with invalid signatures
			let arkoor = vtxo.as_arkoor().context("asp gave non-arkoor vtxo for arkoor sync")?;
			if let Err(e) = oor::verify_oor(arkoor, Some(self.oor_pubkey())) {
				warn!("Could not validate OOR signature, dropping vtxo. {}", e);
				continue;
			}

			// Not sure if this can happen, but well.
			if self.db.has_spent_vtxo(vtxo.id())? {
				debug!("Not adding OOR vtxo {} because it is considered spent", vtxo.id());
			}

			if self.db.get_vtxo(vtxo.id())?.is_none() {
				debug!("Storing new OOR vtxo {} with value {}", vtxo.id(), vtxo.spec().amount);
				self.db.register_receive(&vtxo).context("failed to store OOR vtxo")?;
			}
		}

		Ok(())
	}

	async fn offboard(&mut self, vtxos: Vec<Vtxo>, address: Option<Address>) -> anyhow::Result<Offboard> {
		if vtxos.is_empty() {
			bail!("no VTXO to offboard");
		}

		let vtxo_sum = vtxos.iter().map(|v| v.amount()).sum::<Amount>();

		let addr = match address {
			Some(addr) => addr,
			None => self.onchain.address()?,
		};

		let round = self.participate_round(move |round| {
			let fee = OffboardRequest::calculate_fee(&addr.script_pubkey(), round.offboard_feerate)
				.expect("bdk created invalid scriptPubkey");

			if fee > vtxo_sum {
				bail!("offboarded amount is lower than fees. Need {fee}, got: {vtxo_sum}");
			}

			let offb = OffboardRequest {
				amount: vtxo_sum - fee,
				script_pubkey: addr.script_pubkey(),
			};

			Ok((vtxos.clone(), Vec::new(), vec![offb]))
		}).await.context("round failed")?;

		Ok(Offboard { round })
	}

	/// Offboard all vtxos to a given address or default to bark onchain address
	pub async fn offboard_all(&mut self, address: Option<Address>) -> anyhow::Result<()> {
		let input_vtxos = self.db.get_all_spendable_vtxos()?;

		self.offboard(input_vtxos, address).await?;

		Ok(())
	}

	/// Offboard vtxos selection to a given address or default to bark onchain address
	pub async fn offboard_vtxos(&mut self, vtxos: Vec<VtxoId>, address: Option<Address>) -> anyhow::Result<()> {
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

	/// Refresh vtxo's.
	///
	/// Returns the [RoundId] of the round if a successful refresh occured.
	/// It will return [None] if no [Vtxo] needed to be refreshed.
	pub async fn refresh_vtxos(
		&mut self,
		vtxos: Vec<Vtxo>
	) -> anyhow::Result<Option<RoundId>> {
		if vtxos.is_empty() {
			warn!("There is no VTXO to refresh!");
			return Ok(None)
		}

		let total_amount = vtxos.iter().map(|v| v.amount()).sum::<Amount>();

		let user_keypair = self.derive_store_next_keypair()?;
		let payment_request = PaymentRequest {
			pubkey: user_keypair.public_key(),
			amount: total_amount
		};

		let round = self.participate_round(move |_| {
			Ok((vtxos.clone(), vec![payment_request.clone()], Vec::new()))
		}).await.context("round failed")?;
		Ok(Some(round))
	}

	pub async fn send_oor_payment(&mut self, destination: PublicKey, amount: Amount) -> anyhow::Result<VtxoId> {
		let mut asp = self.require_asp()?;

		let fr = self.onchain.chain_source.regular_feerate();
		let change_pubkey = self.oor_pubkey();

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
				} else if avail < output.amount + P2TR_DUST {
					None
				} else {
					let change_amount = avail - output.amount;
					Some(PaymentRequest {
						pubkey: change_pubkey,
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

		let (sec_nonces, pub_nonces, keypairs) = {
			let mut secs = Vec::with_capacity(payment.inputs.len());
			let mut pubs = Vec::with_capacity(payment.inputs.len());
			let mut keypairs = Vec::with_capacity(payment.inputs.len());

			for input in payment.inputs.iter() {
				let keypair_idx = self.db.get_vtxo_key_index(&input)?;
				let keypair = self.vtxo_seed.derive_keypair(keypair_idx);

				let (s, p) = musig::nonce_pair(&keypair);
				secs.push(s);
				pubs.push(p);
				keypairs.push(keypair);
			}
			(secs, pubs, keypairs)
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

		trace!("OOR prevouts: {:?}", payment.inputs.iter().map(|i| i.spec().txout()).collect::<Vec<_>>());
		let input_vtxos = payment.inputs.clone();
		let signed = payment.sign_finalize_user(
			sec_nonces,
			&pub_nonces,
			&keypairs,
			&asp_pub_nonces,
			&asp_part_sigs,
		);
		trace!("OOR tx: {}", bitcoin::consensus::encode::serialize_hex(&signed.signed_transaction()));
		let vtxos = signed.output_vtxos().into_iter().map(|v| Vtxo::from(v)).collect::<Vec<_>>();

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

		let change = vtxos.get(1);
		self.db.register_send(
			&input_vtxos,
			output.pubkey.to_string(),
			change,
			Some(account_for_fee)).context("failed to store OOR vtxo")?;

		Ok(user_vtxo.id())
	}

	pub async fn send_bolt11_payment(
		&mut self,
		invoice: &Bolt11Invoice,
		user_amount: Option<Amount>,
	) -> anyhow::Result<Vec<u8>> {
		let properties = self.db.read_properties()?.context("Missing config")?;
		if invoice.network() != properties.network {
			bail!("BOLT-11 invoice is for wrong network: {}", invoice.network());
		}

		if !self.db.get_all_movements_by_destination(&invoice.to_string())?.is_empty() {
			bail!("Invoice has already been paid");
		}

		let mut asp = self.require_asp()?;

		let inv_amount = invoice.amount_milli_satoshis()
			.map(|v| Amount::from_sat(v.div_ceil(1000)));
		if let (Some(_), Some(inv)) = (user_amount, inv_amount) {
			bail!("Invoice has amount of {} encoded. Please omit amount argument", inv);
		}
		let amount = user_amount.or(inv_amount).context("amount required on invoice without amount")?;

		let change_keypair = self.derive_store_next_keypair()?;

		// The anchor output has an amount
		let anchor_amount = bitcoin_ext::P2WSH_DUST;
		let forwarding_fee = Amount::from_sat(350);
		let inputs = self.db.get_expiring_vtxos(amount + anchor_amount + forwarding_fee)?;


		let (sec_nonces, pub_nonces, keypairs) = {
			let mut secs = Vec::with_capacity(inputs.len());
			let mut pubs = Vec::with_capacity(inputs.len());
			let mut keypairs = Vec::with_capacity(inputs.len());

			for input in inputs.iter() {
				let keypair_idx = self.db.get_vtxo_key_index(&input)?;
				let keypair = self.vtxo_seed.derive_keypair(keypair_idx);

				let (s, p) = musig::nonce_pair(&keypair);
				secs.push(s);
				pubs.push(p);
				keypairs.push(keypair);
			}
			(secs, pubs, keypairs)
		};

		let req = rpc::Bolt11PaymentRequest {
			invoice: invoice.to_string(),
			amount_sats: user_amount.map(|a| a.to_sat()),
			input_vtxos: inputs.iter().map(|v| v.encode()).collect(),
			user_pubkey: change_keypair.public_key().serialize().to_vec(),
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

		trace!("htlc prevouts: {:?}", inputs.iter().map(|i| i.spec().txout()).collect::<Vec<_>>());
		let input_vtxos = payment.inputs.clone();
		let signed = payment.sign_finalize_user(
			sec_nonces,
			&pub_nonces,
			&keypairs,
			&asp_pub_nonces,
			&asp_part_sigs,
		);

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

		let payment_preimage = payment_preimage.ok_or_else(|| anyhow!("Payment failed: {}", last_msg))?;
		let change_vtxo = if let Some(change_vtxo) = signed.change_vtxo() {
			info!("Adding change VTXO of {}", change_vtxo.pseudo_spec.amount);
			trace!("htlc tx: {}", bitcoin::consensus::encode::serialize_hex(&change_vtxo.htlc_tx));
			Some(change_vtxo.into())
		} else {
			None
		};

		self.db.register_send(
			&input_vtxos,
			invoice.to_string(),
			change_vtxo.as_ref(),
			Some(anchor_amount + forwarding_fee)).context("failed to store OOR vtxo")?;

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

	/// Send to an onchain address in an Ark round.
	///
	/// It is advised to sync your wallet before calling this method.
	pub async fn send_round_onchain_payment(&mut self, addr: Address, amount: Amount) -> anyhow::Result<SendOnchain> {
		let change_keypair = self.derive_store_next_keypair()?;

		// Prepare the payment.
		let input_vtxos = self.db.get_all_spendable_vtxos()?;

		// do a quick check to fail early if we don't have enough money
		let maybe_fee = OffboardRequest::calculate_fee(
			&addr.script_pubkey(), FeeRate::from_sat_per_vb(1).unwrap(),
		).expect("script from address");
		let in_sum = input_vtxos.iter().map(|v| v.amount()).sum::<Amount>();
		if in_sum < amount + maybe_fee {
			bail!("Balance too low");
		}

		let round = self.participate_round(move |round| {
			let offb = OffboardRequest {
				script_pubkey: addr.script_pubkey(),
				amount: amount,
			};

			let out_value = amount + offb.fee(round.offboard_feerate).expect("script from address");
			let change = {
				if in_sum < out_value {
					bail!("Balance too low");
				} else if in_sum <= out_value + P2TR_DUST {
					info!("No change, emptying wallet.");
					None
				} else {
					let amount = in_sum - out_value;
					info!("Adding change vtxo for {}", amount);
					Some(PaymentRequest {
						pubkey: change_keypair.public_key(),
						amount: amount,
					})
				}
			};

			Ok((input_vtxos.clone(), change.into_iter().collect(), vec![offb]))
		}).await.context("round failed")?;

		Ok(SendOnchain { round })
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
		mut round_input: impl FnMut(&RoundInfo) -> anyhow::Result<
			(Vec<Vtxo>, Vec<PaymentRequest>, Vec<OffboardRequest>)
		>,
	) -> anyhow::Result<RoundId> {
		let mut asp = self.require_asp()?;

		info!("Waiting for a round start...");
		let mut events = asp.client.subscribe_rounds(rpc::Empty {}).await?.into_inner()
			.map(|m| {
				let m = m.context("received error on event stream")?;
				let e = RoundEvent::try_from(m).context("error converting rpc round event")?;
				trace!("Received round event: {}", e);
				Ok::<_, anyhow::Error>(e)
			});

		// We keep this Option with the latest round info.
		// It allows us to conveniently restart when something unexpected happens:
		// - when a new attempt starts, we update the info and restart
		// - when a new round starts, we set it to the new round info and restart
		// - when the asp misbehaves, we set it to None and restart
		let mut next_round_info = None;

		'round: loop {
			// If we don't have a round info yet, wait for round start.
			let mut round_state = if let Some(info) = next_round_info.take() {
				warn!("Unexpected new round started...");
				RoundState::new(info)
			} else {
				debug!("Waiting for a new round to start...");
				loop {
					match events.next().await.context("events stream broke")?? {
						RoundEvent::Start(e) => {
							break RoundState::new(e);
						},
						_ => trace!("ignoring irrelevant message"),
					}
				}
			};

			// then we expect the first attempt message
			match events.next().await.context("events stream broke")?? {
				RoundEvent::Attempt(attempt) => {
					round_state.process_attempt(attempt);
				},
				RoundEvent::Start(e) => {
					next_round_info = Some(e);
					continue 'round;
				},
				//TODO(stevenroose) make this robust
				other => panic!("Unexpected message: {:?}", other),
			};

			info!("Round started");

			let (input_vtxos, pay_reqs, offb_reqs) = round_input(&round_state.info)
				.context("error providing round input")?;
			// Convert the input vtxos to a map to cache their ids.
			let input_vtxos = input_vtxos.into_iter()
				.map(|v| (v.id(), v))
				.collect::<HashMap<_, _>>();
			debug!("Spending vtxos: {:?}", input_vtxos.keys());

			'attempt: loop {
				assert!(round_state.attempt.is_some());

				// Assign cosign pubkeys to the payment requests.
				let cosign_keys = iter::repeat_with(|| Keypair::new(&SECP, &mut rand::thread_rng()))
					.take(pay_reqs.len())
					.collect::<Vec<_>>();
				let vtxo_reqs = pay_reqs.iter().zip(cosign_keys.iter()).map(|(req, ck)| {
					VtxoRequest {
						pubkey: req.pubkey,
						amount: req.amount,
						cosign_pk: ck.public_key(),
					}
				}).collect::<Vec<_>>();

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

				let res = asp.client.submit_payment(rpc::SubmitPaymentRequest {
					input_vtxos: input_vtxos.iter().map(|(id, vtxo)| {
						let key = self.vtxo_seed.derive_keypair(
							self.db.get_vtxo_key_index(vtxo).expect("owned vtxo key should be in database")
						);
						rpc::InputVtxo {
							vtxo_id: id.to_bytes().to_vec(),
							ownership_proof: {
								let sig = round_state.challenge().sign_with(*id, key);
								sig.serialize().to_vec()
							},
						}
					}).collect(),
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
				}).await;

				if let Err(e) = res {
					warn!("Could not submit payment, trying next round: {}", e);
					continue 'round
				}


				// ****************************************************************
				// * Wait for vtxo proposal from asp.
				// ****************************************************************

				debug!("Waiting for vtxo proposal from asp...");
				let (vtxo_tree, unsigned_round_tx, vtxo_cosign_agg_nonces, connector_pubkey) = {
					match events.next().await.context("events stream broke")?? {
						RoundEvent::VtxoProposal {
							round_seq,
							unsigned_round_tx,
							vtxos_spec,
							cosign_agg_nonces,
							connector_pubkey,
						} => {
							if round_seq != round_state.info.round_seq {
								warn!("Unexpected different round id");
								continue 'round;
							}
							(vtxos_spec, unsigned_round_tx, cosign_agg_nonces, connector_pubkey)
						},
						RoundEvent::Start(e) => {
							next_round_info = Some(e);
							continue 'round;
						},
						RoundEvent::Attempt(e) => {
							if round_state.process_attempt(e) {
								continue 'attempt;
							} else {
								continue 'round;
							}
						},
						//TODO(stevenroose) make this robust
						other => panic!("Unexpected message: {:?}", other),
					}
				};

				//TODO(stevenroose) remove these magic numbers
				if unsigned_round_tx.output.len() < 2 {
					bail!("asp sent round tx with less than 2 outputs: {}",
						bitcoin::consensus::encode::serialize_hex(&unsigned_round_tx),
					);
				}
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
						error!("asp didn't include all of our vtxos, missing: {:?}", my_vtxos);
						continue 'round;
					}

					let mut my_offbs = offb_reqs.clone();
					for offb in unsigned_round_tx.output.iter().skip(2) {
						if let Some(i) = my_offbs.iter().position(|o| o.to_txout() == *offb) {
							my_offbs.swap_remove(i);
						}
					}
					if !my_offbs.is_empty() {
						error!("asp didn't include all of our offboards, missing: {:?}", my_offbs);
						continue 'round;
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
					let res = asp.client.provide_vtxo_signatures(rpc::VtxoSignaturesRequest {
						pubkey: key.public_key().serialize().to_vec(),
						signatures: part_sigs.iter().map(|s| s.serialize().to_vec()).collect(),
					}).await;

					if let Err(e) = res {
						warn!("Could not provide vtxo signatures, trying next round: {}", e);
						continue 'round
					}
				}


				// ****************************************************************
				// * Then proceed to get a round proposal and sign forfeits
				// ****************************************************************

				debug!("Wait for round proposal from asp...");
				let (vtxo_cosign_sigs, forfeit_nonces) = {
					match events.next().await.context("events stream broke")?? {
						RoundEvent::RoundProposal { round_seq, cosign_sigs, forfeit_nonces } => {
							if round_seq != round_state.info.round_seq {
								warn!("Unexpected different round id");
								continue 'round;
							}
							(cosign_sigs, forfeit_nonces)
						},
						RoundEvent::Start(e) => {
							next_round_info = Some(e);
							continue 'round;
						},
						RoundEvent::Attempt(e) => {
							if round_state.process_attempt(e) {
								continue 'attempt;
							} else {
								continue 'round;
							}
						},
						//TODO(stevenroose) make this robust
						other => panic!("Unexpected message: {:?}", other),
					}
				};

				// Validate the vtxo tree.
				if let Err(e) = unsigned_vtxos.verify_cosign_sigs(&vtxo_cosign_sigs) {
					bail!("Received incorrect vtxo cosign signatures from asp: {}", e);
				}
				let signed_vtxos = unsigned_vtxos
					.into_signed_tree(vtxo_cosign_sigs)
					.into_cached_tree();

				// Check that the connector key is correct.
				let conn_txout = unsigned_round_tx.output.get(1).expect("checked before");
				let expected_conn_txout = ConnectorChain::output(forfeit_nonces.len(), connector_pubkey);
				if *conn_txout != expected_conn_txout {
					bail!("round tx from asp has unexpected connector output: {:?} (expected {:?})",
						conn_txout, expected_conn_txout,
					);
				}

				// Make forfeit signatures.
				let connectors = ConnectorChain::new(
					forfeit_nonces.values().next().unwrap().len(),
					conns_utxo,
					connector_pubkey,
				);
				let forfeit_sigs = input_vtxos.iter().map(|(id, vtxo)| {
					let keypair_idx = self.db.get_vtxo_key_index(&vtxo)?;
					let vtxo_keypair = self.vtxo_seed.derive_keypair(keypair_idx);

					let sigs = connectors.connectors().enumerate().map(|(i, (conn, _))| {
						let (sighash, _tx) = ark::forfeit::forfeit_sighash_exit(
							vtxo, conn, connector_pubkey,
						);
						let asp_nonce = forfeit_nonces.get(&id)
							.with_context(|| format!("missing asp forfeit nonce for {}", id))?
							.get(i)
							.context("asp didn't provide enough forfeit nonces")?;

						let (nonce, sig) = musig::deterministic_partial_sign(
							&vtxo_keypair,
							[asp.info.asp_pubkey],
							&[asp_nonce],
							sighash.to_byte_array(),
							Some(vtxo.spec().vtxo_taptweak().to_byte_array()),
						);
						Ok((nonce, sig))
					}).collect::<anyhow::Result<Vec<_>>>()?;
					Ok((id, sigs))
				}).collect::<anyhow::Result<HashMap<_, _>>>()?;
				debug!("Sending {} sets of forfeit signatures for our inputs", forfeit_sigs.len());
				let res = asp.client.provide_forfeit_signatures(rpc::ForfeitSignaturesRequest {
					signatures: forfeit_sigs.into_iter().map(|(id, sigs)| {
						rpc::ForfeitSignatures {
							input_vtxo_id: id.to_bytes().to_vec(),
							pub_nonces: sigs.iter().map(|s| s.0.serialize().to_vec()).collect(),
							signatures: sigs.iter().map(|s| s.1.serialize().to_vec()).collect(),
						}
					}).collect(),
				}).await;

				if let Err(e) = res {
					warn!("Could not provide forfeit signatures, trying next round: {}", e);
					continue 'round
				}


				// ****************************************************************
				// * Wait for the finishing of the round.
				// ****************************************************************

				debug!("Waiting for round to finish...");
				let signed_round_tx = match events.next().await.context("events stream broke")?? {
					RoundEvent::Finished { round_seq, signed_round_tx } => {
						if round_seq != round_state.info.round_seq {
							bail!("Unexpected round ID from round finished event: {} != {}",
								round_seq, round_state.info.round_seq);
						}
						signed_round_tx
					},
					RoundEvent::Start(e) => {
						next_round_info = Some(e);
						continue 'round;
					},
					RoundEvent::Attempt(e) => {
						if round_state.process_attempt(e) {
							continue 'attempt;
						} else {
							continue 'round;
						}
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

				// Finally we save state after refresh
				let mut new_vtxos: Vec<Vtxo> = vec![];
				for (idx, req) in signed_vtxos.spec.spec.vtxos.iter().enumerate() {
					//TODO(stevenroose) this is broken, need to match vtxorequest exactly
					if pay_reqs.iter().any(|p| p.pubkey == req.pubkey && p.amount == req.amount) {
						let vtxo = self.build_vtxo(&signed_vtxos, idx)?.expect("must be in tree");
						new_vtxos.push(vtxo);
					}
				}

				// if there is one offboard req, we register as a spend, else as a refresh
				// TODO: this is broken in case of multiple offb_reqs, but currently we don't allow that
				if let Some(offboard) = offb_reqs.get(0) {
					let params = Params::new(self.properties().unwrap().network);
					let address = Address::from_script(&offboard.script_pubkey, params)?;
					self.db.register_send(
						input_vtxos.values(),
						address.to_string(),
						new_vtxos.get(0), None
					)?;
				} else {
					self.db.register_refresh(input_vtxos.values(), &new_vtxos)?;
				}

				info!("Round finished");
				return Ok(signed_round_tx.compute_txid().into())
			}
		}
	}
}

struct RoundState {
	info: RoundInfo,
	attempt: Option<RoundAttempt>,
}

impl RoundState {
	/// Create a new [RoundState] from a [RoundEvent::Start].
	///
	/// Panics if any other event type is passed.
	fn new(info: RoundInfo) -> RoundState {
		RoundState { info, attempt: None }
	}

	/// Process a new round attempt message.
	///
	/// If the attempt event belonged to the same round and we could
	/// succesfully update, we return true.
	/// If the attempt belongs to a different round and we have to restart,
	/// we return false.
	fn process_attempt(&mut self, attempt: RoundAttempt) -> bool {
		if attempt.round_seq == self.info.round_seq {
			self.attempt = Some(attempt);
			true
		} else {
			false
		}
	}

	fn challenge(&self) -> VtxoOwnershipChallenge {
		self.attempt.as_ref().expect("called challenge outside attempt loop").challenge
	}
}

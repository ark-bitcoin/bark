pub extern crate ark;
pub extern crate bark_json as json;

pub extern crate lightning_invoice;
pub extern crate lnurl as lnurllib;

#[macro_use] extern crate anyhow;
#[macro_use] extern crate serde;

mod exit;
mod lnurl;
pub mod movement;
pub mod onchain;
pub mod persist;
pub use persist::sqlite::SqliteClient;
mod psbtext;
pub mod vtxo_selection;
mod vtxo_state;

pub use bark_json::primitives::UtxoInfo;
pub use bark_json::cli::{Offboard, Board, SendOnchain};

use std::collections::{HashMap, HashSet};
use std::convert::TryFrom;
use std::iter;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context};
use bip39::Mnemonic;
use bitcoin::{Address, Amount, FeeRate, Network, OutPoint, Txid};
use bitcoin::bip32::{self, ChildNumber, Fingerprint};
use bitcoin::hashes::{sha256, Hash};
use bitcoin::hex::DisplayHex;
use bitcoin::params::Params;
use bitcoin::secp256k1::{self, rand, Keypair, PublicKey};
use bitcoin::secp256k1::rand::Rng;
use lnurllib::lightning_address::LightningAddress;
use lightning_invoice::Bolt11Invoice;
use log::{trace, debug, info, warn, error};
use rusqlite::ToSql;
use tokio_stream::{Stream, StreamExt};

use ark::board::{BoardBuilder, BOARD_FUNDING_TX_VTXO_VOUT};
use ark::{ArkInfo, OffboardRequest, ProtocolEncoding, SignedVtxoRequest, Vtxo, VtxoId, VtxoPolicy, VtxoRequest};
use ark::arkoor::ArkoorPackageBuilder;
use ark::connectors::ConnectorChain;
use ark::musig::{self, MusigPubNonce, MusigSecNonce};
use ark::rounds::{
	RoundAttempt, RoundEvent, RoundId, RoundInfo, VtxoOwnershipChallenge,
	MIN_ROUND_TX_OUTPUTS, ROUND_TX_CONNECTOR_VOUT, ROUND_TX_VTXO_TREE_VOUT,
};
use ark::tree::signed::{CachedSignedVtxoTree, SignedVtxoTreeSpec};
use ark::util::{Decodable, Encodable};
use aspd_rpc::{self as rpc, protos};
use bitcoin_ext::{AmountExt, BlockHeight, P2TR_DUST, DEEPLY_CONFIRMED};
use bitcoin_ext::bdk::WalletExt;

use crate::exit::Exit;
use crate::movement::{Movement, MovementArgs};
use crate::onchain::Utxo;
use crate::persist::BarkPersister;
use crate::vtxo_selection::{FilterVtxos, VtxoFilter};
use crate::vtxo_state::VtxoState;
use crate::vtxo_selection::RefreshStrategy;

const ARK_PURPOSE_INDEX: u32 = 350;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeychainKind {
	/// Internal keypairs are used for VTXO board, refreshes and change outputs
	Internal,
	/// External keypairs are shared externally to receive payments
	External,
}

impl Into<ChildNumber> for KeychainKind {
	fn into(self) -> ChildNumber {
		match self {
			KeychainKind::Internal => ChildNumber::from_hardened_idx(0).unwrap(),
			KeychainKind::External => ChildNumber::from_hardened_idx(1).unwrap(),
		}
	}
}

impl TryFrom<i64> for KeychainKind {
	type Error = anyhow::Error;

	fn try_from(value: i64) -> Result<Self, Self::Error> {
		match value {
			0 => Ok(KeychainKind::Internal),
			1 => Ok(KeychainKind::External),
			_ => Err(anyhow::anyhow!("Invalid keychain kind: {}", value)),
		}
	}
}

impl ToSql for KeychainKind {
	fn to_sql(&self) -> rusqlite::Result<rusqlite::types::ToSqlOutput<'_>> {
		match self {
			KeychainKind::Internal => Ok(0.into()),
			KeychainKind::External => Ok(1.into()),
		}
	}
}

#[derive(Clone, Serialize, Deserialize)]
pub enum OffchainPayment {
	Lightning(Bolt11Invoice),
}

impl Encodable for OffchainPayment {}
impl Decodable for OffchainPayment {}

pub struct OffchainOnboard {
	pub payment_hash: [u8; 32],
	pub payment_preimage: [u8; 32],
	pub payment: OffchainPayment,
}

lazy_static::lazy_static! {
	/// Global secp context.
	static ref SECP: secp256k1::Secp256k1<secp256k1::All> = secp256k1::Secp256k1::new();
}

lazy_static::lazy_static! {
	/// Arbitrary fee for Lightning onboarding. Subject to change when we have a fee schedule.
	static ref LN_ONBOARD_FEE_SATS: Amount = Amount::from_sat(350);
}

struct ArkoorCreateResult {
	input: Vec<Vtxo>,
	created: Vec<Vtxo>,
	change: Option<Vtxo>,
}

pub struct Pagination {
	pub page_index: u16,
	pub page_size: u16,
}

impl From<Utxo> for UtxoInfo {
	fn from(value: Utxo) -> Self {
		match value {
			Utxo::Local(o) => UtxoInfo {
				outpoint: o.outpoint,
				amount: o.txout.value,
				confirmation_height: o.chain_position.confirmation_height_upper_bound()
			},
			Utxo::Exit(e) => UtxoInfo {
				outpoint: e.vtxo.point(),
				amount: e.vtxo.amount(),
				confirmation_height: Some(e.height),
			},
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
	pub vtxo_refresh_expiry_threshold: BlockHeight,

	/// A fallback fee rate to use in sat/kWu when we fail to retrieve a fee rate from the
	/// configured bitcoind/esplora connection.
	///
	/// Example for 1 sat/vB: --fallback-fee-rate 250
	pub fallback_fee_rate: Option<FeeRate>,
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
			vtxo_refresh_expiry_threshold: 288,
			fallback_fee_rate: None,
		}
	}
}

#[derive(Debug)]
enum AttemptResult {
	Success(RoundResult),
	WaitNewRound,
	NewRoundStarted(RoundInfo),
	NewAttemptStarted,
}

#[derive(Debug)]
struct RoundResult {
	round_id: RoundId,
	/// VTXOs created in the round
	vtxos: Vec<Vtxo>,
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

		Self(master.derive_priv(&SECP, &[ARK_PURPOSE_INDEX.into()]).unwrap())
	}

	fn fingerprint(&self) -> Fingerprint {
		self.0.fingerprint(&SECP)
	}

	fn derive_keychain(&self, kind: KeychainKind, keypair_idx: u32) -> Keypair {
		self.0.derive_priv(&SECP, &[kind.into(), keypair_idx.into()]).unwrap().to_keypair(&SECP)
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

		let res = client.handshake(protos::HandshakeRequest { version: our_version })
			.await.context("ark info request failed")?.into_inner();

		if let Some(ref msg) = res.psa {
			warn!("Message from Ark server: \"{}\"", msg);
		}

		if let Some(info) = res.ark_info {
			let info = ArkInfo::try_from(info).context("invalid ark info from asp")?;
			if network != info.network {
				bail!("ASP is for net {} while we are on net {}", info.network, network);
			}
			// we print the error message as a warning, because we still succeeded
			if let Some(msg) = res.error {
				warn!("Warning from Ark server: \"{}\"", msg);
			}
			Ok(AspConnection { info, client })
		} else {
			let msg = res.error.as_ref().map(|s| s.as_str()).unwrap_or("NO MESSAGE");
			bail!("Ark server handshake failed: {}", msg);
		}
	}
}

pub struct Wallet {
	pub onchain: onchain::Wallet,
	pub exit: Exit,

	config: Config,
	db: Arc<dyn BarkPersister>,
	vtxo_seed: VtxoSeed,
	asp: Option<AspConnection>,
}

impl Wallet {
	/// Derive and store the keypair directly after currently last revealed one
	pub fn derive_store_next_keypair(&self, keychain: KeychainKind) -> anyhow::Result<Keypair> {
		let last_revealed = self.db.get_last_vtxo_key_index(keychain)?;

		let index = last_revealed.map(|i| i + 1).unwrap_or(u32::MIN);
		let keypair = self.vtxo_seed.derive_keychain(keychain, index);

		self.db.store_vtxo_key(keychain, index, keypair.public_key())?;
		Ok(keypair)
	}

	pub fn peak_keypair(&self, keychain: KeychainKind, index: u32) -> anyhow::Result<Keypair> {
		let keypair = self.vtxo_seed.derive_keychain(keychain, index);
		if self.db.check_vtxo_key_exists(&keypair.public_key())? {
			Ok(keypair)
		} else {
			bail!("VTXO key {} does not exist, please derive it first", index)
		}
	}

	/// Create new wallet.
	pub async fn create<P: BarkPersister>(
		mnemonic: &Mnemonic,
		network: Network,
		config: Config,
		db: P,
		mnemonic_birthday: Option<BlockHeight>,
	) -> anyhow::Result<Wallet> {
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
				.saturating_sub(DEEPLY_CONFIRMED)
		};
		let id = wallet.onchain.chain.block_id(bday).await
			.with_context(|| format!("failed to get block height {} from chain source", bday))?;
		wallet.onchain.wallet.set_checkpoint(id.height, id.hash);
		wallet.onchain.persist()?;

		Ok(wallet)
	}

	/// Open existing wallet.
	pub async fn open<P: BarkPersister>(mnemonic: &Mnemonic, db: P) -> anyhow::Result<Wallet> {
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
			onchain::ChainSource::Bitcoind { url: url.clone(), auth }
		} else {
			bail!("Need to either provide esplora or bitcoind info");
		};

		let db = Arc::new(db);
		let onchain = onchain::Wallet::create(
			properties.network, seed, db.clone(), chain_source.clone(), config.fallback_fee_rate,
		).context("failed to create onchain wallet")?;

		let asp = match AspConnection::handshake(&config.asp_address, properties.network).await {
			Ok(asp) => Some(asp),
			Err(e) => {
				warn!("Ark server handshake failed: {}", e);
				None
			}
		};

		let exit = Exit::new(db.clone(), chain_source.clone(), &onchain).await?;

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
	pub fn offchain_balance(&self) -> anyhow::Result<Amount> {
		let mut sum = Amount::ZERO;
		for vtxo in self.db.get_all_spendable_vtxos()? {
			sum += vtxo.amount();
			debug!("Vtxo {}: {}", vtxo.id(), vtxo.amount());
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
	pub async fn get_expiring_vtxos(&mut self, threshold: BlockHeight) -> anyhow::Result<Vec<Vtxo>> {
		let expiry = self.onchain.tip().await? + threshold;
		let filter = VtxoFilter::new(&self).expires_before(expiry);
		Ok(self.vtxos_with(filter)?)
	}

	async fn register_all_unregistered_boards(&self) -> anyhow::Result<()> {
		let unregistered_boards = self.db.get_vtxos_by_state(&[VtxoState::UnregisteredBoard])?;
		trace!("Re-attempt registration of {} boards", unregistered_boards.len());
		for board in unregistered_boards {
			if let Err(e) = self.register_board(board.id()).await {
				warn!("Failed to register board {}: {}", board.id(), e);
			}
		};

		Ok(())
	}

	/// Performs maintenance tasks on the wallet
	///
	/// This tasks include onchain-sync, off-chain sync,
	/// registering onboard with the server.
	///
	/// This tasks will only include anything that has to wait
	/// for a round. The maintenance call cannot be used to
	/// refresh VTXOs.
	pub async fn maintenance(&mut self) -> anyhow::Result<()> {
		info!("Starting wallet maintenance");
		self.sync().await?;
		self.register_all_unregistered_boards().await?;
		info!("Performing maintenance refresh");
		self.maintenance_refresh().await?;
		Ok(())
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
		let user_keypair = self.derive_store_next_keypair(KeychainKind::Internal)?;
		self.board(amount, user_keypair).await
	}

	pub async fn board_all(&mut self) -> anyhow::Result<Board> {
		let user_keypair = self.derive_store_next_keypair(KeychainKind::Internal)?;

		let throwaway_addr = self.onchain.address()?;
		let board_all_tx = self.onchain.prepare_send_all_tx(throwaway_addr)?;

		// Deduct fee from vtxo spec
		let fee = board_all_tx.fee().context("Unable to calculate fee")?;
		let amount = self.onchain.balance().checked_sub(fee)
			.context("not enough money for a board")?;

		assert_eq!(board_all_tx.outputs.len(), 1);
		assert_eq!(board_all_tx.unsigned_tx.tx_out(0).unwrap().value, amount);

		self.board(amount, user_keypair).await
	}

	async fn board(
		&mut self,
		amount: Amount,
		user_keypair: Keypair,
	) -> anyhow::Result<Board> {
		let mut asp = self.require_asp()?;
		let properties = self.db.read_properties()?.context("Missing config")?;
		let current_height = self.onchain.tip().await?;

		let expiry_height = current_height + asp.info.vtxo_expiry_delta as BlockHeight;
		let builder = BoardBuilder::new(
			amount,
			user_keypair.public_key(),
			expiry_height,
			asp.info.asp_pubkey,
			asp.info.vtxo_exit_delta,
		);

		let addr = Address::from_script(&builder.funding_script_pubkey(), properties.network).unwrap();

		// We create the onboard tx template, but don't sign it yet.
		let board_psbt = self.onchain.prepare_tx([(addr, amount)])?;

		let utxo = OutPoint::new(board_psbt.unsigned_tx.compute_txid(), BOARD_FUNDING_TX_VTXO_VOUT);
		let builder = builder
			.set_funding_utxo(utxo)
			.generate_user_nonces();

		let cosign_resp = asp.client.request_board_cosign(protos::BoardCosignRequest {
			amount: amount.to_sat(),
			utxo: bitcoin::consensus::serialize(&utxo), //TODO(stevenroose) change to own
			expiry_height: expiry_height,
			user_pubkey: user_keypair.public_key().serialize().to_vec(),
			pub_nonce: builder.user_pub_nonce().serialize().to_vec(),
		}).await.context("error requesting board cosign")?
			.into_inner().try_into().context("invalid cosign response from server")?;

		ensure!(builder.verify_cosign_response(&cosign_resp),
			"invalid board cosignature received from server",
		);

		// Store vtxo first before we actually make the on-chain tx.
		let vtxo = builder.build_vtxo(&cosign_resp, &user_keypair)?;

		self.db.register_movement(MovementArgs {
			spends: &[],
			receives: &[(&vtxo, VtxoState::UnregisteredBoard)],
			recipients: &[],
			fees: None
		}).context("db error storing vtxo")?;

		let tx = self.onchain.finish_tx(board_psbt)?;

		trace!("Broadcasting board tx: {}", bitcoin::consensus::encode::serialize_hex(&tx));
		self.onchain.broadcast_tx(&tx).await?;

		let res = self.register_board(vtxo.id()).await;
		info!("Board successful");
		res
	}

	/// Registers a board to the Ark server
	async fn register_board(&self, vtxo_id: VtxoId) -> anyhow::Result<Board> {
		trace!("Attempting to register board {} to server", vtxo_id);
		let mut asp = self.require_asp()?;

		// Get the vtxo and funding transaction from the database
		let vtxo = self.db.get_vtxo(vtxo_id)?
			.with_context(|| format!("VTXO doesn't exist: {}", vtxo_id))?;

		let funding_tx = self.onchain.get_wallet_tx(vtxo.chain_anchor().txid)
			.context("Failed to find funding_tx for {}")?;

		// Register the vtxo with the server
		asp.client.register_board_vtxo(protos::BoardVtxoRequest {
			board_vtxo: vtxo.serialize(),
			board_tx: bitcoin::consensus::serialize(&funding_tx),
		}).await.context("error registering board with the asp")?;

		// Remember that we have stored the vtxo
		// No need to complain if the vtxo is already registered
		let allowed_states = &[VtxoState::UnregisteredBoard, VtxoState::Spendable];
		self.db.update_vtxo_state_checked(vtxo_id, VtxoState::Spendable, allowed_states)?;

		Ok(Board {
			funding_txid: funding_tx.compute_txid(),
			vtxos: vec![vtxo.into()],
		})
	}

	fn build_vtxo(&self, vtxos: &CachedSignedVtxoTree, leaf_idx: usize) -> anyhow::Result<Option<Vtxo>> {
		let vtxo = vtxos.build_vtxo(leaf_idx).context("invalid leaf idx..")?;

		if self.db.get_vtxo(vtxo.id())?.is_some() {
			debug!("Not adding vtxo {} because it already exists", vtxo.id());
			return Ok(None)
		}

		debug!("Built new vtxo {} with value {}", vtxo.id(), vtxo.amount());
		Ok(Some(vtxo))
	}

	/// Checks if the provided VTXO has some counterparty risk in the current wallet
	///
	/// An arkoor vtxo is considered to have some counterparty risk
	/// if it is (directly or not) based on round VTXOs that aren't owned by the wallet
	fn has_counterparty_risk(&self, vtxo: &Vtxo) -> anyhow::Result<bool> {
		for past_pk in vtxo.past_arkoor_pubkeys() {
			if !self.db.check_vtxo_key_exists(&past_pk)? {
				return Ok(true);
			}
		}
		Ok(false)
	}

	/// Sync with the Ark and look for received vtxos.
	pub async fn sync_ark(&self) -> anyhow::Result<()> {
		self.sync_rounds().await?;
		self.sync_oors().await?;

		Ok(())
	}

	/// Fetch new rounds from the Ark Server and check if one of their VTXOs
	/// is in the provided set of public keys
	pub async fn sync_rounds(&self) -> anyhow::Result<()> {
		let mut asp = self.require_asp()?;

		let keychain = KeychainKind::Internal;
		let last_pk_index = self.db.get_last_vtxo_key_index(keychain)?.unwrap_or_default();
		let pubkeys = (0..=last_pk_index).map(|idx| {
			self.vtxo_seed.derive_keychain(keychain, idx).public_key()
		}).collect::<HashSet<_>>();

		//TODO(stevenroose) we won't do reorg handling here
		let current_height = self.onchain.tip().await?;
		let last_sync_height = self.db.get_last_ark_sync_height()?;
		debug!("Querying ark for rounds since height {}", last_sync_height);
		let req = protos::FreshRoundsRequest { start_height: last_sync_height };
		let fresh_rounds = asp.client.get_fresh_rounds(req).await?.into_inner();
		debug!("Received {} new rounds from ark", fresh_rounds.txids.len());

		for txid in fresh_rounds.txids {
			let txid = Txid::from_slice(&txid).context("invalid txid from asp")?;
			let req = protos::RoundId { txid: txid.to_byte_array().to_vec() };
			let round = asp.client.get_round(req).await?.into_inner();

			let tree = SignedVtxoTreeSpec::deserialize(&round.signed_vtxos)
				.context("invalid signed vtxo tree from asp")?
				.into_cached_tree();

			for (idx, dest) in tree.spec.spec.vtxos.iter().enumerate() {
				if let VtxoPolicy::Pubkey { user_pubkey } = dest.vtxo.policy {
					if pubkeys.contains(&user_pubkey) {
						if let Some(vtxo) = self.build_vtxo(&tree, idx)? {
							self.db.register_movement(MovementArgs {
								spends: &[],
								receives: &[(&vtxo, VtxoState::Spendable)],
								recipients: &[],
								fees: None,
							})?;
						}
					}
				}
			}
		}

		//TODO(stevenroose) we currently actually could accidentally be syncing
		// a round multiple times because new blocks could have come in since we
		// took current height

		self.db.store_last_ark_sync_height(current_height)?;

		Ok(())
	}

	async fn sync_oors(&self) -> anyhow::Result<()> {
		let keychain = KeychainKind::External;
		let last_pk_index = self.db.get_last_vtxo_key_index(keychain)?.unwrap_or_default();
		let pubkeys = (0..=last_pk_index).map(|idx| {
			self.vtxo_seed.derive_keychain(keychain, idx).public_key()
		}).collect::<HashSet<_>>();

		for pk in pubkeys {
			self.sync_arkoor_by_pk(&pk).await?;
		}

		Ok(())
	}

	/// Sync with the Ark and look for out-of-round received VTXOs
	/// by public key
	pub async fn sync_arkoor_by_pk(&self, pk: &PublicKey) -> anyhow::Result<()> {
		let mut asp = self.require_asp()?;

		// Then sync OOR vtxos.
		debug!("Emptying OOR mailbox at ASP...");
		let req = protos::ArkoorVtxosRequest { pubkey: pk.serialize().to_vec() };
		let packages = asp.client.empty_arkoor_mailbox(req).await
			.context("error fetching oors")?.into_inner().packages;
		debug!("ASP has {} arkoor packages for us", packages.len());

		for package in packages {
			let mut vtxos = Vec::with_capacity(package.vtxos.len());
			for vtxo in package.vtxos {
				let vtxo = match Vtxo::deserialize(&vtxo) {
					Ok(vtxo) => vtxo,
					Err(e) => {
						warn!("Invalid vtxo from asp: {}", e);
						continue;
					}
				};


				let txid = vtxo.chain_anchor().txid;
				let chain_anchor = self.onchain.chain.get_tx(&txid).await?.with_context(|| {
					format!("received arkoor vtxo with unknown chain anchor: {}", txid)
				})?;
				if let Err(e) = vtxo.validate(&chain_anchor) {
					error!("Received invalid arkoor VTXO from server: {}", e);
					continue;
				}

				match self.db.has_spent_vtxo(vtxo.id()) {
					Ok(spent) if spent => {
						debug!("Not adding OOR vtxo {} because it is considered spent", vtxo.id());
						continue;
					},
					_ => {}
				}

				if let Ok(Some(_)) = self.db.get_vtxo(vtxo.id()) {
					debug!("Not adding OOR vtxo {} because it already exists", vtxo.id());
					continue;
				}

				vtxos.push(vtxo);
			}

			self.db.register_movement(MovementArgs {
				spends: &[],
				receives: &vtxos.iter().map(|v| (v, VtxoState::Spendable)).collect::<Vec<_>>(),
				recipients: &[],
				fees: None,
			}).context("failed to store OOR vtxo")?;
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

		let RoundResult { round_id, .. } = self.participate_round(move |round| {
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

		Ok(Offboard { round: round_id })
	}

	/// Offboard all vtxos to a given address or default to bark onchain address
	pub async fn offboard_all(&mut self, address: Option<Address>) -> anyhow::Result<Offboard> {
		let input_vtxos = self.db.get_all_spendable_vtxos()?;

		Ok(self.offboard(input_vtxos, address).await?)
	}

	/// Offboard vtxos selection to a given address or default to bark onchain address
	pub async fn offboard_vtxos(
		&mut self,
		vtxos: Vec<VtxoId>,
		address: Option<Address>,
	) -> anyhow::Result<Offboard> {
		let input_vtxos =  vtxos
				.into_iter()
				.map(|vtxoid| match self.db.get_vtxo(vtxoid)? {
					Some(vtxo) => Ok(vtxo),
					_ => bail!("cannot find requested vtxo: {}", vtxoid),
				})
				.collect::<anyhow::Result<_>>()?;

		Ok(self.offboard(input_vtxos, address).await?)
	}

	/// This will refresh all provided VTXO Ids.
	///
	/// Returns the [RoundId] of the round if a successful refresh occurred.
	/// It will return [None] if no [Vtxo] needed to be refreshed.
	pub async fn refresh_vtxos(&self, mut vtxos: Vec<Vtxo>) -> anyhow::Result<Option<RoundId>> {
		if vtxos.is_empty() {
			info!("Skipping refresh since no VTXOs are provided.");
			return Ok(None);
		}

		vtxos.sort_unstable();

		if let Some(dup) = vtxos.windows(2).find(|w| w[0].id() == w[1].id()) {
			bail!("duplicate VTXO id detected: {}", dup[0].id());
		}

		let total_amount = vtxos.iter().map(|v| v.amount()).sum();

		info!("Refreshing {} VTXOs (total amount = {}).", vtxos.len(), total_amount);

		let user_keypair = self.derive_store_next_keypair(KeychainKind::Internal)?;
		let req = VtxoRequest {
			policy: VtxoPolicy::Pubkey { user_pubkey: user_keypair.public_key() },
			amount: total_amount,
		};

		let RoundResult { round_id, .. } = self.participate_round(move |_| {
			Ok((vtxos.to_vec(), vec![req.clone()], Vec::new()))
		}).await.context("round failed")?;

		Ok(Some(round_id))
	}

	/// Performs a refresh of all VTXOs that are due to be refreshed, if any.
	pub async fn maintenance_refresh(&self) -> anyhow::Result<Option<RoundId>> {
		let vtxos = self.get_vtxos_to_refresh().await?;
		if vtxos.len() == 0 {
			return Ok(None);
		}

		self.refresh_vtxos(vtxos).await
	}

	/// This will find any VTXO that meets must-refresh criteria.
	/// Then, if there are some VTXOs to refresh, it will
	/// also add those that meet should-refresh criteria.
	///
	/// Returns a list of Vtxo's
	async fn get_vtxos_to_refresh(&self) -> anyhow::Result<Vec<Vtxo>> {
		let tip = self.onchain.tip().await?;

		// Check if there is any VTXO that we must refresh
		let must_refresh_vtxos = self.vtxos_with(RefreshStrategy::must_refresh(self, tip))?;
		if must_refresh_vtxos.is_empty() {
			return Ok(vec![]);
		} else {
			// If we need to do a refresh, we take all the should_refresh vtxo's as well
			// This helps us to aggregate some VTXOs
			let should_refresh_vtxos = self.vtxos_with(RefreshStrategy::should_refresh(self, tip))?;
			Ok(should_refresh_vtxos)
		}
	}

	/// Select several vtxos to cover the provided amount
	///
	/// Returns an error if amount cannot be reached
	///
	/// If `max_depth` is set, it will filter vtxos that have a depth greater than it.
	fn select_vtxos_to_cover(&self, amount: Amount, max_depth: Option<u16>) -> anyhow::Result<Vec<Vtxo>> {
		let inputs = self.db.get_all_spendable_vtxos()?;

		// Iterate over all rows until the required amount is reached
		let mut result = Vec::new();
		let mut total_amount = bitcoin::Amount::ZERO;
		for input in inputs {
			if let Some(max_depth) = max_depth {
				if input.arkoor_depth() >= max_depth {
					warn!("VTXO {} reached max depth of {}, skipping it. Please refresh your VTXO.", input.id(), max_depth);
					continue;
				}
			}

			total_amount += input.amount();
			result.push(input);

			if total_amount >= amount {
				return Ok(result)
			}
		}

		bail!("Insufficient money available. Needed {} but {} is available",
			amount, total_amount,
		);
	}

	/// Create Arkoor VTXOs for a given destination and amount
	///
	/// Outputs cannot have more than one input, so we can create new
	/// arkoors for each input needed to match requested amount + one
	/// optional change output.
	async fn create_arkoor_vtxos(
		&mut self,
		destination: PublicKey,
		amount: Amount,
	) -> anyhow::Result<ArkoorCreateResult> {
		let mut asp = self.require_asp()?;
		let change_pubkey = self.derive_store_next_keypair(KeychainKind::Internal)?.public_key();

		let req = VtxoRequest {
			amount: amount,
			policy: VtxoPolicy::Pubkey { user_pubkey: destination },
		};

		let inputs = self.select_vtxos_to_cover(
			req.amount + P2TR_DUST, Some(asp.info.max_arkoor_depth),
		)?;

		let mut secs = Vec::with_capacity(inputs.len());
		let mut pubs = Vec::with_capacity(inputs.len());
		let mut keypairs = Vec::with_capacity(inputs.len());
		for input in inputs.iter() {
			let keypair = {
				let (keychain, keypair_idx) = self.db.get_vtxo_key(&input)?;
				self.vtxo_seed.derive_keychain(keychain, keypair_idx)
			};

			let (s, p) = musig::nonce_pair(&keypair);
			secs.push(s);
			pubs.push(p);
			keypairs.push(keypair);
		}

		let builder = ArkoorPackageBuilder::new(&inputs, &pubs, req, Some(change_pubkey))?;

		let req = protos::ArkoorPackageCosignRequest {
			arkoors: builder.arkoors.iter().map(|a| a.into()).collect(),
		};
		let cosign_resp: Vec<_> = asp.client.request_arkoor_package_cosign(req).await?
			.into_inner().try_into().context("invalid server cosign response")?;
		ensure!(builder.verify_cosign_response(&cosign_resp),
			"invalid arkoor cosignature received from server",
		);

		let (sent, change) = builder.build_vtxos(&cosign_resp, &keypairs, secs)?;

		if let Some(change) = change.as_ref() {
			info!("Added change VTXO of {}", change.amount());
		}

		Ok(ArkoorCreateResult {
			input: inputs,
			created: sent,
			change: change,
		})
	}


	pub async fn send_arkoor_payment(
		&mut self,
		destination: PublicKey,
		amount: Amount,
	) -> anyhow::Result<Vec<Vtxo>> {
		let mut asp = self.require_asp()?;

		if amount < P2TR_DUST {
			bail!("Sent amount must be at least {}", P2TR_DUST);
		}

		let arkoor = self.create_arkoor_vtxos(destination, amount).await?;

		let req = protos::ArkoorPackage {
			arkoors: arkoor.created.iter().map(|v| protos::ArkoorVtxo {
				pubkey: destination.serialize().to_vec(),
				vtxo: v.serialize().to_vec(),
			}).collect(),
		};

		if let Err(e) = asp.client.post_arkoor_package_mailbox(req).await {
			error!("Failed to post the arkoor vtxo to the recipients mailbox: '{}'", e);
			//NB we will continue to at least not lose our own change
		}

		self.db.register_movement(MovementArgs {
			spends: &arkoor.input.iter().collect::<Vec<_>>(),
			receives: &arkoor.change.as_ref().map(|v| vec![(v, VtxoState::Spendable)]).unwrap_or(vec![]),
			recipients: &[(&destination.to_string(), amount)],
			fees: None,
		}).context("failed to store arkoor vtxo")?;

		Ok(arkoor.created)
	}

	pub async fn send_bolt11_payment(
		&mut self,
		invoice: &Bolt11Invoice,
		user_amount: Option<Amount>,
	) -> anyhow::Result<[u8; 32]> {
		let properties = self.db.read_properties()?.context("Missing config")?;
		let current_height = self.onchain.tip().await?;

		if invoice.network() != properties.network {
			bail!("BOLT-11 invoice is for wrong network: {}", invoice.network());
		}

		if self.db.check_recipient_exists(&invoice.to_string())? {
			bail!("Invoice has already been paid");
		}

		let mut asp = self.require_asp()?;

		let inv_amount = invoice.amount_milli_satoshis().map(|v| Amount::from_msat_ceil(v));
		if let (Some(_), Some(inv)) = (user_amount, inv_amount) {
			bail!("Invoice has amount of {} encoded. Please omit user amount argument", inv);
		}

		let amount = user_amount.or(inv_amount)
			.context("amount required on invoice without amount")?;
		if amount < P2TR_DUST {
			bail!("Sent amount must be at least {}", P2TR_DUST);
		}

		let change_keypair = self.derive_store_next_keypair(KeychainKind::Internal)?;

		let htlc_expiry = current_height + asp.info.htlc_expiry_delta as u32;
		let pay_req = VtxoRequest {
			amount: amount,
			policy: VtxoPolicy::ServerHtlcSend {
				user_pubkey: change_keypair.public_key(),
				payment_hash: *invoice.payment_hash(),
				htlc_expiry: htlc_expiry,
			},
		};

		let inputs = self.select_vtxos_to_cover(pay_req.amount + P2TR_DUST, Some(asp.info.max_arkoor_depth))?;

		let mut secs = Vec::with_capacity(inputs.len());
		let mut pubs = Vec::with_capacity(inputs.len());
		let mut keypairs = Vec::with_capacity(inputs.len());
		for input in inputs.iter() {
			let keypair = {
				let (keychain, keypair_idx) = self.db.get_vtxo_key(&input)?;
				self.vtxo_seed.derive_keychain(keychain, keypair_idx)
			};

			let (s, p) = musig::nonce_pair(&keypair);
			secs.push(s);
			pubs.push(p);
			keypairs.push(keypair);
		}

		let builder = ArkoorPackageBuilder::new(&inputs, &pubs, pay_req, Some(change_keypair.public_key()))?;

		let req = protos::Bolt11PaymentRequest {
			invoice: invoice.to_string(),
			user_amount_sat: user_amount.map(|a| a.to_sat()),
			input_ids: inputs.iter().map(|v| v.id().to_bytes().to_vec()).collect(),
			pub_nonces: pubs.iter().map(|p| p.serialize().to_vec()).collect(),
			user_pubkey: change_keypair.public_key().serialize().to_vec(),
		};

		let cosign_resp: Vec<_> = asp.client.start_bolt11_payment(req).await?
			.into_inner().try_into().context("invalid server cosign response")?;

		ensure!(builder.verify_cosign_response(&cosign_resp),
			"invalid arkoor cosignature received from server",
		);

		let (htlc_vtxos, change_vtxo) = builder.build_vtxos(&cosign_resp, &keypairs, secs)?;

		// Validate the new vtxos. They have the same chain anchor.
		for (vtxo, input) in htlc_vtxos.iter().zip(inputs.iter()) {
			if let Ok(tx) = self.onchain.chain.get_tx(&input.chain_anchor().txid).await {
				let tx = tx.with_context(|| {
					format!("input vtxo chain anchor not found: {}", input.chain_anchor().txid)
				})?;
				vtxo.validate(&tx).context("invalid htlc vtxo")?;
				if let Some(ref change) = change_vtxo {
					change.validate(&tx).context("invalid htlc vtxo")?;
				}
			} else {
				warn!("We couldn't validate the new VTXOs because of chain source error.");
			}
		}

		let req = protos::SignedBolt11PaymentDetails {
			invoice: invoice.to_string(),
			htlc_vtxo_ids: htlc_vtxos.iter().map(|v| v.id().to_bytes().to_vec()).collect(),
			wait: true,
		};

		let res = asp.client.finish_bolt11_payment(req).await?.into_inner();
		debug!("Progress update: {}", res.progress_message);
		let payment_preimage = <[u8; 32]>::try_from(res.payment_preimage()).ok();

		// The client will receive the change VTXO if it exists
		if let Some(ref change_vtxo) = change_vtxo {
			info!("Adding change VTXO of {}", change_vtxo.amount());

		}

		let receive_vtxos = change_vtxo.iter()
			.map(|v| (v, VtxoState::Spendable))
			.collect::<Vec<_>>();

		if let Some(preimage) = payment_preimage {
			info!("Payment succeeded! Preimage: {}", preimage.as_hex());
			self.db.register_movement(MovementArgs {
				spends: &inputs.iter().collect::<Vec<_>>(),
				receives: &receive_vtxos,
				recipients: &[(&invoice.to_string(), amount)],
				fees: None,
			}).context("failed to store OOR vtxo")?;
			Ok(preimage)
		} else {
			info!("Payment failed! Revoking...");
			let mut secs = Vec::with_capacity(htlc_vtxos.len());
			let mut pubs = Vec::with_capacity(htlc_vtxos.len());
			let mut keypairs = Vec::with_capacity(htlc_vtxos.len());
			for input in htlc_vtxos.iter() {
				let keypair = {
					let (keychain, keypair_idx) = self.db.get_vtxo_key(&input)?;
					self.vtxo_seed.derive_keychain(keychain, keypair_idx)
				};

				let (s, p) = musig::nonce_pair(&keypair);
				secs.push(s);
				pubs.push(p);
				keypairs.push(keypair);
			}

			let revocation = ArkoorPackageBuilder::new_htlc_revocation(&htlc_vtxos, &pubs)?;

			let req = protos::RevokeBolt11PaymentRequest {
				input_ids: revocation.arkoors.iter()
					.map(|i| i.input.id().to_bytes().to_vec())
					.collect(),
				pub_nonces: revocation.arkoors.iter()
					.map(|i| i.user_nonce.serialize().to_vec())
					.collect(),
			};
			let cosign_resp: Vec<_> = asp.client.revoke_bolt11_payment(req).await?
				.into_inner().try_into().context("invalid server cosign response")?;
			ensure!(revocation.verify_cosign_response(&cosign_resp),
				"invalid arkoor cosignature received from server",
			);

			let (vtxos, change) = revocation.build_vtxos(&cosign_resp, &keypairs, secs)?;
			assert!(change.is_none(), "unexpected change: {:?}", change);

			self.db.register_movement(MovementArgs {
				spends: &inputs.iter().collect::<Vec<_>>(),
				receives: &vtxos.iter().map(|v| (v, VtxoState::Spendable))
					.chain(change_vtxo.as_ref().map(|c| (c, VtxoState::Spendable)))
					.collect::<Vec<_>>(),
				recipients: &[],
				fees: None,
			})?;

			bail!("Payment failed: {}", res.progress_message);
		}
	}

	/// Create, store and return a bolt11 invoice for offchain onboarding
	pub async fn bolt11_invoice(&mut self, amount: Amount) -> anyhow::Result<Bolt11Invoice> {
		let mut asp = self.require_asp()?;

		let preimage = rand::thread_rng().gen::<[u8; 32]>();
		let payment_hash = sha256::Hash::hash(&preimage);
		info!("Start bolt11 onboard with preimage / payment hash: {} / {}",
			preimage.as_hex(), payment_hash.as_byte_array().as_hex());

		let req = protos::StartBolt11OnboardRequest {
			payment_hash: payment_hash.as_byte_array().to_vec(),
			amount_sat: amount.to_sat(),
		};

		let resp = asp.client.start_bolt11_onboard(req).await?.into_inner();
		info!("Ark Server is ready to receive LN payment to invoice: {}.", resp.bolt11);

		let invoice = Bolt11Invoice::from_str(&resp.bolt11)
			.context("invalid bolt11 invoice returned by asp")?;

		self.db.store_offchain_onboard(
			payment_hash.as_byte_array(),
			&preimage,
			OffchainPayment::Lightning(invoice.clone()),
		)?;

		Ok(invoice)
	}

	async fn create_fee_vtxos(&mut self, fees: Amount) -> anyhow::Result<Vec<Vtxo>> {
		let pubkey = self.derive_store_next_keypair(KeychainKind::Internal)?.public_key();
		let oor = self.create_arkoor_vtxos(pubkey, fees).await?;
		let receives = oor.created.iter().map(|v| (v, VtxoState::Spendable))
			.chain(oor.change.iter().map(|v| (v, VtxoState::Spendable)))
			.collect::<Vec<_>>();

		// TODO: we should ensure no fee is applied in this send
		self.db.register_movement(MovementArgs {
			spends: &oor.input.iter().collect::<Vec<_>>(),
			receives: &receives,
			recipients: &[],
			fees: None,
		})?;

		Ok(oor.created)
	}

	pub async fn claim_bolt11_payment(&mut self, invoice: Bolt11Invoice) -> anyhow::Result<()> {
		let mut asp = self.require_asp()?;
		let current_height = self.onchain.tip().await?;

		let offchain_onboard = self.db.fetch_offchain_onboard_by_payment_hash(
			invoice.payment_hash().as_byte_array()
		)?.context("no offchain onboard found")?;

		let keypair = self.derive_store_next_keypair(KeychainKind::Internal)?;
		let (sec_nonce, pub_nonce) = musig::nonce_pair(&keypair);

		let amount = Amount::from_msat_floor(
			invoice.amount_milli_satoshis().context("invoice must have amount specified")?
		);

		let req = protos::SubscribeBolt11OnboardRequest {
			bolt11: invoice.to_string(),
		};

		info!("Waiting payment...");
		asp.client.subscribe_bolt11_onboard(req).await?.into_inner();
		info!("Lightning payment arrived!");

		// Create a VTXO to pay receive fees:
		let fee_vtxos = self.create_fee_vtxos(*LN_ONBOARD_FEE_SATS).await?;

		let htlc_expiry = current_height + asp.info.vtxo_expiry_delta as u32;
		let fee_vtxo_cloned = fee_vtxos.clone();
		let RoundResult { vtxos, .. } = self.participate_round(move |_| {
			let inputs = fee_vtxo_cloned.clone();
			let htlc_pay_req = VtxoRequest {
				amount: amount,
				policy: VtxoPolicy::ServerHtlcRecv {
					user_pubkey: keypair.public_key(),
					payment_hash: *invoice.payment_hash(),
					htlc_expiry: htlc_expiry,
				},
			};

			Ok((inputs, vec![htlc_pay_req], vec![]))
		}).await.context("round failed")?;

		let [htlc_vtxo] = vtxos.try_into().expect("should have only one");
		info!("Got HTLC vtxo in round: {}", htlc_vtxo.id());
		trace!("Got HTLC vtxo in round: {}", htlc_vtxo.serialize().as_hex());

		// Claiming arkoor against preimage
		let pay_req = VtxoRequest {
			policy: VtxoPolicy::Pubkey { user_pubkey: keypair.public_key() },
			amount: amount,
		};

		let inputs = [htlc_vtxo];
		let pubs = [pub_nonce];
		let builder = ArkoorPackageBuilder::new(&inputs, &pubs, pay_req, None)?;

		let req = protos::ClaimBolt11OnboardRequest {
			arkoor: Some(builder.arkoors.first().unwrap().into()),
			payment_preimage: offchain_onboard.payment_preimage.to_vec(),
		};

		info!("Claiming arkoor against payment preimage");
		let cosign_resp = asp.client.claim_bolt11_onboard(req).await
			.context("failed to claim bolt11 onboard")?
			.into_inner().try_into().context("invalid server cosign response")?;
		ensure!(builder.verify_cosign_response(&[&cosign_resp]),
			"invalid arkoor cosignature received from server",
		);

		let (vtxos, _) = builder.build_vtxos(
			&[cosign_resp],
			&[keypair],
			vec![sec_nonce],
		)?;
		let [vtxo] = vtxos.try_into().expect("had exactly one request");

		info!("Got an arkoor from lightning! {}", vtxo.id());
		self.db.register_movement(MovementArgs {
			spends: &fee_vtxos.iter().collect::<Vec<_>>(),
			receives: &[(&vtxo, VtxoState::Spendable)],
			recipients: &[],
			fees: Some(fee_vtxos.iter().map(|v| v.amount()).sum::<Amount>()),
		})?;

		Ok(())
	}

	/// Send to a lightning address.
	///
	/// Returns the invoice paid and the preimage.
	pub async fn send_lnaddr(
		&mut self,
		addr: &LightningAddress,
		amount: Amount,
		comment: Option<&str>,
	) -> anyhow::Result<(Bolt11Invoice, [u8; 32])> {
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
		let balance = self.offchain_balance()?;

		// do a quick check to fail early and not wait for round if we don't have enough money
		let early_fees = OffboardRequest::calculate_fee(
			&addr.script_pubkey(), FeeRate::BROADCAST_MIN,
		).expect("script from address");

		if balance < amount + early_fees {
			bail!("Your balance is too low. Needed: {}, available: {}", amount + early_fees, balance);
		}

		let RoundResult { round_id, .. } = self.participate_round(|round| {
			let offb = OffboardRequest {
				script_pubkey: addr.script_pubkey(),
				amount: amount,
			};

			let spent_amount = offb.amount + offb.fee(round.offboard_feerate)?;
			let input_vtxos = self.select_vtxos_to_cover(spent_amount, None)?;

			let in_sum = input_vtxos.iter().map(|v| v.amount()).sum::<Amount>();

			let change = {
				if in_sum < offb.amount {
					// unreachable, because we checked for enough balance above
					bail!("Balance too low");
				} else if in_sum <= spent_amount + P2TR_DUST {
					info!("No change, emptying wallet.");
					None
				} else {
					let amount = in_sum - spent_amount;
					let change_keypair = self.derive_store_next_keypair(KeychainKind::Internal)?;
					info!("Adding change vtxo for {}", amount);
					Some(VtxoRequest {
						amount: amount,
						policy: VtxoPolicy::Pubkey { user_pubkey: change_keypair.public_key() },
					})
				}
			};

			Ok((input_vtxos.clone(), change.into_iter().collect(), vec![offb]))
		}).await.context("round failed")?;

		Ok(SendOnchain { round: round_id })
	}

	async fn new_round_attempt<S: Stream<Item = anyhow::Result<RoundEvent>> + Unpin>(
		&self,
		events: &mut S,
		round_state: &mut RoundState,
		input_vtxos: &HashMap<VtxoId, Vtxo>,
		pay_reqs: &[VtxoRequest],
		offb_reqs: &[OffboardRequest],
	) -> anyhow::Result<AttemptResult> {
		let mut asp = self.require_asp()?;

		assert!(round_state.attempt.is_some());

		// Assign cosign pubkeys to the payment requests.
		let cosign_keys = iter::repeat_with(|| Keypair::new(&SECP, &mut rand::thread_rng()))
			.take(pay_reqs.len())
			.collect::<Vec<_>>();
		let vtxo_reqs = pay_reqs.iter().zip(cosign_keys.iter()).map(|(req, ck)| {
			SignedVtxoRequest {
				vtxo: req.clone(),
				cosign_pubkey: ck.public_key(),
			}
		}).collect::<Vec<_>>();

		// Prepare round participation info.
		// For each of our requested vtxo output, we need a set of public and secret nonces.
		let cosign_nonces = cosign_keys.iter()
			.map(|key| {
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

		let res = asp.client.submit_payment(protos::SubmitPaymentRequest {
			input_vtxos: input_vtxos.iter().map(|(id, vtxo)| {
				let keypair = {
					let (keychain, keypair_idx) = self.db.get_vtxo_key(vtxo)
						.expect("owned vtxo key should be in database");
					self.vtxo_seed.derive_keychain(keychain, keypair_idx)
				};

				protos::InputVtxo {
					vtxo_id: id.to_bytes().to_vec(),
					ownership_proof: {
						let sig = round_state.challenge().sign_with(*id, keypair);
						sig.serialize().to_vec()
					},
				}
			}).collect(),
			vtxo_requests: vtxo_reqs.iter().zip(cosign_nonces.iter()).map(|(r, n)| {
				protos::SignedVtxoRequest {
					vtxo: Some(protos::VtxoRequest {
						amount: r.vtxo.amount.to_sat(),
						policy: r.vtxo.policy.serialize(),
					}),
					cosign_pubkey: r.cosign_pubkey.serialize().to_vec(),
					public_nonces: n.1.iter().map(|n| n.serialize().to_vec()).collect(),
				}
			}).collect(),
			offboard_requests: offb_reqs.iter().map(|r| {
				protos::OffboardRequest {
					amount: r.amount.to_sat(),
					offboard_spk: r.script_pubkey.to_bytes(),
				}
			}).collect(),
		}).await;

		if let Err(e) = res {
			warn!("Could not submit payment, trying next round: {}", e);
			return Ok(AttemptResult::WaitNewRound);
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
						return Ok(AttemptResult::WaitNewRound);
					}
					(vtxos_spec, unsigned_round_tx, cosign_agg_nonces, connector_pubkey)
				},
				RoundEvent::Start(round_info) => {
					return Ok(AttemptResult::NewRoundStarted(round_info));
				},
				RoundEvent::Attempt(e) if round_state.process_attempt(e.clone()) => {
					return Ok(AttemptResult::NewAttemptStarted)
				},
				other => {
					warn!("Unexpected message, waiting for new round: {:?}", other);
					return Ok(AttemptResult::WaitNewRound);
				}
			}
		};

		if unsigned_round_tx.output.len() < MIN_ROUND_TX_OUTPUTS {
			bail!("asp sent round tx with less than 2 outputs: {}",
				bitcoin::consensus::encode::serialize_hex(&unsigned_round_tx),
			);
		}
		let vtxos_utxo = OutPoint::new(unsigned_round_tx.compute_txid(), ROUND_TX_VTXO_TREE_VOUT);
		let conns_utxo = OutPoint::new(unsigned_round_tx.compute_txid(), ROUND_TX_CONNECTOR_VOUT);

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
				return Ok(AttemptResult::WaitNewRound)
			}

			let mut my_offbs = offb_reqs.iter().collect::<Vec<_>>();
			for offb in unsigned_round_tx.output.iter().skip(2) {
				if let Some(i) = my_offbs.iter().position(|o| o.to_txout() == *offb) {
					my_offbs.swap_remove(i);
				}
			}
			if !my_offbs.is_empty() {
				error!("asp didn't include all of our offboards, missing: {:?}", my_offbs);
				return Ok(AttemptResult::WaitNewRound)
			}
		}

		// Make vtxo signatures from top to bottom, just like sighashes are returned.
		let unsigned_vtxos = vtxo_tree.into_unsigned_tree(vtxos_utxo);
		for ((req, key), (sec, _pub)) in vtxo_reqs.iter().zip(&cosign_keys).zip(cosign_nonces) {
			let leaf_idx = unsigned_vtxos.spec.leaf_idx_of(&req).expect("req included");
			let part_sigs = unsigned_vtxos.cosign_branch(
				&vtxo_cosign_agg_nonces, leaf_idx, key, sec,
			).context("failed to cosign branch: our request not part of tree")?;
			info!("Sending {} partial vtxo cosign signatures for pk {}",
				part_sigs.len(), key.public_key(),
			);
			let res = asp.client.provide_vtxo_signatures(protos::VtxoSignaturesRequest {
				pubkey: key.public_key().serialize().to_vec(),
				signatures: part_sigs.iter().map(|s| s.serialize().to_vec()).collect(),
			}).await;

			if let Err(e) = res {
				warn!("Could not provide vtxo signatures, trying next round: {}", e);
				return Ok(AttemptResult::WaitNewRound)
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
							return Ok(AttemptResult::WaitNewRound);
						}
						(cosign_sigs, forfeit_nonces)
					},
					RoundEvent::Start(e) => {
						return Ok(AttemptResult::NewRoundStarted(e));
					},
					RoundEvent::Attempt(e) => {
						if round_state.process_attempt(e) {
							return Ok(AttemptResult::NewAttemptStarted)
						} else {
							return Ok(AttemptResult::WaitNewRound);
						}
					},
					other => {
						warn!("Unexpected message, waiting for new round: {:?}", other);
						return Ok(AttemptResult::WaitNewRound);
					}
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
		let conn_txout = unsigned_round_tx.output.get(ROUND_TX_CONNECTOR_VOUT as usize)
			.expect("checked before");
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
			let vtxo_keypair = {
				let (keychain, keypair_idx) = self.db.get_vtxo_key(&vtxo)?;
				self.vtxo_seed.derive_keychain(keychain, keypair_idx)
			};

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
					Some(vtxo.output_taproot().tap_tweak().to_byte_array()),
				);
				Ok((nonce, sig))
			}).collect::<anyhow::Result<Vec<_>>>()?;
			Ok((id, sigs))
		}).collect::<anyhow::Result<HashMap<_, _>>>()?;
		debug!("Sending {} sets of forfeit signatures for our inputs", forfeit_sigs.len());
		let res = asp.client.provide_forfeit_signatures(protos::ForfeitSignaturesRequest {
			signatures: forfeit_sigs.into_iter().map(|(id, sigs)| {
				protos::ForfeitSignatures {
					input_vtxo_id: id.to_bytes().to_vec(),
					pub_nonces: sigs.iter().map(|s| s.0.serialize().to_vec()).collect(),
					signatures: sigs.iter().map(|s| s.1.serialize().to_vec()).collect(),
				}
			}).collect(),
		}).await;

		if let Err(e) = res {
			warn!("Could not provide forfeit signatures, trying next round: {}", e);
			return Ok(AttemptResult::WaitNewRound)
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
				return Ok(AttemptResult::NewRoundStarted(e));
			},
			RoundEvent::Attempt(e) if round_state.process_attempt(e.clone()) => {
				return Ok(AttemptResult::NewAttemptStarted)
			},
			other => {
				warn!("Unexpected message, waiting for new round: {:?}", other);
				return Ok(AttemptResult::WaitNewRound);
			}
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
			if pay_reqs.contains(&req.vtxo) {
				let vtxo = self.build_vtxo(&signed_vtxos, idx)?.expect("must be in tree");
				new_vtxos.push(vtxo);
			}
		}

		for vtxo in &new_vtxos {
			info!("New VTXO from round: {} ({}, {})", vtxo.id(), vtxo.amount(), vtxo.policy_type());
		}

		// validate the received vtxos
		// This is more like a sanity check since we crafted them ourselves.
		for vtxo in &new_vtxos {
			vtxo.validate(&signed_round_tx).context("built invalid vtxo")?;
		}

		// if there is one offboard req, we register as a spend, else as a refresh
		// TODO: this is broken in case of multiple offb_reqs, but currently we don't allow that

		let params = Params::new(self.properties().unwrap().network);
		let sent = offb_reqs.iter().map(|o| {
			let address = Address::from_script(&o.script_pubkey, &params)?;
			Ok((address.to_string(), o.amount))
		}).collect::<anyhow::Result<Vec<_>>>()?;

		let received = new_vtxos.iter()
			.filter(|v| { matches!(v.policy(), VtxoPolicy::Pubkey { .. })})
			.map(|v| (v, VtxoState::Spendable))
			.collect::<Vec<_>>();

		// NB: if there is no received VTXO nor sent in the round, for now we assume
		// the movement will be registered later (e.g: lightning receive use case)
		//
		// Later, we will split the round participation and registration might be more
		// manual
		if !sent.is_empty() || !received.is_empty() {
			self.db.register_movement(MovementArgs {
				spends: &input_vtxos.values().collect::<Vec<_>>(),
				receives: &received,
				recipients: &sent.iter().map(|(addr, amount)| (addr.as_str(), *amount)).collect::<Vec<_>>(),
				fees: None
			}).context("failed to store OOR vtxo")?;
		}

		info!("Round finished");
		return Ok(AttemptResult::Success(RoundResult {
			round_id: signed_round_tx.compute_txid().into(),
			vtxos: new_vtxos,
		}))
	}

	/// Participate in a round.
	///
	/// NB Instead of taking the input and output data as arguments, we take a closure that is
	/// called to get these values. This is so because for offboards, the fee rate used for the
	/// offboards is only announced in the beginning of the round and can change between round
	/// attempts. Lateron this will also be useful so we can randomize destinations between failed
	/// round attempts for better privacy.
	async fn participate_round(
		&self,
		mut round_input: impl FnMut(&RoundInfo) -> anyhow::Result<
			(Vec<Vtxo>, Vec<VtxoRequest>, Vec<OffboardRequest>)
		>,
	) -> anyhow::Result<RoundResult> {
		let mut asp = self.require_asp()?;

		info!("Waiting for a round start...");
		let mut events = asp.client.subscribe_rounds(protos::Empty {}).await?.into_inner()
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

			info!("Round started");

			let (input_vtxos, pay_reqs, offb_reqs) = round_input(&round_state.info)
				.context("error providing round input")?;

			if let Some(payreq) = pay_reqs.iter().find(|p| p.amount < P2TR_DUST) {
				bail!("VTXO amount must be at least {}, requested {}", P2TR_DUST, payreq.amount);
			}

			if let Some(offb) = offb_reqs.iter().find(|o| o.amount < P2TR_DUST) {
				bail!("Offboard amount must be at least {}, requested {}", P2TR_DUST, offb.amount);
			}

			// then we expect the first attempt message
			match events.next().await.context("events stream broke")?? {
				RoundEvent::Attempt(attempt) if attempt.round_seq == round_state.info.round_seq => {
					round_state.process_attempt(attempt);
				},
				RoundEvent::Start(e) => {
					next_round_info = Some(e);
					continue 'round;
				},
				//TODO(stevenroose) make this robust
				other => panic!("Unexpected message: {:?}", other),
			};

			// Convert the input vtxos to a map to cache their ids.
			let input_vtxos = input_vtxos.into_iter()
				.map(|v| (v.id(), v))
				.collect::<HashMap<_, _>>();
			debug!("Spending vtxos: {:?}", input_vtxos.keys());

			'attempt: loop {
				let attempt_res = self.new_round_attempt(
					&mut events,
					&mut round_state,
					&input_vtxos,
					&pay_reqs,
					&offb_reqs,
				).await?;

				match attempt_res {
					AttemptResult::NewRoundStarted(round_info) => {
						next_round_info = Some(round_info);
						continue 'round;
					},
					AttemptResult::NewAttemptStarted => {
						continue 'attempt;
					},
					AttemptResult::WaitNewRound => {
						continue 'round;
					},
					AttemptResult::Success(round_result) => {
						return Ok(round_result)
					}
				}
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

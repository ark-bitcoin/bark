
pub extern crate ark;
pub extern crate bark_json as json;

pub extern crate lightning_invoice;
pub extern crate lnurl as lnurllib;

#[macro_use] extern crate anyhow;
#[macro_use] extern crate serde;

pub mod persist;
use ark::board::BOARD_TX_VTXO_VOUT;
use ark::oor::unsigned_oor_tx;
use ark::util::{Decodable, Encodable};
use ark::vtxo::VtxoSpkSpec;
use bip39::rand::Rng;
use bitcoin::params::Params;
use bitcoin_ext::bdk::WalletExt;
use movement::{Movement, MovementArgs};
pub use persist::sqlite::SqliteClient;
pub mod vtxo_selection;
mod exit;
mod lnurl;
pub mod onchain;
mod psbtext;
mod vtxo_state;
pub mod movement;

#[cfg(test)]
pub mod test;

pub use bark_json::primitives::UtxoInfo;
pub use bark_json::cli::{Offboard, Board, SendOnchain};
use rusqlite::ToSql;

use std::iter;
use std::collections::{HashMap, HashSet};
use std::convert::TryFrom;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context};
use bip39::Mnemonic;
use bitcoin::{secp256k1, Address, Amount, FeeRate, Network, OutPoint, Psbt, Txid};
use bitcoin::bip32::{self, ChildNumber, Fingerprint};
use bitcoin::hashes::{sha256, Hash};
use bitcoin::hex::DisplayHex;
use bitcoin::secp256k1::{rand, Keypair, PublicKey};
use lnurllib::lightning_address::LightningAddress;
use lightning_invoice::Bolt11Invoice;
use log::{trace, debug, info, warn, error};
use tokio_stream::{Stream, StreamExt};

use ark::{
	oor, ArkInfo, ArkoorVtxo, OffboardRequest, PaymentRequest, RoundVtxo, Vtxo,
	VtxoId, VtxoRequest, VtxoSpec,
};
use ark::connectors::ConnectorChain;
use ark::musig::{self, MusigPubNonce, MusigSecNonce};
use ark::rounds::{
	RoundAttempt,
	RoundEvent,
	RoundId,
	RoundInfo,
	VtxoOwnershipChallenge,
	MIN_ROUND_TX_OUTPUTS,
	ROUND_TX_CONNECTOR_VOUT,
	ROUND_TX_VTXO_TREE_VOUT,
};
use ark::tree::signed::{CachedSignedVtxoTree, SignedVtxoTreeSpec};
use aspd_rpc::{self as rpc, protos};
use bitcoin_ext::{AmountExt, BlockHeight, P2TR_DUST, DEEPLY_CONFIRMED};

use crate::exit::Exit;
use crate::onchain::Utxo;
use crate::persist::BarkPersister;
use crate::vtxo_selection::{FilterVtxos, VtxoFilter};
use crate::vtxo_state::VtxoState;

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

struct OorCreateResult {
	input: Vec<Vtxo>,
	created: Vtxo,
	change: Option<Vtxo>,
	fee: Amount
}


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
					confirmation_height: {
						let exit_delta = e.vtxo.exit_delta() as BlockHeight;
						Some(e.spendable_at_height + exit_delta)
					},
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
	pub vtxo_refresh_threshold: BlockHeight
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
			onchain::ChainSource::Bitcoind {
				url: url.clone(),
				auth: auth,
			}
		} else {
			bail!("Need to either provide esplora or bitcoind info");
		};

		let db = Arc::new(db);
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

	async fn register_all_unregistered_boards(&self) -> anyhow::Result<()>
	{
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
		let asp = self.require_asp()?;
		let properties = self.db.read_properties()?.context("Missing config")?;

		let user_keypair = self.derive_store_next_keypair(KeychainKind::Internal)?;
		let current_height = self.onchain.tip().await?;
		let spec = VtxoSpec {
			user_pubkey: user_keypair.public_key(),
			asp_pubkey: asp.info.asp_pubkey,
			expiry_height: current_height + asp.info.vtxo_expiry_delta as BlockHeight,
			exit_delta: asp.info.vtxo_exit_delta,
			spk: VtxoSpkSpec::Exit,
			amount: amount,
		};

		let addr = Address::from_script(&ark::board::board_spk(&spec), properties.network).unwrap();

		// We create the onboard tx template, but don't sign it yet.
		let board_tx = self.onchain.prepare_tx([(addr, amount)])?;

		self.board(spec, user_keypair, board_tx).await
	}

	pub async fn board_all(&mut self) -> anyhow::Result<Board> {
		let asp = self.require_asp()?;
		let properties = self.db.read_properties()?.context("Missing config")?;

		let user_keypair = self.derive_store_next_keypair(KeychainKind::Internal)?;
		let current_height = self.onchain.tip().await?;
		let mut spec = VtxoSpec {
			user_pubkey: user_keypair.public_key(),
			asp_pubkey: asp.info.asp_pubkey,
			expiry_height: current_height + asp.info.vtxo_expiry_delta as BlockHeight,
			exit_delta: asp.info.vtxo_exit_delta,
			spk: VtxoSpkSpec::Exit,
			// amount is temporarily set to total balance but will
			// have fees deducted after psbt construction
			amount: self.onchain.balance()
		};

		let addr = Address::from_script(&ark::board::board_spk(&spec), properties.network).unwrap();
		let board_all_tx = self.onchain.prepare_send_all_tx(addr)?;

		// Deduct fee from vtxo spec
		let fee = board_all_tx.fee().context("Unable to calculate fee")?;
		spec.amount = spec.amount.checked_sub(fee).unwrap();

		assert_eq!(board_all_tx.outputs.len(), 1);
		assert_eq!(board_all_tx.unsigned_tx.tx_out(0).unwrap().value, spec.amount);

		self.board(spec, user_keypair, board_all_tx).await
	}

	async fn board(
		&mut self,
		spec: VtxoSpec,
		user_keypair: Keypair,
		board_tx: Psbt,
	) -> anyhow::Result<Board> {
		let mut asp = self.require_asp()?;

		let utxo = OutPoint::new(board_tx.unsigned_tx.compute_txid(), BOARD_TX_VTXO_VOUT);
		// We ask the ASP to cosign our board vtxo exit tx.
		let (user_part, priv_user_part) = ark::board::new_user(spec, utxo);
		let asp_part = {
			let res = asp.client.request_board_cosign(protos::BoardCosignRequest {
				user_part: user_part.encode(),
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

		self.db.register_movement(MovementArgs {
			spends: &[],
			receives: &[(&vtxo, VtxoState::UnregisteredBoard)],
			recipients: &[],
			fees: None
		}).context("db error storing vtxo")?;

		let tx = self.onchain.finish_tx(board_tx)?;

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
		let board_vtxo = vtxo.as_board()
			.with_context(|| format!("Expected type 'board'. Received '{}'", vtxo.vtxo_type()))?;

		let funding_tx = self.onchain.get_wallet_tx(board_vtxo.onchain_output.txid)
			.context("Failed to find funding_tx for {}")?;

		// Register the vtxo with the server
		asp.client.register_board_vtxo(protos::BoardVtxoRequest {
			board_vtxo: vtxo.encode(),
			board_tx: bitcoin::consensus::serialize(&funding_tx),
		}).await.context("error registering board with the asp")?;

		// Remember that we have stored the vtxo
		// No need to complain if the vtxo is already registered
		let allowed_states = &[VtxoState::UnregisteredBoard, VtxoState::Spendable];
		self.db.update_vtxo_state_checked(vtxo_id, VtxoState::Spendable, allowed_states)?;


		Ok(
			Board {
				funding_txid: funding_tx.compute_txid(),
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
				spk: dest.spk,
			},
			leaf_idx: leaf_idx,
			exit_branch: exit_branch.into_iter().cloned().collect(),
		});

		if self.db.get_vtxo(vtxo.id())?.is_some() {
			debug!("Not adding vtxo {} because it already exists", vtxo.id());
			return Ok(None)
		}

		debug!("Built new vtxo {} with value {}", vtxo.id(), vtxo.amount());
		Ok(Some(vtxo))
	}

	/// Checks if the provided VTXO has some counterparty risk in the current wallet
	///
	/// A [Vtxo::Arkoor] is considered to have some counterparty risk
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
			Vtxo::Board(_) => Ok(!self.db.check_vtxo_key_exists(&vtxo.spec().user_pubkey)?),
			Vtxo::Round(_) => Ok(!self.db.check_vtxo_key_exists(&vtxo.spec().user_pubkey)?),
		}
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

			let tree = SignedVtxoTreeSpec::decode(&round.signed_vtxos)
				.context("invalid signed vtxo tree from asp")?
				.into_cached_tree();

			for (idx, dest) in tree.spec.spec.vtxos.iter().enumerate() {
				if pubkeys.contains(&dest.pubkey) {
					if let Some(vtxo) = self.build_vtxo(&tree, idx)? {
						match vtxo.spec().spk {
							VtxoSpkSpec::Exit { .. } => self.db.register_movement(MovementArgs {
								spends: &[],
								receives: &[(&vtxo, VtxoState::Spendable)],
								recipients: &[],
								fees: None,
							})?,
							VtxoSpkSpec::HtlcIn { .. } => {},
							VtxoSpkSpec::HtlcOut { .. } => {}
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
			self.sync_oor_by_pk(&pk).await?;
		}

		Ok(())
	}

	/// Sync with the Ark and look for out-of-round received VTXOs
	/// by public key
	pub async fn sync_oor_by_pk(&self, pk: &PublicKey) -> anyhow::Result<()> {
		let mut asp = self.require_asp()?;

		// Then sync OOR vtxos.
		debug!("Emptying OOR mailbox at ASP...");
		let req = protos::OorVtxosRequest { pubkey: pk.serialize().to_vec() };
		let resp = asp.client.empty_oor_mailbox(req).await.context("error fetching oors")?;
		let oors = resp.into_inner().vtxos.into_iter()
			.map(|b| Vtxo::decode(&b).context("invalid vtxo from asp"))
			.collect::<Result<Vec<_>, _>>()?;
		debug!("ASP has {} OOR vtxos for us", oors.len());
		for vtxo in oors {
			// TODO: we need to test receiving arkoors with invalid signatures
			let arkoor = vtxo.as_arkoor().context("asp gave non-arkoor vtxo for arkoor sync")?;
			if let Err(e) = oor::verify_oor(arkoor, Some(*pk)) {
				warn!("Could not validate OOR signature, dropping vtxo. {}", e);
				continue;
			}

			// Not sure if this can happen, but well.
			if self.db.has_spent_vtxo(vtxo.id())? {
				debug!("Not adding OOR vtxo {} because it is considered spent", vtxo.id());
			}

			if self.db.get_vtxo(vtxo.id())?.is_none() {
				debug!("Storing new OOR vtxo {} with value {}", vtxo.id(), vtxo.amount());
				self.db.register_movement(MovementArgs {
					spends: &[],
					receives: &[(&vtxo, VtxoState::Spendable)],
					recipients: &[],
					fees: None,
				}).context("failed to store OOR vtxo")?;
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

		let user_keypair = self.derive_store_next_keypair(KeychainKind::Internal)?;
		let payment_request = PaymentRequest {
			pubkey: user_keypair.public_key(),
			amount: total_amount,
			spk: VtxoSpkSpec::Exit,
		};

		let RoundResult { round_id, .. } = self.participate_round(move |_| {
			Ok((vtxos.clone(), vec![payment_request.clone()], Vec::new()))
		}).await.context("round failed")?;
		Ok(Some(round_id))
	}

	async fn create_oor_vtxo(&mut self, destination: PublicKey, amount: Amount)
		-> anyhow::Result<OorCreateResult>
	{
		let mut asp = self.require_asp()?;
		let change_pubkey = self.derive_store_next_keypair(KeychainKind::Internal)?.public_key();

		let output = PaymentRequest {
			pubkey: destination,
			amount: amount,
			spk: VtxoSpkSpec::Exit,
		};

		// TODO: implement oor fees. Once implemented, we should add an additional
		// output to each impacted oor payment else the tx would be valid
		// (bitcoin rpc error: "tx with dust output must be 0-fee")
		let offchain_fees = Amount::ZERO;
		let spent_amount = amount + offchain_fees;

		let input_vtxos = self.db.select_vtxos_to_cover(spent_amount + P2TR_DUST)?;

		let change = {
			let sum = input_vtxos.iter().map(|v| v.amount()).sum::<Amount>();

			// At this point, `sum` is >= to `spent_amount`
			if sum > spent_amount {
				let change_amount = sum - spent_amount;
				Some(PaymentRequest {
					pubkey: change_pubkey,
					amount: change_amount,
					spk: VtxoSpkSpec::Exit,
				})
			} else {
				None
			}
		};
		let outputs = Some(output.clone()).into_iter().chain(change).collect::<Vec<_>>();

		let payment = ark::oor::OorPayment::new(
			asp.info.asp_pubkey,
			asp.info.vtxo_exit_delta,
			input_vtxos,
			outputs,
		);

		// it's a bit fragile, but if there is a second output, it's our change
		if let Some(o) = payment.outputs.get(1) {
			info!("Added change VTXO of {}", o.amount);
		}

		let (sec_nonces, pub_nonces, keypairs) = {
			let mut secs = Vec::with_capacity(payment.inputs.len());
			let mut pubs = Vec::with_capacity(payment.inputs.len());
			let mut keypairs = Vec::with_capacity(payment.inputs.len());

			for input in payment.inputs.iter() {
				let (keychain, keypair_idx) = self.db.get_vtxo_key(&input)?;
				let keypair = self.vtxo_seed.derive_keychain(keychain, keypair_idx);

				let (s, p) = musig::nonce_pair(&keypair);
				secs.push(s);
				pubs.push(p);
				keypairs.push(keypair);
			}
			(secs, pubs, keypairs)
		};

		let req = protos::OorCosignRequest {
			payment: payment.encode(),
			pub_nonces: pub_nonces.iter().map(|n| n.serialize().to_vec()).collect(),
		};
		let resp = asp.client.request_oor_cosign(req).await.context("cosign request failed")?.into_inner();

		let asp_pub_nonces = resp.asp_pub_nonces()?;
		let asp_part_sigs = resp.asp_part_sigs()?;
		if asp_pub_nonces.len() != payment.inputs.len() || asp_part_sigs.len() != payment.inputs.len() {
			bail!("invalid length of asp response");
		}

		trace!("OOR prevouts: {:?}", payment.inputs.iter().map(|i| i.txout()).collect::<Vec<_>>());
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
		let user_vtxo = vtxos.get(0).context("no vtxo created")?.clone();
		let change_vtxo = vtxos.last().map(|c| c.clone());

		Ok(OorCreateResult {
			input: input_vtxos,
			created: user_vtxo,
			change: change_vtxo,
			fee: offchain_fees
		})
	}


	pub async fn send_oor_payment(&mut self, destination: PublicKey, amount: Amount) -> anyhow::Result<Vtxo> {
		let mut asp = self.require_asp()?;

		if amount < P2TR_DUST {
			bail!("Sent amount must be at least {}", P2TR_DUST);
		}

		let oor = self.create_oor_vtxo(destination, amount).await?;

		let req = protos::OorVtxo {
			pubkey: destination.serialize().to_vec(),
			vtxo: oor.created.clone().encode(),
		};

		if let Err(e) = asp.client.post_oor_mailbox(req).await {
			error!("Failed to post the OOR vtxo to the recipients mailbox: '{}'; vtxo: {}",
				e, oor.created.encode().as_hex(),
			);
			//NB we will continue to at least not lose our own change
		}

		self.db.register_movement(MovementArgs {
			spends: &oor.input.iter().collect::<Vec<_>>(),
			receives: &oor.change.as_ref().map(|v| vec![(v, VtxoState::Spendable)]).unwrap_or(vec![]),
			recipients: &[(&destination.to_string(), amount)],
			fees: Some(oor.fee)
		}).context("failed to store OOR vtxo")?;

		Ok(oor.created)
	}

	pub async fn send_bolt11_payment(
		&mut self,
		invoice: &Bolt11Invoice,
		user_amount: Option<Amount>,
	) -> anyhow::Result<[u8; 32]> {
		let properties = self.db.read_properties()?.context("Missing config")?;

		if invoice.network() != properties.network {
			bail!("BOLT-11 invoice is for wrong network: {}", invoice.network());
		}

		if self.db.check_recipient_exists(&invoice.to_string())? {
			bail!("Invoice has already been paid");
		}

		let mut asp = self.require_asp()?;

		let inv_amount = invoice.amount_milli_satoshis()
			.map(|v| Amount::from_sat(v.div_ceil(1000)));
		if let (Some(_), Some(inv)) = (user_amount, inv_amount) {
			bail!("Invoice has amount of {} encoded. Please omit amount argument", inv);
		}

		let amount = user_amount.or(inv_amount).context("amount required on invoice without amount")?;
		if amount < P2TR_DUST {
			bail!("Sent amount must be at least {}", P2TR_DUST);
		}

		let change_keypair = self.derive_store_next_keypair(KeychainKind::Internal)?;

		let forwarding_fee = Amount::from_sat(350);
		let inputs = self.db.select_vtxos_to_cover(amount + forwarding_fee)?;


		let (sec_nonces, pub_nonces, keypairs) = {
			let mut secs = Vec::with_capacity(inputs.len());
			let mut pubs = Vec::with_capacity(inputs.len());
			let mut keypairs = Vec::with_capacity(inputs.len());

			for input in inputs.iter() {
				let (keychain, keypair_idx) = self.db.get_vtxo_key(&input)?;
				let keypair = self.vtxo_seed.derive_keychain(keychain, keypair_idx);

				let (s, p) = musig::nonce_pair(&keypair);
				secs.push(s);
				pubs.push(p);
				keypairs.push(keypair);
			}
			(secs, pubs, keypairs)
		};

		let req = protos::Bolt11PaymentRequest {
			invoice: invoice.to_string(),
			amount_sats: user_amount.map(|a| a.to_sat()),
			input_vtxos: inputs.iter().map(|v| v.encode()).collect(),
			user_pubkey: change_keypair.public_key().serialize().to_vec(),
			user_nonces: pub_nonces.iter().map(|n| n.serialize().to_vec()).collect(),
		};
		let resp = asp.client.start_bolt11_payment(req).await
			.context("htlc request failed")?.into_inner();

		let asp_pub_nonces = resp.asp_pub_nonces()?;
		let asp_part_sigs = resp.asp_part_sigs()?;
		if asp_pub_nonces.len() != inputs.len() || asp_part_sigs.len() != inputs.len() {
			bail!("invalid length of asp response");
		}

		let payment = ark::lightning::Bolt11Payment::decode(&resp.details)
			.context("invalid bolt11 payment details from asp")?;



		trace!("htlc prevouts: {:?}", inputs.iter().map(|i| i.txout()).collect::<Vec<_>>());
		let input_vtxos = payment.inputs.clone();
		let signed = payment.sign_finalize_user(
			sec_nonces,
			&pub_nonces,
			&keypairs,
			&asp_pub_nonces,
			&asp_part_sigs,
		);

		let req = protos::SignedBolt11PaymentDetails {
			signed_payment: signed.clone().encode(),
			wait: true,
		};

		let res = asp.client.finish_bolt11_payment(req).await?.into_inner();
		debug!("Progress update: {}", res.progress_message);
		let payment_preimage = <[u8; 32]>::try_from(res.payment_preimage()).ok();

		// The client will receive the change VTXO if it exists
		let change_vtxo = if let Some(change_vtxo) = signed.change_vtxo() {
			info!("Adding change VTXO of {}", change_vtxo.amount());
			trace!("htlc tx: {}", bitcoin::consensus::encode::serialize_hex(&unsigned_oor_tx(&change_vtxo.inputs, &change_vtxo.output_specs)));
			Some(change_vtxo.into())
		} else {
			None
		};
		let receive_vtxos = change_vtxo
			.iter()
			.map(|v| (v, VtxoState::Spendable))
			.collect::<Vec<_>>();

		if let Some(preimage) = payment_preimage {
			self.db.register_movement(MovementArgs {
				spends: &input_vtxos.iter().collect::<Vec<_>>(),
				receives: &receive_vtxos,
				recipients: &[(&invoice.to_string(), amount)],
				fees: Some(forwarding_fee)
			}).context("failed to store OOR vtxo")?;
			Ok(preimage)
		} else {
			let htlc_vtxo = signed.htlc_vtxo().into();
			let (keychain, keypair_idx) = self.db.get_vtxo_key(&htlc_vtxo)?;
			let keypair = self.vtxo_seed.derive_keychain(keychain, keypair_idx);
			let (sec_nonce, pub_nonce) = musig::nonce_pair(&keypair);

			let req = protos::RevokeBolt11PaymentRequest {
				signed_payment: signed.encode(),
				pub_nonces: vec![pub_nonce.serialize().to_vec()],
			};

			let resp = asp.client.revoke_bolt11_payment(req).await?.into_inner();
			let asp_pub_nonces = resp.asp_pub_nonces()?;
			let asp_part_sigs = resp.asp_part_sigs()?;
			if asp_pub_nonces.len() != inputs.len() || asp_part_sigs.len() != inputs.len() {
				bail!("invalid length of asp response");
			}

			let revocation_payment = signed.revocation_payment();
			let signed_revocation = revocation_payment.sign_finalize_user(
				vec![sec_nonce],
				&[pub_nonce],
				&[keypair],
				&asp_pub_nonces,
				&asp_part_sigs,
			);

			trace!("OOR tx: {}", bitcoin::consensus::encode::serialize_hex(&signed_revocation.signed_transaction()));

			let vtxo = Vtxo::from(signed_revocation
				.output_vtxos()
				.first()
				.expect("there should be one output")
				.clone()
			);

			self.db.register_movement(MovementArgs {
				spends: &input_vtxos.iter().collect::<Vec<_>>(),
				receives: &if let Some(ref change) = change_vtxo {
					vec![(&vtxo, VtxoState::Spendable), (change, VtxoState::Spendable)]
				} else {
					vec![(&vtxo, VtxoState::Spendable)]
				},
				recipients: &[],
				fees: None
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
			amount_sats: amount.to_sat()
		};

		let resp = asp.client.start_bolt11_onboard(req).await?.into_inner();
		info!("Ark Server is ready to receive LN payment to invoice: {}.", resp.bolt11);

		let invoice = Bolt11Invoice::from_str(&resp.bolt11)
			.context("invalid bolt11 invoice returned by asp")?;

		self.db.store_offchain_onboard(
			payment_hash.as_byte_array(),
			&preimage,
			OffchainPayment::Lightning(invoice.clone())
		)?;

		Ok(invoice)
	}

	async fn create_fee_vtxo(&mut self, fees: Amount) -> anyhow::Result<Vtxo> {
		let pubkey = self.derive_store_next_keypair(KeychainKind::Internal)?.public_key();
		let oor = self.create_oor_vtxo(pubkey, fees).await?;
		let receives = [&oor.created].into_iter()
			.chain(&oor.change)
			.map(|v| (v, VtxoState::Spendable))
			.collect::<Vec<_>>();

		// TODO: we should ensure no fee is applied in this send
		self.db.register_movement(MovementArgs {
			spends: &oor.input.iter().collect::<Vec<_>>(),
			receives: &receives,
			recipients: &[],
			fees: None
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
		let fee_vtxo = self.create_fee_vtxo(*LN_ONBOARD_FEE_SATS).await?;

		let cloned = fee_vtxo.clone();
		let RoundResult { vtxos, .. } = self.participate_round(move |_| {
			let inputs = vec![cloned.clone()];
			let htlc_pay_req = PaymentRequest {
				pubkey: keypair.public_key(),
				amount: amount,
				spk: VtxoSpkSpec::HtlcIn {
					payment_hash: *invoice.payment_hash(),
					htlc_expiry: current_height + asp.info.vtxo_expiry_delta as u32,
				}
			};

			Ok((inputs, vec![htlc_pay_req], vec![]))
		}).await.context("round failed")?;

		info!("Got HTLC vtxo in round: {}", vtxos.first().expect("should have one").id());

		// Claiming arkoor against preimage
		let pay_req = PaymentRequest {
			pubkey: keypair.public_key(),
			amount: amount,
			spk: VtxoSpkSpec::Exit,
		};

		let payment = ark::oor::OorPayment::new(
			asp.info.asp_pubkey,
			asp.info.vtxo_exit_delta,
			vtxos,
			vec![pay_req],
		);
		let (sec_nonce, pub_nonce) = musig::nonce_pair(&keypair);

		let req = protos::ClaimBolt11OnboardRequest {
			payment: payment.encode(),
			payment_preimage: offchain_onboard.payment_preimage.to_vec(),
			pub_nonces: vec![pub_nonce.serialize().to_vec()],
		};

		info!("Claiming arkoor against payment preimage");
		let resp = asp.client.claim_bolt11_onboard(req).await?.into_inner();
		let asp_pub_nonces = resp.asp_pub_nonces()?;
		let asp_part_sigs = resp.asp_part_sigs()?;
		if asp_pub_nonces.len() != payment.inputs.len() || asp_part_sigs.len() != payment.inputs.len() {
			bail!("invalid length of asp response");
		}

		let signed_payment = payment.sign_finalize_user(
			vec![sec_nonce],
			&vec![pub_nonce],
			&vec![keypair],
			&asp_pub_nonces,
			&asp_part_sigs,
		);

		trace!("OOR tx: {}", bitcoin::consensus::encode::serialize_hex(&signed_payment.signed_transaction()));
		let vtxo = Vtxo::from(signed_payment
			.output_vtxos()
			.first()
			.expect("there should be one output")
			.clone()
		);

		info!("Got an arkoor from lightning! {}", vtxo.id());
		self.db.register_movement(MovementArgs {
			spends: &[&fee_vtxo],
			receives: &[(&vtxo, VtxoState::Spendable)],
			recipients: &[],
			fees: Some(fee_vtxo.amount()),
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
			let input_vtxos = self.db.select_vtxos_to_cover(spent_amount + P2TR_DUST)?;

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
					Some(PaymentRequest {
						pubkey: change_keypair.public_key(),
						amount: amount,
						spk: VtxoSpkSpec::Exit,
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
		pay_reqs: &Vec<PaymentRequest>,
		offb_reqs: &Vec<OffboardRequest>,
	) -> anyhow::Result<AttemptResult> {
		let mut asp = self.require_asp()?;

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
				spk: req.spk,
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
				let (keychain, keypair_idx) = self.db.get_vtxo_key(vtxo)
					.expect("owned vtxo key should be in database");
				let key = self.vtxo_seed.derive_keychain(keychain, keypair_idx);

				protos::InputVtxo {
					vtxo_id: id.to_bytes().to_vec(),
					ownership_proof: {
						let sig = round_state.challenge().sign_with(*id, key);
						sig.serialize().to_vec()
					},
				}
			}).collect(),
			vtxo_requests: vtxo_reqs.iter().zip(cosign_nonces.iter()).map(|(r, n)| {
				protos::VtxoRequest {
					amount: r.amount.to_sat(),
					vtxo_public_key: r.pubkey.serialize().to_vec(),
					cosign_pubkey: r.cosign_pk.serialize().to_vec(),
					public_nonces: n.1.iter().map(|n| n.serialize().to_vec()).collect(),
					vtxo_spk: r.spk.encode().to_vec(),
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

			let mut my_offbs = offb_reqs.clone();
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
			let part_sigs = unsigned_vtxos.cosign_branch(
				&vtxo_cosign_agg_nonces,
				req,
				key,
				sec,
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
			let (keychain, keypair_idx) = self.db.get_vtxo_key(&vtxo)?;
			let vtxo_keypair = self.vtxo_seed.derive_keychain(keychain, keypair_idx);

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
			//TODO(stevenroose) this is broken, need to match vtxorequest exactly
			if pay_reqs.iter().any(|p| p.pubkey == req.pubkey && p.amount == req.amount) {
				let vtxo = self.build_vtxo(&signed_vtxos, idx)?.expect("must be in tree");
				new_vtxos.push(vtxo);
			}
		}

		// if there is one offboard req, we register as a spend, else as a refresh
		// TODO: this is broken in case of multiple offb_reqs, but currently we don't allow that


		let params = Params::new(self.properties().unwrap().network);
		let sent = offb_reqs.iter().map(|o| {
			let address = Address::from_script(&o.script_pubkey, &params)?;
			Ok((address.to_string(), o.amount))
		}).collect::<anyhow::Result<Vec<_>>>()?;

		let received = new_vtxos.iter()
			.filter(|v| { matches!(
				v.as_round().expect("comming from round").spec.spk,
				VtxoSpkSpec::Exit { .. }
			)})
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
			(Vec<Vtxo>, Vec<PaymentRequest>, Vec<OffboardRequest>)
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

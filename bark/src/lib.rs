#![doc = include_str!("../README.md")]

pub extern crate ark;
pub extern crate bark_json as json;

pub extern crate lightning_invoice;
pub extern crate lnurl as lnurllib;

#[macro_use] extern crate anyhow;
#[macro_use] extern crate serde;

pub mod exit;
pub mod movement;
pub mod onchain;
pub mod persist;
pub mod server;
pub mod vtxo_state;
pub mod vtxo_selection;

pub use self::config::Config;
pub use self::persist::sqlite::SqliteClient;
pub use bark_json::primitives::UtxoInfo;
pub use bark_json::cli::{Offboard, Board, SendOnchain};

mod config;
mod lnurl;
mod psbtext;
mod round;

use std::collections::{HashMap, HashSet};

use core::fmt;
use std::convert::TryFrom;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context};
use bip39::Mnemonic;
use bitcoin::{Amount, FeeRate, Network, OutPoint, Transaction};
use bitcoin::bip32::{self, Fingerprint};
use bitcoin::hashes::Hash;
use bitcoin::hex::DisplayHex;
use bitcoin::secp256k1::{self, Keypair, PublicKey};
use lnurllib::lightning_address::LightningAddress;
use lightning_invoice::Bolt11Invoice;
use lightning::util::ser::Writeable;
use log::{trace, debug, info, warn, error};
use futures::StreamExt;
use serde::ser::StdError;
use tokio_stream::Stream;

use ark::{ArkInfo, OffboardRequest, ProtocolEncoding, Vtxo, VtxoId, VtxoPolicy, VtxoRequest};
use ark::address::VtxoDelivery;
use ark::arkoor::ArkoorPackageBuilder;
use ark::board::{BoardBuilder, BOARD_FUNDING_TX_VTXO_VOUT};
use ark::lightning::{Bolt12Invoice, Bolt12InvoiceExt, Invoice, Offer, Preimage, PaymentHash};
use ark::musig;
use ark::rounds::{RoundEvent, RoundId, RoundInfo, RoundSeq, VtxoOwnershipChallenge};
use ark::tree::signed::{CachedSignedVtxoTree, SignedVtxoTreeSpec};
use ark::vtxo::{PubkeyVtxoPolicy, ServerHtlcSendVtxoPolicy, VtxoPolicyType};
use server_rpc::{self as rpc, protos, TryFromBytes};
use bitcoin_ext::{AmountExt, BlockHeight, P2TR_DUST};

use round::{
	error_before_forfeit,
	AttemptStartedState,
	RoundAbandonedState,
	ProgressResult,
	RoundState,
	ToAbandoned,
};

use crate::exit::Exit;
use crate::movement::{Movement, MovementArgs, MovementKind};
use crate::onchain::{ChainSourceClient, PreparePsbt, ExitUnilaterally, Utxo, GetWalletTx, SignPsbt};
use crate::persist::{BarkPersister, LightningReceive, StoredVtxoRequest};
use crate::server::ServerConnection;
use crate::vtxo_selection::{FilterVtxos, VtxoFilter};
use crate::vtxo_state::{VtxoState, VtxoStateKind, WalletVtxo};
use crate::vtxo_selection::RefreshStrategy;

const ARK_PURPOSE_INDEX: u32 = 350;

lazy_static::lazy_static! {
	/// Global secp context.
	static ref SECP: secp256k1::Secp256k1<secp256k1::All> = secp256k1::Secp256k1::new();
}

/// The different balances of a Bark wallet.
#[derive(Debug, Clone)]
pub struct Balance {
	/// Coins that are spendable in the Ark, either in-round or out-of-round.
	pub spendable: Amount,
	/// Coins that are in the process of being sent over Lightning.
	pub pending_lightning_send: Amount,
	/// Coins locked in a round.
	pub pending_in_round: Amount,
	/// Coins that are in the process of unilaterally exiting the Ark.
	pub pending_exit: Amount,
}

// TODO: we set it to 0 for now to avoid breaking UX,
// but we should implement "pending confirmation" vtxo state and only allow a subset of actions for it
const ROUND_DEEPLY_CONFIRMED: u32 = 0;

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
				amount: o.amount,
				confirmation_height: o.confirmation_height,
			},
			Utxo::Exit(e) => UtxoInfo {
				outpoint: e.vtxo.point(),
				amount: e.vtxo.amount(),
				confirmation_height: Some(e.height),
			},
		}
	}
}

#[derive(Debug, Clone)]
/// Struct to communicate your specific participation requests for an Ark round.
pub struct RoundParticipation {
	inputs: Vec<Vtxo>,
	outputs: Vec<StoredVtxoRequest>,
	offboards: Vec<OffboardRequest>,
}

/// Unrecoverable errors that can occur during a round attempt. For
/// recoverable/retryable errors, use `AttemptResult::WaitNewRound` instead.
///
/// Errors are categorized based on when they occur in relation to forfeit
/// signature creation.
#[derive(Debug)]
enum AttemptError {
	/// Occurs before forfeit signatures are created
	/// and sent to the Ark Server. At this point, input VTXOs are still valid and
	/// can be safely exited since the Ark Server cannot double spend them via a
	/// forfeit transaction. The wallet can safely move on to another round.
	/// Includes a `RoundAbandonedState` to ensure proper round state cleanup.
	BeforeSigningForfeit(RoundAbandonedState),

	/// Occurs after forfeit signatures are created
	/// and sent to the Ark Server. This is a critical error since the Ark Server
	/// now has valid forfeit signatures for the input VTXOs and could broadcast
	/// them at any time, potentially invalidating those VTXOs. The wallet must
	/// cancel the round and take precautions against potential VTXO invalidation.
	AfterSigningForfeit,

	/// Occurs when updating the round state fails.
	DatabaseError(String),

	/// Occurs when the events stream breaks.
	StreamError(anyhow::Error),
}

impl fmt::Display for AttemptError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			AttemptError::BeforeSigningForfeit(abandoned) => {
				write!(f, "An error occured in round attempt before forfeit signature. Round was abandoned: {:?}", abandoned)
			},
			AttemptError::AfterSigningForfeit => {
				write!(f, "An error occured in round attempt after forfeit signature.")
			},
			AttemptError::DatabaseError(msg) => {
				write!(f, "An error occured while updating the round state: {}", msg)
			},
			AttemptError::StreamError(e) => {
				write!(f, "An error occured while processing the events stream: {}", e)
			},
		}
	}
}

impl StdError for AttemptError {}

/// Result of a round attempt.
enum AttemptResult {
	/// A new round was started by the server.
	///
	/// Includes the new round info to let caller process it.
	NewRoundStarted(RoundInfo),

	/// The attempt could not be completed and the client should wait for
	/// a new round to be started by the server.
	WaitNewRound,

	/// A new attempt was started by the server, most probably because one of the participants
	/// dropped out during the round.
	///
	/// Includes the updated round state to let caller process it.
	NewAttemptStarted((AttemptStartedState, VtxoOwnershipChallenge)),

	/// The attempt was successfully processed and its transaction is now
	/// pending confirmations. Should be sync regularly to check when movement
	/// can be settled and new vtxos created.
	///
	/// Includes the round result.
	Success(RoundResult),
}

#[derive(Debug)]
struct RoundResult {
	round_id: RoundId,
}

pub struct OffchainBalance {
	pub available: Amount,
	pub pending_in_round: Amount,
	pub pending_exit: Amount,
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

	fn derive_keypair(&self, idx: u32) -> Keypair {
		self.0.derive_priv(&SECP, &[idx.into()]).unwrap().to_keypair(&SECP)
	}
}


pub struct Wallet {
	/// The chain source the wallet is connected to
	pub chain: Arc<ChainSourceClient>,
	pub exit: Exit,

	config: Config,
	db: Arc<dyn BarkPersister>,
	vtxo_seed: VtxoSeed,
	server: Option<ServerConnection>,

}

impl Wallet {
	pub fn chain_source<P: BarkPersister>(db: Arc<P>) -> anyhow::Result<onchain::ChainSource> {
		let config = db.read_config()?.context("Wallet is not initialised")?;

		// create on-chain wallet
		if let Some(ref url) = config.esplora_address {
			Ok(onchain::ChainSource::Esplora {
				url: url.clone(),
			})
		} else if let Some(ref url) = config.bitcoind_address {
			let auth = if let Some(ref c) = config.bitcoind_cookiefile {
				bitcoin_ext::rpc::Auth::CookieFile(c.clone())
			} else {
				bitcoin_ext::rpc::Auth::UserPass(
					config.bitcoind_user.clone().context("need bitcoind auth config")?,
					config.bitcoind_pass.clone().context("need bitcoind auth config")?,
				)
			};
			Ok(onchain::ChainSource::Bitcoind {
				url: url.clone(),
				auth: auth,
			})
		} else {
			bail!("Need to either provide esplora or bitcoind info");
		}
	}

	pub fn require_chainsource_version(&self) -> anyhow::Result<()> {
		self.chain.require_version()
	}

	/// Derive and store the keypair directly after currently last revealed one,
	/// together with its index.
	pub fn derive_store_next_keypair(&self) -> anyhow::Result<(Keypair, u32)> {
		let last_revealed = self.db.get_last_vtxo_key_index()?;

		let index = last_revealed.map(|i| i + 1).unwrap_or(u32::MIN);
		let keypair = self.vtxo_seed.derive_keypair(index);

		self.db.store_vtxo_key(index, keypair.public_key())?;
		Ok((keypair, index))
	}

	pub fn peak_keypair(&self, index: u32) -> anyhow::Result<Keypair> {
		let keypair = self.vtxo_seed.derive_keypair(index);
		if self.db.check_vtxo_key_exists(&keypair.public_key())? {
			Ok(keypair)
		} else {
			bail!("VTXO key {} does not exist, please derive it first", index)
		}
	}

	/// Generate a new Ark address.
	///
	/// This derives and stores the keypair directly after currently last revealed one
	pub fn new_address(&self) -> anyhow::Result<ark::Address> {
		let ark = &self.require_server()?;
		let network = self.properties()?.network;
		let pubkey = self.derive_store_next_keypair()?.0.public_key();

		Ok(ark::Address::builder()
			.testnet(network != bitcoin::Network::Bitcoin)
			.server_pubkey(ark.info.server_pubkey)
			.pubkey_policy(pubkey)
			.into_address().unwrap())
	}

	/// Peak for Ark address at the given key index.
	pub fn peak_address(&self, index: u32) -> anyhow::Result<ark::Address> {
		let ark = &self.require_server()?;
		let network = self.properties()?.network;
		let pubkey = self.peak_keypair(index)?.public_key();

		Ok(ark::Address::builder()
			.testnet(network != bitcoin::Network::Bitcoin)
			.server_pubkey(ark.info.server_pubkey)
			.pubkey_policy(pubkey)
			.into_address().unwrap())
	}

	/// Generate a new Ark address and the index of the key used to create it
	///
	/// This derives and stores the keypair directly after currently last revealed one.
	pub fn new_address_with_index(&self) -> anyhow::Result<(ark::Address, u32)> {
		let ark = &self.require_server()?;
		let network = self.properties()?.network;
		let (keypair, index) = self.derive_store_next_keypair()?;
		let pubkey = keypair.public_key();
		let addr = ark::Address::builder()
			.testnet(network != bitcoin::Network::Bitcoin)
			.server_pubkey(ark.info.server_pubkey)
			.pubkey_policy(pubkey)
			.into_address().unwrap();
		Ok((addr, index))
	}

	/// Create new wallet.
	pub async fn create<P: BarkPersister>(
		mnemonic: &Mnemonic,
		network: Network,
		config: Config,
		db: Arc<P>,
		force: bool,
	) -> anyhow::Result<Wallet> {
		trace!("Config: {:?}", config);
		if let Some(existing) = db.read_config()? {
			trace!("Existing config: {:?}", existing);
			bail!("cannot overwrite already existing config")
		}

		if !force{
			if let Err(_) = ServerConnection::connect(&config.server_address, network).await {
				bail!("Not connected to a server. If you are sure use the --force flag.");
			}
		}

		let wallet_fingerprint = VtxoSeed::new(network, &mnemonic.to_seed("")).fingerprint();
		let properties = WalletProperties {
			network: network,
			fingerprint: wallet_fingerprint,
		};

		// write the config to db
		db.init_wallet(&config, &properties).context("cannot init wallet in the database")?;

		// from then on we can open the wallet
		let wallet = Wallet::open(&mnemonic, db).await.context("failed to open wallet")?;
		wallet.require_chainsource_version()?;

		Ok(wallet)
	}

	pub async fn create_with_onchain<P: BarkPersister, W: ExitUnilaterally>(
		mnemonic: &Mnemonic,
		network: Network,
		config: Config,
		db: Arc<P>,
		onchain: &W,
		force: bool,
	) -> anyhow::Result<Wallet> {
		let mut wallet = Wallet::create(mnemonic, network, config, db, force).await?;
		wallet.exit.load(onchain).await?;
		Ok(wallet)
	}

	/// Open existing wallet.
	pub async fn open<P: BarkPersister>(mnemonic: &Mnemonic, db: Arc<P>) -> anyhow::Result<Wallet> {
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
				bitcoin_ext::rpc::Auth::CookieFile(c.clone())
			} else {
				bitcoin_ext::rpc::Auth::UserPass(
					config.bitcoind_user.clone().context("need bitcoind auth config")?,
					config.bitcoind_pass.clone().context("need bitcoind auth config")?,
				)
			};
			onchain::ChainSource::Bitcoind { url: url.clone(), auth }
		} else {
			bail!("Need to either provide esplora or bitcoind info");
		};

		let chain_source_client = ChainSourceClient::new(
			chain_source, properties.network, config.fallback_fee_rate,
		).await?;
		let chain = Arc::new(chain_source_client);

		let srv = match ServerConnection::connect(&config.server_address, properties.network).await {
			Ok(s) => Some(s),
			Err(e) => {
				warn!("Ark server handshake failed: {}", e);
				None
			}
		};

		let exit = Exit::new(db.clone(), chain.clone()).await?;

		Ok(Wallet { config, db, vtxo_seed, exit, server: srv, chain })
	}

	pub async fn open_with_onchain<P: BarkPersister, W: ExitUnilaterally>(
		mnemonic: &Mnemonic,
		db: Arc<P>,
		onchain: &W,
	) -> anyhow::Result<Wallet> {
		let mut wallet = Wallet::open(mnemonic, db).await?;
		wallet.exit.load(onchain).await?;
		Ok(wallet)
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

	fn require_server(&self) -> anyhow::Result<ServerConnection> {
		self.server.clone().context("You should be connected to Ark server to perform this action")
	}

	/// Return ArkInfo fetched on last handshake
	pub fn ark_info(&self) -> Option<&ArkInfo> {
		self.server.as_ref().map(|a| &a.info)
	}

	/// Return the balance of the wallet.
	///
	/// Make sure you sync before calling this method.
	pub fn balance(&self) -> anyhow::Result<Balance> {
		let spendable = self.db.get_all_spendable_vtxos()?.iter()
			.map(|v| v.amount()).sum();

		let pending_lightning_send = self.db.get_vtxos_by_state(&[VtxoStateKind::PendingLightningSend])?
			.iter().map(|v| v.vtxo.amount()).sum();

		let pending_in_round = self.db.get_in_round_vtxos()?.iter()
			.map(|v| v.amount()).sum();

		let pending_exit = self.exit.pending_total()?;

		Ok(Balance {
			spendable,
			pending_in_round,
			pending_lightning_send,
			pending_exit,
		})
	}

	pub fn get_vtxo_by_id(&self, vtxo_id: VtxoId) -> anyhow::Result<WalletVtxo> {
		let vtxo = self.db.get_wallet_vtxo(vtxo_id)
			.with_context(|| format!("Error when querying vtxo {} in database", vtxo_id))?
			.with_context(|| format!("The VTXO with id {} cannot be found", vtxo_id))?;
		Ok(vtxo)
	}

	pub fn movements(&self, pagination: Pagination) -> anyhow::Result<Vec<Movement>> {
		Ok(self.db.get_paginated_movements(pagination)?)
	}

	/// Returns all spendable vtxos
	pub fn vtxos(&self) -> anyhow::Result<Vec<Vtxo>> {
		Ok(self.db.get_all_spendable_vtxos()?)
	}

	/// Returns all unspent vtxos matching the provided predicate
	pub fn vtxos_with(&self, filter: &impl FilterVtxos) -> anyhow::Result<Vec<Vtxo>> {
		let vtxos = self.vtxos()?;
		Ok(filter.filter(vtxos).context("error filtering vtxos")?)
	}

	/// Returns all in-round vtxos matching the provided predicate
	pub fn inround_vtxos_with(&self, filter: &impl FilterVtxos) -> anyhow::Result<Vec<Vtxo>> {
		let vtxos = self.db.get_in_round_vtxos()?;
		Ok(filter.filter(vtxos).context("error filtering vtxos")?)
	}

	/// Returns all vtxos that will expire within
	/// `threshold_blocks` blocks
	pub async fn get_expiring_vtxos(&mut self, threshold: BlockHeight) -> anyhow::Result<Vec<Vtxo>> {
		let expiry = self.chain.tip().await? + threshold;
		let filter = VtxoFilter::new(&self).expires_before(expiry);
		Ok(self.vtxos_with(&filter)?)
	}

	async fn register_all_unregistered_boards(
		&self,
		wallet: &mut impl GetWalletTx,
	) -> anyhow::Result<()> {
		let unregistered_boards = self.db.get_vtxos_by_state(&[VtxoStateKind::UnregisteredBoard])?;

		if unregistered_boards.is_empty() {
			return Ok(());
		}

		trace!("Re-attempt registration of {} boards", unregistered_boards.len());
		for board in unregistered_boards {
			if let Err(e) = self.register_board(wallet, board.vtxo.id()).await {
				warn!("Failed to register board {}: {}", board.vtxo.id(), e);
			} else {
				info!("Registered board {}", board.vtxo.id());
			}
		};

		Ok(())
	}

	/// Performs maintenance tasks on the wallet
	///
	/// This tasks include onchain-sync, off-chain sync,
	/// registering board with the server.
	///
	/// This tasks will only include anything that has to wait
	/// for a round. The maintenance call cannot be used to
	/// refresh VTXOs.
	pub async fn maintenance<W: PreparePsbt + SignPsbt + ExitUnilaterally>(
		&mut self,
		wallet: &mut W,
	) -> anyhow::Result<()> {
		info!("Starting wallet maintenance");
		self.sync().await?;
		self.register_all_unregistered_boards(wallet).await?;
		self.maintenance_refresh().await?;
		self.sync_pending_lightning_vtxos().await?;

		// NB: order matters here, after syncing lightning, we might have new exits to start
		self.sync_exits(wallet).await?;
		Ok(())
	}

	/// Sync status of unilateral exits.
	pub async fn sync_exits<W: ExitUnilaterally>(
		&mut self,
		onchain: &mut W,
	) -> anyhow::Result<()> {
		self.exit.sync_exit(onchain).await?;
		Ok(())
	}

	/// Sync offchain wallet and update onchain fees
	pub async fn sync(&mut self) -> anyhow::Result<()> {
		// NB: order matters here, if syncing call fails, we still want to update the fee rates
		if let Err(e) = self.chain.update_fee_rates(self.config.fallback_fee_rate).await {
			warn!("Error updating fee rates: {}", e);
		}

		if let Err(e) = self.sync_rounds().await {
			error!("Error in round sync: {}", e);
		}
		if let Err(e) = self.sync_oors().await {
			error!("Error in arkoor sync: {}", e);
		}

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

	/// Board a VTXO with the given amount.
	///
	/// NB we will spend a little more on-chain to cover fees.
	pub async fn board_amount<W: PreparePsbt + SignPsbt + GetWalletTx>(
		&mut self,
		wallet: &mut W,
		amount: Amount,
	) -> anyhow::Result<Board> {
		let (user_keypair, _) = self.derive_store_next_keypair()?;
		self.board(wallet, Some(amount), user_keypair).await
	}

	/// Board a VTXO with all the funds in your on-chain wallet.
	pub async fn board_all<W: PreparePsbt + SignPsbt + GetWalletTx>(
		&mut self,
		wallet: &mut W,
	) -> anyhow::Result<Board> {
		let (user_keypair, _) = self.derive_store_next_keypair()?;
		self.board(wallet, None, user_keypair).await
	}

	async fn board<W: PreparePsbt + SignPsbt + GetWalletTx>(
		&mut self,
		wallet: &mut W,
		amount: Option<Amount>,
		user_keypair: Keypair,
	) -> anyhow::Result<Board> {
		let mut srv = self.require_server()?;
		let properties = self.db.read_properties()?.context("Missing config")?;
		let current_height = self.chain.tip().await?;

		let expiry_height = current_height + srv.info.vtxo_expiry_delta as BlockHeight;
		let builder = BoardBuilder::new(
			user_keypair.public_key(),
			expiry_height,
			srv.info.server_pubkey,
			srv.info.vtxo_exit_delta,
		);

		let addr = bitcoin::Address::from_script(&builder.funding_script_pubkey(), properties.network).unwrap();

		// We create the board tx template, but don't sign it yet.
		let fee_rate = self.chain.fee_rates().await.regular;
		let (board_psbt, amount) = if let Some(amount) = amount {
			let psbt = wallet.prepare_tx([(addr, amount)], fee_rate)?;
			(psbt, amount)
		} else {
			let psbt = wallet.prepare_drain_tx(addr, fee_rate)?;
			assert_eq!(psbt.unsigned_tx.output.len(), 1);
			let amount = psbt.unsigned_tx.output[0].value;
			(psbt, amount)
		};

		let utxo = OutPoint::new(board_psbt.unsigned_tx.compute_txid(), BOARD_FUNDING_TX_VTXO_VOUT);
		let builder = builder
			.set_funding_details(amount, utxo)
			.generate_user_nonces();

		let cosign_resp = srv.client.request_board_cosign(protos::BoardCosignRequest {
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
			kind: MovementKind::Board,
			spends: &[],
			receives: &[(&vtxo, VtxoState::UnregisteredBoard)],
			recipients: &[],
			fees: None,
		}).context("db error storing vtxo")?;

		let tx = wallet.finish_tx(board_psbt)?;

		trace!("Broadcasting board tx: {}", bitcoin::consensus::encode::serialize_hex(&tx));
		self.chain.broadcast_tx(&tx).await?;

		let res = self.register_board(wallet, vtxo.id()).await;
		info!("Board successful");
		res
	}

	/// Registers a board to the Ark server
	async fn register_board(
		&self,
		wallet: &mut impl GetWalletTx,
		vtxo_id: VtxoId,
	) -> anyhow::Result<Board> {
		trace!("Attempting to register board {} to server", vtxo_id);
		let mut srv = self.require_server()?;

		// Get the vtxo and funding transaction from the database
		let vtxo = self.db.get_wallet_vtxo(vtxo_id)?
			.with_context(|| format!("VTXO doesn't exist: {}", vtxo_id))?;

		let txid = vtxo.vtxo.chain_anchor().txid;
		let funding_tx = wallet.get_wallet_tx(txid)
			.context(anyhow!("Failed to find funding_tx for {}", txid))?;

		// Register the vtxo with the server
		srv.client.register_board_vtxo(protos::BoardVtxoRequest {
			board_vtxo: vtxo.vtxo.serialize(),
			board_tx: bitcoin::consensus::serialize(&funding_tx),
		}).await.context("error registering board with the Ark server")?;

		// Remember that we have stored the vtxo
		// No need to complain if the vtxo is already registered
		let allowed_states = &[VtxoStateKind::UnregisteredBoard, VtxoStateKind::Spendable];
		self.db.update_vtxo_state_checked(vtxo_id, VtxoState::Spendable, allowed_states)?;

		Ok(Board {
			funding_txid: funding_tx.compute_txid(),
			vtxos: vec![vtxo.vtxo.into()],
		})
	}

	fn build_vtxo(&self, vtxos: &CachedSignedVtxoTree, leaf_idx: usize) -> anyhow::Result<Option<Vtxo>> {
		let vtxo = vtxos.build_vtxo(leaf_idx).context("invalid leaf idx..")?;

		if self.db.get_wallet_vtxo(vtxo.id())?.is_some() {
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
		Ok(!self.db.check_vtxo_key_exists(&vtxo.user_pubkey())?)
	}

	/// Fetch new rounds from the Ark Server and check if one of their VTXOs
	/// is in the provided set of public keys
	pub async fn sync_rounds(&self) -> anyhow::Result<()> {
		let tip = self.chain.tip().await?;
		self.sync_pending_rounds(tip).await?;

		self.sync_past_rounds().await?;
		Ok(())
	}

	async fn sync_pending_rounds(&self, tip: u32) -> anyhow::Result<()> {
		info!("Syncing pending rounds at tip: {}", tip);
		let rounds = self.db.list_pending_rounds()?;

		for round in rounds {
			match round {
				RoundState::AttemptStarted(state) => {
					// TODO: later we can try to catch up last event
					state.to_abandoned_state(&self.db)?;
				},
				RoundState::PaymentSubmitted(state) => {
					// TODO: later we can try to catch up last event
					state.to_abandoned_state(&self.db)?;
				},
				RoundState::VtxoTreeSigned(state) => {
					// TODO: later we can try to catch up last event
					state.to_abandoned_state(&self.db)?;
				},
				RoundState::ForfeitSigned(state) => {
					// TODO: later we can try to catch up last event
					state.progress(None, self).await?;
				},
				RoundState::PendingConfirmation(state) => {
					// TODO: later we can try to catch up last event
					state.progress(self).await?;
				},
				RoundState::RoundConfirmed(_) |
				RoundState::RoundAbandoned(_) |
				RoundState::RoundCancelled(_) => {
					continue;
				},
			}
		}

		Ok(())
	}

	async fn sync_past_rounds(&self) -> anyhow::Result<()> {
		let mut srv = self.require_server()?;

		let last_synced_round = self.db.get_last_synced_round()?;
		debug!("Querying ark for rounds since round id {:?}", last_synced_round);

		let fresh_rounds = srv.client.get_fresh_rounds(protos::FreshRoundsRequest {
			last_round_txid: last_synced_round.map(|r| r.to_string()),
		}).await?.into_inner().txids.into_iter()
			.map(|txid| RoundId::from_slice(&txid))
			.collect::<Result<Vec<_>, _>>()?;

		if fresh_rounds.is_empty() {
			debug!("No new rounds to sync");
			return Ok(());
		}

		debug!("Received {} new rounds from ark", fresh_rounds.len());
		let last_round = fresh_rounds.last().unwrap().clone();

		let last_pk_index = self.db.get_last_vtxo_key_index()?.unwrap_or_default();
		let pubkeys = (0..=last_pk_index).map(|idx| {
			self.vtxo_seed.derive_keypair(idx).public_key()
		}).collect::<HashSet<_>>();

		let results = tokio_stream::iter(fresh_rounds).map(|round_id| {
			let pubkeys = pubkeys.clone();
			let mut srv = srv.clone();

			async move {
				if self.db.get_round_attempt_by_round_txid(round_id)?.is_some() {
					debug!("Skipping round {} because it already exists", round_id);
					return Ok::<_, anyhow::Error>(());
				}

				let req = protos::RoundId { txid: round_id.as_round_txid().to_byte_array().to_vec() };
				let round = srv.client.get_round(req).await?.into_inner();

				let tree = SignedVtxoTreeSpec::deserialize(&round.signed_vtxos)
					.context("invalid signed vtxo tree from srv")?
					.into_cached_tree();

				let mut reqs = Vec::new();
				let mut vtxos = vec![];
				for (idx, dest) in tree.spec.spec.vtxos.iter().enumerate() {
					if pubkeys.contains(&dest.vtxo.policy.user_pubkey()) {
						if let Some(vtxo) = self.build_vtxo(&tree, idx)? {
							reqs.push(StoredVtxoRequest {
								request_policy: dest.vtxo.policy.clone(),
								amount: dest.vtxo.amount,
								state: VtxoState::Spendable,
							});

							vtxos.push(vtxo);
						}
					}
				}

				let round_tx = Transaction::from_bytes(&round.round_tx)?;
				self.db.store_pending_confirmation_round(
					RoundSeq::new(0), round_id, round_tx, reqs, vtxos,
				)?;

				Ok(())
			}
		})
		.buffer_unordered(10)
		.collect::<Vec<_>>()
		.await;

		for result in results {
			if let Err(e) = result {
				return Err(e).context("failed to sync round");
			}
		}

		self.db.store_last_synced_round(last_round)?;

		Ok(())
	}

	async fn sync_oors(&self) -> anyhow::Result<()> {
		let last_pk_index = self.db.get_last_vtxo_key_index()?.unwrap_or_default();
		let pubkeys = (0..=last_pk_index).map(|idx| {
			self.vtxo_seed.derive_keypair(idx).public_key()
		}).collect::<Vec<_>>();

		self.sync_arkoor_for_pubkeys(&pubkeys).await?;

		Ok(())
	}

	/// Sync with the Ark and look for out-of-round received VTXOs
	/// by public key
	pub async fn sync_arkoor_for_pubkeys(
		&self,
		public_keys: &[PublicKey],
	) -> anyhow::Result<()> {
		let mut srv = self.require_server()?;

		for pubkeys in public_keys.chunks(rpc::MAX_NB_MAILBOX_PUBKEYS) {
			// Then sync OOR vtxos.
			debug!("Emptying OOR mailbox at Ark server...");
			let req = protos::ArkoorVtxosRequest {
				pubkeys: pubkeys.iter().map(|pk| pk.serialize().to_vec()).collect(),
			};
			let packages = srv.client.empty_arkoor_mailbox(req).await
				.context("error fetching oors")?.into_inner().packages;
			debug!("Ark server has {} arkoor packages for us", packages.len());

			for package in packages {
				let mut vtxos = Vec::with_capacity(package.vtxos.len());
				for vtxo in package.vtxos {
					let vtxo = match Vtxo::deserialize(&vtxo) {
						Ok(vtxo) => vtxo,
						Err(e) => {
							warn!("Invalid vtxo from Ark server: {}", e);
							continue;
						}
					};


					let txid = vtxo.chain_anchor().txid;
					let chain_anchor = self.chain.get_tx(&txid).await?.with_context(|| {
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

					if let Ok(Some(_)) = self.db.get_wallet_vtxo(vtxo.id()) {
						debug!("Not adding OOR vtxo {} because it already exists", vtxo.id());
						continue;
					}

					vtxos.push(vtxo);
				}

				self.db.register_movement(MovementArgs {
					kind: MovementKind::ArkoorReceive,
					spends: &[],
					receives: &vtxos.iter().map(|v| (v, VtxoState::Spendable)).collect::<Vec<_>>(),
					recipients: &[],
					fees: None,
				}).context("failed to store OOR vtxo")?;
			}
		}

		Ok(())
	}

	async fn offboard(
		&mut self,
		vtxos: Vec<Vtxo>,
		address: bitcoin::Address,
	) -> anyhow::Result<Offboard> {
		if vtxos.is_empty() {
			bail!("no VTXO to offboard");
		}

		let vtxo_sum = vtxos.iter().map(|v| v.amount()).sum::<Amount>();

		let RoundResult { round_id, .. } = self.participate_round(move |round| {
			let fee = OffboardRequest::calculate_fee(&address.script_pubkey(), round.offboard_feerate)
				.expect("bdk created invalid scriptPubkey");

			if fee > vtxo_sum {
				bail!("offboarded amount is lower than fees. Need {fee}, got: {vtxo_sum}");
			}

			let offb = OffboardRequest {
				amount: vtxo_sum - fee,
				script_pubkey: address.script_pubkey(),
			};

			Ok(RoundParticipation {
				inputs: vtxos.clone(),
				outputs: Vec::new(),
				offboards: vec![offb],
			})
		}).await.context("round failed")?;

		Ok(Offboard { round: round_id })
	}

	/// Offboard all vtxos to a given address
	pub async fn offboard_all(&mut self, address: bitcoin::Address) -> anyhow::Result<Offboard> {
		let input_vtxos = self.db.get_all_spendable_vtxos()?;

		Ok(self.offboard(input_vtxos, address).await?)
	}

	/// Offboard vtxos selection to a given address
	pub async fn offboard_vtxos(
		&mut self,
		vtxos: Vec<VtxoId>,
		address: bitcoin::Address,
	) -> anyhow::Result<Offboard> {
		let input_vtxos =  vtxos
				.into_iter()
				.map(|vtxoid| match self.db.get_wallet_vtxo(vtxoid)? {
					Some(vtxo) => Ok(vtxo.vtxo),
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

		let (user_keypair, _) = self.derive_store_next_keypair()?;
		let req = VtxoRequest {
			policy: VtxoPolicy::Pubkey(PubkeyVtxoPolicy { user_pubkey: user_keypair.public_key() }),
			amount: total_amount,
		};

		let RoundResult { round_id, .. } = self.participate_round(move |_| {
			Ok(RoundParticipation {
				inputs: vtxos.to_vec(),
				outputs: vec![StoredVtxoRequest::from_parts(req.clone(), VtxoState::Spendable)],
				offboards: Vec::new(),
			})
		}).await.context("round failed")?;

		Ok(Some(round_id))
	}

	/// Performs a refresh of all VTXOs that are due to be refreshed, if any.
	pub async fn maintenance_refresh(&self) -> anyhow::Result<Option<RoundId>> {
		let vtxos = self.get_vtxos_to_refresh().await?;
		if vtxos.len() == 0 {
			return Ok(None);
		}

		info!("Performing maintenance refresh");
		self.refresh_vtxos(vtxos).await
	}

	/// This will find any VTXO that meets must-refresh criteria.
	/// Then, if there are some VTXOs to refresh, it will
	/// also add those that meet should-refresh criteria.
	///
	/// Returns a list of Vtxo's
	async fn get_vtxos_to_refresh(&self) -> anyhow::Result<Vec<Vtxo>> {
		let tip = self.chain.tip().await?;
		let fee_rate = self.chain.fee_rates().await.fast;

		// Check if there is any VTXO that we must refresh
		let must_refresh_vtxos = self.vtxos_with(&RefreshStrategy::must_refresh(self, tip, fee_rate))?;
		if must_refresh_vtxos.is_empty() {
			return Ok(vec![]);
		} else {
			// If we need to do a refresh, we take all the should_refresh vtxo's as well
			// This helps us to aggregate some VTXOs
			let should_refresh_vtxos = self.vtxos_with(&RefreshStrategy::should_refresh(self, tip, fee_rate))?;
			Ok(should_refresh_vtxos)
		}
	}

	async fn sync_pending_lightning_vtxos(&mut self) -> anyhow::Result<()> {
		let vtxos = self.db.get_vtxos_by_state(&[VtxoStateKind::PendingLightningSend])?;

		if vtxos.is_empty() {
			return Ok(());
		}

		info!("Syncing {} pending lightning vtxos", vtxos.len());

		let mut htlc_vtxos_by_payment_hash = HashMap::<_, Vec<_>>::new();
		for vtxo in vtxos {
			let invoice = vtxo.state.as_pending_lightning_send().unwrap();
			htlc_vtxos_by_payment_hash.entry(invoice.0.payment_hash()).or_default().push(vtxo);
		}

		for (_, vtxos) in htlc_vtxos_by_payment_hash {
			self.check_lightning_payment(&vtxos).await?;
		}

		Ok(())
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
		destination_policy: VtxoPolicy,
		amount: Amount,
	) -> anyhow::Result<ArkoorCreateResult> {
		let mut srv = self.require_server()?;
		let change_pubkey = self.derive_store_next_keypair()?.0.public_key();

		let req = VtxoRequest {
			amount: amount,
			policy: destination_policy,
		};

		let inputs = self.select_vtxos_to_cover(
			req.amount + P2TR_DUST, Some(srv.info.max_arkoor_depth),
		)?;

		let mut secs = Vec::with_capacity(inputs.len());
		let mut pubs = Vec::with_capacity(inputs.len());
		let mut keypairs = Vec::with_capacity(inputs.len());
		for input in inputs.iter() {
			let keypair = {
				let keypair_idx = self.db.get_vtxo_key(&input)?;
				self.vtxo_seed.derive_keypair(keypair_idx)
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
		let cosign_resp: Vec<_> = srv.client.request_arkoor_package_cosign(req).await?
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

	/// Validate if we can send arkoor payments to the given address
	pub fn validate_arkoor_address(&self, address: &ark::Address) -> anyhow::Result<()> {
		let asp = self.require_server()?;

		if !address.ark_id().is_for_server(asp.info.server_pubkey) {
			bail!("Ark address is for different server");
		}

		// Not all policies are supported for sending arkoor
		match address.policy().policy_type() {
			VtxoPolicyType::Pubkey => {},
			VtxoPolicyType::ServerHtlcRecv | VtxoPolicyType::ServerHtlcSend => {
				bail!("VTXO policy in address cannot be used for arkoor payment: {}",
					address.policy().policy_type(),
				);
			}
		}

		if address.delivery().is_empty() {
			bail!("No VTXO delivery mechanism provided in address");
		}
		// We first see if we know any of the deliveries, if not, we will log
		// the unknown onces.
		// We do this in two parts because we shouldn't log unknown ones if there is one known.
		if !address.delivery().iter().any(|d| !d.is_unknown()) {
			for d in address.delivery() {
				if let VtxoDelivery::Unknown { delivery_type, data } = d {
					info!("Unknown delivery in address: type={:#x}, data={}",
						delivery_type, data.as_hex(),
					);
				}
			}
		}

		Ok(())
	}

	pub async fn send_arkoor_payment(
		&mut self,
		destination: &ark::Address,
		amount: Amount,
	) -> anyhow::Result<Vec<Vtxo>> {
		let mut srv = self.require_server()?;

		self.validate_arkoor_address(&destination).context("cannot send to address")?;

		if amount < P2TR_DUST {
			bail!("Sent amount must be at least {}", P2TR_DUST);
		}

		let arkoor = self.create_arkoor_vtxos(destination.policy().clone(), amount).await?;

		let req = protos::ArkoorPackage {
			arkoors: arkoor.created.iter().map(|v| protos::ArkoorVtxo {
				pubkey: destination.policy().user_pubkey().serialize().to_vec(),
				vtxo: v.serialize().to_vec(),
			}).collect(),
		};

		if let Err(e) = srv.client.post_arkoor_package_mailbox(req).await {
			error!("Failed to post the arkoor vtxo to the recipients mailbox: '{}'", e);
			//NB we will continue to at least not lose our own change
		}

		self.db.register_movement(MovementArgs {
			kind: MovementKind::ArkoorSend,
			spends: &arkoor.input.iter().collect::<Vec<_>>(),
			receives: &arkoor.change.as_ref().map(|v| vec![(v, VtxoState::Spendable)]).unwrap_or(vec![]),
			recipients: &[(&destination.to_string(), amount)],
			fees: None,
		}).context("failed to store arkoor vtxo")?;

		Ok(arkoor.created)
	}

	async fn process_lightning_revocation(&self, htlc_vtxos: &[Vtxo]) -> anyhow::Result<()> {
		let mut srv = self.require_server()?;

		info!("Processing {} HTLC VTXOs for revocation", htlc_vtxos.len());

		let mut secs = Vec::with_capacity(htlc_vtxos.len());
		let mut pubs = Vec::with_capacity(htlc_vtxos.len());
		let mut keypairs = Vec::with_capacity(htlc_vtxos.len());
		for input in htlc_vtxos.into_iter() {
			let keypair = {
				let keypair_idx = self.db.get_vtxo_key(&input)?;
				self.vtxo_seed.derive_keypair(keypair_idx)
			};

			let (s, p) = musig::nonce_pair(&keypair);
			secs.push(s);
			pubs.push(p);
			keypairs.push(keypair);
		}

		let revocation = ArkoorPackageBuilder::new_htlc_revocation(&htlc_vtxos, &pubs)?;

		let req = protos::RevokeLightningPaymentRequest {
			htlc_vtxo_ids: revocation.arkoors.iter()
				.map(|i| i.input.id().to_bytes().to_vec())
				.collect(),
			user_nonces: revocation.arkoors.iter()
				.map(|i| i.user_nonce.serialize().to_vec())
				.collect(),
		};
		let cosign_resp: Vec<_> = srv.client.revoke_lightning_payment(req).await?
			.into_inner().try_into().context("invalid server cosign response")?;
		ensure!(revocation.verify_cosign_response(&cosign_resp),
			"invalid arkoor cosignature received from server",
		);

		let (vtxos, _) = revocation.build_vtxos(&cosign_resp, &keypairs, secs)?;
		for vtxo in &vtxos {
			info!("Got revocation VTXO: {}: {}", vtxo.id(), vtxo.amount());
		}

		self.db.register_movement(MovementArgs {
			kind: MovementKind::LightningSendRevocation,
			spends: &htlc_vtxos.iter().collect::<Vec<_>>(),
			receives: &vtxos.iter().map(|v| (v, VtxoState::Spendable)).collect::<Vec<_>>(),
			recipients: &[],
			fees: None,
		})?;

		info!("Revoked {} HTLC VTXOs", vtxos.len());

		Ok(())
	}

	pub async fn send_lightning_payment(
		&mut self,
		invoice: Invoice,
		user_amount: Option<Amount>,
	) -> anyhow::Result<Preimage> {
		let properties = self.db.read_properties()?.context("Missing config")?;
		let current_height = self.chain.tip().await?;

		if invoice.network() != properties.network {
			bail!("Invoice is for wrong network: {}", invoice.network());
		}

		if self.db.check_recipient_exists(&invoice.to_string())? {
			bail!("Invoice has already been paid");
		}

		invoice.check_signature()?;

		let mut srv = self.require_server()?;

		let inv_amount = invoice.amount_milli_satoshis().map(|v| Amount::from_msat_ceil(v));
		if let (Some(_), Some(inv)) = (user_amount, inv_amount) {
			bail!("Invoice has amount of {} encoded. Please omit user amount argument", inv);
		}

		let amount = user_amount.or(inv_amount)
			.context("amount required on invoice without amount")?;
		if amount < P2TR_DUST {
			bail!("Sent amount must be at least {}", P2TR_DUST);
		}

		let (change_keypair, _) = self.derive_store_next_keypair()?;

		let htlc_expiry = current_height + srv.info.htlc_expiry_delta as u32;
		let pay_req = VtxoRequest {
			amount,
			policy: VtxoPolicy::ServerHtlcSend(ServerHtlcSendVtxoPolicy {
				user_pubkey: change_keypair.public_key(),
				payment_hash: invoice.payment_hash(),
				htlc_expiry,
			}),
		};

		let inputs = self.select_vtxos_to_cover(
			pay_req.amount + P2TR_DUST,
			Some(srv.info.max_arkoor_depth),
		)?;

		let mut secs = Vec::with_capacity(inputs.len());
		let mut pubs = Vec::with_capacity(inputs.len());
		let mut keypairs = Vec::with_capacity(inputs.len());
		for input in inputs.iter() {
			let keypair = {
				let keypair_idx = self.db.get_vtxo_key(&input)?;
				self.vtxo_seed.derive_keypair(keypair_idx)
			};

			let (s, p) = musig::nonce_pair(&keypair);
			secs.push(s);
			pubs.push(p);
			keypairs.push(keypair);
		}

		let builder = ArkoorPackageBuilder::new(
			&inputs, &pubs, pay_req, Some(change_keypair.public_key()),
		)?;

		let req = protos::LightningPaymentRequest {
			invoice: invoice.to_string(),
			user_amount_sat: user_amount.map(|a| a.to_sat()),
			input_vtxo_ids: inputs.iter().map(|v| v.id().to_bytes().to_vec()).collect(),
			user_nonces: pubs.iter().map(|p| p.serialize().to_vec()).collect(),
			user_pubkey: change_keypair.public_key().serialize().to_vec(),
		};

		let cosign_resp: Vec<_> = srv.client.start_lightning_payment(req).await
			.context("htlc request failed")?.into_inner()
			.try_into().context("invalid arkoor cosign response from server")?;

		ensure!(builder.verify_cosign_response(&cosign_resp),
			"invalid arkoor cosignature received from server",
		);

		let (htlc_vtxos, change_vtxo) = builder.build_vtxos(&cosign_resp, &keypairs, secs)?;

		// Validate the new vtxos. They have the same chain anchor.
		for (vtxo, input) in htlc_vtxos.iter().zip(inputs.iter()) {
			if let Ok(tx) = self.chain.get_tx(&input.chain_anchor().txid).await {
				let tx = tx.with_context(|| {
					format!("input vtxo chain anchor not found: {}", input.chain_anchor().txid)
				})?;
				vtxo.validate(&tx).context("invalid lightning htlc vtxo")?;
			} else {
				warn!("We couldn't validate the new VTXOs because of chain source error.");
			}
		}

		// Validate the change vtxo. It has the same chain anchor as the last input.
		if let Some(ref change) = change_vtxo {
			let last_input = inputs.last().context("no inputs provided")?;
			let tx = self.chain.get_tx(&last_input.chain_anchor().txid).await?;
			let tx = tx.with_context(|| {
				format!("input vtxo chain anchor not found: {}", last_input.chain_anchor().txid)
			})?;
			change.validate(&tx).context("invalid lightning change vtxo")?;
		}

		let pending_lightning_state = VtxoState::PendingLightningSend {
			invoice: invoice.clone(),
			amount: amount,
		};

		self.db.register_movement(MovementArgs {
			kind: MovementKind::LightningSend,
			spends: &inputs.iter().collect::<Vec<_>>(),
			receives: &htlc_vtxos.iter()
				.map(|v| (v, pending_lightning_state.clone()))
				.chain(change_vtxo.as_ref().map(|c| (c, VtxoState::Spendable)))
				.collect::<Vec<_>>(),
			recipients: &[],
			fees: None,
		}).context("failed to store OOR vtxo")?;

		let req = protos::SignedLightningPaymentDetails {
			invoice: invoice.to_string(),
			htlc_vtxo_ids: htlc_vtxos.iter().map(|v| v.id().to_bytes().to_vec()).collect(),
			wait: true,
		};

		let res = srv.client.finish_lightning_payment(req).await?.into_inner();
		debug!("Progress update: {}", res.progress_message);
		let payment_preimage = Preimage::try_from(res.payment_preimage()).ok();

		if let Some(preimage) = payment_preimage {
			info!("Payment succeeded! Preimage: {}", preimage.as_hex());
			self.db.register_movement(MovementArgs {
				kind: MovementKind::LightningSend,
				spends: &htlc_vtxos.iter().collect::<Vec<_>>(),
				receives: &[],
				recipients: &[(&invoice.to_string(), amount)],
				fees: None,
			}).context("failed to store OOR vtxo")?;
			Ok(preimage)
		} else {
			self.process_lightning_revocation(&htlc_vtxos).await?;
			bail!("No preimage, payment failed: {}", res.progress_message);
		}
	}

	pub async fn check_lightning_payment(&mut self, htlc_vtxos: &[WalletVtxo]) -> anyhow::Result<Option<Preimage>> {
		let mut srv = self.require_server()?;
		let tip = self.chain.tip().await?;

		// we check that all htlc have the same invoice, amount, and HTLC out spec
		let mut parts = None;
		for vtxo in htlc_vtxos.iter() {
			if let VtxoState::PendingLightningSend { ref invoice, amount } = vtxo.state {
				let policy = vtxo.vtxo.policy().as_server_htlc_send()
					.context("VTXO is not an HTLC send")?;
				let this_parts = (invoice, amount, policy);
				if parts.get_or_insert_with(|| this_parts) != &this_parts {
					bail!("All lightning htlc should have the same invoice, amount, and policy");
				}
			}
		}

		let (invoice, amount, spk_spec) = parts.context("no htlc vtxo provided")?;
		let payment_hash = ark::lightning::PaymentHash::from(invoice.payment_hash());
		let req = protos::CheckLightningPaymentRequest {
			hash: payment_hash.to_vec(),
			wait: false,
		};
		let res = srv.client.check_lightning_payment(req).await?.into_inner();

		let payment_status = protos::PaymentStatus::try_from(res.status)?;

		let should_revoke = match payment_status {
			protos::PaymentStatus::Failed => {
				info!("Payment failed ({}): revoking VTXO", res.progress_message);
				true
			},
			protos::PaymentStatus::Pending => {
				trace!("Payment is still pending, HTLC expiry: {}, tip: {}", spk_spec.htlc_expiry, tip);
				if tip > spk_spec.htlc_expiry {
					info!("Payment is still pending, but HTLC is expired: revoking VTXO");
					true
				} else {
					info!("Payment is still pending and HTLC is not expired ({}): doing nothing for now", spk_spec.htlc_expiry);
					false
				}
			},
			protos::PaymentStatus::Complete => {
				let preimage: Preimage = res.payment_preimage.context("payment completed but no preimage")?
					.try_into().map_err(|_| anyhow!("preimage is not 32 bytes"))?;
				info!("Payment is complete, preimage, {}", preimage.as_hex());

				self.db.register_movement(MovementArgs {
					kind: MovementKind::LightningSend,
					spends: &htlc_vtxos.iter().map(|v| &v.vtxo).collect::<Vec<_>>(),
					receives: &[],
					recipients: &[(&invoice.to_string(), amount)],
					fees: None,
				}).context("failed to store OOR vtxo")?;

				return Ok(Some(preimage));
			},
		};

		if should_revoke {
			if let Err(e) = self.process_lightning_revocation(&htlc_vtxos.iter().map(|v| v.vtxo.clone()).collect::<Vec<_>>()).await {
				warn!("Failed to revoke VTXO: {}", e);

				// if one of the htlc is about to expire, we exit all of them.
				// Maybe we want a different behavior here, but we have to decide whether
				// htlc vtxos revocation is a all or nothing process.
				let min_expiry = htlc_vtxos.iter()
					.map(|v| v.vtxo.spec().expiry_height).min().unwrap();
				if tip > min_expiry.saturating_sub(self.config().vtxo_refresh_expiry_threshold) {
					warn!("Some VTXO is about to expire soon, marking to exit");
					self.exit.mark_vtxos_for_exit(&htlc_vtxos.iter().map(|v| v.vtxo.clone()).collect::<Vec<_>>())?;
				}
			}
		}

		Ok(None)
	}

	/// Create, store and return a bolt11 invoice for offchain boarding
	pub async fn bolt11_invoice(&mut self, amount: Amount) -> anyhow::Result<Bolt11Invoice> {
		let mut srv = self.require_server()?;

		let preimage = Preimage::random();
		let payment_hash = ark::lightning::PaymentHash::from_preimage(preimage);
		info!("Start bolt11 board with preimage / payment hash: {} / {}",
			preimage.as_hex(), payment_hash.as_hex());

		let req = protos::StartLightningReceiveRequest {
			payment_hash: payment_hash.to_vec(),
			amount_sat: amount.to_sat(),
		};

		let resp = srv.client.start_lightning_receive(req).await?.into_inner();
		info!("Ark Server is ready to receive LN payment to invoice: {}.", resp.bolt11);

		let invoice = Bolt11Invoice::from_str(&resp.bolt11)
			.context("invalid bolt11 invoice returned by Ark server")?;

		self.db.store_lightning_receive(payment_hash, preimage, &invoice)?;

		Ok(invoice)
	}

	pub fn lightning_receive_status(
		&self,
		payment: impl Into<PaymentHash>,
	) -> anyhow::Result<Option<LightningReceive>> {
		Ok(self.db.fetch_lightning_receive_by_payment_hash(payment.into())?)
	}

	pub fn lightning_receives(&self, pagination: Pagination) -> anyhow::Result<Vec<LightningReceive>> {
		Ok(self.db.get_paginated_lightning_receives(pagination)?)
	}

	async fn claim_htlc_vtxo(&self, vtxo: &WalletVtxo) -> anyhow::Result<()> {
		let mut srv = self.require_server()?;

		let payment_hash = vtxo.state.as_pending_lightning_recv().context("vtxo is not pending lightning recv")?;

		let lightning_receive = self.db.fetch_lightning_receive_by_payment_hash(payment_hash)?
			.context("no lightning receive found")?;

		let keypair_index = self.db.get_vtxo_key(&vtxo.vtxo)?;
		let keypair = self.peak_keypair(keypair_index)?;
		let (sec_nonce, pub_nonce) = musig::nonce_pair(&keypair);

		// Claiming arkoor against preimage
		let pay_req = VtxoRequest {
			policy: VtxoPolicy::new_pubkey(keypair.public_key()),
			amount: vtxo.vtxo.amount(),
		};

		let inputs = [vtxo.vtxo.clone()];
		let pubs = [pub_nonce];
		let builder = ArkoorPackageBuilder::new(&inputs, &pubs, pay_req, None)?;

		let req = protos::ClaimLightningReceiveRequest {
			arkoor: Some(builder.arkoors.first().unwrap().into()),
			payment_preimage: lightning_receive.payment_preimage.to_vec(),
		};

		info!("Claiming arkoor against payment preimage");
		self.db.set_preimage_revealed(lightning_receive.payment_hash)?;
		let cosign_resp = srv.client.claim_lightning_receive(req).await?
			.into_inner().try_into().context("invalid server cosign response")?;

		ensure!(builder.verify_cosign_response(&[&cosign_resp]),
			"invalid arkoor cosignature received from server",
		);

		let (outputs, _) = builder.build_vtxos(
			&[cosign_resp],
			&[keypair],
			vec![sec_nonce],
		)?;
		let [output_vtxo] = outputs.try_into().expect("had exactly one request");

		info!("Got an arkoor from lightning! {}", output_vtxo.id());
		self.db.register_movement(MovementArgs {
			kind: MovementKind::LightningReceive,
			spends: &[&vtxo.vtxo],
			receives: &[(&output_vtxo, VtxoState::Spendable)],
			recipients: &[],
			fees: None,
		})?;

		Ok(())
	}


	pub async fn finish_lightning_receive(&mut self, invoice: &Bolt11Invoice) -> anyhow::Result<()> {
		let tip = self.chain.tip().await?;
		let mut srv = self.require_server()?;

		let payment_hash = ark::lightning::PaymentHash::from(invoice);

		let (keypair, _) = self.derive_store_next_keypair()?;

		let amount = Amount::from_msat_floor(
			invoice.amount_milli_satoshis().context("invoice must have amount specified")?
		);

		let req = protos::SubscribeLightningReceiveRequest {
			bolt11: invoice.to_string(),
		};

		info!("Waiting payment...");
		srv.client.subscribe_lightning_receive(req).await?.into_inner();
		info!("Lightning payment arrived!");

		// In order to onboard we need to show an input.
		// (this is so that it can be slashed if we bail on the round)
		// We create an output with the same value.
		let (antidos_input, antidos_output) = {
			let inputs = self.select_vtxos_to_cover(Amount::ONE_SAT, None)?;
			if inputs.is_empty() {
				bail!("Need to have existing VTXOs in order to receive lightning");
			}
			assert_eq!(inputs.len(), 1);
			let [input] = inputs.try_into().unwrap();
			let change_pubkey = self.derive_store_next_keypair()?.0.public_key();
			let output = VtxoRequest {
				amount: input.amount(),
				policy: VtxoPolicy::new_pubkey(change_pubkey),
			};
			(input, output)
		};

		let state = VtxoState::PendingLightningRecv { payment_hash };

		let expiry_height = tip + srv.info.htlc_expiry_delta as BlockHeight;
		self.participate_round(move |_| {
			let htlc_pay_req = VtxoRequest {
				amount: amount,
				policy: VtxoPolicy::new_server_htlc_recv(keypair.public_key(), payment_hash, expiry_height),
			};

			Ok(RoundParticipation {
				inputs: vec![antidos_input.clone()],
				outputs: vec![
					StoredVtxoRequest::from_parts(htlc_pay_req, state.clone()),
					StoredVtxoRequest::from_parts(antidos_output.clone(), VtxoState::Spendable),
				],
				offboards: vec![],
			})
		}).await.context("round failed")?;

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
	) -> anyhow::Result<(Bolt11Invoice, Preimage)> {
		let invoice = lnurl::lnaddr_invoice(addr, amount, comment).await
			.context("lightning address error")?;
		info!("Attempting to pay invoice {}", invoice);
		let preimage = self.send_lightning_payment(Invoice::Bolt11(invoice.clone()), None).await
			.context("bolt11 payment error")?;
		Ok((invoice, preimage))
	}

	pub async fn pay_offer(
		&mut self,
		offer: Offer,
		amount: Option<Amount>,
	) -> anyhow::Result<(Bolt12Invoice, Preimage)> {
		let mut srv = self.require_server()?;

		let offer_bytes = {
			let mut bytes = Vec::new();
			offer.write(&mut bytes).unwrap();
			bytes
		};

		let req = protos::FetchBolt12InvoiceRequest {
			offer: offer_bytes,
			amount_sat: amount.map(|a| a.to_sat()),
		};

		let resp = srv.client.fetch_bolt12_invoice(req).await?.into_inner();

		let invoice = Bolt12Invoice::try_from(resp.invoice)
			.map_err(|_| anyhow::anyhow!("invalid invoice"))?;

		invoice.validate_issuance(offer)?;

		let preimage = self.send_lightning_payment(Invoice::Bolt12(invoice.clone()), None).await
			.context("bolt11 payment error")?;
		Ok((invoice, preimage))
	}

	/// Send to an onchain address in an Ark round.
	///
	/// It is advised to sync your wallet before calling this method.
	pub async fn send_round_onchain_payment(
		&mut self,
		addr: bitcoin::Address,
		amount: Amount,
	) -> anyhow::Result<SendOnchain> {
		let balance = self.balance()?.spendable;

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
					let (change_keypair, _) = self.derive_store_next_keypair()?;
					info!("Adding change vtxo for {}", amount);
					Some(VtxoRequest {
						amount: amount,
						policy: VtxoPolicy::new_pubkey(change_keypair.public_key()),
					})
				}
			};

			Ok(RoundParticipation {
				inputs: input_vtxos.clone(),
				outputs: change.into_iter()
					.map(|c| StoredVtxoRequest::from_parts(c, VtxoState::Spendable)).collect(),
				offboards: vec![offb],
			})
		}).await.context("round failed")?;

		Ok(SendOnchain { round: round_id })
	}

	async fn new_round_attempt<S: Stream<Item = anyhow::Result<RoundEvent>> + Unpin>(
		&self,
		events: &mut S,
		challenge: VtxoOwnershipChallenge,
		round_state: AttemptStartedState,
		participation: &RoundParticipation,
	) -> Result<AttemptResult, AttemptError> {
		debug!("New round attempt. round seq: {}, attempt seq: {}, challenge: {}",
			round_state.round_seq, round_state.attempt_seq, challenge.inner().as_hex());

		let mut srv = match self.require_server() {
			Ok(srv) => srv,
			Err(e) => {
				error!("Cannot get Server connection: {}", e);
				return Err(error_before_forfeit(&self.db, round_state));
			}
		};

		let mut round_state = RoundState::from(round_state);
		// We don't have an event at first because this function is already triggered by the attempt start one
		let mut event = None;

		loop {
			let progress_res =
				round_state.progress(
					event,
					&mut srv,
					&self,
					challenge,
					participation,
				).await.expect("tried to progress a round state that cannot progress")?;

			round_state = match progress_res {
				ProgressResult::Progress { state} => {
					if let RoundState::PendingConfirmation(state) = state {
						return Ok(AttemptResult::Success(RoundResult {
							round_id: state.round_txid,
						}));
					}

					event = Some(events.next().await.context("event stream broke")
						.map_err(|e| AttemptError::StreamError(e))?
						.map_err(|e| AttemptError::StreamError(e))?);

					state
				}
				ProgressResult::Wait(state) => {
					event = Some(events.next().await.context("event stream broke")
						.map_err(|e| AttemptError::StreamError(e))?
						.map_err(|e| AttemptError::StreamError(e))?);

					tokio::time::sleep(Duration::from_secs(1)).await;

					state
				}
				ProgressResult::WaitNewRound => {
					return Ok(AttemptResult::WaitNewRound)
				}
				ProgressResult::NewRoundStarted(round_info) => {
					return Ok(AttemptResult::NewRoundStarted(round_info));
				}
				ProgressResult::NewAttemptStarted((round_state, challenge)) => {
					return Ok(AttemptResult::NewAttemptStarted((round_state, challenge)));
				}
			};
		}
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
		mut round_input: impl FnMut(&RoundInfo) -> anyhow::Result<RoundParticipation>,
	) -> anyhow::Result<RoundResult> {
		let mut srv = self.require_server()?;

		info!("Waiting for a round start...");
		let mut events = srv.client.subscribe_rounds(protos::Empty {}).await?.into_inner()
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
		// - when the server misbehaves, we set it to None and restart
		let mut next_round_info = None;

		'round: loop {
			// If we don't have a round info yet, wait for round start.
			let round_info = if let Some(info) = next_round_info.take() {
				warn!("Unexpected new round started...");
				info
			} else {
				debug!("Waiting for a new round to start...");
				loop {
					match events.next().await.context("events stream broke")?? {
						RoundEvent::Start(info) => {
							break info;
						},
						_ => trace!("ignoring irrelevant message"),
					}
				}
			};

			info!("Round started");
			debug!("Started round #{}", round_info.round_seq);

			let participation = round_input(&round_info)
				.context("error providing round input")?;

			if let Some(payreq) = participation.outputs.iter().find(|p| p.amount < P2TR_DUST) {
				bail!("VTXO amount must be at least {}, requested {}", P2TR_DUST, payreq.amount);
			}

			if let Some(offb) = participation.offboards.iter().find(|o| o.amount < P2TR_DUST) {
				bail!("Offboard amount must be at least {}, requested {}", P2TR_DUST, offb.amount);
			}

			// then we expect the first attempt message
			let (mut updated, mut challenge)= match events.next().await.context("events stream broke")?? {
				RoundEvent::Attempt(attempt) if attempt.round_seq == round_info.round_seq => {
					let round_state = self.db.store_new_round_attempt(
						round_info.round_seq, attempt.attempt_seq, participation.clone()
					)?;
					(round_state, attempt.challenge)
				},
				RoundEvent::Start(e) => {
					next_round_info = Some(e);
					continue 'round;
				},
				//TODO(stevenroose) make this robust
				other => panic!("Unexpected message: {:?}", other),
			};

			debug!("Submitting payment request with {} inputs, {} vtxo outputs and {} offboard outputs",
				participation.inputs.len(), participation.outputs.len(), participation.outputs.len(),
			);

			'attempt: loop {
				let attempt_res = self.new_round_attempt(
					&mut events,
					challenge,
					updated,
					&participation,
				).await?;

				match attempt_res {
					AttemptResult::NewRoundStarted(new_round_info) => {
						next_round_info = Some(new_round_info);
						continue 'round;
					},
					AttemptResult::NewAttemptStarted((state, new_challenge)) => {
						updated = state;
						challenge = new_challenge;
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

#[macro_use] extern crate anyhow;
#[macro_use] extern crate async_trait;
#[macro_use] extern crate serde;
#[macro_use] extern crate aspd_log;

#[macro_use]
mod error;

mod cln;
pub(crate) mod flux;
pub mod database;
pub mod forfeits;
mod psbtext;
mod serde_util;
pub mod sweeps;
mod rpcserver;
mod round;
pub(crate) mod system;
mod txindex;
mod telemetry;
pub mod wallet;
pub mod config;
pub use crate::config::Config;

use std::borrow::Borrow;
use std::collections::{HashSet, HashMap};
use std::fs;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use ark::vtxo::ServerHtlcRecvVtxoPolicy;
use bdk_bitcoind_rpc::bitcoincore_rpc::RpcApi;
use bitcoin::{bip32, Address, Amount, OutPoint, Transaction};
use bitcoin::secp256k1::{self, Keypair, PublicKey};
use lightning_invoice::Bolt11Invoice;
use log::{info, trace, warn, error};
use tokio::sync::{broadcast, mpsc, oneshot, Mutex};

use ark::{Vtxo, VtxoId, VtxoPolicy, VtxoRequest};
use ark::arkoor::{ArkoorBuilder, ArkoorCosignResponse, ArkoorPackageBuilder};
use ark::board::BoardBuilder;
use ark::lightning::{PaymentHash, Preimage};
use ark::musig::{self, PublicNonce};
use ark::rounds::RoundEvent;
use aspd_rpc::protos;
use bitcoin_ext::{AmountExt, BlockHeight, BlockRef, TransactionExt, P2TR_DUST};
use bitcoin_ext::rpc::{BitcoinRpcClient, BitcoinRpcErrorExt, BitcoinRpcExt};

use crate::cln::ClnManager;
use crate::database::model::{LightningHtlcSubscriptionStatus, LightningPaymentStatus};
use crate::error::ContextExt;
use crate::flux::VtxosInFlux;
use crate::forfeits::ForfeitWatcher;
use crate::round::RoundInput;
use crate::system::RuntimeManager;
use crate::telemetry::init_telemetry;
use crate::txindex::TxIndex;
use crate::txindex::broadcast::{TxNursery, TxBroadcastHandle};
use crate::sweeps::VtxoSweeper;
use crate::wallet::{PersistedWallet, WalletKind, MNEMONIC_FILE};

lazy_static::lazy_static! {
	/// Global secp context.
	static ref SECP: secp256k1::Secp256k1<secp256k1::All> = secp256k1::Secp256k1::new();
}

/// The HD keypath to use for the ASP key.
const ASP_KEY_PATH: &str = "m/2'/0'";


pub struct RoundHandle {
	round_event_tx: broadcast::Sender<RoundEvent>,
	round_input_tx: mpsc::UnboundedSender<(RoundInput, oneshot::Sender<anyhow::Error>)>,
	round_trigger_tx: mpsc::Sender<()>,
}

pub struct Server {
	config: Config,
	db: database::Db,
	asp_key: Keypair,
	// NB this needs to be an Arc so we can take a static guard
	rounds_wallet: Arc<Mutex<PersistedWallet>>,
	bitcoind: BitcoinRpcClient,
	chain_tip: Mutex<BlockRef>,

	rtmgr: RuntimeManager,
	tx_broadcast_handle: TxBroadcastHandle,
	vtxo_sweeper: VtxoSweeper,
	rounds: RoundHandle,
	forfeits: ForfeitWatcher,
	/// All vtxos that are currently being processed in any way.
	/// (Plus a small buffer to optimize allocations.)
	vtxos_in_flux: VtxosInFlux,
	cln: ClnManager,
}

impl Server {
	pub async fn create(cfg: Config) -> anyhow::Result<()> {
		if cfg.legacy_wallet {
			bail!("We don't support creating new legacy wallets.");
		}

		// Check for mnemonic file to see if aspd was already initialized.
		if cfg.data_dir.join(MNEMONIC_FILE).exists() {
			bail!("Found existing mnemonic file in datadir, aspd probably already initialized!");
		}

		let bitcoind = BitcoinRpcClient::new(&cfg.bitcoind.url, cfg.bitcoind_auth())
			.context("failed to create bitcoind rpc client")?;
		// Check if our bitcoind is on the expected network.
		let chain_info = bitcoind.get_blockchain_info()?;
		if chain_info.chain != cfg.network {
			bail!("Our bitcoind is running on network {} while we are configured for network {}",
				chain_info.chain, cfg.network,
			);
		}
		let deep_tip = bitcoind.deep_tip()
			.context("failed to fetch deep tip from bitcoind")?;

		info!("Creating aspd server at {}", cfg.data_dir.display());

		// create dir if not exit, but check that it's empty
		fs::create_dir_all(&cfg.data_dir).context("can't create dir")?;

		let db = database::Db::create(&cfg.postgres).await?;

		// Initiate key material.
		let seed = {
			let mnemonic = bip39::Mnemonic::generate(12).expect("12 is valid");

			fs::write(cfg.data_dir.join(MNEMONIC_FILE), mnemonic.to_string().as_bytes())
				.context("failed to store mnemonic")?;

			mnemonic.to_seed("")
		};
		let seed_xpriv = bip32::Xpriv::new_master(cfg.network, &seed).unwrap();

		// Store initial wallet states to avoid full chain sync.
		for wallet in [WalletKind::Rounds, WalletKind::Forfeits] {
			let wallet_xpriv = seed_xpriv.derive_priv(&*SECP, &[wallet.child_number()])
				.expect("can't error");
			let _wallet = PersistedWallet::load_from_xpriv(
				db.clone(), cfg.network, &wallet_xpriv, wallet, deep_tip, false,
			);
		}

		Ok(())
	}

	pub async fn open_round_wallet(
		cfg: &Config,
		db: database::Db,
		master_xpriv: &bip32::Xpriv,
		deep_tip: BlockRef,
	) -> anyhow::Result<PersistedWallet> {
		let wallet_xpriv = if cfg.legacy_wallet {
			master_xpriv.clone()
		} else {
			master_xpriv.derive_priv(&*SECP, &[WalletKind::Rounds.child_number()])
				.expect("can't error")
		};
		Ok(PersistedWallet::load_from_xpriv(
			db, cfg.network, &wallet_xpriv, WalletKind::Rounds, deep_tip, cfg.legacy_wallet,
		).await?)
	}

	/// Start the server.
	pub async fn start(cfg: Config) -> anyhow::Result<Arc<Self>> {
		info!("Starting aspd at {}", cfg.data_dir.display());

		info!("Connecting to db at {}:{}", cfg.postgres.host, cfg.postgres.port);
		let db = database::Db::connect(&cfg.postgres)
			.await
			.context("failed to connect to db")?;

		let bitcoind = BitcoinRpcClient::new(&cfg.bitcoind.url, cfg.bitcoind_auth())
			.context("failed to create bitcoind rpc client")?;
		// Check if our bitcoind is on the expected network.
		let chain_info = bitcoind.get_blockchain_info()?;
		if chain_info.chain != cfg.network {
			bail!("Our bitcoind is running on network {} while we are configured for network {}",
				chain_info.chain, cfg.network,
			);
		}

		let seed = wallet::read_mnemonic_from_datadir(&cfg.data_dir)?.to_seed("");
		let master_xpriv = bip32::Xpriv::new_master(cfg.network, &seed).unwrap();

		let deep_tip = bitcoind.deep_tip().context("failed to query node for deep tip")?;
		let mut rounds_wallet = Self::open_round_wallet(&cfg, db.clone(), &master_xpriv, deep_tip)
			.await.context("error loading wallet")?;

		let asp_path = bip32::DerivationPath::from_str(ASP_KEY_PATH).unwrap();
		let asp_xpriv = master_xpriv.derive_priv(&SECP, &asp_path).unwrap();
		let asp_key = Keypair::from_secret_key(&SECP, &asp_xpriv.private_key);

		init_telemetry(&cfg, asp_key.public_key());
		// *******************
		// * START PROCESSES *
		// *******************

		let rtmgr = RuntimeManager::new();
		let _startup_worker = rtmgr.spawn("Bootstrapping");
		rtmgr.run_shutdown_signal_listener(Duration::from_secs(60));

		let txindex = TxIndex::start(
			deep_tip,
			rtmgr.clone(),
			bitcoind.clone(),
			cfg.txindex_check_interval,
		);

		let tx_nursery = TxNursery::new(
			rtmgr.clone(),
			txindex.clone(),
			bitcoind.clone(),
			cfg.transaction_rebroadcast_interval,
		);

		let vtxo_sweeper = VtxoSweeper::start(
			rtmgr.clone(),
			cfg.vtxo_sweeper.clone(),
			cfg.network,
			bitcoind.clone(),
			db.clone(),
			txindex.clone(),
			tx_nursery.broadcast_handle(),
			asp_key.clone(),
			rounds_wallet.reveal_next_address(
				bdk_wallet::KeychainKind::External,
			).address,
		).await.context("failed to start VtxoSweeper")?;

		let forfeits = ForfeitWatcher::start(
			rtmgr.clone(),
			cfg.forfeit_watcher.clone(),
			cfg.network,
			bitcoind.clone(),
			db.clone(),
			txindex.clone(),
			tx_nursery.broadcast_handle(),
			master_xpriv.derive_priv(&*SECP, &[WalletKind::Forfeits.child_number()])
				.expect("can't error"),
			asp_key.clone(),
		).await.context("failed to start VtxoSweeper")?;

		let cln = ClnManager::start(
			rtmgr.clone(),
			&cfg,
			db.clone(),
		).await.context("failed to start ClnManager")?;

		let (round_event_tx, _rx) = broadcast::channel(8);
		let (round_input_tx, round_input_rx) = tokio::sync::mpsc::unbounded_channel();
		let (round_trigger_tx, round_trigger_rx) = tokio::sync::mpsc::channel(1);

		let srv = Server {
			rounds_wallet: Arc::new(Mutex::new(rounds_wallet)),
			chain_tip: Mutex::new(bitcoind.tip().context("failed to fetch tip")?),
			rounds: RoundHandle { round_event_tx, round_input_tx, round_trigger_tx },
			vtxos_in_flux: VtxosInFlux::new(),
			config: cfg.clone(),
			db,
			asp_key,
			bitcoind,
			rtmgr,
			tx_broadcast_handle: tx_nursery.broadcast_handle(),
			vtxo_sweeper,
			forfeits,
			cln,
		};

		let srv = Arc::new(srv);

		tokio::spawn(run_tip_fetcher(srv.clone()));

		let srv2 = srv.clone();
		tokio::spawn(async move {
			let res = round::run_round_coordinator(&srv2, round_input_rx, round_trigger_rx)
				.await.context("error from round scheduler");
			info!("Round coordinator exited with {:?}", res);
		});

		// RPC

		let srv2 = srv.clone();
		tokio::spawn(async move {
			let res = rpcserver::run_public_rpc_server(srv2)
				.await.context("error running public gRPC server");
			info!("RPC server exited with {:?}", res);
		});

		if cfg.rpc.admin_address.is_some() {
			let srv2 = srv.clone();
			tokio::spawn(async move {
				let res = rpcserver::run_admin_rpc_server(srv2)
					.await.context("error running admin gRPC server");
				info!("Admin RPC server exited with {:?}", res);
			});
		}

		// Broadcast manager
		tokio::spawn(async move {
			let res = tx_nursery.run()
				.await.context("Error from TransactionBroadcastManager");
			info!("TransactionBroadcastManager exited with {:?}", res);
		});

		Ok(srv)
	}

	/// Waits for aspd to terminate.
	pub async fn wait(&self) {
		self.rtmgr.wait().await;
		slog!(AspdTerminated);
	}

	/// Starts the server and waits until it terminates.
	///
	/// This is equivalent to calling [Server::start] and [Server::wait] in one go.
	pub async fn run(cfg: Config) -> anyhow::Result<()> {
		let srv = Server::start(cfg).await?;
		srv.wait().await;
		Ok(())
	}

	pub async fn chain_tip(&self) -> BlockRef {
		self.chain_tip.lock().await.clone()
	}

	/// Sync all the system's wallets.
	///
	/// This includes the rounds wallet sending new funds to the forfeits
	/// wallet if it's running low.
	pub async fn sync_wallets(&self) -> anyhow::Result<()> {
		// First sync both wallets.
		let (rounds_balance, _) = tokio::try_join!(
			async {
				self.rounds_wallet.lock().await.sync(&self.bitcoind, false).await
			},
			async { self.forfeits.wallet_sync().await },
		)?;

		// Then try rebalance.
		let forfeit_wallet = self.forfeits.wallet_status().await?;
		if forfeit_wallet.total_balance < self.config.forfeit_watcher_min_balance {
			let amount = self.config.forfeit_watcher_min_balance * 2;
			if rounds_balance.total() < amount {
				warn!("Rounds wallet doesn't have sufficient funds to fund forfeit watcher.");
			} else {
				let mut wallet = self.rounds_wallet.lock().await;
				let addr = forfeit_wallet.address.assume_checked();
				let feerate = self.config.round_tx_feerate; //TODO(stevenroose) fix this
				info!("Sending {amount} to forfeit wallet address {addr}...");
				let tx = match wallet.send(&addr, amount, feerate).await {
					Ok(tx) => tx,
					Err(e) => {
						warn!("Error sending from round to forfeit wallet: {:?}", e);
						return Err(e).context("error sending tx from round to forfeit wallet");
					},
				};
				drop(wallet);

				let tx = self.tx_broadcast_handle.broadcast_tx(tx).await;
				// wait until it's actually broadcast
				tokio::time::timeout(Duration::from_millis(5_000), async {
					loop {
						if tx.status().await.seen() {
							break;
						}
						tokio::time::sleep(Duration::from_millis(500)).await;
					}
				}).await.context("waiting for tx broadcast timed out")?;

				// then re-sync
				self.forfeits.wallet_sync().await?;
			}
		}

		Ok(())
	}

	pub async fn new_onchain_address(&self) -> anyhow::Result<Address> {
		let mut wallet = self.rounds_wallet.lock().await;
		let ret = wallet.reveal_next_address(bdk_wallet::KeychainKind::External).address;
		wallet.persist().await?;
		Ok(ret)
	}

	/// Fetch all the utxos in our wallet that are being spent or created by txs
	/// from the VtxoSweeper.
	pub async fn pending_sweep_utxos(&self) -> anyhow::Result<HashSet<OutPoint>> {
		let ret = self.db.fetch_pending_sweeps().await?.values()
			.map(|tx| tx.all_related_utxos())
			.flatten().collect();
		Ok(ret)
	}

	pub async fn cosign_board(
		&self,
		amount: Amount,
		user_pubkey: PublicKey,
		expiry_height: BlockHeight,
		utxo: OutPoint,
		user_pub_nonce: PublicNonce,
	) -> anyhow::Result<ark::board::BoardCosignResponse> {
		if amount < P2TR_DUST {
			return badarg!("board amount must be at least {}", P2TR_DUST);
		}

		if let Some(max) = self.config.max_vtxo_amount {
			if amount > max {
				return badarg!("board amount exceeds limit of {max}");
			}
		}

		//TODO(stevenroose) make this more robust
		let tip = self.chain_tip().await;
		if expiry_height < tip.height {
			bail!("vtxo already expired: {} (tip = {})", expiry_height, tip.height);
		}

		let builder = BoardBuilder::new_for_cosign(
			user_pubkey,
			expiry_height,
			self.asp_key.public_key(),
			self.config.vtxo_exit_delta,
			amount,
			utxo,
			user_pub_nonce,
		);

		info!("Cosigning board request for utxo {}", utxo);
		let resp = builder.server_cosign(&self.asp_key);

		slog!(CosignedBoard, utxo, amount);

		Ok(resp)
	}

	/// Registers a board
	///
	/// It will broadcast the funding_transaction if it is unseen and
	/// wil regisert the vtxo in the databse
	pub async fn register_board(&self, vtxo: Vtxo, tx: Transaction) -> anyhow::Result<()> {
		//TODO(stevenroose) validate board vtxo

		// Since the user might have just created and broadcast this tx very recently,
		// it's very likely that we won't have it in our mempool yet.
		// We will first check if we have it, if not, try to broadcast it.
		match self.bitcoind.custom_get_raw_transaction_info(&vtxo.chain_anchor().txid, None) {
			Ok(Some(txinfo)) => {
				let conf = txinfo.confirmations.unwrap_or(0);
				trace!("Board tx {} has {} confirmations", vtxo.chain_anchor().txid, conf);
			},
			Ok(None) => {
				// First check if the tx is actually standard and inputs are unspent.
				let ret = self.bitcoind.test_mempool_accept(&[&tx])?
					.into_iter().next().expect("we submitted one");
				// NB if the only reject reason is that tx is already in mempool, then we can continue
				if !ret.allowed && ret.reject_reason.iter().any(|s| s != "txn-already-in-mempool") {
					return badarg!("Tx not allowed in mempool: {}",
						ret.reject_reason.as_ref().map(|s| s.as_str()).unwrap_or("unknown"),
					);
				}

				// Then broadcast to our own mempool and peers.
				if let Err(e) = self.bitcoind.broadcast_tx(&tx) {
					if !e.is_already_in_mempool() {
						return badarg!("board tx not accepted in mempool");
					}
				}
				trace!("We submitted board tx with txid {} to mempool", vtxo.chain_anchor().txid);
			},
			Err(e) => bail!("error fetching tx info for board tx: {e}"),
		}

		// Accepted, let's register
		self.db.upsert_vtxos(&[vtxo.clone().into()]).await.context("db error")?;

		slog!(RegisteredBoard, onchain_utxo: vtxo.chain_anchor(), vtxo: vtxo.point(),
			amount: vtxo.amount(),
		);

		Ok(())
	}

	/// Validate all arkoor inputs are not too deep
	fn validate_arkoor_inputs<V: Borrow<Vtxo>>(
		&self,
		inputs: impl IntoIterator<Item = V>,
	) -> anyhow::Result<()> {
		for input in inputs {
			if input.borrow().arkoor_depth() >= self.config.max_arkoor_depth {
				return badarg!("OOR depth reached maximum of {}, please refresh your VTXO: {}",
					self.config.max_arkoor_depth, input.borrow().id());
			}
		}

		Ok(())
	}

	/// Validate all board inputs are deeply confirmed
	async fn validate_board_inputs<V: Borrow<Vtxo>>(
		&self,
		inputs: impl IntoIterator<Item = V>,
	) -> anyhow::Result<()> {
		// TODO(stevenroose) cache this check
		for vtxo in inputs {
			let vtxo = vtxo.borrow();
			if vtxo.is_arkoor() {
				continue;
			}

			let txid = vtxo.chain_anchor().txid;
			if self.db.is_round_tx(txid).await? {
				continue;
			}

			match self.bitcoind.custom_get_raw_transaction_info(&txid, None) {
				Ok(Some(tx)) => {
					let confs = tx.confirmations.unwrap_or(0) as usize;
					if confs < self.config.round_board_confirmations {
						slog!(UnconfirmedBoardSpendAttempt, vtxo: vtxo.id(), confirmations: confs);
						return badarg!("input board vtxo tx not deeply confirmed (has {confs} confs, \
							but requires {})", self.config.round_board_confirmations,
						);
					}
				},
				Ok(None) => {
					slog!(UnconfirmedBoardSpendAttempt, vtxo: vtxo.id(), confirmations: 0);
					return badarg!("input board vtxo tx was not found, \
						requires {} confs)", self.config.round_board_confirmations,
					);
				},
				Err(e) => bail!("error getting raw tx for board vtxo: {e}"),
			}
		}

		Ok(())
	}

	/// Perform the arkoor cosign from the builder.
	/// Assumes that sanity checks on the input have been performed.
	/// Will lock the input vtxo in flux.
	async fn cosign_oor_package_with_builder(
		&self,
		builder: &ArkoorPackageBuilder<'_, VtxoRequest>,
	) -> anyhow::Result<Vec<ArkoorCosignResponse>> {
		let inputs = builder.inputs();
		let input_ids = inputs.iter().map(|input| input.id()).collect::<Vec<_>>();
		let _lock = match self.vtxos_in_flux.lock(&input_ids) {
			Ok(l) => l,
			Err(id) => {
				slog!(ArkoorInputAlreadyInFlux, vtxo: id);
				return badarg!("attempted to sign arkoor tx for vtxo already in flux: {}", id);
			},
		};

		match self.db.check_set_vtxo_oor_spent_package(&builder).await {
			Ok(Some(dup)) => {
				badarg!("attempted to sign arkoor tx for already spent vtxo {}", dup)
			},
			Ok(None) => {
				info!("Cosigning arkoor for inputs: {:?}", input_ids);
				// let's sign the tx
				Ok(builder.server_cosign(&self.asp_key))
			},
			Err(e) => Err(e),
		}
	}

	async fn cosign_oor_package(
		&self,
		arkoor_args: Vec<(VtxoId, musig::PublicNonce, Vec<VtxoRequest>)>,
	) -> anyhow::Result<Vec<ArkoorCosignResponse>> {
		let ids = arkoor_args.iter().map(|(id, _, _)| *id).collect::<Vec<_>>();
		let input_vtxos = self.db.get_vtxos_by_id(&ids).await?
			.into_iter().map(|s| s.vtxo).collect::<Vec<_>>();

		let arkoors = arkoor_args.iter().zip(input_vtxos.iter())
			.map(|((_, user_nonce, outputs), vtxo)| {
				ArkoorBuilder::new(
					&vtxo,
					&user_nonce,
					outputs,
				).badarg("invalid arkoor")
			})
			.collect::<anyhow::Result<Vec<_>>>()?;

		self.validate_arkoor_inputs(&input_vtxos)?;
		self.validate_board_inputs(&input_vtxos).await
			.context("invalid board inputs")?;

		let builder = ArkoorPackageBuilder::from_arkoors(arkoors)
			.badarg("error creating arkoor package")?;

		self.cosign_oor_package_with_builder(&builder).await
	}


	// lightning

	pub async fn start_lightning_payment(
		&self,
		invoice: Bolt11Invoice,
		amount: Amount,
		user_pubkey: PublicKey,
		inputs: Vec<Vtxo>,
		user_nonces: Vec<musig::PublicNonce>,
	) -> anyhow::Result<Vec<ArkoorCosignResponse>> {
		let payment_hash = PaymentHash::from(*invoice.payment_hash());
		if self.db.get_open_lightning_payment_attempt_by_payment_hash(&payment_hash).await?.is_some() {
			return badarg!("payment already in progress for this invoice");
		}

		let input_ids = inputs.iter().map(|input| input.id()).collect::<Vec<_>>();
		let _lock = match self.vtxos_in_flux.lock(&input_ids) {
			Ok(l) => l,
			Err(id) => return badarg!("attempted to sign arkoor tx for vtxo already in flux: {}", id),
		};

		self.validate_arkoor_inputs(&inputs)?;
		self.validate_board_inputs(&inputs).await.context("invalid board inputs")?;

		//TODO(stevenroose) check that vtxos are valid

		let expiry = {
			//TODO(stevenroose) this is kinda fragile when a block happens after
			// the user did the same calculation
			let tip = self.bitcoind.get_block_count()? as BlockHeight;
			tip + self.config.htlc_expiry_delta as BlockHeight
		};

		let pay_req = VtxoRequest {
			amount: amount,
			policy: VtxoPolicy::new_server_htlc_send(user_pubkey, payment_hash, expiry),
		};

		let package = ArkoorPackageBuilder::new(&inputs, &user_nonces, pay_req, Some(user_pubkey))
			.badarg("error creating arkoor package")?;

		match self.db.check_set_vtxo_oor_spent_package(&package).await {
			Ok(Some(dup)) => {
				badarg!("attempted to sign arkoor tx for already spent vtxo {}", dup)
			},
			Ok(None) => {
				info!("Cosigning arkoor for inputs: {:?}", input_ids);
				// let's sign the tx
				Ok(package.server_cosign(&self.asp_key))
			},
			Err(e) => Err(e),
		}
	}

	/// Try to finish the lightning payment that was previously started.
	async fn finish_lightning_payment(
		&self,
		invoice: Bolt11Invoice,
		htlc_vtxo_ids: Vec<VtxoId>,
		wait: bool,
	) -> anyhow::Result<protos::LightningPaymentResult> {
		//TODO(stevenroose) validate vtxo generally (based on input)
		let invoice_payment_hash = PaymentHash::from(*invoice.payment_hash());

		let htlc_vtxos = self.db.get_vtxos_by_id(&htlc_vtxo_ids).await?;

		let mut vtxos = vec![];
		for htlc_vtxo in htlc_vtxos {
			if !htlc_vtxo.is_spendable() {
				return badarg!("input vtxo is already spent");
			}

			let vtxo = htlc_vtxo.vtxo.clone();

			//TODO(stevenroose) need to check that the input vtxos are actually marked
			// as spent for this specific payment
			if vtxo.asp_pubkey() != self.asp_key.public_key() {
				return badarg!("invalid asp pubkey used");
			}

			let payment_hash = vtxo.server_htlc_out_payment_hash()
				.context("vtxo provided is not an outgoing htlc vtxo")?;
			if payment_hash != invoice_payment_hash {
				return badarg!("htlc payment hash doesn't match invoice");
			}

			//TODO(stevenroose) no fee is charged here now
			if vtxo.amount() < P2TR_DUST {
				return badarg!("htlc vtxo amount is below dust threshold");
			}

			vtxos.push(vtxo);
		}

		let htlc_vtxo_sum = vtxos.iter().map(|v| v.spec().amount).sum::<Amount>();
		if let Some(amount) = invoice.amount_milli_satoshis() {
			if htlc_vtxo_sum < Amount::from_msat_ceil(amount) {
				return badarg!("htlc vtxo amount too low for invoice");
				// any remainder we just keep, can later become fee
			}
		}

		// Spawn a task that performs the payment
		let res = self.cln.pay_bolt11(&invoice, htlc_vtxo_sum, wait).await;

		Self::process_lightning_pay_response(invoice_payment_hash, res)
	}

	async fn check_lightning_payment(
		&self,
		payment_hash: PaymentHash,
		wait: bool,
	) -> anyhow::Result<protos::LightningPaymentResult> {
		let res = self.cln.check_bolt11(&payment_hash, wait).await;

		Self::process_lightning_pay_response(payment_hash, res)
	}

	fn process_lightning_pay_response(
		payment_hash: PaymentHash,
		res: anyhow::Result<Preimage>,
	) -> anyhow::Result<protos::LightningPaymentResult> {
		match res {
			Ok(preimage) => {
				Ok(protos::LightningPaymentResult {
					progress_message: "Payment completed".to_string(),
					status: protos::PaymentStatus::Complete.into(),
					payment_hash: payment_hash.to_vec(),
					payment_preimage: Some(preimage.to_vec())
				})
			},
			Err(e) => {
				let status = e.downcast_ref::<LightningPaymentStatus>();
				if let Some(LightningPaymentStatus::Failed) = status {
					Ok(protos::LightningPaymentResult {
						progress_message: format!("Payment failed: {}", e),
						status: protos::PaymentStatus::Failed.into(),
						payment_hash: payment_hash.to_vec(),
						payment_preimage: None
					})
				} else {
					Ok(protos::LightningPaymentResult {
						progress_message: format!("Error during payment: {:?}", e),
						status: protos::PaymentStatus::Failed.into(),
						payment_hash: payment_hash.to_vec(),
						payment_preimage: None
					})
				}
			},
		}
	}

	async fn revoke_bolt11_payment(
		&self,
		htlc_vtxo_ids: Vec<VtxoId>,
		user_nonces: Vec<musig::PublicNonce>,
	) -> anyhow::Result<Vec<ArkoorCosignResponse>> {
		let tip = self.bitcoind.get_block_count()? as BlockHeight;
		let db = self.db.clone();

		let htlc_vtxos = self.db.get_vtxos_by_id(&htlc_vtxo_ids).await?;

		let first = htlc_vtxos.first().badarg("vtxo is empty")?.vtxo.spec();
		let first_policy = first.policy.as_server_htlc_send().context("vtxo is not outgoing htlc vtxo")?;

		let mut vtxos = vec![];
		for htlc_vtxo in htlc_vtxos {
			let spec = htlc_vtxo.vtxo.spec();
			let policy = spec.policy.as_server_htlc_send()
				.context("vtxo is not outgoing htcl vtxo")?;

			if policy != first_policy {
				return badarg!("all revoked htlc vtxos must have same policy");
			}

			vtxos.push(htlc_vtxo.vtxo);
		}

		let invoice = db.get_lightning_invoice_by_payment_hash(&first_policy.payment_hash).await?;

		// If payment not found but input vtxos are found, we can allow revoke
		if let Some(invoice) = invoice {
			match invoice.last_attempt_status {
				Some(status) if status == LightningPaymentStatus::Failed => {},
				Some(status) if status == LightningPaymentStatus::Succeeded => {
					if let Some(preimage) = invoice.preimage {
						return badarg!("This lightning payment has completed. preimage: {}",
							preimage.as_hex());
					} else {
						error!("This lightning payment has completed, but no preimage found. Accepting revocation");
					}
				},
				_ if tip > first_policy.htlc_expiry => {
					// Check one last time to see if it completed
					if let Ok(preimage) = self.cln.check_bolt11(&invoice.payment_hash, false).await {
						return badarg!("This lightning payment has completed. preimage: {}",
							preimage.as_hex());
					}
				},
				_ => return badarg!("This lightning payment is not eligible for revocation yet")
			}
		}

		let pay_req = VtxoRequest {
			amount: vtxos.iter().map(|v| v.amount()).sum(),
			policy: VtxoPolicy::new_pubkey(vtxos.first().unwrap().user_pubkey()),
		};
		let package = ArkoorPackageBuilder::new(&vtxos, &user_nonces, pay_req, None)?;
		self.cosign_oor_package_with_builder(&package).await
	}

	async fn start_bolt11_board(&self, payment_hash: PaymentHash, amount: Amount)
		-> anyhow::Result<protos::StartBolt11BoardResponse>
	{
		info!("Starting bolt11 board with payment_hash: {}", payment_hash.as_hex());

		let subscriptions = self.db
			.get_htlc_subscriptions_by_payment_hash(&payment_hash)
			.await?;

		let subscriptions_by_status = subscriptions.iter()
			.fold::<HashMap<_, Vec<_>>, _>(HashMap::new(), |mut acc, sub| {
				acc.entry(sub.status).or_default().push(sub);
				acc
			});

		if subscriptions_by_status.contains_key(&LightningHtlcSubscriptionStatus::Settled) {
			bail!("invoice already settled");
		}

		if subscriptions_by_status.contains_key(&LightningHtlcSubscriptionStatus::Accepted) {
			bail!("invoice already accepted");
		}

		if let Some(created) = subscriptions_by_status.get(&LightningHtlcSubscriptionStatus::Created) {
			if let Some(subscription) = created.first() {
				trace!("Found existing created subscription, returning invoice: {}", subscription.invoice.to_string());
				return Ok(protos::StartBolt11BoardResponse {
					bolt11: subscription.invoice.to_string()
				})
			}
		}

		let invoice = self.cln.generate_invoice(payment_hash, amount).await?;
		trace!("Hold invoice created. payment_hash: {}, amount: {}, {}", payment_hash, amount, invoice.to_string());

		Ok(protos::StartBolt11BoardResponse {
			bolt11: invoice.to_string()
		})
	}

	async fn subscribe_bolt11_board(&self, invoice: Bolt11Invoice)
		-> anyhow::Result<protos::SubscribeBolt11BoardResponse>
	{
		let invoice_payment_hash = PaymentHash::from(*invoice.payment_hash());
		let status = LightningHtlcSubscriptionStatus::Settled;
		if self.db.get_htlc_subscription_by_payment_hash(
			&invoice_payment_hash, status).await?.is_some()
		{
			bail!("invoice already settled");
		}

		let htlc = loop {
			let status = LightningHtlcSubscriptionStatus::Accepted;
			let htlc = self.db
				.get_htlc_subscription_by_payment_hash(&invoice_payment_hash, status)
				.await?;

			if let Some(htlc) = htlc {
				break htlc;
			}

			tokio::time::sleep(self.config.invoice_check_interval).await;
		};

		let amount = Amount::from_msat_floor(htlc.invoice.amount_milli_satoshis()
			.expect("invoice generated by us should have amount"));

		Ok(protos::SubscribeBolt11BoardResponse {
			invoice: invoice.to_string(),
			amount_sat: amount.to_sat(),
		})
	}

	async fn claim_bolt11_htlc(
		&self,
		input_vtxo_id: VtxoId,
		vtxo_req: VtxoRequest,
		user_nonce: musig::PublicNonce,
		payment_preimage: &Preimage,
	) -> anyhow::Result<ArkoorCosignResponse> {
		let [input_vtxo] = self.db.get_vtxos_by_id(&[input_vtxo_id]).await
			.context("claim bolt11 input vtxo fetch error")?.try_into().unwrap();

		if let VtxoPolicy::ServerHtlcRecv(ServerHtlcRecvVtxoPolicy { payment_hash, .. }) = input_vtxo.vtxo.policy() {
			let payment_hash_from_preimage = PaymentHash::from_preimage(*payment_preimage);
			if payment_hash_from_preimage != *payment_hash {
				bail!("input vtxo payment hash does not match preimage");
			}

			let status = LightningHtlcSubscriptionStatus::Accepted;
			let htlc_subscription = self.db
				.get_htlc_subscription_by_payment_hash(&payment_hash, status).await?
				.context("no htlc subscription found")?;

			self.cln.settle_invoice(
				htlc_subscription.lightning_htlc_subscription_id,
				payment_preimage,
			).await?.context("could not settle invoice")?;

			let input = [input_vtxo.vtxo];
			let pubs = vec![user_nonce];
			let package = ArkoorPackageBuilder::new(&input, &pubs, vtxo_req, None)?;

			let mut arkoors = self.cosign_oor_package_with_builder(&package).await?;
			Ok(arkoors.pop().expect("should have one"))
		} else {
			bail!("invalid claim input: {:?}", input_vtxo);
		}
	}
}


async fn run_tip_fetcher(srv: Arc<Server>) {
	let _worker = srv.rtmgr.spawn_critical("TipFetcher");

	loop {
		tokio::select! {
			// Periodic interval for chain tip fetch
			() = tokio::time::sleep(Duration::from_secs(1)) => {},
			_ = srv.rtmgr.shutdown_signal() => {
				info!("Shutdown signal received. Exiting fetch_tip loop...");
				break;
			}
		}

		match srv.bitcoind.tip() {
			Ok(t) => {
				let mut lock = srv.chain_tip.lock().await;
				if t != *lock {
					*lock = t;
					telemetry::set_block_height(t.height);
					slog!(TipUpdated, height: t.height, hash: t.hash);
				}
			}
			Err(e) => {
				warn!("Error getting chain tip from bitcoind: {}", e);
			},
		}
	}

	info!("Chain tip loop terminated gracefully.");
}

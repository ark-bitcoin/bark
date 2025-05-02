

#[macro_use] extern crate anyhow;
#[macro_use] extern crate async_trait;
#[macro_use] extern crate serde;
#[macro_use] extern crate aspd_log;

#[macro_use]
mod error;

mod cln;
mod bitcoind;
pub(crate) mod flux;
pub mod database;
mod psbtext;
mod serde_util;
pub mod sweeps;
mod rpcserver;
mod round;
pub(crate) mod system;
mod txindex;
mod telemetry;
mod wallet;
pub mod config;
pub use crate::config::Config;

use std::collections::HashSet;
use std::fs;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use bip39::Mnemonic;
use bitcoin::consensus::encode::serialize_hex;
use bitcoin::{bip32, Address, Amount, OutPoint, Transaction};
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{self, Keypair, PublicKey};
use bitcoin_ext::rpc::{BitcoinRpcErrorExt, BitcoinRpcExt};
use bitcoin_ext::{BlockHeight, BlockRef, TransactionExt, P2TR_DUST};
use lightning_invoice::Bolt11Invoice;
use log::{trace, info, warn, error};
use tokio::sync::{oneshot, Mutex};
use tokio::signal::unix::{signal, SignalKind};

use ark::{musig, BoardVtxo, Vtxo, VtxoId, VtxoSpec};
use ark::lightning::{Bolt11Payment, SignedBolt11Payment};
use ark::musig::{MusigPartialSignature, MusigPubNonce};
use ark::rounds::RoundEvent;
use aspd_rpc::protos;

use crate::bitcoind::{BitcoinRpcClient, RpcApi};
use crate::cln::ClnManager;
use crate::database::model::LightningPaymentStatus;
use crate::error::ContextExt;
use crate::flux::VtxosInFlux;
use crate::round::RoundInput;
use crate::system::RuntimeManager;
use crate::telemetry::TelemetryMetrics;
use crate::txindex::TxIndex;
use crate::sweeps::VtxoSweeper;
use crate::wallet::{BdkWalletExt, PersistedWallet, WalletKind, MNEMONIC_FILE};

lazy_static::lazy_static! {
	/// Global secp context.
	static ref SECP: secp256k1::Secp256k1<secp256k1::All> = secp256k1::Secp256k1::new();
}

/// The HD keypath to use for the ASP key.
const ASP_KEY_PATH: &str = "m/2'/0'";


pub struct RoundHandle {
	round_event_tx: tokio::sync::broadcast::Sender<RoundEvent>,
	round_input_tx: tokio::sync::mpsc::UnboundedSender<(RoundInput, oneshot::Sender<anyhow::Error>)>,
	round_trigger_tx: tokio::sync::mpsc::Sender<()>,
}

pub struct App {
	config: Config,
	db: database::Db,
	rtmgr: RuntimeManager,
	master_xpriv: bip32::Xpriv,
	asp_key: Keypair,
	// NB this needs to be an Arc so we can take a static guard
	rounds_wallet: Arc<Mutex<PersistedWallet>>,
	bitcoind: BitcoinRpcClient,
	chain_tip: Mutex<BlockRef>,
	txindex: TxIndex,
	vtxo_sweeper: Option<VtxoSweeper>,

	rounds: Option<RoundHandle>,
	/// All vtxos that are currently being processed in any way.
	/// (Plus a small buffer to optimize allocations.)
	vtxos_in_flux: VtxosInFlux,
	cln: Option<ClnManager>,
	telemetry_metrics: TelemetryMetrics,
}

impl App {
	pub async fn create(cfg: Config) -> anyhow::Result<()> {
		if cfg.legacy_wallet {
			bail!("We don't support creating new legacy wallets.");
		}

		// Check for mnemonic file to see if aspd was already initialized.
		if cfg.data_dir.join(MNEMONIC_FILE).exists() {
			bail!("Found existing mnemonic file in datadir, aspd probably already initialized!");
		}

		info!("Creating aspd server at {}", cfg.data_dir.display());

		// create dir if not exit, but check that it's empty
		fs::create_dir_all(&cfg.data_dir).context("can't create dir")?;

		let bitcoind = BitcoinRpcClient::new(&cfg.bitcoind.url, cfg.bitcoind_auth())
			.context("failed to create bitcoind rpc client")?;
		let deep_tip = bitcoind.deep_tip()
			.context("failed to fetch deep tip from bitcoind")?;

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
		for wallet in [WalletKind::Rounds] {
			let wallet_xpriv = seed_xpriv.derive_priv(&*SECP, &[wallet.child_number()])
				.expect("can't error");
			let _wallet = PersistedWallet::load_from_xpriv(
				db.clone(), cfg.network, &wallet_xpriv, wallet, deep_tip, false,
			);
		}

		Ok(())
	}

	pub async fn open(cfg: Config) -> anyhow::Result<Arc<Self>> {
		info!("Starting aspd at {}", cfg.data_dir.display());

		info!("Connecting to db at {}:{}", cfg.postgres.host, cfg.postgres.port);
		let db = database::Db::connect(&cfg.postgres)
			.await
			.context("failed to connect to db")?;

		let bitcoind = BitcoinRpcClient::new(&cfg.bitcoind.url, cfg.bitcoind_auth())
			.context("failed to create bitcoind rpc client")?;

		let seed = wallet::read_mnemonic_from_datadir(&cfg.data_dir)?.to_seed("");
		let master_xpriv = bip32::Xpriv::new_master(cfg.network, &seed).unwrap();

		let wallet_xpriv = if cfg.legacy_wallet {
			master_xpriv.clone()
		} else {
			master_xpriv.derive_priv(&*SECP, &[WalletKind::Rounds.child_number()])
				.expect("can't error")
		};
		let deep_tip = bitcoind.deep_tip().context("failed to query node for deep tip")?;
		let rounds_wallet = PersistedWallet::load_from_xpriv(
			db.clone(), cfg.network, &wallet_xpriv, WalletKind::Rounds, deep_tip, cfg.legacy_wallet,
		).await.context("error loading wallet")?;

		let asp_path = bip32::DerivationPath::from_str(ASP_KEY_PATH).unwrap();
		let asp_xpriv = master_xpriv.derive_priv(&SECP, &asp_path).unwrap();
		let asp_key = Keypair::from_secret_key(&SECP, &asp_xpriv.private_key);

		Ok(Arc::new(App {
			rounds_wallet: Arc::new(Mutex::new(rounds_wallet)),
			txindex: TxIndex::new(),
			vtxo_sweeper: None,
			chain_tip: Mutex::new(bitcoind.tip().context("failed to fetch tip")?),
			rounds: None,
			vtxos_in_flux: VtxosInFlux::new(),
			config: cfg.clone(),
			db: db.clone(),
			asp_key,
			master_xpriv,
			bitcoind,
			rtmgr: RuntimeManager::new_with_telemetry(telemetry::spawn_gauge()),
			cln: None,
			telemetry_metrics: TelemetryMetrics::disabled(),
		}))
	}

	/// Perform all startup processes.
	async fn startup(self: &Arc<Self>) -> anyhow::Result<()> {
		// Check if our bitcoind is on the expected network.
		let chain_info = self.bitcoind.get_blockchain_info()?;
		if chain_info.chain != self.config.network {
			bail!("Our bitcoind is running on network {} while we are configured for network {}",
				chain_info.chain, self.config.network,
			);
		}

		Ok(())
	}

	pub async fn start(self: &mut Arc<Self>) -> anyhow::Result<()> {
		let (round_event_tx, _rx) = tokio::sync::broadcast::channel(8);
		let (round_input_tx, round_input_rx) = tokio::sync::mpsc::unbounded_channel();
		let (round_trigger_tx, round_trigger_rx) = tokio::sync::mpsc::channel(1);

		let telemetry_metrics = telemetry::init_telemetry(&self.config, self.asp_key.public_key());

		let mut_self = Arc::get_mut(self).context("can only start if we are unique Arc")?;
		let rtmgr = mut_self.rtmgr.clone();
		mut_self.rounds = Some(RoundHandle { round_event_tx, round_input_tx, round_trigger_tx });
		mut_self.txindex.start(
			rtmgr.clone(),
			mut_self.bitcoind.clone(),
			mut_self.config.txindex_check_interval,
		);
		//TODO(stevenroose) this will be cleaned up if we unify App::open and App::start
		mut_self.vtxo_sweeper = Some(VtxoSweeper::start(
			rtmgr.clone(),
			mut_self.config.vtxo_sweeper.clone(),
			mut_self.config.network,
			mut_self.bitcoind.clone(),
			mut_self.db.clone(),
			mut_self.txindex.clone(),
			mut_self.asp_key.clone(),
			mut_self.rounds_wallet.lock().await.reveal_next_address(
				bdk_wallet::KeychainKind::External,
			).address,
		).await.context("failed to start VtxoSweeper")?);
		mut_self.cln = Some(ClnManager::start(
			rtmgr.clone(),
			&mut_self.config,
			mut_self.db.clone(),
		).await.context("failed to start ClnManager")?);
		mut_self.telemetry_metrics = telemetry_metrics;

		// First perform all startup tasks...
		info!("Starting startup tasks...");
		self.startup().await.context("startup error")?;
		info!("Startup tasks done");

		// Spawn a task to handle Ctrl+C
		let rt = rtmgr.clone();
		tokio::spawn(async move {
			let ctrl_c = async {
				tokio::signal::ctrl_c()
					.await
					.expect("Failed to listen for Ctrl+C");
				info!("Ctrl+C received! Sending shutdown signal...");
			};

			let sigterm = async {
				let mut sigterm_stream =
					signal(SignalKind::terminate()).expect("Failed to listen for SIGTERM");
				sigterm_stream.recv().await;
				info!("SIGTERM received! Sending shutdown signal...");
			};

			tokio::select! {
				_ = ctrl_c => {}
				_ = sigterm => {}
			}

			let _ = rt.shutdown();
			for i in (1..=60).rev() {
				if rt.shutdown_done() {
					return;
				}
				info!("Forced exit in {} seconds...", i);
				tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
			}
			std::process::exit(0);
		});

		// Then start all our subprocesses
		let app = self.clone();
		tokio::spawn(async move {
			let res = rpcserver::run_public_rpc_server(app)
				.await.context("error running public gRPC server");
			info!("RPC server exited with {:?}", res);
		});

		let app = self.clone();
		tokio::spawn(async move {
			let res = round::run_round_coordinator(&app, round_input_rx, round_trigger_rx)
				.await.context("error from round scheduler");
			info!("Round coordinator exited with {:?}", res);
		});

		let app = self.clone();
		tokio::spawn(async move {
			let _worker = app.rtmgr.spawn_critical("TipFetcher");

			loop {
				tokio::select! {
					// Periodic interval for chain tip fetch
					() = tokio::time::sleep(Duration::from_secs(1)) => {},
					_ = app.rtmgr.shutdown_signal() => {
						info!("Shutdown signal received. Exiting fetch_tip loop...");
						break;
					}
				}

				match app.bitcoind.tip() {
					Ok(t) => {
						let mut lock = app.chain_tip.lock().await;
						if t != *lock {
							*lock = t;
							app.telemetry_metrics.set_block_height(t.height);
							slog!(TipUpdated, height: t.height, hash: t.hash);
						}
					}
					Err(e) => {
						warn!("Error getting chain tip from bitcoind: {}", e);
					},
				}
			}

			info!("Chain tip loop terminated gracefully.");
		});

		// These tasks do only run if the config is provided
		if self.config.rpc.admin_address.is_some() {
			let app = self.clone();
			tokio::spawn(async move {
				let res = rpcserver::run_admin_rpc_server(app)
					.await.context("error running admin gRPC server");
				info!("Admin RPC server exited with {:?}", res);
			});
		}

		rtmgr.wait().await;

		slog!(AspdTerminated);

		Ok(())
	}

	pub async fn chain_tip(&self) -> BlockRef {
		self.chain_tip.lock().await.clone()
	}

	pub fn try_rounds(&self) -> anyhow::Result<&RoundHandle> {
		self.rounds.as_ref().context("no round scheduler started yet")
	}

	pub fn rounds(&self) -> &RoundHandle {
		self.try_rounds().expect("should only call this in round scheduler code")
	}

	pub async fn new_onchain_address(&self) -> anyhow::Result<Address> {
		let mut wallet = self.rounds_wallet.lock().await;
		let ret = wallet.reveal_next_address(bdk_wallet::KeychainKind::External).address;
		wallet.persist().await?;
		Ok(ret)
	}

	pub async fn drain(
		&self,
		address: Address<bitcoin::address::NetworkUnchecked>,
	) -> anyhow::Result<Transaction> {
		//TODO(stevenroose) also claim all expired round vtxos here!

		let addr = address.require_network(self.config.network)?;

		let mut wallet = self.rounds_wallet.lock().await;
		let mut b = wallet.build_tx();
		b.drain_to(addr.script_pubkey());
		b.drain_wallet();
		let psbt = b.finish().context("error building tx")?;

		let tx = wallet.finish_tx(psbt)?;
		wallet.commit_tx(&tx);
		wallet.persist().await?;
		drop(wallet);

		if let Err(e) = self.bitcoind.broadcast_tx(&tx) {
			error!("Error broadcasting tx: {}", e);
			error!("Try yourself: {}", bitcoin::consensus::encode::serialize_hex(&tx));
		}

		Ok(tx)
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
		user_part: ark::board::UserPart,
	) -> anyhow::Result<ark::board::AspPart> {
		if user_part.spec.asp_pubkey != self.asp_key.public_key() {
			return badarg!("ASP public key is incorrect!");
		}

		if user_part.spec.amount < P2TR_DUST {
			return badarg!("board amount must be at least {}", P2TR_DUST);
		}

		if let Some(max) = self.config.max_vtxo_amount {
			if user_part.spec.amount > max {
				return badarg!("board amount exceeds limit of {max}");
			}
		}

		info!("Cosigning board request for utxo {}", user_part.utxo);
		let ret = ark::board::new_asp(&user_part, &self.asp_key);
		let exit_tx = user_part.exit_tx();
		let exit_txid = exit_tx.compute_txid();
		slog!(CosignedBoard, utxo: user_part.utxo, amount: user_part.spec.amount, exit_txid);
		Ok(ret)
	}

	pub async fn validate_board_spec(&self, spec: &VtxoSpec) -> anyhow::Result<()> {
		let tip = self.chain_tip().await;

		if spec.asp_pubkey != self.asp_key.public_key() {
			bail!("invalid asp pubkey: {} != {}", spec.asp_pubkey, self.asp_key.public_key());
		}

		//TODO(stevenroose) make this more robust
		if spec.expiry_height < tip.height {
			bail!("vtxo already expired: {} (tip = {})", spec.expiry_height, tip.height);
		}

		let exit_delta = spec.spk
			.exit_delta()
			.with_context(|| format!("VTXO spk must be exit variant. Found: {}", spec.spk))?;

		if exit_delta != self.config.vtxo_exit_delta {
			bail!("invalid exit delta: {} != {}", exit_delta, self.config.vtxo_exit_delta);
		}

		Ok(())
	}

	/// Registers a board
	///
	/// It will broadcast the funding_transaction if it is unseen and
	/// wil regisert the vtxo in the databse
	pub async fn register_board(
		&self,
		vtxo: BoardVtxo,
		tx: Transaction,
	) -> anyhow::Result<()> {
		self.validate_board_spec(&vtxo.spec).await.badarg("invalid board vtxo spec")?;
		vtxo.validate_tx(&tx).badarg("board tx doesn't match vtxo spec")?;

		// Since the user might have just created and broadcast this tx very recently,
		// it's very likely that we won't have it in our mempool yet.
		// We will first check if we have it, if not, try to broadcast it.
		match self.bitcoind.custom_get_raw_transaction_info(&vtxo.onchain_output.txid, None) {
			Ok(txinfo) => {
				let conf = txinfo.confirmations.unwrap_or(0);
				trace!("Board tx {} has {} confirmations", vtxo.onchain_output.txid, conf);
			},
			Err(e) if e.is_not_found() => {
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
				trace!("We submitted board tx with txid {} to mempool", vtxo.onchain_output.txid);
			},
			Err(e) => bail!("error fetching tx info for board tx: {e}"),
		}

		// Accepted, let's register
		self.db.upsert_vtxos(&[vtxo.clone().into()]).await.context("db error")?;

		slog!(RegisteredBoard, onchain_utxo: vtxo.onchain_output, vtxo: vtxo.point(),
			amount: vtxo.spec.amount,
		);

		Ok(())
	}

	/// Validate all board inputs are deeply confirmed
	fn validate_board_inputs(
		&self,
		inputs: &[Vtxo],
	) -> anyhow::Result<Option<(VtxoId, usize)>> {
		// TODO(stevenroose) cache this check
		for board in inputs.iter().filter_map(|v| v.as_board()) {
			let txid = board.onchain_output.txid;
			let id = board.id();
			match self.bitcoind.custom_get_raw_transaction_info(&txid, None) {
				Ok(tx) => {
					let confs = tx.confirmations.unwrap_or(0) as usize;
					if confs < self.config.round_board_confirmations {
						slog!(UnconfirmedBoardSpendAttempt, vtxo: id, confirmations: confs);
						return badarg!("input board vtxo tx not deeply confirmed (has {confs} confs, \
							but requires {})", self.config.round_board_confirmations,
						);
					}
				},
				Err(e) if e.is_not_found() => {
					slog!(UnconfirmedBoardSpendAttempt, vtxo: id, confirmations: 0);
					return badarg!("input board vtxo tx was not found, \
						requires {} confs)", self.config.round_board_confirmations,
					);
				},
				Err(e) => {
					bail!("error getting raw tx for board vtxo: {e}");
				},
			}
		}

		Ok(None)
	}

	pub async fn cosign_oor(
		&self,
		payment: &ark::oor::OorPayment,
		user_nonces: &[musig::MusigPubNonce],
	) -> anyhow::Result<(Vec<musig::MusigPubNonce>, Vec<musig::MusigPartialSignature>)> {
		let ids = payment.inputs.iter().map(|v| v.id()).collect::<Vec<_>>();

		if let Some(out) = payment.outputs.iter().find(|o| o.amount < P2TR_DUST) {
			return badarg!("VTXO amount must be at least {}, requested {}", P2TR_DUST, out.amount);
		}

		if let Some(max) = self.config.max_vtxo_amount {
			for r in &payment.outputs {
				if r.amount > max {
					return badarg!("output exceeds maximum vtxo amount of {max}");
				}
			}
		}

		let _lock = match self.vtxos_in_flux.lock(&ids) {
			Ok(l) => l,
			Err(id) => return badarg!("attempted to sign OOR for vtxo already in flux: {}", id),
		};

		self.validate_board_inputs(&payment.inputs)
			.map_err(|e| e.context("arkoor cosign failed"))?;

		let txid = payment.txid();
		let new_vtxos = payment
			.unsigned_output_vtxos()
			.into_iter()
			.map(|a| a.into())
			.collect::<Vec<_>>();
		let ret = match self.db.check_set_vtxo_oor_spent(&ids, txid, &new_vtxos).await {
			Ok(Some(dup)) => {
				return badarg!("attempted to sign OOR for already spent vtxo {}", dup);
			},
			Ok(None) => {
				info!("Cosigning OOR tx {} with inputs: {:?}", txid, ids);
				let (nonces, sigs) = payment.sign_asp(&self.asp_key, &user_nonces);
				Ok((nonces, sigs))
			},
			Err(e) => Err(e),
		};

		ret
	}

	// lightning

	pub async fn start_bolt11_payment(
		&self,
		invoice: Bolt11Invoice,
		amount: Amount,
		input_vtxos: Vec<Vtxo>,
		user_pk: PublicKey,
		user_nonces: &[musig::MusigPubNonce],
	) -> anyhow::Result<(
		Bolt11Payment,
		Vec<musig::MusigPubNonce>,
		Vec<musig::MusigPartialSignature>,
	)> {
		let ids = input_vtxos.iter().map(|i| i.id()).collect::<Vec<_>>();
		let _lock = match self.vtxos_in_flux.lock(&ids) {
			Ok(l) => l,
			Err(id) => return badarg!("attempted to sign OOR for vtxo already in flux: {}", id),
		};

		if let Err(e) = self.validate_board_inputs(&input_vtxos) {
			return Err(e).context("oor cosign failed");
		}

		//TODO(stevenroose) check that vtxos are valid

		let expiry = {
			//TODO(stevenroose) bikeshed this
			let tip = self.bitcoind.get_block_count()? as BlockHeight;
			tip + 7 * 18
		};

		let details = Bolt11Payment {
			invoice,
			inputs: input_vtxos,
			asp_pubkey: self.asp_key.public_key(),
			user_pubkey: user_pk,
			payment_amount: amount,
			forwarding_fee: Amount::ZERO, //TODO(stevenroose) set fee schedule
			htlc_delta: self.config.htlc_delta,
			htlc_expiry_delta: self.config.htlc_expiry_delta,
			htlc_expiry: expiry,
			exit_delta: self.config.vtxo_exit_delta,
		};

		if let Err(e) = details.check_amounts() {
			return Err(e).badarg("invalid amounts");
		}

		let txid = details.unsigned_transaction().compute_txid();
		let new_vtxos = details
			.unsigned_change_vtxo()
			.map(|vtxo| vec![vtxo.into()])
			.unwrap_or_default();

		match self.db.check_set_vtxo_oor_spent(&ids, txid, &new_vtxos).await {
			Ok(Some(dup)) => {
				badarg!("attempted to sign OOR for already spent vtxo {}", dup)
			},
			Ok(None) => {
				info!("Cosigning HTLC tx {} with inputs: {:?}", txid, ids);
				// let's sign the tx
				let (nonces, part_sigs) = details.sign_asp(
					&self.asp_key,
					user_nonces,
				);
				Ok((details, nonces, part_sigs))
			},
			Err(e) => Err(e),
		}
	}

	/// Try to finish the bolt11 payment that was previously started.
	async fn finish_bolt11_payment(
		&self,
		signed: SignedBolt11Payment,
	) -> anyhow::Result<protos::Bolt11PaymentResult> {
		//TODO(stevenroose) need to check that the input vtxos are actually marked
		// as spent for this specific payment
		if signed.payment.asp_pubkey != self.asp_key.public_key() {
			return badarg!("invalid asp pubkey used");
		}

		if let Err(e) = signed.payment.check_amounts() {
			return badarg!("invalid amounts on bolt11 payment: {}", e);
		}
		if let Err(e) = signed.validate_signatures(&crate::SECP) {
			return badarg!("bad signatures on payment: {}", e);
		}

		let payment_hash = signed.payment.invoice.payment_hash().clone();

		// Spawn a task that performs the payment
		let res = self.cln.as_ref().expect("started").pay_bolt11(&signed).await;

		match res {
			Ok(preimage) => {
				Ok(protos::Bolt11PaymentResult {
					progress_message: "Payment completed".to_string(),
					status: protos::PaymentStatus::Complete.into(),
					payment_hash: payment_hash.as_byte_array().to_vec(),
					payment_preimage: Some(preimage.to_vec())
				})
			},
			Err(e) => {
				let status = e.downcast_ref::<LightningPaymentStatus>();
				if let Some(LightningPaymentStatus::Failed) = status {
					Ok(protos::Bolt11PaymentResult {
						progress_message: format!("Payment failed: {}", e),
						status: protos::PaymentStatus::Failed.into(),
						payment_hash: payment_hash.as_byte_array().to_vec(),
						payment_preimage: None
					})
				} else {
					Ok(protos::Bolt11PaymentResult {
						progress_message: format!("Error during payment: {:?}", e),
						status: protos::PaymentStatus::Failed.into(),
						payment_hash: payment_hash.as_byte_array().to_vec(),
						payment_preimage: None
					})
				}
			},
		}
	}

	async fn revoke_bolt11_payment(
		&self,
		signed: &SignedBolt11Payment,
		user_nonces: &[musig::MusigPubNonce],
	) -> anyhow::Result<(Vec<musig::MusigPubNonce>, Vec<musig::MusigPartialSignature>)> {
		let db = self.db.clone();
		let payment_hash = signed.payment.invoice.payment_hash().clone();

		let invoice = db.get_lightning_invoice_by_payment_hash(&payment_hash).await
			.context("error fetching invoice by payment hash")?;

		match invoice.payment_status {
			LightningPaymentStatus::Succeeded => {
				return badarg!("This lightning payment has completed. preimage: {}",
						serialize_hex(&invoice.clone().preimage.unwrap()))
			}
			LightningPaymentStatus::Failed => {}
			LightningPaymentStatus::Submitted => {
				return badarg!("This lightning payment is not eligible for revocation yet");
			}
			LightningPaymentStatus::Requested => {
				return badarg!("This lightning payment is not eligible for revocation yet");
			}
		}

		let parts = self.process_revocation(signed, user_nonces).await?;

		Ok(parts)
	}

	async fn process_revocation(
		&self,
		signed: &SignedBolt11Payment,
		user_nonces: &[MusigPubNonce],
	) -> anyhow::Result<(Vec<MusigPubNonce>, Vec<MusigPartialSignature>)> {
		signed.validate_signatures(&crate::SECP)
			.badarg("bad signatures on payment")?;

		if signed.htlc_vtxo().spec().asp_pubkey != self.asp_key.public_key() {
			bail!("Payment wasn't signed with ASP's pubkey")
		}

		let htlc_vtxo = signed.htlc_vtxo();
		let revocation_oor = signed.revocation_payment();

		self.db.upsert_vtxos(&vec![htlc_vtxo.into()]).await?;

		let parts = self.cosign_oor(&revocation_oor, user_nonces).await?;

		Ok(parts)
	}

	// ** SOME ADMIN COMMANDS **
	pub async fn get_master_mnemonic(&self) -> anyhow::Result<Mnemonic> {
		Ok(wallet::read_mnemonic_from_datadir(&self.config.data_dir)?)
	}
}


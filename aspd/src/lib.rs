

#[macro_use] extern crate anyhow;
#[macro_use] extern crate log;
#[macro_use] extern crate serde;


mod database;
mod lightning;
mod psbtext;
mod serde_util;
mod rpc;
mod rpcserver;
mod round;

use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::str::FromStr;
use std::time::Duration;

use anyhow::Context;
use ark::lightning::{Bolt11Payment, SignedBolt11Payment};
use bark_cln::grpc;
use bark_cln::grpc::pay_response::PayStatus;
use bdk_bitcoind_rpc::bitcoincore_rpc::RpcApi;
use bitcoin::hex::DisplayHex;
use bitcoin::{
	bip32, psbt, sighash, taproot, Address, Amount, FeeRate, Network, OutPoint, Transaction,
	Weight, Witness,
};
use bitcoin::secp256k1::{self, Keypair, PublicKey};
use lightning_invoice::Bolt11Invoice;
use tokio::sync::Mutex;

use ark::util::KeypairExt;
use ark::{musig, Vtxo};

use crate::psbtext::{PsbtInputExt, RoundMeta};
use crate::round::{RoundEvent, RoundInput};

lazy_static::lazy_static! {
	/// Global secp context.
	static ref SECP: secp256k1::Secp256k1<secp256k1::All> = secp256k1::Secp256k1::new();
}

//TODO(stevenroose) sanity check deltas
#[derive(Debug, Deserialize, Serialize)]
pub struct Config {
	pub network: bitcoin::Network,
	pub public_rpc_address: SocketAddr,
	pub admin_rpc_address: Option<SocketAddr>,
	pub bitcoind_url: String,
	pub bitcoind_cookie: String,

	// vtxo spec
	pub vtxo_expiry_delta: u16,
	pub vtxo_exit_delta: u16,
	/// Add fee anchors on all VTXO tree intermediate txs.
	pub vtxo_node_anchors: bool,
	// ln
	pub htlc_delta: u16,
	pub htlc_expiry_delta: u16,

	pub round_interval: Duration,
	pub round_submit_time: Duration,
	pub round_sign_time: Duration,
	pub nb_round_nonces: usize,
	//TODO(stevenroose) get these from a fee estimator service
	/// Fee rate used for the round tx.
	pub round_tx_feerate: FeeRate,

	// limits
	pub max_onboard_value: Option<Amount>,

	// lightning
	#[serde(skip_serializing_if = "Option::is_none")]
	#[serde(default)]
	pub cln_config: Option<ClnConfig>
}

// NB some random defaults to have something
impl Default for Config {
	fn default() -> Config {
		Config {
			network: bitcoin::Network::Regtest,
			public_rpc_address: "0.0.0.0:3535".parse().unwrap(),
			admin_rpc_address: Some("127.0.0.1:3536".parse().unwrap()),
			bitcoind_url: "http://127.0.0.1:38332".into(),
			bitcoind_cookie: "~/.bitcoin/signet/.cookie".into(),
			vtxo_expiry_delta: 1 * 24 * 6, // 1 day
			vtxo_exit_delta: 2 * 6, // 2 hrs
			vtxo_node_anchors: true,
			htlc_delta: 1 * 6, // 1 hr
			htlc_expiry_delta: 1 * 6, // 1 hr
			round_interval: Duration::from_secs(10),
			round_submit_time: Duration::from_secs(2),
			round_sign_time: Duration::from_secs(2),
			nb_round_nonces: 100,
			round_tx_feerate: FeeRate::from_sat_per_vb(10).unwrap(),
			max_onboard_value: None,
			cln_config: None,
		}
	}
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ClnConfig {
	#[serde(with = "serde_util::uri")]
	pub grpc_uri: tonic::transport::Uri,
	pub grpc_server_cert_path: PathBuf,
	pub grpc_client_cert_path: PathBuf,
	pub grpc_client_key_path: PathBuf,
}

impl Config {
	pub fn read_from_datadir<P: AsRef<Path>>(datadir: P) -> anyhow::Result<Self> {
		let path = datadir.as_ref().join("config.json");
		trace!("Reading configuraton from file {}", path.display());
		let bytes = fs::read(&path)
			.with_context(|| format!("failed to read config file: {}", path.display()))?;

		serde_json::from_slice::<Self>(&bytes).context("invalid config file")
	}

	pub fn write_to_datadir<P: AsRef<Path>>(&self, datadir: P) -> anyhow::Result<()> {
		let path = datadir.as_ref().join("config.json");
		trace!("Dumping configuration from file {}", path.display());

		// write the config to disk
		let config_str = serde_json::to_string_pretty(&self)?;
		fs::write(path, config_str.as_bytes())
			.context("failed to write config file")?;

			Ok(())
	}

	pub fn create_backup_in_datadir<P: AsRef<Path>>(datadir: P) -> anyhow::Result<()> {
		let mut index = 0;
		let source = datadir.as_ref().join("config.json");

		// Create the destination file-path
		// We don't delete data
		let mut destination = datadir.as_ref().join(format!("config.backup.json.v{}", index));
		while destination.exists() {
			index+=1;
			destination = datadir.as_ref().join(format!("config.backup.json.v{}", index))
		}

		// Create the copy
		fs::copy(source, destination).context("Failed to create back-up")?;
		Ok(())
	}
}

pub struct RoundHandle {
	round_event_tx: tokio::sync::broadcast::Sender<RoundEvent>,
	round_input_tx: tokio::sync::mpsc::UnboundedSender<RoundInput>,
	round_trigger_tx: tokio::sync::mpsc::Sender<()>,
}

pub struct App {
	config: Config,
	db: database::Db,
	master_xpriv: bip32::Xpriv,
	master_key: Keypair,
	wallet: Mutex<bdk_wallet::wallet::Wallet>,
	bitcoind: bdk_bitcoind_rpc::bitcoincore_rpc::Client,

	rounds: Option<RoundHandle>,
}

impl App {
	fn wallet_from_seed(
		network: Network,
		seed: &[u8],
		state: Option<bdk_wallet::wallet::ChangeSet>,
	) -> anyhow::Result<(Keypair, bip32::Xpriv, bdk_wallet::wallet::Wallet)> {
		//NB BDK currently doesn't support single-key wallets and this makes
		// that we are required to have two different descriptors.
		// We should fix this once BDK fixes this.
		let (master_key, xpriv, xpriv2) = {
			let seed_xpriv = bip32::Xpriv::new_master(network, &seed).unwrap();
			let path = bip32::DerivationPath::from_str("m/0").unwrap();
			let xpriv = seed_xpriv.derive_priv(&SECP, &path).unwrap();
			let path2 = bip32::DerivationPath::from_str("m/1").unwrap();
			let xpriv2 = seed_xpriv.derive_priv(&SECP, &path2).unwrap();
			let keypair = Keypair::from_secret_key(&SECP, &xpriv.private_key);
			(keypair, xpriv, xpriv2)
		};

		let wallet = {
			let desc = format!("tr({})", xpriv);
			let desc2 = format!("tr({})", xpriv2);
			debug!("Opening BDK wallet with descriptor {}", desc);
			debug!("Using descriptors {} and {}", desc, desc2);
			bdk_wallet::wallet::Wallet::new_or_load(&desc, &desc2, state, network)
				.context("failed to create or load bdk wallet")?
		};

		Ok((master_key, xpriv, wallet))
	}

	pub async fn create(datadir: &Path, config: Config) -> anyhow::Result<()> {
		info!("Creating aspd server at {}", datadir.display());
		trace!("Config: {:?}", config);

		// create dir if not exit, but check that it's empty
		fs::create_dir_all(&datadir).context("can't create dir")?;
		if fs::read_dir(&datadir).context("can't read dir")?.next().is_some() {
			bail!("dir is not empty");
		}

		let bitcoind = bdk_bitcoind_rpc::bitcoincore_rpc::Client::new(
			&config.bitcoind_url,
			bdk_bitcoind_rpc::bitcoincore_rpc::Auth::CookieFile(config.bitcoind_cookie.as_str().into()),
		).context("failed to create bitcoind rpc client")?;
		let tip_hash = bitcoind.get_best_block_hash().context("can't fetch tip hash")?;
		let tip = bitcoind.get_block_header_info(&tip_hash).context("can't fetch tip")?;

		// write the config to disk
		let config_str = serde_json::to_string_pretty(&config)
			.expect("serialization can't error");
		fs::write(datadir.join("config.json"), config_str.as_bytes())
			.context("failed to write config file")?;

		// create mnemonic and store in empty db
		let db_path = datadir.join("aspd_db");
		info!("Loading db at {}", db_path.display());
		let db = database::Db::open(&db_path).context("failed to open db")?;

		// Initiate key material.
		let mnemonic = bip39::Mnemonic::generate(12).expect("12 is valid");
		db.store_master_mnemonic_and_seed(&mnemonic)
			.context("failed to store mnemonic")?;

		// Store initial wallet state to avoid full chain sync.
		let seed = mnemonic.to_seed("");
		let (_, _, mut wallet) = Self::wallet_from_seed(config.network, &seed, None)
			.expect("shouldn't fail on empty state");
		wallet.insert_checkpoint(bdk_wallet::chain::BlockId {
			height: tip.height as u32,
			hash: tip.hash,
		}).expect("should work, might fail if tip is genesis");
		let cs = wallet.take_staged().expect("should have stored tip");
		ensure!(db.read_aggregate_changeset().await.context("db error")?.is_none(), "db not empty");
		db.store_changeset(&cs).await.context("error storing initial wallet state")?;

		Ok(())
	}

	pub async fn open(datadir: &Path) -> anyhow::Result<Arc<Self>> {
		info!("Starting aspd at {}", datadir.display());

		let config = Config::read_from_datadir(datadir)?;
		trace!("Config: {:?}", config);

		let db_path = datadir.join("aspd_db");
		info!("Loading db at {}", db_path.display());
		let db = database::Db::open(&db_path).context("failed to open db")?;

		let seed = db.get_master_seed()
			.context("db error")?
			.context("db doesn't contain seed")?;
		let init = db.read_aggregate_changeset().await?;
		let (master_key, xpriv, wallet) = Self::wallet_from_seed(config.network, &seed, init)
			.context("error loading wallet")?;

		let bitcoind = bdk_bitcoind_rpc::bitcoincore_rpc::Client::new(
			&config.bitcoind_url,
			bdk_bitcoind_rpc::bitcoincore_rpc::Auth::CookieFile(config.bitcoind_cookie.as_str().into()),
		).context("failed to create bitcoind rpc client")?;

		Ok(Arc::new(App {
			config: config,
			db: db,
			master_xpriv: xpriv,
			master_key: master_key,
			wallet: Mutex::new(wallet),
			bitcoind: bitcoind,
			rounds: None,
		}))
	}

	pub fn start(self: &mut Arc<Self>) -> anyhow::Result<tokio::task::JoinHandle<anyhow::Result<()>>> {
		let mut_self = Arc::get_mut(self).context("can only start if we are unique Arc")?;

		let (round_event_tx, _rx) = tokio::sync::broadcast::channel(8);
		let (round_input_tx, round_input_rx) = tokio::sync::mpsc::unbounded_channel();
		let (round_trigger_tx, round_trigger_rx) = tokio::sync::mpsc::channel(1);

		mut_self.rounds = Some(RoundHandle {
			round_event_tx: round_event_tx,
			round_input_tx: round_input_tx,
			round_trigger_tx: round_trigger_tx,
		});

		let app = self.clone();
		let jh = tokio::spawn(async move {
			//TODO(stevenroose) make this block less redundant
			if app.config.admin_rpc_address.is_some() {
				tokio::select! {
					ret = rpcserver::run_public_rpc_server(app.clone()) => {
						ret.context("error from public gRPC server")
					},
					ret = rpcserver::run_admin_rpc_server(app.clone()) => {
						ret.context("error from admin gRPC server")
					},
					ret = round::run_round_coordinator(app.clone(), round_input_rx, round_trigger_rx) => {
						ret.context("error from round scheduler")
					},
				}
			} else {
				tokio::select! {
					ret = rpcserver::run_public_rpc_server(app.clone()) => {
						ret.context("error from public gRPC server")
					},
					ret = round::run_round_coordinator(app.clone(), round_input_rx, round_trigger_rx) => {
						ret.context("error from round scheduler")
					},
				}
			}
		});

		Ok(jh)
	}

	pub fn try_rounds(&self) -> anyhow::Result<&RoundHandle> {
		self.rounds.as_ref().context("no round scheduler started yet")
	}

	pub fn rounds(&self) -> &RoundHandle {
		self.try_rounds().expect("should only call this in round scheduler code")
	}

	pub async fn onchain_address(&self) -> anyhow::Result<Address> {
		let mut wallet = self.wallet.lock().await;
		let ret = wallet.next_unused_address(bdk_wallet::KeychainKind::Internal).address;
		// should always return the same address
		debug_assert_eq!(ret, wallet.next_unused_address(bdk_wallet::KeychainKind::Internal).address);
		Ok(ret)
	}

	pub async fn sync_onchain_wallet(&self) -> anyhow::Result<Amount> {
		let mut wallet = self.wallet.lock().await;
		let prev_tip = wallet.latest_checkpoint();
		// let keychain_spks = self.wallet.spks_of_all_keychains();

		debug!("Starting onchain sync at block height {}", prev_tip.height());
		let mut emitter = bdk_bitcoind_rpc::Emitter::new(&self.bitcoind, prev_tip.clone(), prev_tip.height());
		while let Some(em) = emitter.next_block()? {
			wallet.apply_block_connected_to(&em.block, em.block_height(), em.connected_to())?;

			if em.block_height() % 10_000 == 0 {
				debug!("Synced until block {}, committing...", em.block_height());
				if let Some(change) = wallet.take_staged() {
					self.db.store_changeset(&change).await?;
				}
			}
		}

		// mempool
		let mempool = emitter.mempool()?;
		wallet.apply_unconfirmed_txs(mempool.iter().map(|(tx, time)| (tx, *time)));
		if let Some(change) = wallet.take_staged() {
			self.db.store_changeset(&change).await?;
		}

		// rebroadcast unconfirmed txs
		// NB during some round failures we commit a tx but fail to broadcast it,
		// so this ensures we still broadcast them afterwards
		for tx in wallet.transactions() {
			if !tx.chain_position.is_confirmed() {
				let bc = self.bitcoind.send_raw_transaction(&*tx.tx_node.tx);
				if let Err(e) = bc {
					warn!("Error broadcasting pending tx: {}", e);
				}
			}
		}

		let balance = wallet.balance();
		Ok(balance.total())
	}

	pub async fn drain(
		&self,
		address: Address<bitcoin::address::NetworkUnchecked>,
	) -> anyhow::Result<Transaction> {
		//TODO(stevenroose) also claim all expired round vtxos here!

		let addr = address.require_network(self.config.network)?;

		let mut wallet = self.wallet.lock().await;
		let mut b = wallet.build_tx();
		b.drain_to(addr.script_pubkey());
		b.drain_wallet();
		let mut psbt = b.finish().context("error building tx")?;
		let finalized = wallet.sign(&mut psbt, bdk_wallet::SignOptions::default())?;
		assert!(finalized);
		let tx = psbt.extract_tx()?;
		if let Some(change) = wallet.take_staged() {
			self.db.store_changeset(&change).await?;
		}
		drop(wallet);

		if let Err(e) = self.bitcoind.send_raw_transaction(&tx) {
			error!("Error broadcasting tx: {}", e);
			error!("Try yourself: {}", bitcoin::consensus::encode::serialize_hex(&tx));
		}

		Ok(tx)
	}

	pub fn cosign_onboard(&self, user_part: ark::onboard::UserPart) -> ark::onboard::AspPart {
		info!("Cosigning onboard request for utxo {}", user_part.utxo);
		ark::onboard::new_asp(&user_part, &self.master_key)
	}

	pub fn cosign_oor(
		&self,
		payment: &ark::oor::OorPayment,
		user_nonces: &[musig::MusigPubNonce],
	) -> anyhow::Result<(Vec<musig::MusigPubNonce>, Vec<musig::MusigPartialSignature>)> {
		let ids = payment.inputs.iter().map(|v| v.id()).collect::<Vec<_>>();
		if let Some(dup) = self.db.atomic_check_mark_oors_cosigned(ids.iter().copied())? {
			bail!("attempted to double sign OOR for vtxo {}", dup)
		} else {
			info!("Cosigning OOR tx {} with inputs: {:?}", payment.txid(), ids);
			let (nonces, sigs) = payment.sign_asp(&self.master_key, &user_nonces);
			Ok((nonces, sigs))
		}
	}

	// lightning

	pub fn start_bolt11(
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
		//TODO(stevenroose) check that vtxos are valid

		//TODO(stevenroose) sanity check that inputs match up to the amount

		let expiry = {
			//TODO(stevenroose) bikeshed this
			let tip = self.bitcoind.get_block_count()? as u32;
			tip + 7 * 18
		};
		let details = Bolt11Payment {
			invoice,
			inputs: input_vtxos,
			asp_pubkey: self.master_key.public_key(),
			user_pubkey: user_pk,
			payment_amount: amount,
			forwarding_fee: Amount::from_sat(350), //TODO(stevenroose) set fee schedule
			htlc_delta: self.config.htlc_delta,
			htlc_expiry_delta: self.config.htlc_expiry_delta,
			htlc_expiry: expiry,
			exit_delta: self.config.vtxo_exit_delta,
		};
		if !details.check_amounts() {
			bail!("invalid amounts");
		}

		// let's sign the tx
		let (nonces, part_sigs) = details.sign_asp(
			&self.master_key,
			user_nonces,
		);

		Ok((details, nonces, part_sigs))
	}

	/// Pays a bolt-11 invoice.
	///
	/// Returns the payment preimage.
	pub async fn pay_bolt11(&self, payment: SignedBolt11Payment) -> anyhow::Result<Vec<u8>> {
		// TODO: Store the payment state somewhere and handle stuck payments properly
		// If your funds get stuck paying a lightning-invoice might take a very long-time.
		if self.config.cln_config.is_none() {
			bail!("asp doesn't support Lightning integration");
		}

		let invoice = payment.payment.invoice;
		if invoice.check_signature().is_err() {
			bail!("Invalid signature in Bolt-11 invoice");
		}

		let cln_config = self.config.cln_config.as_ref().unwrap();
		let mut cln_client = cln_config.grpc_client().await?;

		let pay_response = cln_client.pay(grpc::PayRequest {
			bolt11: invoice.to_string(),
			label: None,
			maxfee: None,
			maxfeepercent: None,
			retry_for: None,
			maxdelay: None,
			amount_msat: if invoice.amount_milli_satoshis().is_none() {
				Some(grpc::Amount {
					msat: payment.payment.payment_amount.to_sat() * 1000,
				})
			} else {
				None
			},
			description: None,
			exemptfee: None,
			riskfactor: None,
			exclude: vec![],
			localinvreqid: None,
			partial_msat: None,
		}).await?.into_inner();

		let status = match PayStatus::try_from(pay_response.status) {
			Ok(status) => status,
			Err(_) => {
				error!("An invalid payment status was returned by Core Lightning: {}", pay_response.status);
				bail!("An unexpected error occured");
			}
		};

		match status {
			PayStatus::Complete => {
				info!("Forwarded bolt11 invoice of {} (preimage: {}). Invoice: {}",
					payment.payment.payment_amount, pay_response.payment_preimage.as_hex(), invoice.to_string(),
				);
				Ok(pay_response.payment_preimage)
			},
			PayStatus::Failed => {
				//TODO(stevenroose) do something to give back vtxo to user or so
				bail!("Failed to pay bolt11-invoice");
			},
			PayStatus::Pending => {
				// We are not supporting stuck payments yet.
				// This is bad
				error!("Stuck payment");
				bail!("Payment is stilll pending");
			}
		}
	}

	/// Returns a set of UTXOs from previous rounds that can be spent.
	///
	/// It fills in the PSBT inputs with the fields required to sign,
	/// for signing use [sign_round_utxo_inputs].
	fn spendable_expired_vtxos(&self, height: u32) -> anyhow::Result<Vec<SpendableUtxo>> {
		let pubkey = self.master_key.public_key();

		let expired_rounds = self.db.get_expired_rounds(height)?;
		let mut ret = Vec::with_capacity(2 * expired_rounds.len());
		for round_txid in expired_rounds {
			let round = self.db.get_round(round_txid)?.expect("db has round");

			// First add the vtxo tree utxo.
			let (
				spend_cb, spend_script, spend_lv, spend_merkle,
			) = round.signed_tree.spec.expiry_scriptspend();
			let mut psbt_in = psbt::Input {
				witness_utxo: Some(round.tx.output[0].clone()),
				sighash_type: Some(sighash::TapSighashType::Default.into()),
				tap_internal_key: Some(round.signed_tree.spec.cosign_agg_pk),
				tap_scripts: [(spend_cb, (spend_script, spend_lv))].into_iter().collect(),
				tap_merkle_root: Some(spend_merkle),
				non_witness_utxo: None,
				..Default::default()
			};
			psbt_in.set_round_meta(round_txid, RoundMeta::Vtxo);
			ret.push(SpendableUtxo {
				point: OutPoint::new(round_txid, 0),
				psbt: psbt_in,
				weight: ark::tree::signed::NODE_SPEND_WEIGHT,
			});

			// Then add the connector output.
			// NB this is safe because we will use SIGHASH_ALL.
			let mut psbt_in = psbt::Input {
				witness_utxo: Some(round.tx.output[1].clone()),
				sighash_type: Some(sighash::TapSighashType::Default.into()),
				tap_internal_key: Some(pubkey.x_only_public_key().0),
				non_witness_utxo: None,
				..Default::default()
			};
			psbt_in.set_round_meta(round_txid, RoundMeta::Connector);
			ret.push(SpendableUtxo {
				point: OutPoint::new(round_txid, 1),
				psbt: psbt_in,
				weight: ark::connectors::INPUT_WEIGHT,
			});
		}

		Ok(ret)
	}

	fn sign_round_utxo_inputs(&self, psbt: &mut psbt::Psbt) -> anyhow::Result<()> {
		let mut shc = sighash::SighashCache::new(&psbt.unsigned_tx);
		let prevouts = psbt.inputs.iter()
			.map(|i| i.witness_utxo.clone().unwrap())
			.collect::<Vec<_>>();

		let connector_keypair = self.master_key.for_keyspend();
		for (idx, input) in psbt.inputs.iter_mut().enumerate() {
			if let Some((_round, meta)) = input.get_round_meta().context("corrupt psbt")? {
				match meta {
					RoundMeta::Vtxo => {
						let (control, (script, lv)) = input.tap_scripts.iter().next()
							.context("corrupt psbt: missing tap_scripts")?;
						let leaf_hash = taproot::TapLeafHash::from_script(script, *lv);
						let sighash = shc.taproot_script_spend_signature_hash(
							idx,
							&sighash::Prevouts::All(&prevouts),
							leaf_hash,
							sighash::TapSighashType::Default,
						).expect("all prevouts provided");
						trace!("Signing expired VTXO input for sighash {}", sighash);
						let sig = SECP.sign_schnorr(&sighash.into(), &self.master_key);
						let wit = Witness::from_slice(
							&[&sig[..], script.as_bytes(), &control.serialize()],
						);
						debug_assert_eq!(wit.size(), ark::tree::signed::NODE_SPEND_WEIGHT.to_wu() as usize);
						input.final_script_witness = Some(wit);
					},
					RoundMeta::Connector => {
						let sighash = shc.taproot_key_spend_signature_hash(
							idx,
							&sighash::Prevouts::All(&prevouts),
							sighash::TapSighashType::Default,
						).expect("all prevouts provided");
						trace!("Signing expired connector input for sighash {}", sighash);
						let sig = SECP.sign_schnorr(&sighash.into(), &connector_keypair);
						input.final_script_witness = Some(Witness::from_slice(&[sig[..].to_vec()]));
					},
				}
			}
		}

		Ok(())
	}

	// ** SOME ADMIN COMMANDS **

	pub fn get_master_mnemonic(&self) -> anyhow::Result<String> {
		Ok(self.db.get_master_mnemonic()?.expect("app running"))
	}

	pub fn drop_all_oor_conflicts(&self) -> anyhow::Result<()> {
		self.db.clear_oor_cosigned()
	}
}

pub(crate) struct SpendableUtxo {
	pub point: OutPoint,
	pub psbt: psbt::Input,
	pub weight: Weight,
}

impl SpendableUtxo {
	pub fn amount(&self) -> Amount {
		self.psbt.witness_utxo.as_ref().unwrap().value
	}
}

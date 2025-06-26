
use std::collections::{hash_map, HashMap, HashSet};
use std::time::Duration;

use anyhow::Context;
use bitcoin::{OutPoint, Transaction, Txid, FeeRate, bip32, Network, Amount};
use bitcoin::hashes::Hash;
use bitcoin::key::Keypair;

use log::{error, debug, info, trace, warn};
use tokio::sync::{mpsc, oneshot};
use tokio_stream::StreamExt;

use ark::{musig, Vtxo, VtxoId};
use ark::connectors::{ConnectorChain, ConnectorIter};
use ark::rounds::RoundId;
use aspd_rpc as rpc;
use bitcoin_ext::rpc::{BitcoinRpcClient, BitcoinRpcExt};
use bitcoin_ext::{KeypairExt, TransactionExt};
use bitcoin_ext::bdk::WalletExt;

use crate::database::model::{ForfeitClaimState, ForfeitRoundState, ForfeitState, StoredRound};
use crate::error::AnyhowErrorExt;
use crate::system::RuntimeManager;
use crate::txindex::{Tx, TxIndex};
use crate::txindex::broadcast::TxBroadcastHandle;
use crate::wallet::{BdkWalletExt, PersistedWallet, WalletKind};
use crate::{serde_util, SECP, database, telemetry};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
	/// The fallback feerate for txs claiming forfeited vtxos.
	#[serde(with = "serde_util::fee_rate")]
	pub claim_fallback_feerate: FeeRate,
	#[serde(with = "serde_util::duration")]
	pub wake_interval: Duration,
}

impl Default for Config {
	fn default() -> Self {
	    Self {
			claim_fallback_feerate: FeeRate::from_sat_per_vb_unchecked(25),
			wake_interval: Duration::from_millis(60_000),
		}
	}
}

fn finalize_forfeit_tx(
	vtxo: &Vtxo,
	ff: &ForfeitState,
	conn_idx: usize,
	conn: OutPoint,
	conn_key: &Keypair,
	asp_key: &Keypair,
) -> Transaction {
	// First sign the forfeit input and combine with user part sig.
	let forfeit_sig = {
		let (sighash, _tx) = ark::forfeit::forfeit_sighash_exit(
			&vtxo, conn, conn_key.public_key(),
		);
		let agg_nonce = musig::nonce_agg(&[
			&ff.user_nonces.get(conn_idx).expect("user nonce index"),
			&ff.pub_nonces.get(conn_idx).expect("pub nonce index"),
		]);
		let sec_nonce = ff.sec_nonces.get(conn_idx).expect("sec nonce index").to_sec_nonce();
		let (part, sig) = musig::partial_sign(
			[vtxo.user_pubkey(), vtxo.asp_pubkey()],
			agg_nonce,
			&asp_key,
			sec_nonce,
			sighash.to_byte_array(),
			Some(vtxo.output_taproot().tap_tweak().to_byte_array()),
			Some(&[&ff.user_part_sigs.get(conn_idx).expect("user part sig index")]),
		);

		// Validate our partial sig
		debug_assert!({
			let (key_agg, _) = musig::tweaked_key_agg(
				[vtxo.user_pubkey(), vtxo.asp_pubkey()],
				vtxo.output_taproot().tap_tweak().to_byte_array(),
			);
			let session = musig::Session::new(
				&musig::SECP,
				&key_agg,
				agg_nonce,
				&sighash.to_byte_array(),
			);
			session.partial_verify(
				&musig::SECP,
				&key_agg,
				&part,
				ff.pub_nonces.get(conn_idx).expect("pub nonce index"),
				musig::pubkey_to(vtxo.asp_pubkey()),
			)
		}, "invalid partial ff signature created");

		sig.expect("forfeit partial siging failed")
	};

	// Then sign the connector input
	let conn_sig = {
		let (sighash, _tx) = ark::forfeit::forfeit_sighash_connector(
			&vtxo, conn, conn_key.public_key(),
		);
		SECP.sign_schnorr(&sighash.into(), &conn_key.for_keyspend(&*SECP))
	};

	ark::forfeit::create_forfeit_tx(
		&vtxo,
		conn,
		Some(&forfeit_sig),
		Some(&conn_sig),
	)
}

struct RoundState {
	id: RoundId,
	nb_input_vtxos: u32,
	nb_connectors_used: u32,
	connector_key: Keypair,

	// Cached variable.
	connectors: ConnectorIter<'static>,
}

impl RoundState {
	fn new_from_db(state: ForfeitRoundState) -> RoundState {
		let connector_key = Keypair::from_secret_key(&SECP, &state.connector_key);
		RoundState {
			id: state.round_id,
			nb_input_vtxos: state.nb_input_vtxos,
			nb_connectors_used: state.nb_connectors_used,
			connectors: {
				let chain = ConnectorChain::new(
					state.nb_input_vtxos as usize,
					OutPoint::new(state.round_id.as_round_txid(), 1),
					connector_key.public_key(),
				);
				let mut iter = chain.connectors_signed(&connector_key).unwrap().into_owned();
				if state.nb_connectors_used > 0 {
					assert!(state.nb_connectors_used <= state.nb_input_vtxos);
					let _ = iter.nth(state.nb_connectors_used as usize - 1);
				}
				iter
			},
			connector_key,
		}
	}

	fn new_from_round(round: &StoredRound) -> RoundState {
		let connector_key = Keypair::from_secret_key(&SECP, &round.connector_key);
		RoundState {
			id: round.id,
			nb_input_vtxos: round.nb_input_vtxos as u32,
			nb_connectors_used: 0,
			connectors: {
				let chain = ConnectorChain::new(
					round.nb_input_vtxos,
					OutPoint::new(round.id.as_round_txid(), 1),
					connector_key.public_key(),
				);
				chain.connectors_signed(&connector_key).unwrap().into_owned()
			},
			connector_key: connector_key,
		}
	}

	fn next_connector(&mut self) -> (u32, OutPoint, Option<Transaction>) {
		let (conn, tx) = self.connectors.next().expect("asked for too many connectors");
		let conn_idx = self.nb_connectors_used;
		self.nb_connectors_used += 1;
		(conn_idx, conn, tx)
	}
}

/// Two variants of a connector.
#[derive(Debug)]
enum Connector {
	/// The special case of a round with a single input:
	/// the connector is an output directly on the round tx.
	RoundTx {
		txid: Txid,
		output_idx: u32,
	},
	/// Regular connector from a connector tx.
	ConnectorTx {
		tx: Transaction,
		/// We pay close attention to this connector.
		/// Since the first connector per connector tx always has index 1,
		/// we only broadcast connector txs when this index is 1.
		output_idx: u32,
	},
}

impl Connector {
	fn point(&self) -> OutPoint {
		match self {
			Self::RoundTx { txid, output_idx: idx } => OutPoint::new(*txid, *idx),
			Self::ConnectorTx { tx, output_idx: idx } => OutPoint::new(tx.compute_txid(), *idx),
		}
	}

	/// Returns the connector tx to be broadcast if we should broadcast one.
	fn broadcast(&self) -> Option<&Transaction> {
		match self {
			Self::RoundTx { .. } => None,
			Self::ConnectorTx { tx, output_idx: idx } if *idx == 1 => Some(tx),
			Self::ConnectorTx { .. } => None,
		}
	}
}


#[derive(Clone)]
pub struct ClaimState {
	vtxo: VtxoId,

	/// Connector tx and cpfp for the forfeit.
	/// Can be [None] if the connector is straight on the round tx.
	connector_tx: Option<Tx>,
	_connector_cpfp: Option<Tx>,
	connector: OutPoint,

	forfeit_tx: Tx,
	forfeit_cpfp: Option<Tx>,
}

impl ClaimState {
	async fn new_from_db(txindex: &TxIndex, state: ForfeitClaimState<'_>, bitcoind: &BitcoinRpcClient) -> anyhow::Result<ClaimState> {
		Ok(ClaimState {
			vtxo: state.vtxo,
			connector_tx: match state.connector_tx {
				Some(tx) => Some(txindex.register_with_bitcoind(tx.into_owned(), bitcoind).await?),
				None => None,
			},
			_connector_cpfp: match state.connector_cpfp {
				Some(tx) => Some(txindex.register_with_bitcoind(tx.into_owned(), bitcoind).await?),
				None => None,
			},
			connector: state.connector,
			forfeit_tx: txindex.register_with_bitcoind(state.forfeit_tx.into_owned(), bitcoind).await?,
			forfeit_cpfp: match state.forfeit_cpfp {
				Some(tx) => Some(txindex.register_with_bitcoind(tx.into_owned(), bitcoind).await?),
				None => None,
			},
		})
	}

	/// Start broadcasting the connector.
	///
	/// Returns the pair of connector tx and cpfp tx.
	async fn start_connector(
		proc: &mut Process,
		connector_tx: Transaction,
	) -> anyhow::Result<(Tx, Tx)> {
		//TODO(stevenroose) use fee estimation here once available
		let feerate = proc.config.claim_fallback_feerate;
		let psbt = proc.wallet.make_p2a_cpfp(&connector_tx, feerate)
			.context("error making cpfp tx for connector")?;
		let cpfp = proc.wallet.finish_tx(psbt)?;

		let txs = proc.broadcaster.broadcast_pkg([connector_tx, cpfp]).await;
		let [conn, cpfp] = txs.try_into().unwrap();
		debug!("Broadcasted cpfp tx {} for connector tx {}", cpfp.txid, conn.txid);
		Ok((conn, cpfp))
	}

	async fn start(
		proc: &mut Process,
		vtxo: VtxoId,
		connector: Connector,
		forfeit_tx: Transaction,
	) -> anyhow::Result<ClaimState> {
		// First broadcast the connector, if any.
		let connector_point = connector.point();
		let (connector_tx, connector_cpfp) = if let Some(tx) = connector.broadcast() {
			let (conn, cpfp) = Self::start_connector(proc, tx.clone()).await?;
			(Some(conn), Some(cpfp))
		} else {
			(None, None)
		};

		// Then return the state and wait for connector to confirm.
		Ok(ClaimState {
			vtxo, connector_tx,
			_connector_cpfp: connector_cpfp,
			connector: connector_point,
			forfeit_tx: proc.txindex.register_with_bitcoind(forfeit_tx, &proc.bitcoind).await?,
			forfeit_cpfp: None,
		})
	}
}

struct Process {
	config: Config,
	db: database::Db,
	txindex: TxIndex,
	broadcaster: TxBroadcastHandle,
	bitcoind: BitcoinRpcClient,
	wallet: PersistedWallet,
	asp_key: Keypair,

	// runtime state

	/// Index of all vtxo exit txs to their vtxo id.
	exit_txs: Vec<(Tx, VtxoId)>,

	/// Forfeit state we keep for each round.
	///
	/// We lazily fill this when needed.
	rounds: HashMap<RoundId, RoundState>,

	/// Ongoing claims.
	claims: Vec<ClaimState>,
}

impl Process {
	async fn load_state_from_db(&mut self) -> anyhow::Result<()> {
		let rounds = self.db.get_forfeits_round_states().await?;
		self.rounds = HashMap::with_capacity(rounds.len());
		for round in rounds {
			self.rounds.insert(round.round_id, RoundState::new_from_db(round));
		}

		let claims = self.db.get_forfeits_claim_states().await?;
		self.claims = Vec::with_capacity(claims.len());
		for claim in claims {
			self.claims.push(ClaimState::new_from_db(&self.txindex, claim, &self.bitcoind).await?);
		}

		Ok(())
	}

	async fn register_vtxo(&mut self, vtxo: &Vtxo) -> anyhow::Result<()> {
		let vtxo_id = vtxo.id();
		let exit_tx = vtxo.transactions().last().unwrap().tx;
		let indexed_tx = self.txindex.register_with_bitcoind(exit_tx, &self.bitcoind).await?;
		self.exit_txs.push((indexed_tx, vtxo_id));
		Ok(())
	}

	async fn handle_exit_tx(&mut self, vtxo_id: VtxoId) -> anyhow::Result<()> {
		let [vtxo] = self.db.get_vtxos_by_id(&[vtxo_id]).await
			.context("failed to fetch forfeit vtxo")?
			.try_into().expect("1 id 1 vtxo");
		let ff_state = vtxo.forfeit_state.as_ref().expect("vtxo is forfeited");
		let round_state = match self.rounds.entry(ff_state.round_id) {
			hash_map::Entry::Occupied(e) => e.into_mut(),
			hash_map::Entry::Vacant(e) => {
				let round = self.db.get_round(ff_state.round_id).await
					.context("db error fetching round")?
					.expect("corrupt db: vtxo mentions round that doesn't exist");
				e.insert(RoundState::new_from_round(&round))
			},
		};

		// Gather the connector tx from our connector chain.
		let (conn_idx, connector, conn_tx) = round_state.next_connector();

		// Create the forfeit tx.
		let ff_tx = finalize_forfeit_tx(
			&vtxo.vtxo,
			&ff_state,
			conn_idx as usize,
			connector,
			&round_state.connector_key,
			&self.asp_key,
		);

		let connector = if let Some(conn_tx) = conn_tx {
			Connector::ConnectorTx {
				tx: conn_tx,
				output_idx: if conn_idx == round_state.nb_input_vtxos { 0 } else { 1 },
			}
		} else {
			Connector::RoundTx {
				txid: round_state.id.as_round_txid(),
				output_idx: ark::rounds::ROUND_TX_CONNECTOR_VOUT,
			}
		};
		let claim = ClaimState::start(self, vtxo_id, connector, ff_tx).await
			.with_context(|| format!("error starting forfeit claim for vtxo {}", vtxo_id))?;
		self.claims.push(claim);

		Ok(())
	}

	async fn detect_forfeit_confirms(&mut self) -> anyhow::Result<()> {
		let mut new_confirmed = HashSet::new();
		for (tx, vtxo) in &self.exit_txs {
			let status = tx.status().await;
			if let Some(block_ref) = status.confirmed_in() {
				slog!(ForfeitedExitConfirmed, vtxo: *vtxo, exit_tx: tx.txid, block_height: block_ref.height);
				new_confirmed.insert(*vtxo);
			} else if status.seen() {
				slog!(ForfeitedExitInMempool, vtxo: *vtxo, exit_tx: tx.txid);
			}
		}

		for vtxo in &new_confirmed {
			self.handle_exit_tx(*vtxo).await?;
		}
		self.exit_txs.retain(|(_tx, vtxo)| !new_confirmed.contains(vtxo));

		Ok(())
	}

	/// Try to make progress on the claim.
	///
	/// Returns `true` once the claim tx is confirmed.
	//TODO(stevenroose) change to deeply confirmed for true
	async fn progress_claim(
		&mut self,
		claim_idx: usize,
	) -> anyhow::Result<bool> {
		let claim = self.claims.get_mut(claim_idx).unwrap();
		trace!("Progressing claim for vtxo {}", claim.vtxo);

		if claim.forfeit_tx.confirmed().await {
			trace!("Forfeit tx {} confirmed, done", claim.forfeit_tx.txid);
			return Ok(true);
		}

		if let Some(ref tx) = claim.connector_tx {
			if !tx.confirmed().await {
				trace!("Connector tx {} not yet confirmed", tx.txid);
				return Ok(false);
			}
		}

		if claim.forfeit_cpfp.is_none() {
			trace!("Preparing to broadcast forfeit tx and cpfp...");
			let block_ref = match claim.connector_tx {
				Some(ref tx) => tx.status().await.confirmed_in().expect("just confirmed"),
				// If there is no connector tx, it's the round tx. Quickly fetch status.
				None => self.txindex.get(&claim.connector.txid).await.expect("In index").status().await
					.confirmed_in()
					.expect("connector tx should be confirmed"),
			};
			slog!(ConnectorConfirmed, connector_txid: claim.connector.txid, vtxo: claim.vtxo, block_height: block_ref.height);

			// Let's broadcast the forfeit then finally.
			//TODO(stevenroose) use fee estimationi here
			let feerate = self.config.claim_fallback_feerate;
			let psbt = self.wallet.make_p2a_cpfp(&claim.forfeit_tx.tx, feerate)
				.context("error making cpfp tx for forfeit")?;
			let cpfp = self.wallet.finish_tx(psbt)?;

			let txs = self.broadcaster.broadcast_pkg([claim.forfeit_tx.tx.clone(), cpfp]).await;
			let [forfeit, cpfp] = txs.try_into().unwrap();
			debug!("Broadcasted cpfp tx {} for forfeit tx {}", cpfp.txid, forfeit.txid);
			slog!(ForfeitBroadcasted, forfeit_txid: forfeit.txid, vtxo: claim.vtxo, cpfp_txid: cpfp.txid);
			claim.forfeit_cpfp = Some(cpfp);
		}

		// keep on waiting
		Ok(false)
	}

	async fn progress_pending_claims(&mut self) -> anyhow::Result<()> {
		let mut idx = 0;
		while idx < self.claims.len() {
			if self.progress_claim(idx).await.context("error progressing forfeit claim")? {
				self.claims.swap_remove(idx);
			} else {
				idx += 1;
			}
		}
		Ok(())
	}

	async fn run(
		mut self,
		rtmgr: RuntimeManager,
		mut ctrl_rx: mpsc::UnboundedReceiver<Ctrl>,
	) {
		let _worker = rtmgr.spawn_critical("ForfeitWatcher");

		// We keep these locally so that we can retry registering them
		// if we encounter a db error.
		let mut new_forfeits = Vec::<VtxoId>::new();

		info!("Starting forfeit watcher");
		let mut interval = tokio::time::interval(self.config.wake_interval);
		interval.reset();
		loop {
			tokio::select! {
				// Periodic interval for sweeping
				_ = interval.tick() => {},
				Some(ctrl) = ctrl_rx.recv() => {
					match ctrl {
						Ctrl::RegisterForfeits(forfeits) => {
							new_forfeits.extend(forfeits);
						},
						Ctrl::WalletSync(resp) => {
							let _ = self.wallet.sync(&self.bitcoind, true).await;
							let _ = resp.send(());
						},
						Ctrl::WalletStatus(resp) => {
							let _ = resp.send(self.wallet.status());
						},
					}
					continue;
				},
				_ = rtmgr.shutdown_signal() => {
					info!("Shutdown signal received. Exiting forfeit watcher...");
					break;
				},
			}
			trace!("Forfeit watcher waking up...");


			// If we have received new forfeited vtxos from a round, register them.
			let mut idx = 0;
			while idx < new_forfeits.len() {
				match self.db.get_vtxos_by_id(&[new_forfeits[idx]]).await {
					Ok(vtxos) => {
						match self.register_vtxo(&vtxos[0].vtxo).await {
							Ok(()) => {
								// No need to increment idx
								// We have removed the current entry and start again
								new_forfeits.swap_remove(idx);
							},
							Err(e) => {
								warn!("Error fetching newly forfeited vtxo from the db: {}", e);
								idx+=1;
							}
						}
					},
					Err(e)  => {
						warn!("Error fetching newly forfeited vtxo from the db: {}", e);
						idx+=1;
					}
				}
			}

			// Sync our wallet
			if let Err(e) = self.wallet.sync(&self.bitcoind, true).await {
				error!("Error syncing ForfeitWatcher wallet: {:?}", e);
			}

			// Then check if any have been broadcasted.
			if let Err(e) = self.detect_forfeit_confirms().await {
				error!("Error while performing forfeit watcher checks: {}", e);
			}

			// Then finally make progress on all pending claims.
			if let Err(e) = self.progress_pending_claims().await {
				error!("Error trying to progress forfeit claims: {}", e.full_msg());
			}

			let pending_claim_volume = self.claims.iter().map(|s|
				s.clone().forfeit_cpfp.map(|t| t.tx.output_value()).unwrap_or_else(|| s.forfeit_tx.tx.output_value())
			).sum::<Amount>().to_sat();

			telemetry::set_forfeit_metrics(
				self.exit_txs.len(),
				self.exit_txs.iter().map(|(t, _)| t.tx.output_value()).sum::<Amount>().to_sat(),
				self.claims.len(),
				pending_claim_volume,
			);

			interval.reset();
		}

		info!("Forfeit watcher terminated gracefully.");
	}
}

enum Ctrl {
	RegisterForfeits(Vec<VtxoId>),
	WalletSync(oneshot::Sender<()>),
	WalletStatus(oneshot::Sender<rpc::WalletStatus>),
}

pub struct ForfeitWatcher {
	ctrl_tx: mpsc::UnboundedSender<Ctrl>,
}

impl ForfeitWatcher {
	pub async fn start(
		rtmgr: RuntimeManager,
		config: Config,
		network: Network,
		bitcoind: BitcoinRpcClient,
		db: database::Db,
		txindex: TxIndex,
		broadcaster: TxBroadcastHandle,
		wallet_xpriv: bip32::Xpriv,
		asp_key: Keypair,
	) -> anyhow::Result<Self> {
		let deep_tip = bitcoind.deep_tip().context("failed to fetch deep tip from bitcoind")?;
		let wallet = PersistedWallet::load_from_xpriv(
			db.clone(),
			network,
			&wallet_xpriv,
			WalletKind::Forfeits,
			deep_tip,
			false,
		).await.context("error loading ForfeitWatcher wallet")?;

		let mut proc = Process {
			config, db: db.clone(), txindex, bitcoind, wallet, asp_key, broadcaster,
			exit_txs: Vec::new(),
			rounds: HashMap::new(),
			claims: Vec::new(),
		};

		// Fetch state from db.
		proc.load_state_from_db().await.context("error loading state from db")?;

		// Fetch all forfeited vtxos and register their exit txs.
		let mut forfeited_vtxos = Box::pin(db.fetch_all_forfeited_vtxos().await
			.context("db: failed to fetch forfeited vtxos")?);
		while let Some(res) = forfeited_vtxos.next().await {
			let (vtxo, _) = res.context("db: error fetching forfeited vtxo")?;
			proc.register_vtxo(&vtxo).await.context("bitcoind: Failed to get status of vtxo")?;
		}
		drop(forfeited_vtxos); // make borrowck happy

		let (ctrl_tx, ctrl_rx) = mpsc::unbounded_channel();
		tokio::spawn(proc.run(rtmgr, ctrl_rx));

		Ok(ForfeitWatcher { ctrl_tx })
	}

	pub async fn wallet_sync(&self) -> anyhow::Result<()> {
		let (resp_tx, resp_rx) = oneshot::channel();
		self.ctrl_tx.send(Ctrl::WalletSync(resp_tx)).context("process down")?;
		Ok(resp_rx.await.context("no response")?)
	}

	pub async fn wallet_status(&self) -> anyhow::Result<rpc::WalletStatus> {
		let (resp_tx, resp_rx) = oneshot::channel();
		self.ctrl_tx.send(Ctrl::WalletStatus(resp_tx)).context("process down")?;
		Ok(resp_rx.await.context("no response")?)
	}

	pub fn register_forfeits(&self, new_forfeits: Vec<VtxoId>) -> anyhow::Result<()> {
		self.ctrl_tx.send(Ctrl::RegisterForfeits(new_forfeits)).context("process down")?;
		Ok(())
	}
}

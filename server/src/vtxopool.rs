
use std::{fmt, str};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{self, AtomicBool};
use std::time::Duration;

use anyhow::Context;
use bitcoin::secp256k1::{rand, Keypair};
use bitcoin::{Amount, FeeRate, OutPoint};
use bitcoin_ext::bdk::WalletExt;
use bitcoin_ext::BlockHeight;
use futures::{stream, StreamExt, TryStreamExt};
use log::{info, warn};

use ark::{musig, Vtxo, VtxoId, VtxoPolicy, VtxoRequest};
use ark::arkoor::ArkoorPackageBuilder;
use ark::tree::signed::builder::SignedTreeBuilder;

use crate::database::vtxopool::PoolVtxo;
use crate::wallet::BdkWalletExt;
use crate::{database, Server, SECP};


/// Type used to express a vtxo issuance target for the [VtxoPool]
///
/// The string representation is `"<amount>:<count>"`, for example
/// `"10000sat:50"` or `"0.01 btc:30"`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct VtxoTarget {
	pub amount: Amount,
	pub count: usize,
}

impl fmt::Display for VtxoTarget {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}:{}", self.amount, self.count)
	}
}

impl str::FromStr for VtxoTarget {
	type Err = &'static str;
	fn from_str(s: &str) -> Result<Self, Self::Err> {
		let mut parts = s.split(":");
		Ok(VtxoTarget {
			amount: parts.next().unwrap().parse().map_err(|_| "invalid amount")?,
			count: parts.next().ok_or("invalid vtxo target format")?
				.parse().map_err(|_| "invalid count")?,
		})
	}
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
	/// the amounts to create vtxos in
	///
	/// The string representation of the elements is `"<amount>:<count>"`,
	/// for example `["10000sat:50", "0.01 btc:30"]`.
	#[serde(with = "crate::serde_util::string::vec")]
	pub vtxo_targets: Vec<VtxoTarget>,
	/// below what percentage of the target should we issue more vtxos
	pub vtxo_target_issue_threshold: u8,
	/// number of blocks for the vtxo lifetime
	pub vtxo_lifetime: u16,
	/// number of blocks before their expiry to discard vtxos
	pub vtxo_pre_expiry: u16,
	/// maximum arkoor depth to keep change until
	pub vtxo_max_arkoor_depth: u16,

	#[serde(with = "crate::serde_util::fee_rate")]
	pub issue_tx_fallback_feerate: FeeRate,
	#[serde(with = "crate::serde_util::duration")]
	pub issue_interval: Duration,
}

impl Default for Config {
	fn default() -> Self {
		Self {
			vtxo_targets: Vec::new(),
			vtxo_target_issue_threshold: 80,
			vtxo_lifetime: 144 * 3,
			vtxo_pre_expiry: 144,
			vtxo_max_arkoor_depth: 3,

			issue_tx_fallback_feerate: FeeRate::from_sat_per_vb_unchecked(1),
			issue_interval: Duration::from_secs(60),
		}
	}
}

impl Config {
	/// The lifetime we want for the ephemeral keys on the VTXOs
	///
	/// We take double the created VTXO lifetime.
	fn vtxo_key_lifetime(&self) -> Duration {
		// take double as a buffer
		Duration::from_secs(60 * 10 * self.vtxo_lifetime as u64 * 2)
	}
}


/// To make it clear what we are storing
type ArkoorDepth = u16;

#[derive(Default)]
struct Data {
	/// A quick manual index into the vtxo pool.
	/// We first order by expiry height and then by amount.
	pool: BTreeMap<BlockHeight, BTreeMap<Amount, Vec<(VtxoId, ArkoorDepth)>>>,
}

impl Data {
	/// Insert a new vtxo into the pool data
	pub fn insert(&mut self, vtxo: VtxoId, expiry: BlockHeight, amount: Amount, depth: ArkoorDepth) {
		self.pool.entry(expiry).or_default().entry(amount).or_default().push((vtxo, depth));
	}

	/// Shorthand to insert a series of vtxos at once
	pub fn insert_vtxos(&mut self, vtxos: &[PoolVtxo]) {
		for v in vtxos {
			self.insert(v.vtxo, v.expiry_height, v.amount, v.depth);
		}
	}

	pub async fn load_from_db(db: &database::Db) -> anyhow::Result<Self> {
		let stream = db.load_vtxopool().await?;
		tokio::pin!(stream);

		let mut ret = Data::default();
		while let Some(v) = stream.try_next().await? {
			ret.insert(v.vtxo, v.expiry_height, v.amount, v.depth);
		}
		Ok(ret)
	}

	/// Tally the total number of vtxos in the pool
	#[cfg(any(debug_assertions, test))]
	fn len(&self) -> usize {
		let mut len = 0;
		for (_, map) in &self.pool {
			for (_, vec) in map {
				len += vec.len();
			}
		}
		len
	}

	/// Tally the number of vtxos we have for the given amount
	pub fn count_amount(&self, amount: Amount) -> usize {
		let mut count = 0;
		for (_, map) in &self.pool {
			count += map.get(&amount).map(|v| v.len()).unwrap_or(0);
		}
		count
	}

	/// Prune the data structure from empty vectors and maps
	fn prune(&mut self) {
		#[cfg(debug_assertions)]
		let before = self.len();

		self.pool.retain(|_, c| {
			c.retain(|_, c| !c.is_empty());
			!c.is_empty()
		});

		#[cfg(debug_assertions)]
		debug_assert_eq!(before, self.len());
	}

	/// Prune all vtxos expiring before or on the threshold
	pub fn prune_expiring(&mut self, threshold: BlockHeight) {
		self.pool.retain(|h, _| *h > threshold);
	}

	/// Take inputs from the pool to match the required amount
	///
	/// Will always prioritize VTXOs that are closer to expiry.
	///
	/// Returns empty vector on failure.
	pub fn take_inputs(
		&mut self,
		required_amount: Amount,
	) -> Vec<(VtxoId, BlockHeight, Amount, ArkoorDepth)> {
		// The strategy here is to always prioritize expiry.
		// For each expiry "bucket", pick the highest amount if the
		// required amount exceeds it, otherwise pick the smallest amount
		// larger than the required amount.
		//
		// This means that for 700, we won't pick 500 + 200, but just 1000.
		//
		// This also means that if we only have a some small ones at the earliest
		// height and larger ones at further heights, we'll pick all the small ones
		// before we move up to the next height.

		let mut remaining = required_amount;
		let mut ret = Vec::<(VtxoId, BlockHeight, Amount, ArkoorDepth)>::new();
		'main:
		for (height, for_height) in self.pool.iter_mut() {
			let mut amount_iter = for_height.iter_mut().rev().peekable();
			while let Some((amount, for_amount)) = amount_iter.next() {
				let next_amount = amount_iter.peek().map(|p| *p.0).unwrap_or(Amount::ZERO);
				while !for_amount.is_empty() && remaining > next_amount {
					let (id, depth) = for_amount.pop().unwrap();
					ret.push((id, *height, *amount, depth));
					remaining = remaining.checked_sub(*amount).unwrap_or(Amount::ZERO);
					if remaining == Amount::ZERO {
						break 'main;
					}
				}
			}
		}

		if remaining != Amount::ZERO {
			// required amount too high, put everything back and return empty
			for (v, h, a, d) in ret {
				self.insert(v, h, a, d);
			}
			return vec![];
		}

		self.prune();

		ret
	}
}


pub struct VtxoPool {
	config: Config,
	started: AtomicBool,

	data: Arc<parking_lot::Mutex<Data>>,
}

impl VtxoPool {
	async fn prepare_arkoor(
		&self,
		srv: &Server,
		req: VtxoRequest,
		inputs: &[(VtxoId, BlockHeight, Amount, ArkoorDepth)],
	) -> anyhow::Result<Vec<Vtxo>> {
		let input_ids = inputs.iter().map(|v| v.0).collect::<Vec<_>>();
		let vtxos = srv.db.get_vtxos_by_id(&input_ids).await?;
		let keys = {
			let mut ret = Vec::with_capacity(vtxos.len());
			for v in &vtxos {
				ret.push(srv.get_ephemeral_cosign_key(v.vtxo.user_pubkey()).await
					.with_context(|| format!(
						"failed to fetch ephemeral keys for vtxo {}: {}",
						v.vtxo.id(), v.vtxo.user_pubkey(),
					))?
				);
			}
			ret
		};

		let (sec_nonces, pub_nonces) = keys.iter()
			.map(|key| musig::nonce_pair(key))
			.collect::<(Vec<_>, Vec<_>)>();

		let change_key = srv.generate_ephemeral_cosign_key(self.config.vtxo_key_lifetime()).await?;
		let builder = ArkoorPackageBuilder::new(
			vtxos.iter().map(|v| &v.vtxo),
			&pub_nonces,
			req.clone(),
			Some(change_key.public_key()),
		).context("arkoor builder error")?;

		let cosign = srv.cosign_oor_package_with_builder(&builder).await?;

		let (ret, change) = builder.build_vtxos(&cosign, &keys, sec_nonces)
			.context("arkoor package error")?;

		srv.db.mark_vtxopool_vtxos_spent(ret.iter().map(|v| v.id())).await
			.context("failed to mark vtxopool vtxos as spent")?;

		for vtxo in &ret {
			slog!(SpentPoolVtxo, vtxo: vtxo.id(), amount: vtxo.amount(), request: req.clone());
		}

		if let Some(ch) = change.filter(|c| c.arkoor_depth() <= self.config.vtxo_max_arkoor_depth) {
			let new = PoolVtxo {
				vtxo: ch.id(),
				amount: ch.amount(),
				expiry_height: ch.expiry_height(),
				depth: ch.arkoor_depth(),
			};
			if let Err(e) = srv.db.store_vtxopool_vtxo(&new).await {
				// don't abort for this
				warn!("Failed to store change from a vtxopool spend: {:#}", e);
			} else {
				self.data.lock().insert_vtxos(&[new]);
				slog!(ChangePoolVtxo, vtxo: ch.id(), amount: ch.amount(), depth: ch.arkoor_depth());
			}
		}

		Ok(ret)
	}

	pub async fn send_arkoor(&self, srv: &Server, req: VtxoRequest) -> anyhow::Result<Vec<Vtxo>> {
		let inputs = self.data.lock().take_inputs(req.amount);
		if inputs.is_empty() {
			bail!("vtxo pool is empty");
		}

		// we try, but if we fail, we place back the inputs
		match self.prepare_arkoor(srv, req, &inputs).await {
			Ok(v) => Ok(v),
			Err(e) => {
				let mut guard = self.data.lock();
				for (v, h, a, d) in inputs {
					guard.insert(v, h, a, d);
				}
				Err(e)
			},
		}
	}

	pub async fn new(config: Config, db: &database::Db) -> anyhow::Result<VtxoPool> {
		Ok(VtxoPool {
			config,
			started: false.into(),
			data: Arc::new(parking_lot::Mutex::new(Data::load_from_db(db).await?)),
		})
	}

	pub fn start(&self, srv: Arc<Server>) {
		if self.started.swap(true, atomic::Ordering::Relaxed) {
			return;
		}

		let proc = Process {
			srv: srv.clone(),
			config: self.config.clone(),
			data: self.data.clone(),
		};
		tokio::spawn(proc.run());
	}
}

struct Process {
	srv: Arc<Server>,
	config: Config,

	data: Arc<parking_lot::Mutex<Data>>,
}

impl Process {
	async fn issue_vtxos(&self, issuance: Vec<(Amount, usize)>) -> anyhow::Result<()> {
		let requests = {
			let mut ret = Vec::with_capacity(issuance.iter().map(|i| i.1).sum());
			for (amount, count) in issuance {
				let keys = stream::iter(0..count).map(|_| {
					self.srv.generate_ephemeral_cosign_key(self.config.vtxo_key_lifetime())
				})
				.buffer_unordered(10)
				.collect::<Vec<_>>().await
				.into_iter().collect::<Result<Vec<_>, _>>()?;

				ret.extend(keys.iter().map(|key| {
					VtxoRequest {
						policy: VtxoPolicy::new_pubkey(key.public_key()),
						amount: amount,
					}
				}));
				slog!(PreparingPoolIssuance, amount, count);
			}
			ret
		};

		let expiry = self.srv.chain_tip().height + self.config.vtxo_lifetime as BlockHeight;

		let cosign_key = Keypair::new(&*SECP, &mut rand::thread_rng());
		let server_cosign_key = self.srv.generate_ephemeral_cosign_key(Duration::from_secs(600)).await?;

		let builder = SignedTreeBuilder::new(
			requests.iter().cloned(),
			cosign_key.public_key(),
			expiry,
			self.srv.server_pubkey,
			server_cosign_key.public_key(),
			self.srv.config.vtxo_exit_delta,
		);

		//TODO(stevenroose) use actual feerate
		let fee_rate = self.config.issue_tx_fallback_feerate;

		let funding_txout = builder.funding_txout();

		let mut wallet = self.srv.rounds_wallet.lock().await;
		if let Err(e) = wallet.sync(&self.srv.bitcoind, false).await {
			warn!("Wallet sync error before funding vtxo pool issuance tx: {:#}", e);
		}
		let funding_psbt = {
			let untrusted = wallet.untrusted_utxos(None);
			let mut b = wallet.build_tx();
			b.unspendable(untrusted);
			b.add_recipient(funding_txout.script_pubkey.clone(), funding_txout.value);
			b.fee_rate(fee_rate);
			b.finish().context("failed to build signed tree funding tx")?
		};

		let funding_txid = funding_psbt.unsigned_tx.compute_txid();
		let total_amount = builder.total_required_value();
		slog!(PreparingPoolIssuanceTx, txid: funding_txid, total_count: requests.len(), total_amount);
		let vout = funding_psbt.unsigned_tx.output.iter().position(|o| *o == funding_txout)
			.context("wallet send didn't include our txout")?;
		let utxo = OutPoint::new(funding_txid, vout as u32);

		let builder = builder
			.set_utxo(utxo)
			.generate_user_nonces(&cosign_key);

		let cosign = self.srv.cosign_vtxo_tree(
			requests.iter().cloned(),
			cosign_key.public_key(),
			server_cosign_key.public_key(),
			expiry,
			utxo,
			builder.user_pub_nonces().to_vec(),
		).await.context("server error cosigning vtxo tree")?;
		builder.verify_cosign_response(&cosign).context("invalid server tree cosign")?;

		let tree = builder.build_tree(&cosign, &cosign_key)
			.context("error finishing signed tree with cosign")?;

		self.srv.register_cosigned_vtxo_tree(
			requests.iter().cloned(),
			cosign_key.public_key(),
			server_cosign_key.public_key(),
			expiry,
			utxo,
			tree.cosign_sigs.clone(),
		).await.context("error registering cosigned tree")?;

		// finish and broadcast the tx
		let tx = wallet.finish_tx(funding_psbt).context("error finishing tree funding tx")?;
		wallet.commit_tx(&tx);
		wallet.persist().await.context("error persisting wallet after signing tree funding tx")?;
		drop(wallet);
		let txid = tx.compute_txid();

		// store the new vtxos
		self.srv.db.upsert_bitcoin_transaction(txid, &tx).await
			.context("error storing unbroadcasted vtxo issuance funding tx")?;
		let tree = tree.into_cached_tree();
		// we rely here on the order of the vtxos being identical to the order of the requests
		let pool_vtxos = tree.all_vtxos().into_iter().map(|v| PoolVtxo {
			vtxo: v.id(),
			amount: v.amount(),
			expiry_height: v.expiry_height(),
			depth: 0,
		}).collect::<Vec<_>>();
		self.srv.db.store_vtxopool_vtxos(&pool_vtxos).await.context("storing pool vtxos")?;
		self.data.lock().insert_vtxos(&pool_vtxos);
		slog!(FinishedPoolIssuance, txid: funding_txid, total_count: requests.len(), total_amount);

		self.srv.tx_nursery.broadcast_tx(tx).await
			.with_context(|| format!("error broadcasting vtxopool issuance tx {}", txid))?;

		//TODO(stevenroose) should ensure tx gets confirmed

		Ok(())
	}

	fn calculate_required_issuance(
		&self,
		expiry_threshold: BlockHeight,
	) -> (Vec<(Amount, usize)>, bool) {
		let mut data = self.data.lock();
		data.prune_expiring(expiry_threshold);

		let mut must_issue = false;
		let mut issuance = Vec::with_capacity(self.config.vtxo_targets.len());
		for target in &self.config.vtxo_targets {
			let count = data.count_amount(target.amount);

			if let Some(issue) = target.count.checked_sub(count) {
				issuance.push((target.amount, issue));
			}

			if count * 100 < target.count * self.config.vtxo_target_issue_threshold as usize {
				must_issue = true;
			}
		}
		(issuance, must_issue)
	}

	/// Check the status of the pool
	async fn check_maybe_issue_vtxos(&self) -> anyhow::Result<()> {
		let tip = self.srv.chain_tip().height;
		let threshold = tip + self.config.vtxo_pre_expiry as BlockHeight;

		// NB this needs to be a different method because otherwise borrowck complains
		// about the mutex not being send even if we add a manual `drop()`
		let (issuance, must_issue) = self.calculate_required_issuance(threshold);

		if must_issue {
			self.issue_vtxos(issuance).await?;
		}

		Ok(())
	}

	async fn run(self) {
		let _worker = self.srv.rtmgr.spawn_critical("VtxoPool");

		let mut timer = tokio::time::interval(self.config.issue_interval);
		loop {
			tokio::select! {
				// Periodic interval for issuing new vtxos
				_ = timer.tick() => {},
				_ = self.srv.rtmgr.shutdown_signal() => {
					info!("Shutdown signal received. Exiting VtxoPool...");
					return;
				},
			}

			if let Err(e) = self.check_maybe_issue_vtxos().await {
				warn!("Error from VTXO pool: {:#}", e);
			}

			timer.reset();
		}
	}
}

#[cfg(test)]
mod test {
	use bitcoin::Txid;
	use bitcoin::hashes::Hash;

	use super::*;

	fn id(i: u32) -> VtxoId {
		OutPoint::new(Txid::all_zeros(), i).into()
	}

	fn sat(v: u64) -> Amount {
		Amount::from_sat(v)
	}

	/// assert a given selection
	#[track_caller]
	fn assert_sel(
		selection: &[(VtxoId, BlockHeight, Amount, ArkoorDepth)],
		expected: &[(BlockHeight, Amount)],
	) {
		let mut sel = selection.to_vec();
		for (height, amount) in expected {
			if let Some(i) = sel.iter().position(|(_, h, a, _)| h == height && a == amount) {
				sel.swap_remove(i);
			} else {
				panic!("missing item: ({}, {}), selection: {:?}",
					height, amount.to_sat(), selection,
				);
			}
		}
		if !sel.is_empty() {
			panic!("additional items: {:?}", sel);
		}
	}

	#[test]
	fn test_vtxo_selection() {
		let vtxos = [
			(id(1), 100, sat(1000)),
			(id(2), 100, sat(1000)),
			(id(3), 100, sat(2000)),
			(id(4), 100, sat(2000)),
			(id(5), 100, sat(3000)),
			(id(6), 100, sat(3000)),
			(id(11), 110, sat(1000)),
			(id(12), 110, sat(1000)),
			(id(13), 110, sat(2000)),
			(id(14), 110, sat(2000)),
			(id(15), 110, sat(3000)),
			(id(16), 110, sat(3000)),
		];
		let len = vtxos.len();

		let mut data = Data::default();
		for (v, h, a) in vtxos {
			data.insert(v, h, a, 0);
		}
		assert_eq!(data.len(), len);

		let sel = data.take_inputs(sat(500));
		assert_sel(&sel, &[(100, sat(1000))]);

		let sel = data.take_inputs(sat(2500));
		assert_sel(&sel, &[(100, sat(3000))]);

		let sel = data.take_inputs(sat(1000));
		assert_sel(&sel, &[(100, sat(1000))]);

		// the 2x 1000 at height 100 are already used
		let sel = data.take_inputs(sat(900));
		assert_sel(&sel, &[(100, sat(2000))]);

		// left at 100: 3000, 2000
		let sel = data.take_inputs(sat(5500));
		assert_sel(&sel, &[(100, sat(2000)), (100, sat(3000)), (110, sat(1000))]);

		let len = data.len();
		let sel = data.take_inputs(Amount::MAX_MONEY);
		assert!(sel.is_empty());
		assert_eq!(data.len(), len);
	}

}

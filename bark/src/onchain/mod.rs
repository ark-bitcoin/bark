
mod chain;
pub use self::chain::ChainSource;

use std::borrow::Borrow;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Context;
use ark::fee;
use ark::util::TransactionExt;
use bdk_wallet::chain::{ChainPosition, ConfirmationTime};
use bdk_wallet::{PersistedWallet, SignOptions, TxOrdering, WalletPersister};
use bdk_esplora::EsploraAsyncExt;
use bitcoin::{
	bip32, psbt, Address, Amount, FeeRate, Network, OutPoint, Psbt, Sequence, Transaction, TxOut,
	Txid, Weight,
};
use serde::ser::StdError;

use crate::persist::BarkPersister;
use crate::{exit, UtxoInfo};
use crate::psbtext::PsbtInputExt;
use self::chain::ChainSourceClient;

pub struct Wallet<P: BarkPersister> {
	wallet: PersistedWallet<P>,
	chain_source: ChainSourceClient,
	db: P,
}

impl <P>Wallet<P> where 
	P: BarkPersister,
	<P as WalletPersister>::Error: 'static + std::fmt::Debug + std::fmt::Display + Send + Sync + StdError
{
	pub fn create(
		network: Network,
		seed: [u8; 64],
		mut db: P,
		chain_source: ChainSource,
	) -> anyhow::Result<Wallet<P>> {
		let xpriv = bip32::Xpriv::new_master(network, &seed).expect("valid seed");
		let desc = format!("tr({}/84'/0'/0'/0/*)", xpriv);

		let wallet_opt = bdk_wallet::Wallet::load()
			.descriptor(bdk_wallet::KeychainKind::External, Some(desc.clone()))
			.extract_keys()
			.check_network(network)
			.load_wallet(&mut db)?;

		let wallet = match wallet_opt {
			Some(wallet) => wallet,
			None => bdk_wallet::Wallet::create_single(desc)
				.network(network)
				.create_wallet(&mut db)?,
		};

		let chain_source = ChainSourceClient::new(chain_source)?;

		Ok(Wallet { wallet, chain_source, db })
	}

	pub fn require_chainsource_version(&self) -> anyhow::Result<()> {
		self.chain_source.require_version()
	}

	pub async fn tip(&self) -> anyhow::Result<u32> {
		self.chain_source.tip().await
	}

	pub async fn broadcast_tx(&self, tx: &Transaction) -> anyhow::Result<()> {
		self.chain_source.broadcast_tx(tx).await
	}

	pub async fn broadcast_package(&self, txs: &[impl Borrow<Transaction>]) -> anyhow::Result<()> {
		self.chain_source.broadcast_package(txs).await
	}

	/// Returns the block height the tx is confirmed in, if any.
	pub async fn tx_confirmed(&self, txid: Txid) -> anyhow::Result<Option<u32>> {
		self.chain_source.tx_confirmed(txid).await
	}

	pub async fn sync(&mut self) -> anyhow::Result<Amount> {
		debug!("Starting wallet sync...");
		let now = SystemTime::now().duration_since(UNIX_EPOCH).expect("now").as_secs();

		let prev_tip = self.wallet.latest_checkpoint();
		match self.chain_source {
			ChainSourceClient::Bitcoind(ref bitcoind) => {
				let mut emitter = bdk_bitcoind_rpc::Emitter::new(
					bitcoind, prev_tip.clone(), prev_tip.height(),
				);
				while let Some(em) = emitter.next_block()? {
					self.wallet.apply_block_connected_to(
						&em.block, em.block_height(), em.connected_to(),
					)?;
					self.wallet.persist(&mut self.db)?;
				}

				let mempool = emitter.mempool()?;
				self.wallet.apply_unconfirmed_txs(mempool);
				self.wallet.persist(&mut self.db)?;
			},
			ChainSourceClient::Esplora(ref client) => {
				const STOP_GAP: usize = 50;
				const PARALLEL_REQS: usize = 4;

				let request = self.wallet.start_full_scan();
				let now = std::time::UNIX_EPOCH.elapsed().unwrap().as_secs();
				let update = client.full_scan(request, STOP_GAP, PARALLEL_REQS).await?;
				self.wallet.apply_update_at(update, Some(now))?;
				self.wallet.persist(&mut self.db)?;
			},
		}

		let balance = self.wallet.balance();

		// Ultimately, let's try to rebroadcast all our unconfirmed txs.
		for tx in self.wallet.transactions() {
			if let ChainPosition::Unconfirmed(last_seen) = tx.chain_position {
				if last_seen < now {
					if let Err(e) = self.broadcast_tx(&tx.tx_node.tx).await {
						warn!("Error broadcasting tx {}: {}", tx.tx_node.txid, e);
					}
				}
			}
		}

		Ok(balance.total())
	}

	pub fn balance(&self) -> Amount {
		self.wallet.balance().total()
	}

	pub fn utxos(&self) -> Vec<UtxoInfo> {
		self.wallet.list_unspent().map(|o| UtxoInfo {
			outpoint: o.outpoint,
			amount: o.txout.value,
			confirmation_height: match o.confirmation_time {
				ConfirmationTime::Confirmed { height, .. } => Some(height),
				_ => None
			}
		}).collect()
	}

	/// Fee rate to use for regular txs like onboards.
	pub fn regular_feerate(&self) -> FeeRate {
		FeeRate::from_sat_per_vb(10).unwrap()
	}

	/// Fee rate to use for urgent txs like exits.
	pub fn urgent_feerate(&self) -> FeeRate {
		FeeRate::from_sat_per_vb(15).unwrap()
	}

	pub fn prepare_tx(&mut self, dest: Address, amount: Amount) -> anyhow::Result<Psbt> {
		let fee_rate = self.regular_feerate();
		let mut b = self.wallet.build_tx();
		b.ordering(TxOrdering::Untouched);
		b.add_recipient(dest.script_pubkey(), amount);
		b.fee_rate(fee_rate);
		Ok(b.finish()?)
	}

	pub fn prepare_send_all_tx(&mut self, dest: Address) -> anyhow::Result<Psbt> {
		let fee_rate = self.regular_feerate();
		let mut b = self.wallet.build_tx();
		b.drain_to(dest.script_pubkey());
		b.drain_wallet();
		b.fee_rate(fee_rate);
		b.finish().context("error building tx")
	}

	pub fn finish_tx(&mut self, mut psbt: Psbt) -> anyhow::Result<Transaction> {
		let opts = SignOptions {
			trust_witness_utxo: true,
			..Default::default()
		};
		let finalized = self.wallet.sign(&mut psbt, opts).context("signing error")?;
		assert!(finalized);
		let tx = psbt.extract_tx()?;
		let unix = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
		self.wallet.apply_unconfirmed_txs([(tx.clone(), unix)]);
		self.wallet.persist(&mut self.db)?;
		Ok(tx)
	}

	pub async fn send_money(&mut self, dest: Address, amount: Amount) -> anyhow::Result<Txid> {
		let psbt = self.prepare_tx(dest, amount)?;
		let tx = self.finish_tx(psbt)?;
		self.broadcast_tx(&tx).await?;
		Ok(tx.compute_txid())
	}

	pub fn new_address(&mut self) -> anyhow::Result<Address> {
		let ret = self.wallet.reveal_next_address(bdk_wallet::KeychainKind::External).address;
		self.wallet.persist(&mut self.db)?;
		Ok(ret)
	}

	fn add_anchors<A>(b: &mut bdk_wallet::TxBuilder<A>, anchors: &[OutPoint])
	where
		A: bdk_wallet::coin_selection::CoinSelectionAlgorithm,
	{
		for utxo in anchors {
			let psbt_in = psbt::Input {
				witness_utxo: Some(ark::fee::dust_anchor()),
				final_script_witness: Some(ark::fee::dust_anchor_witness()),
				..Default::default()
			};
			b.add_foreign_utxo(*utxo, psbt_in, fee::DUST_ANCHOR_SPEND_WEIGHT)
				.expect("adding foreign utxo");
		}
	}

	/// Create a cpfp spend that spends the fee anchors in the given txs.
	///
	/// This method doesn't broadcast any txs.
	pub async fn make_cpfp(
		&mut self,
		txs: &[&Transaction],
		fee_rate: FeeRate,
	) -> anyhow::Result<Transaction> {
		assert!(!txs.is_empty());
		let anchors = txs.iter().map(|tx| {
			tx.fee_anchor().with_context(|| format!("tx {} has no fee anchor", tx.compute_txid()))
		}).collect::<Result<Vec<_>, _>>()?;

		// Since BDK doesn't support adding extra weight for fees, we have to
		// first build the tx regularly, and then build it again.
		// Since we have to guarantee that we have enough money in the inputs,
		// we will "fake" create an output on the first attempt. This might
		// overshoot the fee, but we prefer that over undershooting it.

		let package_weight = txs.iter().map(|t| t.weight()).sum::<Weight>();
		let extra_fee_needed = fee_rate * package_weight;

		// Since BDK doesn't allow tx without recipients, we add a drain output.
		let change_addr = self.wallet.reveal_next_address(bdk_wallet::KeychainKind::Internal);

		let template_weight = {
			let mut b = self.wallet.build_tx();
			b.ordering(TxOrdering::Untouched);
			b.only_witness_utxo();
			Self::add_anchors(&mut b, &anchors);
			b.add_recipient(change_addr.address.script_pubkey(), extra_fee_needed + ark::P2TR_DUST);
			b.fee_rate(fee_rate);
			let mut psbt = b.finish().expect("failed to craft anchor spend template");
			let opts = SignOptions {
				trust_witness_utxo: true,
				..Default::default()
			};
			let finalized = self.wallet.sign(&mut psbt, opts)
				.expect("failed to sign anchor spend template");
			assert!(finalized);
			let tx = psbt.extract_tx()?;
			debug_assert_eq!(tx.input[0].witness.size() as u64, fee::DUST_ANCHOR_SPEND_WEIGHT.to_wu());
			tx.weight()
		};

		let total_weight = template_weight + package_weight;
		let total_fee = fee_rate * total_weight;
		let extra_fee_needed = total_fee;

		// Then build actual tx.
		let mut b = self.wallet.build_tx();
		b.only_witness_utxo();
		b.version(3); // for 1p1c package relay
		Self::add_anchors(&mut b, &anchors);
		b.drain_to(change_addr.address.script_pubkey());
		b.fee_absolute(extra_fee_needed);
		let psbt = b.finish().expect("failed to craft anchor spend tx");
		let tx = self.finish_tx(psbt).context("error finalizing anchor spend tx")?;

		Ok(tx)
	}

	pub async fn create_exit_claim_tx(&mut self, inputs: &[exit::ClaimInput]) -> anyhow::Result<Psbt> {
		assert!(!inputs.is_empty());

		let urgent_fee_rate = self.urgent_feerate();

		// Since BDK doesn't allow tx without recipients, we add a drain output.
		let change_addr = self.wallet.reveal_next_address(bdk_wallet::KeychainKind::Internal);

		let mut b = self.wallet.build_tx();
		b.version(2);
		for input in inputs {
			let mut psbt_in = psbt::Input::default();
			psbt_in.set_claim_input(input);
			psbt_in.witness_utxo = Some(TxOut {
				script_pubkey: input.spec.exit_spk(),
				value: input.spec.amount,
			});
			b.add_foreign_utxo_with_sequence(
				input.utxo,
				psbt_in,
				input.satisfaction_weight(),
				Sequence::from_height(input.spec.exit_delta),
			).expect("error adding foreign utxo for claim input");
		}
		b.drain_to(change_addr.address.script_pubkey());
		b.fee_rate(urgent_fee_rate);

		Ok(b.finish().context("failed to craft claim tx")?)
	}
}

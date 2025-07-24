use std::ops::{Deref, DerefMut};
use std::time::{SystemTime, UNIX_EPOCH};
use std::sync::Arc;

use anyhow::Context;
use bdk_bitcoind_rpc::NO_EXPECTED_MEMPOOL_TXIDS;
use bdk_esplora::EsploraAsyncExt;
use bdk_wallet::chain::ChainPosition;
use bitcoin_ext::bdk::{CpfpError, WalletExt};
use log::{debug, info, warn};

use bdk_wallet::Wallet as BdkWallet;
use bdk_wallet::coin_selection::DefaultCoinSelectionAlgorithm;
use bdk_wallet::{Balance, KeychainKind, LocalOutput, SignOptions, TxBuilder, TxOrdering};
use bitcoin::{
	bip32, psbt, Address, Amount, FeeRate, Network, Psbt, Sequence, Transaction, TxOut, Txid
};
use json::exit::ExitState;

use crate::onchain::chain::InnerChainSourceClient;
use crate::onchain::{
	ChainSourceClient,
	LocalUtxo,
	PrepareBoardTx,
	GetBalance,
	GetSpendingTx,
	GetWalletTx,
	SignPsbt,
	MakeCpfp,
	Utxo,
};
use crate::exit::vtxo::ExitVtxo;
use crate::persist::BarkPersister;
use crate::psbtext::PsbtInputExt;

impl From<LocalOutput> for LocalUtxo {
	fn from(value: LocalOutput) -> Self {
		LocalUtxo {
			outpoint: value.outpoint,
			amount: value.txout.value,
			confirmation_height: value.chain_position.confirmation_height_upper_bound(),
		}
	}
}

/// Trait extension for TxBuilder to add exit outputs
///
/// When used, the resulting PSBT should be signed using [`crate::exit::Exit::sign_psbt`]
pub trait TxBuilderExt {
	fn add_exit_claim_inputs(&mut self, exit_outputs: &[&ExitVtxo]) -> anyhow::Result<()>;
}

impl<Cs> TxBuilderExt for TxBuilder<'_, Cs> {
	fn add_exit_claim_inputs(&mut self, exit_outputs: &[&ExitVtxo]) -> anyhow::Result<()> {
		self.version(2);

		for input in exit_outputs {
			if !matches!(input.state(), ExitState::Spendable(..)) {
				bail!("VTXO exit is not spendable");
			}

			let vtxo = input.vtxo();

			let mut psbt_in = psbt::Input::default();
			psbt_in.set_exit_claim_input(&vtxo);
			psbt_in.witness_utxo = Some(TxOut {
				script_pubkey: vtxo.output_script_pubkey(),
				value: vtxo.amount(),
			});

			self.add_foreign_utxo_with_sequence(
				vtxo.point(),
				psbt_in,
				vtxo.claim_satisfaction_weight(),
				Sequence::from_height(vtxo.exit_delta()),
			).expect("error adding foreign utxo for claim input");
		}

		Ok(())
	}
}

impl <W: Deref<Target = BdkWallet>> GetBalance for W {
	fn get_balance(&self) -> Amount {
		self.deref().balance().total()
	}
}

impl SignPsbt for BdkWallet {
	fn finish_tx(&mut self, mut psbt: Psbt) -> anyhow::Result<Transaction> {
		let opts = SignOptions {
			trust_witness_utxo: true,
			..Default::default()
		};

		let finalized = self.sign(&mut psbt, opts).context("signing error")?;
		assert!(finalized);
		let tx = psbt.extract_tx()?;
		let unix = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
		self.apply_unconfirmed_txs([(tx.clone(), unix)]);
		Ok(tx)
	}
}

impl <W: Deref<Target = BdkWallet>> GetWalletTx for W {
	/// Retrieves a transaction from the wallet
	///
	/// This method will only check the database and will not
	/// use a chain-source to find the transaction
	fn get_wallet_tx(&self, txid: Txid) -> Option<Arc<Transaction>> {
		self.deref().get_tx(txid).map(|tx| tx.tx_node.tx)
	}
}

impl <W: DerefMut<Target = BdkWallet> + SignPsbt> PrepareBoardTx for W {
	fn prepare_board_funding_tx<T: IntoIterator<Item = (Address, Amount)>>(
		&mut self,
		outputs: T,
		fee_rate: FeeRate,
	) -> anyhow::Result<Psbt> {
		let mut b = self.deref_mut().build_tx();
		b.ordering(TxOrdering::Untouched);
		for (dest, amount) in outputs {
			b.add_recipient(dest.script_pubkey(), amount);
		}
		b.fee_rate(fee_rate);
		Ok(b.finish()?)
	}

	fn prepare_board_all_funding_tx(&mut self, fee_rate: FeeRate) -> anyhow::Result<Psbt> {
		let throwaway_addr = self.deref().peek_address(KeychainKind::External, u32::MIN).address;
		let mut b = self.deref_mut().build_tx();
		b.drain_to(throwaway_addr.script_pubkey());
		b.drain_wallet();
		b.fee_rate(fee_rate);
		b.finish().context("error building tx")
	}
}

impl <W: Deref<Target = BdkWallet>> GetSpendingTx for W {
	fn get_spending_tx(&self, txid: Txid) -> Option<Arc<Transaction>> {
		for transaction in self.deref().transactions() {
			if transaction.tx_node.tx.input.iter().any(|i| i.previous_output.txid == txid) {
				return Some(transaction.tx_node.tx);
			}
		}
		None
	}
}

impl <W: DerefMut<Target = BdkWallet>> MakeCpfp for W {
	fn make_p2a_cpfp(&mut self, tx: &Transaction, fee_rate: FeeRate) -> Result<Psbt, CpfpError> {
		WalletExt::make_p2a_cpfp(self.deref_mut(), tx, fee_rate)
	}
}

/// A basic wrapper around the bdk wallet to showcase
/// how to use bark with an external onchain wallet.
///
/// Note: BDK wallet already implements all the traits
/// to be used as an onboard and exit wallet, so that
/// wrapper only needs to proxy the methods.
pub struct OnchainWallet {
	pub inner: BdkWallet,
	db: Arc<dyn BarkPersister>,
}

impl Deref for OnchainWallet {
	type Target = BdkWallet;

	fn deref(&self) -> &Self::Target {
		&self.inner
	}
}

impl DerefMut for OnchainWallet {
	fn deref_mut(&mut self) -> &mut Self::Target {
		&mut self.inner
	}
}

impl OnchainWallet {
	pub fn load_or_create(network: Network, seed: [u8; 64], db: Arc<dyn BarkPersister>) -> anyhow::Result<Self> {
		let xpriv = bip32::Xpriv::new_master(network, &seed).expect("valid seed");
		let desc = bdk_wallet::template::Bip86(xpriv, KeychainKind::External);

		let changeset = db.initialize_bdk_wallet().context("error reading bdk wallet state")?;
		let wallet_opt = bdk_wallet::Wallet::load()
			.descriptor(bdk_wallet::KeychainKind::External, Some(desc.clone()))
			.extract_keys()
			.check_network(network)
			.load_wallet_no_persist(changeset)?;

		let wallet = match wallet_opt {
			Some(wallet) => wallet,
			None => bdk_wallet::Wallet::create_single(desc)
				.network(network)
				.create_wallet_no_persist()?,
		};

		Ok(Self { inner: wallet, db })
	}
}

impl SignPsbt for OnchainWallet {
	fn finish_tx(&mut self, psbt: Psbt) -> anyhow::Result<Transaction> {
		let tx = self.inner.finish_tx(psbt)?;
		self.persist()?;
		Ok(tx)
	}
}

impl OnchainWallet {
	pub fn balance(&self) -> Balance {
		self.inner.balance()
	}

	pub fn list_unspent(&self) -> Vec<LocalOutput> {
		self.inner.list_unspent().collect()
	}

	pub fn address(&mut self) -> anyhow::Result<Address> {
		let ret = self.inner.reveal_next_address(bdk_wallet::KeychainKind::External).address;
		self.persist()?;
		Ok(ret)
	}

	pub fn utxos(&self) -> Vec<Utxo> {
		self.list_unspent().into_iter().map(|o| Utxo::Local(o.into())).collect()
	}

	pub async fn send(&mut self, chain: &ChainSourceClient, dest: Address, amount: Amount, fee_rate: FeeRate
	)	-> anyhow::Result<Txid> {
		let psbt = self.prepare_board_funding_tx([(dest, amount)], fee_rate)?;
		let tx = self.finish_tx(psbt)?;
		chain.broadcast_tx(&tx).await?;
		Ok(tx.compute_txid())
	}

	pub async fn send_many<T: IntoIterator<Item = (Address, Amount)>>(
		&mut self, chain: &ChainSourceClient, dests: T, fee_rate: FeeRate
	) -> anyhow::Result<Txid> {
		let pbst = self.prepare_board_funding_tx(dests, fee_rate)?;
		let tx = self.finish_tx(pbst)?;
		chain.broadcast_tx(&tx).await?;
		Ok(tx.compute_txid())
	}


	pub async fn drain(&mut self, chain: &ChainSourceClient, addr: Address, fee_rate: FeeRate) -> anyhow::Result<Txid> {
		let mut b = self.inner.build_tx();
		b.drain_to(addr.script_pubkey());
		b.drain_wallet();
		b.fee_rate(fee_rate);
		let psbt = b.finish().context("error building tx")?;

		let tx = self.finish_tx(psbt)?;
		chain.broadcast_tx(&tx).await?;
		Ok(tx.compute_txid())
	}

	pub fn build_tx(&mut self) -> TxBuilder<'_, DefaultCoinSelectionAlgorithm> {
		self.inner.build_tx()
	}

	pub async fn sync(&mut self, chain: &ChainSourceClient) -> anyhow::Result<Amount> {
		debug!("Starting wallet sync...");
		let now = SystemTime::now().duration_since(UNIX_EPOCH).expect("now").as_secs();

		let prev_tip = self.inner.latest_checkpoint();
		match chain.inner() {
			InnerChainSourceClient::Bitcoind(ref bitcoind) => {
				debug!("Syncing with bitcoind, starting at block height {}...", prev_tip.height());
				let mut emitter = bdk_bitcoind_rpc::Emitter::new(
					bitcoind, prev_tip.clone(), prev_tip.height(),
					NO_EXPECTED_MEMPOOL_TXIDS,
				);
				let mut count = 0;
				while let Some(em) = emitter.next_block()? {
					self.inner.apply_block_connected_to(
						&em.block, em.block_height(), em.connected_to(),
					)?;
					count += 1;

					if count % 10_000 == 0 {
						self.persist()?;
						info!("Synced until block height {}", em.block_height());
					}
				}

				let mempool = emitter.mempool()?;
				self.inner.apply_evicted_txs(mempool.evicted_ats());
				self.inner.apply_unconfirmed_txs(mempool.new_txs);
				self.persist()?;
				debug!("Finished syncing with bitcoind, {}", self.inner.balance());
			},
			InnerChainSourceClient::Esplora(ref client) => {
				debug!("Syncing with esplora...");
				const STOP_GAP: usize = 50;
				const PARALLEL_REQS: usize = 4;

				let request = self.inner.start_full_scan();
				let update = client.full_scan(request, STOP_GAP, PARALLEL_REQS).await?;
				self.inner.apply_update(update)?;
				self.persist()?;
				debug!("Finished syncing with esplora, {}", self.inner.balance());
			},
		}

		let balance = self.inner.balance();

		// Ultimately, let's try to rebroadcast all our unconfirmed txs.
		let transactions = self.inner.transactions().filter(|tx| {
			if let ChainPosition::Unconfirmed { last_seen, .. } = tx.chain_position {
				match last_seen {
					Some(last_seen) => last_seen < now,
					None => true,
				}
			} else {
				false
			}
		}).collect::<Vec<_>>();
		for tx in transactions {
			if let Err(e) = chain.broadcast_tx(&tx.tx_node.tx).await {
				warn!("Error broadcasting tx {}: {}", tx.tx_node.txid, e);
			}
		}

		Ok(balance.total())
	}

	fn persist(&mut self) -> anyhow::Result<()> {
		if let Some(stage) = self.inner.staged() {
			self.db.store_bdk_wallet_changeset(&*stage)?;
			let _ = self.inner.take_staged();
		}
		Ok(())
	}
}
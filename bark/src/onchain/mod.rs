
mod chain;

use std::time::{SystemTime, UNIX_EPOCH};
use std::sync::Arc;

use anyhow::Context;
use bdk_wallet::coin_selection::BranchAndBoundCoinSelection;
use bdk_wallet::{LocalOutput, SignOptions, TxBuilder, TxOrdering, Wallet as BdkWallet};
use bitcoin::{
	bip32, psbt, sighash, Address, Amount, FeeRate, Network, Psbt, Sequence, Transaction, TxOut,
	Txid,
};
use log::error;

use ark::util::SECP;
use ark::Vtxo;
use bitcoin_ext::{BlockHeight, FeeRateExt};

use crate::VtxoSeed;
use crate::persist::BarkPersister;
use crate::psbtext::PsbtInputExt;
pub use crate::onchain::chain::{ChainSource, ChainSourceClient, FeeRates};

#[derive(Debug, Clone)]
pub enum Utxo {
	Local(LocalOutput),
	Exit(SpendableExit),
}

#[derive(Debug, Clone)]
pub struct SpendableExit {
	pub vtxo: Vtxo,
	pub height: BlockHeight,
}

pub trait TxBuilderExt {
	fn add_exit_outputs(&mut self, exit_outputs: &[SpendableExit]);
}

impl TxBuilderExt for TxBuilder<'_, BranchAndBoundCoinSelection> {
	fn add_exit_outputs(&mut self, exit_outputs: &[SpendableExit]) {
		self.version(2);

		for input in exit_outputs {
			let mut psbt_in = psbt::Input::default();
			psbt_in.set_exit_claim_input(&input.vtxo);
			psbt_in.witness_utxo = Some(TxOut {
				script_pubkey: input.vtxo.output_script_pubkey(),
				value: input.vtxo.amount(),
			});

			self.add_foreign_utxo_with_sequence(
				input.vtxo.point(),
				psbt_in,
				input.vtxo.claim_satisfaction_weight(),
				Sequence::from_height(input.vtxo.exit_delta()),
			).expect("error adding foreign utxo for claim input");
		}
	}
}

pub struct Wallet {
	/// NB: onchain wallet needs to be able to reconstruct
	/// vtxo keypair in order to sign vtxo exit output if any
	seed: [u8; 64],
	network: Network,

	pub(crate) wallet: BdkWallet,
	pub(crate) db: Arc<dyn BarkPersister>,
	pub(crate) fee_rates: FeeRates,
	pub(crate) fallback_fee: Option<FeeRate>,

	pub(crate) exit_outputs: Vec<SpendableExit>,
	pub(crate) chain: ChainSourceClient,
	chain_source: ChainSource,
}

impl Wallet {
	pub fn create(
		network: Network,
		seed: [u8; 64],
		db: Arc<dyn BarkPersister>,
		chain_source: ChainSource,
		fallback_fee: Option<FeeRate>,
	) -> anyhow::Result<Wallet> {
		let xpriv = bip32::Xpriv::new_master(network, &seed).expect("valid seed");
		let desc = format!("tr({}/84'/0'/0'/0/*)", xpriv);

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

		let chain = ChainSourceClient::new(chain_source.clone())?;
		let fee = fallback_fee.unwrap_or(FeeRate::BROADCAST_MIN);
		let fee_rates = FeeRates { fast: fee, regular: fee, slow: fee };

		Ok(Wallet {
			seed,
			network,

			wallet,
			db,
			fee_rates,
			fallback_fee,

			chain,
			chain_source,
			exit_outputs: vec![]
		})
	}

	pub fn require_chainsource_version(&self) -> anyhow::Result<()> {
		self.chain.require_version()
	}

	pub async fn tip(&self) -> anyhow::Result<BlockHeight> {
		self.chain.tip().await
	}

	pub (crate) async fn broadcast_tx(&self, tx: &Transaction) -> anyhow::Result<()> {
		self.chain.broadcast_tx(tx).await
	}

	pub fn persist(&mut self) -> anyhow::Result<()> {
		if let Some(stage) = self.wallet.staged() {
			self.db.store_bdk_wallet_changeset(&*stage)?;
			let _ = self.wallet.take_staged();
		}
		Ok(())
	}

	/// Sync the onchain wallet and returns the balance.
	pub async fn sync(&mut self) -> anyhow::Result<Amount> {
		//TODO improve this..
		let chain = ChainSourceClient::new(self.chain_source.clone())?;
		self.update_fee_rates().await?;
		Ok(chain.sync_wallet(self).await?)
	}

	/// Gets the current fee rates from the chain source, falling back to user-specified values if
	/// necessary
	pub async fn update_fee_rates(&mut self) -> anyhow::Result<()> {
		let fee_rates = match (self.chain.fee_rates().await, self.fallback_fee) {
			(Ok(fee_rates), _) => Ok(fee_rates),
			(Err(e), None) => Err(e),
			(Err(e), Some(fallback)) => {
				error!("Error getting fee rates, falling back to {} sat/kvB: {}", 
					fallback.to_btc_per_kvb(), e,
				);
				Ok(FeeRates { fast: fallback, regular: fallback, slow: fallback })
			}
		};
		self.fee_rates = fee_rates?;
		Ok(())
	}

	/// Return the balance of the onchain wallet.
	///
	/// Make sure you sync before calling this method.
	pub fn balance(&self) -> Amount {
		let exit_total = self.exit_outputs.iter().fold(Amount::ZERO, |acc, v| acc + v.vtxo.amount());
		self.wallet.balance().total() + exit_total
	}

	pub fn utxos(&self) -> Vec<Utxo> {
		let mut utxos = self.wallet.list_unspent().map(|o| Utxo::Local(o)).collect::<Vec<_>>();
		utxos.extend(self.exit_outputs.clone().into_iter().map(|e| Utxo::Exit(e)));

		utxos
	}

	pub (crate) fn prepare_tx<T: IntoIterator<Item = (Address, Amount)>>(
		&mut self,
		outputs: T,
	) -> anyhow::Result<Psbt> {
		let fee_rate = self.fee_rates.regular;
		let mut b = self.wallet.build_tx();
		b.add_exit_outputs(&self.exit_outputs.clone());
		b.ordering(TxOrdering::Untouched);
		for (dest, amount) in outputs {
			b.add_recipient(dest.script_pubkey(), amount);
		}
		b.fee_rate(fee_rate);
		Ok(b.finish()?)
	}

	pub (crate) fn prepare_send_all_tx(&mut self, dest: Address) -> anyhow::Result<Psbt> {
		let fee_rate = self.fee_rates.regular;
		let mut b = self.wallet.build_tx();
		b.add_exit_outputs(&self.exit_outputs.clone());
		b.drain_to(dest.script_pubkey());
		b.drain_wallet();
		b.fee_rate(fee_rate);
		b.finish().context("error building tx")
	}

	fn sign_exit_inputs(&self, psbt: &mut Psbt) -> anyhow::Result<()> {
		let vtxo_seed = VtxoSeed::new(self.network, &self.seed);

		let prevouts = psbt.inputs.iter()
			.map(|i| i.witness_utxo.clone().unwrap())
			.collect::<Vec<_>>();

		let prevouts = sighash::Prevouts::All(&prevouts);
		let mut shc = sighash::SighashCache::new(&psbt.unsigned_tx);

		for (i, input) in psbt.inputs.iter_mut().enumerate() {
			let vtxo = input.get_exit_claim_input();

			if let Some(vtxo) = vtxo {
				let (keychain, keypair_idx) = self.db.get_vtxo_key(&vtxo)?;
				let keypair = vtxo_seed.derive_keychain(keychain, keypair_idx);

				input.maybe_sign_exit_claim_input(
					&SECP,
					&mut shc,
					&prevouts,
					i,
					&keypair
				)?;
			}
		}

		Ok(())
	}

	pub (crate) fn finish_tx(&mut self, mut psbt: Psbt) -> anyhow::Result<Transaction> {
		self.sign_exit_inputs(&mut psbt)?;

		let opts = SignOptions {
			trust_witness_utxo: true,
			..Default::default()
		};
		let finalized = self.wallet.sign(&mut psbt, opts).context("signing error")?;
		assert!(finalized);
		let tx = psbt.extract_tx()?;
		let unix = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
		self.wallet.apply_unconfirmed_txs([(tx.clone(), unix)]);
		self.persist()?;
		Ok(tx)
	}

	pub async fn send(&mut self, dest: Address, amount: Amount) -> anyhow::Result<Txid> {
		let psbt = self.prepare_tx([(dest, amount)])?;
		let tx = self.finish_tx(psbt)?;
		self.broadcast_tx(&tx).await?;
		Ok(tx.compute_txid())
	}

	pub async fn send_many<T: IntoIterator<Item = (Address, Amount)>>(
		&mut self, dests: T
	) -> anyhow::Result<Txid> {
		let pbst = self.prepare_tx(dests)?;
		let tx = self.finish_tx(pbst)?;
		self.broadcast_tx(&tx).await?;
		Ok(tx.compute_txid())
	}

	pub async fn drain(&mut self, dest: Address) -> anyhow::Result<Txid> {
		let psbt = self.prepare_send_all_tx(dest)?;
		let tx = self.finish_tx(psbt)?;
		self.broadcast_tx(&tx).await?;
		Ok(tx.compute_txid())
	}

	/// Reveals a new onchain address
	///
	/// The revealed address is directly persisted, so calling this method twice in a row will result in 2 different addresses
	pub fn address(&mut self) -> anyhow::Result<Address> {
		let ret = self.wallet.reveal_next_address(bdk_wallet::KeychainKind::External).address;
		self.persist()?;
		Ok(ret)
	}

	/// Retrieves a transaction from the wallet
	///
	/// This method will only check the database and will not
	/// use a chain-source to find the transaction
	pub fn get_wallet_tx(&self, txid: Txid) -> Option<Arc<Transaction>> {
		let tx = self.wallet
			.get_tx(txid)?
			.tx_node.tx;

		Some(tx.clone())
	}

	/// Searches for a spending transaction from the given txid
	///
	/// This method will only check the database and will not
	/// use a chain-source to find the transaction
	pub fn get_spending_tx(&self, txid: Txid) -> Option<Arc<Transaction>> {
		for transaction in self.wallet.transactions() {
			if transaction.tx_node.tx.input.iter().any(|i| i.previous_output.txid == txid) {
				return Some(transaction.tx_node.tx);
			}
		}
		None
	}

	pub(crate) fn track_spendable_exit(&mut self, vtxo: &Vtxo, spendable_since: BlockHeight) {
		let p = vtxo.point();
		if self.exit_outputs.iter().any(|e| e.vtxo.point() == p) {
			return;
		}
		self.exit_outputs.push(SpendableExit {
			vtxo: vtxo.clone(),
			height: spendable_since,
		})
	}

	pub(crate) fn remove_spendable_exit(&mut self, vtxo: &Vtxo) {
		let p = vtxo.point();
		let index = self.exit_outputs.iter().position(|e| e.vtxo.point() == p);
		if let Some(index) = index {
			self.exit_outputs.swap_remove(index);
		}
	}
}


use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Context;
use bdk_wallet::{SignOptions, Wallet};
use bitcoin::{hex::DisplayHex, Psbt, Transaction};

use bitcoin_ext::bdk::WalletExt;

use crate::database::Db;


/// aspd-specific extension trait for the BDK [Wallet] struct.
#[async_trait]
pub trait BdkWalletExt: WalletExt {
	/// Persist the committed wallet changes to the database.
	async fn persist(&mut self, db: &Db) -> anyhow::Result<()> {
		if let Some(change) = self.borrow_mut().take_staged() {
			db.store_changeset(&change).await
				.context("error persisting wallet changes to db")?;
		}
		Ok(())
	}

	/// Finish the PSBT by signing it and committing it to the wallet.
	///
	/// This method does not persist changes to the databse.
	fn finish_tx(&mut self, mut psbt: Psbt) -> anyhow::Result<Transaction> {
		let opts = SignOptions {
			trust_witness_utxo: true,
			..Default::default()
		};
		let wallet = self.borrow_mut();
		let finalized = wallet.sign(&mut psbt, opts).context("error signing psbt")?;
		ensure!(finalized, "tx not finalized after signing, psbt: {}", psbt.serialize().as_hex());
		Ok(psbt.extract_tx().context("error extracting finalized tx from psbt")?)
	}

	/// Commit the tx into our BDK wallet.
	fn commit_tx(&mut self, tx: &Transaction) {
		let now = SystemTime::now().duration_since(UNIX_EPOCH)
			.expect("Unix epoch is in the past").as_secs();
		self.borrow_mut().apply_unconfirmed_txs([(tx.clone(), now)]);
	}
}
impl BdkWalletExt for Wallet {}


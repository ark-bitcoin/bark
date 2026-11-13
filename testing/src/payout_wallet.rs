//! A Bitcoin wallet that holds only the expiry payout key of a bark seed, to
//! check that the seed alone can spend an expiry payout.

use anyhow::Context;
use bdk_wallet::signer::SignersContainer;
use bdk_wallet::{KeychainKind, Wallet};
use bitcoin::{Address, FeeRate, Network, OutPoint, PrivateKey, ScriptBuf, Txid};
use bitcoin::bip32::{DerivationPath, Xpriv};
use bitcoin_ext::bdk::WalletExt;
use bitcoin_ext::rpc::RpcApi;

use crate::Bitcoind;

pub struct PayoutWallet {
	wallet: Wallet,
	signers: SignersContainer,
	script: ScriptBuf,
}

impl PayoutWallet {
	/// Restore the wallet of the mailbox key of a bark seed.
	pub fn restore(seed: &[u8; 64], network: Network) -> anyhow::Result<Self> {
		let path = "m/350'/1'".parse::<DerivationPath>()?;
		let keypair = Xpriv::new_master(network, seed)?.derive_priv(&ark::SECP, &path)?.to_keypair(&ark::SECP);
		let descriptor = format!("tr({})", PrivateKey::new(keypair.secret_key(), network));
		let mut wallet = Wallet::create_single(descriptor.clone())
			.network(network).create_wallet_no_persist()?;
		let signers = wallet.build_signers(&descriptor)?;
		let script = wallet.reveal_next_address(KeychainKind::External).address.script_pubkey();
		Ok(Self { wallet, signers, script })
	}

	pub fn script(&self) -> &ScriptBuf {
		&self.script
	}

	/// Scan the chain from genesis.
	pub fn rescan(&mut self, bitcoind: &Bitcoind) -> anyhow::Result<()> {
		let rpc = bitcoind.sync_client();
		let mut emitter = bdk_bitcoind_rpc::Emitter::new(
			&rpc, self.wallet.latest_checkpoint(), 0, self.wallet.unconfirmed_txs());
		while let Some(block) = emitter.next_block()? {
			self.wallet.apply_block_connected_to(&block.block, block.block_height(), block.connected_to())?;
		}
		self.wallet.apply_unconfirmed_txs(emitter.mempool()?.update);
		Ok(())
	}

	/// Spend the payout output `payout` to `destination` and broadcast it.
	pub fn spend(
		&mut self, bitcoind: &Bitcoind, payout: OutPoint, destination: &Address, fee_rate: FeeRate,
	) -> anyhow::Result<Txid> {
		ensure!(self.wallet.list_unspent().any(|utxo| utxo.outpoint == payout), "payout not found");
		let mut builder = self.wallet.build_tx();
		builder.drain_to(destination.script_pubkey()).drain_wallet().fee_rate(fee_rate);
		let mut psbt = builder.finish().context("building the payout spend")?;
		let finalized = self.wallet.sign_with_signers(&mut psbt, &[&self.signers], Default::default())?;
		ensure!(finalized, "failed to sign the payout spend");
		let tx = psbt.extract_tx()?;
		ensure!(tx.input.len() == 1 && tx.input[0].previous_output == payout, "the spend has other inputs");
		Ok(bitcoind.sync_client().send_raw_transaction(&tx)?)
	}
}

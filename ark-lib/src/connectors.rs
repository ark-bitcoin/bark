

use std::iter;

use bitcoin::{
	Address, Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut,
	Weight, Witness,
};
use bitcoin::secp256k1::{Keypair, PublicKey};
use bitcoin::sighash::{self, SighashCache, TapSighashType};

use crate::{fee, util};
use crate::util::KeypairExt;


/// The size in vbytes of each connector tx.
const TX_WEIGHT: Weight = Weight::from_vb_unchecked(154);
pub const INPUT_WEIGHT: Weight = Weight::from_wu(66);


/// A chain of connector outputs.
///
/// Each connector is a p2tr keyspend output for the provided key.
/// Each connector has the p2tr dust value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectorChain {
	len: usize,
	spk: ScriptBuf,
	utxo: OutPoint,
}

impl ConnectorChain {
	/// The total size in vbytes of the connector tree.
	pub fn total_weight(len: usize) -> Weight {
		assert_ne!(len, 0);
		(len - 1) as u64 * TX_WEIGHT
	}

	/// The budget needed for a chain of length [len] to pay for
	/// - dust on 2 outputs per tx
	/// - minrelayfee per tx
	pub fn required_budget(len: usize) -> Amount {
		assert_ne!(len, 0);

		// We need n times dust for connectors.
		fee::DUST * len as u64
	}

	/// Create the scriptPubkey to create a connector chain using the given publick key.
	pub fn output_script(pubkey: PublicKey) -> ScriptBuf {
		ScriptBuf::new_p2tr(&util::SECP, pubkey.x_only_public_key().0, None)
	}

	/// Create the address to create a connector chain using the given publick key.
	pub fn address(network: Network, pubkey: PublicKey) -> Address {
		Address::from_script(&Self::output_script(pubkey), network).unwrap()
	}

	/// Create a connector output.
	pub fn output(len: usize, pubkey: PublicKey) -> TxOut {
		TxOut {
			script_pubkey: Self::output_script(pubkey),
			value: Self::required_budget(len),
		}
	}

	/// Create a new connector tree.
	///
	/// Before calling this method, a utxo should be created with a scriptPubkey
	/// as specified by [ConnectorChain::output_script] or [ConnectorChain::address].
	/// The amount in this output is expected to be exaclty equal to
	/// [ConnectorChain::required_budget].
	pub fn new(len: usize, utxo: OutPoint, pubkey: PublicKey) -> ConnectorChain {
		assert_ne!(len, 0);
		let spk = Self::output_script(pubkey);

		ConnectorChain { len, spk, utxo }
	}

	pub fn len(&self) -> usize {
		self.len
	}

	fn tx(&self, prev: OutPoint, idx: usize) -> Transaction {
		Transaction {
			version: bitcoin::transaction::Version(3),
			lock_time: bitcoin::absolute::LockTime::ZERO,
			input: vec![TxIn {
				previous_output: prev,
				script_sig: ScriptBuf::new(),
				sequence: Sequence::MAX,
				witness: Witness::new(),
			}],
			output: vec![
				TxOut {
					script_pubkey: self.spk.to_owned(),
					value: ConnectorChain::required_budget(self.len - idx - 1),
				},
				TxOut {
					script_pubkey: self.spk.to_owned(),
					value: fee::DUST,
				},
			],
		}
	}

	fn sign_tx(&self, tx: &mut Transaction, idx: usize, keypair: &Keypair) {
		let prevout = TxOut {
			script_pubkey: self.spk.to_owned(),
			value: ConnectorChain::required_budget(self.len - idx),
		};
		let mut shc = SighashCache::new(&*tx);
		let sighash = shc.taproot_key_spend_signature_hash(
			0, &sighash::Prevouts::All(&[&prevout]), TapSighashType::Default,
		).expect("sighash error");
		let sig = util::SECP.sign_schnorr(&sighash.into(), &keypair);
		tx.input[0].witness = Witness::from_slice(&[sig[..].to_vec()]);
	}

	/// Iterator over the signed transactions in this chain.
	pub fn iter_signed_txs<'a>(&'a self, sign_key: &'a Keypair) -> ConnectorTxIter<'a> {
		ConnectorTxIter {
			chain: self,
			sign_key: Some(sign_key.for_keyspend()),
			prev: self.utxo,
			idx: 0,
		}
	}

	/// Iterator over the transactions in this chain.
	pub fn iter_unsigned_txs(&self) -> ConnectorTxIter {
		ConnectorTxIter {
			chain: self,
			sign_key: None,
			prev: self.utxo,
			idx: 0,
		}
	}

	/// Iterator over the connector outpoints in this chain.
	pub fn connectors<'a>(&'a self) -> ConnectorIter<'a> {
		ConnectorIter {
			txs: self.iter_unsigned_txs(),
			maybe_last: Some(self.utxo),
		}
	}
}

pub struct ConnectorTxIter<'a> {
	chain: &'a ConnectorChain,
	sign_key: Option<Keypair>,

	prev: OutPoint,
	idx: usize,
}

impl<'a> iter::Iterator for ConnectorTxIter<'a> {
	type Item = Transaction;

	fn next(&mut self) -> Option<Self::Item> {
		if self.idx >= self.chain.len - 1 {
			return None;
		}

		let mut ret = self.chain.tx(self.prev, self.idx);
		if let Some(ref keypair) = self.sign_key {
			self.chain.sign_tx(&mut ret, self.idx, keypair);
		}

		self.idx += 1;
		self.prev = OutPoint::new(ret.compute_txid(), 0);
		Some(ret)
	}

	fn size_hint(&self) -> (usize, Option<usize>) {
		let s = self.chain.len - 1;
		(s, Some(s))
	}
}

pub struct ConnectorIter<'a> {
	txs: ConnectorTxIter<'a>,
	// On all intermediate txs, only the second output is a connector and
	// the first output continues the chain. On the very last tx, both
	// outputs are connectors. We will keep this variable updated to contain
	// the first output of the last tx we say, so that we can return it once
	// the tx iterator does no longer yield new txs (hence we reached the
	// last tx).
	maybe_last: Option<OutPoint>,
}

impl<'a> iter::Iterator for ConnectorIter<'a> {
	type Item = OutPoint;

	fn next(&mut self) -> Option<Self::Item> {
		if self.maybe_last.is_none() {
			return None;
		}

		if let Some(tx) = self.txs.next() {
			let txid = tx.compute_txid();
			self.maybe_last = Some(OutPoint::new(txid, 0));
			Some(OutPoint::new(txid, 1))
		} else {
			Some(self.maybe_last.take().expect("broken"))
		}
	}

	fn size_hint(&self) -> (usize, Option<usize>) {
		(self.txs.chain.len, Some(self.txs.chain.len))
	}
}

impl<'a> iter::ExactSizeIterator for ConnectorTxIter<'a> {}
impl<'a> iter::FusedIterator for ConnectorTxIter<'a> {}


#[cfg(test)]
mod test {
	use super::*;
	use bitcoin::Txid;
	use bitcoin::hashes::Hash;
	use rand;

	#[test]
	fn test_budget() {
		let key = Keypair::new(&util::SECP, &mut rand::thread_rng());
		let utxo = OutPoint::new(Txid::all_zeros(), 0);

		let chain = ConnectorChain::new(1, utxo, key.public_key());
		assert_eq!(chain.connectors().count(), 1);
		assert_eq!(chain.iter_unsigned_txs().count(), 0);
		assert_eq!(chain.connectors().next().unwrap(), utxo);

		let chain = ConnectorChain::new(2, utxo, key.public_key());
		assert_eq!(chain.connectors().count(), 2);
		assert_eq!(chain.iter_unsigned_txs().count(), 1);
		assert_eq!(chain.iter_signed_txs(&key).count(), 1);
		let tx = chain.iter_signed_txs(&key).next().unwrap();
		assert_eq!(TX_WEIGHT, tx.weight());

		let chain = ConnectorChain::new(100, utxo, key.public_key());
		assert_eq!(chain.connectors().count(), 100);
		assert_eq!(chain.iter_unsigned_txs().count(), 99);
		assert_eq!(chain.iter_signed_txs(&key).count(), 99);
		for tx in chain.iter_signed_txs(&key) {
			assert_eq!(tx.weight(), TX_WEIGHT);
			assert_eq!(tx.input[0].witness.size(), INPUT_WEIGHT.to_wu() as usize);
		}
		let weight = chain.iter_signed_txs(&key).map(|t| t.weight()).sum::<Weight>();
		assert_eq!(weight, ConnectorChain::total_weight(100));
		chain.iter_unsigned_txs().for_each(|t| assert_eq!(t.output[1].value, fee::DUST));
		assert_eq!(fee::DUST, chain.iter_unsigned_txs().last().unwrap().output[0].value);

		let total_value = chain.iter_unsigned_txs().map(|t| t.output[1].value).sum::<Amount>()
			+ chain.iter_unsigned_txs().last().unwrap().output[0].value;
		assert_eq!(ConnectorChain::required_budget(100), total_value);

		// random checks
		let mut txs = chain.iter_unsigned_txs();
		assert_eq!(txs.next().unwrap().output[0].value, ConnectorChain::required_budget(99));
		assert_eq!(txs.next().unwrap().output[0].value, ConnectorChain::required_budget(98));
	}

	#[test]
	fn test_signatures() {
		let key = Keypair::new(&util::SECP, &mut rand::thread_rng());
		let utxo = OutPoint::new(Txid::all_zeros(), 0);
		let spk = ConnectorChain::output_script(key.public_key());

		let mut n = 10;
		let chain = ConnectorChain::new(n, utxo, key.public_key());
		for tx in chain.iter_signed_txs(&key) {
			let amount = ConnectorChain::required_budget(n).to_sat();
			let inputs = vec![bitcoinconsensus::Utxo {
				script_pubkey: spk.as_bytes().as_ptr(),
				script_pubkey_len: spk.len() as u32,
				value: amount as i64,
			}];
			bitcoinconsensus::verify(
				spk.as_bytes(),
				amount,
				&bitcoin::consensus::serialize(&tx),
				Some(&inputs),
				0,
			).expect("verification failed");
			n -= 1;
		}
	}
}

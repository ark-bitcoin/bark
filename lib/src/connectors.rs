

use std::iter;
use std::borrow::Cow;

use bitcoin::{
	Address, Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut,
	Weight, Witness,
};
use bitcoin::secp256k1::{Keypair, PublicKey};
use bitcoin::sighash::{self, SighashCache, TapSighashType};
use bitcoin_ext::{fee, KeypairExt, P2TR_DUST};

use crate::SECP;

/// The output index of the connector chain continuation in the connector tx.
///
/// In the last item of the chain, it is a connector output along with
/// output at index 1.
pub const CONNECTOR_TX_CHAIN_VOUT: u32 = 0;
/// The output index of the connector output in the connector tx.
pub const CONNECTOR_TX_CONNECTOR_VOUT: u32 = 1;

/// The weight of each connector tx.
const TX_WEIGHT: Weight = Weight::from_vb_unchecked(167);

/// The witness weight of a connector input.
pub const INPUT_WEIGHT: Weight = Weight::from_wu(66);


/// A chain of connector outputs.
///
/// Each connector is a p2tr keyspend output for the provided key.
/// Each connector has the p2tr dust value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectorChain {
	/// The total number of connectors in the connector chain.
	len: usize,

	/// The scriptPubkey used by all connector outputs.
	spk: ScriptBuf,

	/// The prevout from where the chain starts.
	///
	/// This should be an output of the round transaction.
	utxo: OutPoint,
}

impl ConnectorChain {
	/// The total size in vbytes of the connector tree.
	pub fn total_weight(len: usize) -> Weight {
		assert_ne!(len, 0);
		(len - 1) as u64 * TX_WEIGHT
	}

	/// The budget needed for a chain of length `len` to pay for
	/// one dust for the connector output per tx
	pub fn required_budget(len: usize) -> Amount {
		assert_ne!(len, 0);

		// Each tx of the chain will hold one output to continue the
		// chain + one output for the connector + one fee anchor output
		// So the required budget is 1 dust per connector
		P2TR_DUST * len as u64
	}

	/// Create the scriptPubkey to create a connector chain using the given publick key.
	pub fn output_script(pubkey: PublicKey) -> ScriptBuf {
		ScriptBuf::new_p2tr(&SECP, pubkey.x_only_public_key().0, None)
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
	/// [ConnectorChain::required_budget] for the given length.
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
				// this is the continuation of the chain
				// (or a connector output if the last tx)
				TxOut {
					script_pubkey: self.spk.to_owned(),
					value: ConnectorChain::required_budget(self.len - idx - 1),
				},
				// this is the connector output
				// (or the second one if the last tx)
				TxOut {
					script_pubkey: self.spk.to_owned(),
					value: P2TR_DUST,
				},
				// this is the fee anchor output
				fee::fee_anchor(),
			],
		}
	}

	/// NB we expect the output key here, not the internal key
	fn sign_tx(&self, tx: &mut Transaction, idx: usize, keypair: &Keypair) {
		let prevout = TxOut {
			script_pubkey: self.spk.to_owned(),
			value: ConnectorChain::required_budget(self.len - idx),
		};
		let mut shc = SighashCache::new(&*tx);
		let sighash = shc.taproot_key_spend_signature_hash(
			0, &sighash::Prevouts::All(&[prevout]), TapSighashType::Default,
		).expect("sighash error");
		let sig = SECP.sign_schnorr_with_aux_rand(&sighash.into(), &keypair, &rand::random());
		tx.input[0].witness = Witness::from_slice(&[&sig[..]]);
	}

	/// Iterator over the signed transactions in this chain.
	///
	/// We expect the internal key here, not the output key.
	pub fn iter_signed_txs(
		&self,
		sign_key: &Keypair,
	) -> Result<ConnectorTxIter<'_>, InvalidSigningKeyError> {
		if self.spk == ConnectorChain::output_script(sign_key.public_key()) {
			Ok(ConnectorTxIter {
				chain: Cow::Borrowed(self),
				sign_key: Some(sign_key.for_keyspend(&*SECP)),
				prev: self.utxo,
				idx: 0,
			})
		} else {
			Err(InvalidSigningKeyError)
		}
	}

	/// Iterator over the transactions in this chain.
	pub fn iter_unsigned_txs(&self) -> ConnectorTxIter<'_> {
		ConnectorTxIter {
			chain: Cow::Borrowed(self),
			sign_key: None,
			prev: self.utxo,
			idx: 0,
		}
	}

	/// Iterator over the connector outpoints and unsigned txs in this chain.
	pub fn connectors(&self) -> ConnectorIter<'_> {
		ConnectorIter {
			txs: self.iter_unsigned_txs(),
			maybe_last: Some((self.utxo, None)),
		}
	}

	/// Iterator over the connector outpoints and signed txs in this chain.
	///
	/// We expect the internal key here, not the output key.
	pub fn connectors_signed(
		&self,
		sign_key: &Keypair,
	) -> Result<ConnectorIter<'_>, InvalidSigningKeyError> {
		Ok(ConnectorIter {
			txs: self.iter_signed_txs(sign_key)?,
			maybe_last: Some((self.utxo, None)),
		})
	}
}

/// An iterator over transactions in a [ConnectorChain].
///
/// See [ConnectorChain::iter_unsigned_txs] and
/// [ConnectorChain::iter_signed_txs] for more info.
pub struct ConnectorTxIter<'a> {
	chain: Cow<'a, ConnectorChain>,
	sign_key: Option<Keypair>,

	prev: OutPoint,
	idx: usize,
}

impl<'a> ConnectorTxIter<'a> {
	/// Upgrade this iterator to a signing iterator.
	pub fn signing(&mut self, sign_key: Keypair) {
		self.sign_key = Some(sign_key);
	}

	/// Convert into owned iterator.
	pub fn into_owned(self) -> ConnectorTxIter<'static> {
		ConnectorTxIter {
			chain: Cow::Owned(self.chain.into_owned()),
			sign_key: self.sign_key,
			prev: self.prev,
			idx: self.idx,
		}
	}
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
		self.prev = OutPoint::new(ret.compute_txid(), CONNECTOR_TX_CHAIN_VOUT);
		Some(ret)
	}

	fn size_hint(&self) -> (usize, Option<usize>) {
		let len = (self.chain.len - 1).saturating_sub(self.idx);
		(len, Some(len))
	}
}

/// An iterator over the connectors in a [ConnectorChain].
///
/// See [ConnectorChain::connectors] and [ConnectorChain::connectors_signed]
/// for more info.
pub struct ConnectorIter<'a> {
	txs: ConnectorTxIter<'a>,
	// On all intermediate txs, only the second output is a connector and
	// the first output continues the chain. On the very last tx, both
	// outputs are connectors. We will keep this variable updated to contain
	// the first output of the last tx we say, so that we can return it once
	// the tx iterator does no longer yield new txs (hence we reached the
	// last tx).
	maybe_last: Option<<Self as Iterator>::Item>,
}

impl<'a> ConnectorIter<'a> {
	/// Upgrade this iterator to a signing iterator.
	pub fn signing(&mut self, sign_key: Keypair) {
		self.txs.signing(sign_key)
	}

	/// Convert into owned iterator.
	pub fn into_owned(self) -> ConnectorIter<'static> {
		ConnectorIter {
			txs: self.txs.into_owned(),
			maybe_last: self.maybe_last,
		}
	}
}

impl<'a> iter::Iterator for ConnectorIter<'a> {
	type Item = (OutPoint, Option<Transaction>);

	fn next(&mut self) -> Option<Self::Item> {
		if self.maybe_last.is_none() {
			return None;
		}

		if let Some(tx) = self.txs.next() {
			let txid = tx.compute_txid();
			self.maybe_last = Some((OutPoint::new(txid, CONNECTOR_TX_CHAIN_VOUT), Some(tx.clone())));
			Some((OutPoint::new(txid, CONNECTOR_TX_CONNECTOR_VOUT), Some(tx)))
		} else {
			Some(self.maybe_last.take().expect("broken"))
		}
	}

	fn size_hint(&self) -> (usize, Option<usize>) {
		let len = self.txs.size_hint().0 + 1;
		(len, Some(len))
	}
}

impl<'a> iter::ExactSizeIterator for ConnectorTxIter<'a> {}
impl<'a> iter::FusedIterator for ConnectorTxIter<'a> {}


/// The signing key passed into [ConnectorChain::iter_signed_txs] or
/// [ConnectorChain::connectors_signed] is incorrect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("signing key doesn't match connector chain")]
pub struct InvalidSigningKeyError;


#[cfg(test)]
mod test {
	use bitcoin::Txid;
	use bitcoin::hashes::Hash;
	use bitcoin_ext::TransactionExt;
	use crate::test::verify_tx;
	use super::*;

	#[test]
	fn test_budget() {
		let key = Keypair::new(&SECP, &mut bitcoin::secp256k1::rand::thread_rng());
		let utxo = OutPoint::new(Txid::all_zeros(), 3);

		let chain = ConnectorChain::new(1, utxo, key.public_key());
		assert_eq!(chain.connectors().count(), 1);
		assert_eq!(chain.iter_unsigned_txs().count(), 0);
		assert_eq!(chain.connectors().next().unwrap().0, utxo);

		let chain = ConnectorChain::new(2, utxo, key.public_key());
		assert_eq!(chain.connectors().count(), 2);
		assert_eq!(chain.iter_unsigned_txs().count(), 1);
		assert_eq!(chain.iter_signed_txs(&key).unwrap().count(), 1);
		let tx = chain.iter_signed_txs(&key).unwrap().next().unwrap();
		assert_eq!(TX_WEIGHT, tx.weight());
		assert_eq!(tx.output_value(), ConnectorChain::required_budget(2));

		let chain = ConnectorChain::new(3, utxo, key.public_key());
		assert_eq!(chain.connectors().count(), 3);
		assert_eq!(chain.iter_unsigned_txs().count(), 2);
		let mut txs = chain.iter_signed_txs(&key).unwrap();
		let tx = txs.next().unwrap();
		assert_eq!(TX_WEIGHT, tx.weight());
		assert_eq!(tx.output_value(), ConnectorChain::required_budget(3));
		let tx = txs.next().unwrap();
		assert_eq!(TX_WEIGHT, tx.weight());
		assert_eq!(tx.output_value(), ConnectorChain::required_budget(2));
		assert!(txs.next().is_none());

		let chain = ConnectorChain::new(100, utxo, key.public_key());
		assert_eq!(chain.connectors().count(), 100);
		assert_eq!(chain.iter_unsigned_txs().count(), 99);
		assert_eq!(chain.iter_signed_txs(&key).unwrap().count(), 99);
		let tx = chain.iter_signed_txs(&key).unwrap().next().unwrap();
		assert_eq!(TX_WEIGHT, tx.weight());
		assert_eq!(tx.output_value(), ConnectorChain::required_budget(100));
		for tx in chain.iter_signed_txs(&key).unwrap() {
			assert_eq!(tx.weight(), TX_WEIGHT);
			assert_eq!(tx.input[0].witness.size(), INPUT_WEIGHT.to_wu() as usize);
		}
		let weight = chain.iter_signed_txs(&key).unwrap().map(|t| t.weight()).sum::<Weight>();
		assert_eq!(weight, ConnectorChain::total_weight(100));
		chain.iter_unsigned_txs().for_each(|t| assert_eq!(t.output[1].value, P2TR_DUST));
		assert_eq!(P2TR_DUST, chain.iter_unsigned_txs().last().unwrap().output[0].value);
	}

	#[test]
	fn test_signatures() {
		let key = Keypair::new(&SECP, &mut bitcoin::secp256k1::rand::thread_rng());
		let utxo = OutPoint::new(Txid::all_zeros(), 3);
		let spk = ConnectorChain::output_script(key.public_key());

		let chain = ConnectorChain::new(10, utxo, key.public_key());
		for (i, tx) in chain.iter_signed_txs(&key).unwrap().enumerate() {
			let amount = ConnectorChain::required_budget(chain.len - i);
			let input = TxOut {
				script_pubkey: spk.clone(),
				value: amount,
			};
			verify_tx(&[input], 0, &tx).expect(&format!("invalid connector tx idx {}", i));
		}
	}
}

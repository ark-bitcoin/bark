
use bitcoin::absolute::LockTime;
use bitcoin::secp256k1::schnorr;
use bitcoin::taproot::{self, ControlBlock};
use bitcoin::{Sequence, Witness};
use bitcoin::{secp256k1::PublicKey, ScriptBuf};
use bitcoin_ext::{BlockDelta, BlockHeight};

use crate::lightning::{PaymentHash, Preimage};
use crate::{Vtxo, scripts};

/// A trait describing a VTXO policy clause.
///
/// It can be used when creating the VTXO, specifying the script pubkey,
/// and check the satisfaction weight when spending it.
pub trait TapScriptClause: Sized + Clone {
	/// The type of witness data required to sign the clause.
	type WitnessData;

	/// Returns the tapscript for the clause.
	fn tapscript(&self) -> ScriptBuf;

	fn control_block(&self, vtxo: &Vtxo) -> ControlBlock {
		vtxo.output_taproot()
			.control_block(&(self.tapscript(), taproot::LeafVersion::TapScript))
			.expect("clause is not in taproot tree")
	}

	/// Constructs the witness for the clause.
	fn witness(
		&self,
		data: Self::WitnessData,
		control_block: ControlBlock,
	) -> Witness;
}

/// A clause that allows to sign and spend the UTXO after a relative
/// timelock.
#[derive(Debug, Clone)]
pub struct DelayedSignClause {
	pub pubkey: PublicKey,
	pub block_delta: BlockDelta,
}

impl DelayedSignClause {
	/// Returns the CSV value for this clause.
	pub fn csv(&self) -> Sequence {
		Sequence::from_height(self.block_delta)
	}
}

impl TapScriptClause for DelayedSignClause {
	type WitnessData = schnorr::Signature;

	fn tapscript(&self) -> ScriptBuf {
		assert_ne!(self.block_delta, 0, "block delta must be non-zero");
		scripts::delayed_sign(self.block_delta, self.pubkey.x_only_public_key().0)
	}

	fn witness(
		&self,
		signature: Self::WitnessData,
		control_block: ControlBlock,
	) -> Witness {
		let mut witness = Witness::new();
		witness.push(&signature[..]);
		witness.push(self.tapscript().as_bytes());
		witness.push(&control_block.serialize()[..]);

		witness
	}
}

impl Into<VtxoClause> for DelayedSignClause {
	fn into(self) -> VtxoClause {
		VtxoClause::DelayedSign(self)
	}
}

/// A clause that allows to sign and spend the UTXO after an absolute
/// timelock.
#[derive(Debug, Clone)]
pub struct TimelockSignClause {
	pub pubkey: PublicKey,
	pub timelock_height: BlockHeight,
}

impl TimelockSignClause {
	/// Returns the absolute timelock for this clause.
	pub fn cltv(&self) -> LockTime {
		LockTime::from_height(self.timelock_height).expect("timelock height is valid")
	}
}

impl TapScriptClause for TimelockSignClause {
	type WitnessData = schnorr::Signature;

	fn tapscript(&self) -> ScriptBuf {
		scripts::timelock_sign(self.timelock_height, self.pubkey.x_only_public_key().0)
	}

	fn witness(
		&self,
		signature: Self::WitnessData,
		control_block: ControlBlock,
	) -> Witness {
		let mut witness = Witness::new();
		witness.push(&signature[..]);
		witness.push(self.tapscript().as_bytes());
		witness.push(&control_block.serialize()[..]);

		witness
	}
}

impl Into<VtxoClause> for TimelockSignClause {
	fn into(self) -> VtxoClause {
		VtxoClause::TimelockSign(self)
	}
}

/// A clause that allows to sign and spend the UTXO after a relative
/// timelock, with an additional absolute one.
#[derive(Debug, Clone)]
pub struct DelayedTimelockClause {
	pub pubkey: PublicKey,
	pub timelock_height: BlockHeight,
	pub block_delta: BlockDelta,
}

impl DelayedTimelockClause {
	/// Returns the relative timelock for this clause.
	pub fn csv(&self) -> Sequence {
		Sequence::from_height(self.block_delta)
	}

	/// Returns the absolute timelock for this clause.
	pub fn cltv(&self) -> LockTime {
		LockTime::from_height(self.timelock_height).expect("timelock height is valid")
	}
}

impl TapScriptClause for DelayedTimelockClause {
	type WitnessData = schnorr::Signature;

	fn tapscript(&self) -> ScriptBuf {
		assert_ne!(self.block_delta, 0, "block delta must be non-zero");
		scripts::delay_timelock_sign(self.block_delta, self.timelock_height, self.pubkey.x_only_public_key().0)
	}

	fn witness(
		&self,
		signature: Self::WitnessData,
		control_block: ControlBlock,
	) -> Witness {
		let mut witness = Witness::new();
		witness.push(&signature[..]);
		witness.push(self.tapscript().as_bytes());
		witness.push(&control_block.serialize()[..]);

		witness
	}
}

impl Into<VtxoClause> for DelayedTimelockClause {
	fn into(self) -> VtxoClause {
		VtxoClause::DelayedTimelock(self)
	}
}

/// A clause that allows to sign and spend the UTXO after a relative
/// timelock, if preimage matching the payment hash is provided.
#[derive(Debug, Clone)]
pub struct HashDelayClause {
	pub pubkey: PublicKey,
	pub payment_hash: PaymentHash,
	pub block_delta: BlockDelta,
}

impl HashDelayClause {
	/// Returns the relative timelock for this clause.
	pub fn csv(&self) -> Sequence {
		assert_ne!(self.block_delta, 0, "block delta must be non-zero");
		Sequence::from_height(self.block_delta)
	}
}

impl TapScriptClause for HashDelayClause {
	type WitnessData = (schnorr::Signature, Preimage);

	fn tapscript(&self) -> ScriptBuf {
		assert_ne!(self.block_delta, 0, "block delta must be non-zero");
		scripts::hash_delay_sign(self.payment_hash.to_sha256_hash(), self.block_delta, self.pubkey.x_only_public_key().0)
	}

	fn witness(
		&self,
		data: Self::WitnessData,
		control_block: ControlBlock,
	) -> Witness {
		let (signature, preimage) = data;

		let mut witness = Witness::new();
		witness.push(&signature[..]);
		witness.push(&preimage.as_ref()[..]);
		witness.push(self.tapscript().as_bytes());
		witness.push(&control_block.serialize()[..]);

		witness
	}
}

impl Into<VtxoClause> for HashDelayClause {
	fn into(self) -> VtxoClause {
		VtxoClause::HashDelay(self)
	}
}

#[derive(Debug, Clone)]
pub enum VtxoClause {
	DelayedSign(DelayedSignClause),
	TimelockSign(TimelockSignClause),
	DelayedTimelock(DelayedTimelockClause),
	HashDelay(HashDelayClause),
}

impl VtxoClause {
	/// Returns the public key associated with this clause.
	pub fn pubkey(&self) -> PublicKey {
		match self {
			Self::DelayedSign(c) => c.pubkey,
			Self::TimelockSign(c) => c.pubkey,
			Self::DelayedTimelock(c) => c.pubkey,
			Self::HashDelay(c) => c.pubkey,
		}
	}

	/// Returns the tapscript for this clause.
	pub fn tapscript(&self) -> ScriptBuf {
		match self {
			Self::DelayedSign(c) => c.tapscript(),
			Self::TimelockSign(c) => c.tapscript(),
			Self::DelayedTimelock(c) => c.tapscript(),
			Self::HashDelay(c) => c.tapscript(),
		}
	}

	/// Returns the relative timelock for this clause, if applicable.
	pub fn csv(&self) -> Option<Sequence> {
		match self {
			Self::DelayedSign(c) => Some(c.csv()),
			Self::TimelockSign(_) => None,
			Self::DelayedTimelock(c) => Some(c.csv()),
			Self::HashDelay(c) => Some(c.csv()),
		}
	}

	/// Computes the total witness size in bytes for spending the VTXO via this clause.
	pub fn control_block(&self, vtxo: &Vtxo) -> ControlBlock {
		match self {
			Self::DelayedSign(c) => c.control_block(vtxo),
			Self::TimelockSign(c) => c.control_block(vtxo),
			Self::DelayedTimelock(c) => c.control_block(vtxo),
			Self::HashDelay(c) => c.control_block(vtxo),
		}
	}
}

#[cfg(test)]
mod tests {
	use std::str::FromStr;

	use bitcoin::taproot::TaprootSpendInfo;
	use bitcoin::{Amount, OutPoint, Transaction, TxIn, TxOut, Txid, sighash};
	use bitcoin::hashes::Hash;
	use bitcoin::key::Keypair;
	use bitcoin_ext::{TaprootSpendInfoExt, fee};

	use crate::{SECP, musig};
	use crate::test::verify_tx;

	use super::*;

	lazy_static! {
		static ref USER_KEYPAIR: Keypair = Keypair::from_str("5255d132d6ec7d4fc2a41c8f0018bb14343489ddd0344025cc60c7aa2b3fda6a").unwrap();
		static ref SERVER_KEYPAIR: Keypair = Keypair::from_str("1fb316e653eec61de11c6b794636d230379509389215df1ceb520b65313e5426").unwrap();
	}

	#[allow(unused)]
	fn all_clause_tested(clause: VtxoClause) -> bool {
		// NB: matcher to ensure all clauses are tested
		match clause {
			VtxoClause::DelayedSign(_) => true,
			VtxoClause::TimelockSign(_) => true,
			VtxoClause::DelayedTimelock(_) => true,
			VtxoClause::HashDelay(_) => true,
		}
	}

	fn transaction() -> Transaction {
		let address = bitcoin::Address::from_str("tb1q00h5delzqxl7xae8ufmsegghcl4jwfvdnd8530")
			.unwrap().assume_checked();

		Transaction {
			version: bitcoin::transaction::Version(3),
			lock_time: bitcoin::absolute::LockTime::ZERO,
			input: vec![],
			output: vec![TxOut {
				script_pubkey: address.script_pubkey(),
				value: Amount::from_sat(900_000),
			}, fee::fee_anchor()]
		}
	}

	fn taproot_material(clause_spk: ScriptBuf) -> (TaprootSpendInfo, ControlBlock) {
		let user_pubkey = USER_KEYPAIR.public_key();
		let server_pubkey = SERVER_KEYPAIR.public_key();

		let combined_pk = musig::combine_keys([user_pubkey, server_pubkey]);
		let taproot = taproot::TaprootBuilder::new()
			.add_leaf(0, clause_spk.clone()).unwrap()
			.finalize(&SECP, combined_pk).unwrap();

		let cb = taproot
			.control_block(&(clause_spk.clone(), taproot::LeafVersion::TapScript))
			.expect("script is in taproot");

		(taproot, cb)
	}

	fn signature(tx: &Transaction, input: &TxOut, clause_spk: ScriptBuf) -> schnorr::Signature {
		let leaf_hash = taproot::TapLeafHash::from_script(
			&clause_spk,
			taproot::LeafVersion::TapScript,
		);

		let mut shc = sighash::SighashCache::new(tx);
		let sighash = shc.taproot_script_spend_signature_hash(
			0, &sighash::Prevouts::All(&[input.clone()]), leaf_hash, sighash::TapSighashType::Default,
		).expect("all prevouts provided");

		SECP.sign_schnorr(&sighash.into(), &*USER_KEYPAIR)
	}

	#[test]
	fn test_delayed_sign_clause() {
		let clause = DelayedSignClause {
			pubkey: USER_KEYPAIR.public_key(),
			block_delta: 100,
		};

		// We compute taproot material for the clause
		let (taproot, cb) = taproot_material(clause.tapscript());
		let tx_in = TxOut {
			script_pubkey: taproot.script_pubkey(),
			value: Amount::from_sat(1_000_000),
		};

		// We build transaction spending input containing clause
		let mut tx = transaction();
		tx.input.push(TxIn {
			previous_output: OutPoint::new(Txid::all_zeros(), 0),
			script_sig: ScriptBuf::default(),
			sequence: clause.csv(),
			witness: Witness::new(),
		});

		// We compute the signature for the transaction
		let signature = signature(&tx, &tx_in, clause.tapscript());
		tx.input[0].witness = clause.witness(signature, cb);

		// We verify the transaction
		verify_tx(&[tx_in], 0, &tx).expect("transaction is invalid");
	}

	#[test]
	fn test_timelock_sign_clause() {
		let clause = TimelockSignClause {
			pubkey: USER_KEYPAIR.public_key(),
			timelock_height: 100,
		};

		// We compute taproot material for the clause
		let (taproot, cb) = taproot_material(clause.tapscript());
		let tx_in = TxOut {
			script_pubkey: taproot.script_pubkey(),
			value: Amount::from_sat(1_000_000),
		};

		// We build transaction spending input containing clause
		let mut tx = transaction();
		tx.lock_time = clause.cltv();
		tx.input.push(TxIn {
			previous_output: OutPoint::new(Txid::all_zeros(), 0),
			script_sig: ScriptBuf::default(),
			sequence: Sequence::ZERO,
			witness: Witness::new(),
		});

		// We compute the signature for the transaction
		let signature = signature(&tx, &tx_in, clause.tapscript());
		tx.input[0].witness = clause.witness(signature, cb);

		// We verify the transaction
		verify_tx(&[tx_in], 0, &tx).expect("transaction is invalid");
	}

	#[test]
	fn test_delayed_timelock_clause() {
		let clause = DelayedTimelockClause {
			pubkey: USER_KEYPAIR.public_key(),
			timelock_height: 100,
			block_delta: 24,
		};

		// We compute taproot material for the clause
		let (taproot, cb) = taproot_material(clause.tapscript());
		let tx_in = TxOut {
			script_pubkey: taproot.script_pubkey(),
			value: Amount::from_sat(1_000_000),
		};

		// We build transaction spending input containing clause
		let mut tx = transaction();
		tx.lock_time = clause.cltv();
		tx.input.push(TxIn {
			previous_output: OutPoint::new(Txid::all_zeros(), 0),
			script_sig: ScriptBuf::default(),
			sequence: clause.csv(),
			witness: Witness::new(),
		});

		// We compute the signature for the transaction
		let signature = signature(&tx, &tx_in, clause.tapscript());
		tx.input[0].witness = clause.witness(signature, cb);

		// We verify the transaction
		verify_tx(&[tx_in], 0, &tx).expect("transaction is invalid");
	}

	#[test]
	fn test_hash_delay_clause() {
		let preimage = Preimage::from_slice(&[0; 32]).unwrap();

		let clause = HashDelayClause {
			pubkey: USER_KEYPAIR.public_key(),
			payment_hash: preimage.compute_payment_hash(),
			block_delta: 24,
		};

		// We compute taproot material for the clause
		let (taproot, cb) = taproot_material(clause.tapscript());
		let tx_in = TxOut {
			script_pubkey: taproot.script_pubkey(),
			value: Amount::from_sat(1_000_000),
		};

		// We build transaction spending input containing clause
		let mut tx = transaction();
		tx.input.push(TxIn {
			previous_output: OutPoint::new(Txid::all_zeros(), 0),
			script_sig: ScriptBuf::default(),
			sequence: clause.csv(),
			witness: Witness::new(),
		});

		// We compute the signature for the transaction
		let signature = signature(&tx, &tx_in, clause.tapscript());
		tx.input[0].witness = clause.witness((signature, preimage), cb);

		// We verify the transaction
		verify_tx(&[tx_in], 0, &tx).expect("transaction is invalid");
	}
}
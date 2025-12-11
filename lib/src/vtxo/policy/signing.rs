
use std::borrow::Borrow;

use bitcoin::hashes::Hash;
use bitcoin::{TapSighash, Transaction, TxOut, Witness, sighash, taproot};

use crate::Vtxo;
use crate::vtxo::policy::clause::VtxoClause;

#[derive(Debug, Clone, PartialEq, Eq, Hash, thiserror::Error)]
#[error("the vtxo has no clause signable by the provided signer")]
pub struct CannotSignVtxoError;

/// A trait to implement a signer for a [Vtxo].
pub trait VtxoSigner {
	/// Returns the witness for a [VtxoClause] if it is signable, otherwise [None].
	fn witness(
		&self,
		clause: &VtxoClause,
		control_block: &taproot::ControlBlock,
		sighash: TapSighash,
	) -> Option<Witness>;

	/// Returns true if the clause is signable, otherwise false.
	fn can_sign(&self, clause: &VtxoClause, vtxo: &Vtxo) -> bool {
		// NB: We won't use the witness after this, so we can use all zeros
		let sighash = TapSighash::all_zeros();
		let cb = clause.control_block(vtxo);
		self.witness(clause, &cb, sighash).is_some()
	}

	/// Returns the first signable clause from [Vtxo]'s policy.
	/// If no clause is signable, returns [None].
	fn find_signable_clause(&self, vtxo: &Vtxo) -> Option<VtxoClause> {
		let exit_delta = vtxo.exit_delta();
		let expiry_height = vtxo.expiry_height();
		let server_pubkey = vtxo.server_pubkey();

		let clauses = vtxo.policy().clauses(exit_delta, expiry_height, server_pubkey);

		for clause in clauses {
			if self.can_sign(&clause, vtxo) {
				return Some(clause);
			}
		}

		None
	}

	/// Return the full witness for a [Vtxo] using the first signable clause.
	///
	/// # Errors
	///
	/// Returns [CannotSignVtxoError] if no clause is signable.
	fn sign_input(
		&self,
		vtxo: &Vtxo,
		input_idx: usize,
		sighash_cache: &mut sighash::SighashCache<impl Borrow<Transaction>>,
		prevouts: &sighash::Prevouts<impl Borrow<TxOut>>,
	) -> Result<Witness, CannotSignVtxoError> {
		let clause = self.find_signable_clause(vtxo).ok_or(CannotSignVtxoError)?;
		let cb = clause.control_block(vtxo);

		let exit_script = clause.tapscript();
		let leaf_hash = taproot::TapLeafHash::from_script(
			&exit_script,
			taproot::LeafVersion::TapScript,
		);

		let sighash = sighash_cache.taproot_script_spend_signature_hash(
			input_idx, &prevouts, leaf_hash, sighash::TapSighashType::Default,
		).expect("all prevouts provided");

		let witness = self.witness(&clause, &cb, sighash)
			.expect("found clause should be signable");

		debug_assert_eq!(
			witness.size(), clause.witness_size(vtxo),
			"actual witness size ({}) does not match expected ({})",
			witness.size(), clause.witness_size(vtxo)
		);

		Ok(witness)
	}
}
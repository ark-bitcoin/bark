
use std::borrow::Borrow;

use bitcoin::hashes::Hash;
use bitcoin::secp256k1::schnorr;
use bitcoin::{sighash, taproot, TapSighash, Transaction, TxOut, Witness};

use crate::Vtxo;
use crate::vtxo::policy::{Policy, VtxoPolicy};
use crate::vtxo::policy::clause::VtxoClause;

#[derive(Debug, Clone, PartialEq, Eq, Hash, thiserror::Error)]
#[error("the vtxo has no clause signable by the provided signer")]
pub struct CannotSignVtxoError;

/// A trait to implement a signer for a [Vtxo].
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
pub trait VtxoSigner<P: Policy = VtxoPolicy> {
	/// Sign a keyspend input
	async fn sign_keyspend<G: Sync + Send>(
		&self,
		vtxo: &Vtxo<G, P>,
		sighash: TapSighash,
	) -> Option<schnorr::Signature>;

	/// Returns the witness for a [VtxoClause] if it is signable, otherwise [None].
	async fn witness(
		&self,
		clause: &VtxoClause,
		control_block: &taproot::ControlBlock,
		sighash: TapSighash,
	) -> Option<Witness>;

	/// Returns true if the clause is signable, otherwise false.
	async fn can_sign<G: Sync + Send>(&self, clause: &VtxoClause, vtxo: &Vtxo<G, P>) -> bool {
		// NB: We won't use the witness after this, so we can use all zeros
		let sighash = TapSighash::all_zeros();
		let cb = clause.control_block(vtxo);
		self.witness(clause, &cb, sighash).await.is_some()
	}

	/// Returns the first signable clause from [Vtxo]'s policy.
	/// If no clause is signable, returns [None].
	async fn find_signable_clause<G: Sync + Send>(&self, vtxo: &Vtxo<G, P>) -> Option<VtxoClause> {
		let exit_delta = vtxo.exit_delta();
		let expiry_height = vtxo.expiry_height();
		let server_pubkey = vtxo.server_pubkey();

		let clauses = vtxo.policy().clauses(exit_delta, expiry_height, server_pubkey);

		for clause in clauses {
			if self.can_sign(&clause, vtxo).await {
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
	async fn sign_input<G: Sync + Send>(
		&self,
		vtxo: &Vtxo<G, P>,
		input_idx: usize,
		sighash_cache: &mut sighash::SighashCache<impl Borrow<Transaction> + Send + Sync>,
		prevouts: &sighash::Prevouts<impl Borrow<TxOut> + Send + Sync>,
	) -> Result<Witness, CannotSignVtxoError> {
		let clause = self.find_signable_clause(vtxo).await
			.ok_or(CannotSignVtxoError)?;
		self.sign_input_with_clause(vtxo, &clause, input_idx, sighash_cache, prevouts).await
	}

	/// Return the full witness for a [Vtxo] using keyspend
	async fn sign_input_with_keyspend<G: Sync + Send>(
		&self,
		vtxo: &Vtxo<G, P>,
		input_idx: usize,
		sighash_cache: &mut sighash::SighashCache<impl Borrow<Transaction> + Send + Sync>,
		prevouts: &sighash::Prevouts<impl Borrow<TxOut> + Send + Sync>,
	) -> Result<Witness, CannotSignVtxoError> {
		let sighash = sighash_cache.taproot_key_spend_signature_hash(
			input_idx, &prevouts, sighash::TapSighashType::Default,
		).expect("all prevouts provided");

		let sig = self.sign_keyspend(vtxo, sighash).await
			.ok_or(CannotSignVtxoError)?;
		let witness = Witness::from_slice(&[&sig[..]]);

		Ok(witness)
	}

	/// Return the full witness for a [Vtxo] using the specified clause.
	///
	/// # Errors
	///
	/// Returns [CannotSignVtxoError] if the clause is not signable.
	async fn sign_input_with_clause<G: Sync + Send>(
		&self,
		vtxo: &Vtxo<G, P>,
		clause: &VtxoClause,
		input_idx: usize,
		sighash_cache: &mut sighash::SighashCache<impl Borrow<Transaction> + Send + Sync>,
		prevouts: &sighash::Prevouts<impl Borrow<TxOut> + Send + Sync>,
	) -> Result<Witness, CannotSignVtxoError> {
		let cb = clause.control_block(vtxo);

		let exit_script = clause.tapscript();
		let leaf_hash = taproot::TapLeafHash::from_script(
			&exit_script,
			taproot::LeafVersion::TapScript,
		);

		let sighash = sighash_cache.taproot_script_spend_signature_hash(
			input_idx, &prevouts, leaf_hash, sighash::TapSighashType::Default,
		).expect("all prevouts provided");

		let witness = self.witness(clause, &cb, sighash).await
			.ok_or(CannotSignVtxoError)?;

		debug_assert_eq!(
			witness.size(), clause.witness_size(vtxo),
			"actual witness size ({}) does not match expected ({})",
			witness.size(), clause.witness_size(vtxo)
		);

		Ok(witness)
	}
}

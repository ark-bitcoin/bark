
use std::borrow::Cow;

use bitcoin::{sighash, Amount, OutPoint, Transaction, TxOut};
use bitcoin::secp256k1::PublicKey;
use bitcoin_ext::TxOutExt;

use crate::util::SECP;
use crate::vtxo::{Vtxo, GenesisTransition};


#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[error("VTXO validation error")]
pub enum VtxoValidationError {
	#[error("the VTXO is invalid: {0}")]
	Invalid(&'static str),
	#[error("the chain anchor output doesn't match the VTXO; expected: {expected:?}")]
	IncorrectChainAnchor {
		expected: TxOut,
	},
	#[error("Cosigned genesis transitions don't have a common pubkey (idx={genesis_item_idx}): \
		cosign_pubkey={cosign_pubkey}")]
	InconsistentCosignPubkeys {
		/// Our determined cosign pubkey.
		/// (This is the pubkey that we found on the last Cosigned item.)
		cosign_pubkey: PublicKey,
		/// The index of the genesis item that is missing our determined cosign pubkey.
		genesis_item_idx: usize,
	},
	#[error("error verifying one of the genesis transitions (idx={genesis_item_idx}): {error}")]
	GenesisTransition {
		error: &'static str,
		genesis_item_idx: usize,
	},
	#[error("non-standard output on genesis item #{genesis_item_idx} other \
		output #{other_output_idx}")]
	NonStandardTxOut {
		genesis_item_idx: usize,
		other_output_idx: usize,
	},
}

impl VtxoValidationError {
	/// Constructor for [VtxoValidationError::GenesisTransition].
	fn transition(genesis_item_idx: usize, error: &'static str) -> Self {
		VtxoValidationError::GenesisTransition { error, genesis_item_idx }
	}
}

pub enum Validation {
	Trusted {
		cosign_pubkey: PublicKey,
	},
	Arkoor,
}


#[inline]
fn verify_transition(
	vtxo: &Vtxo,
	genesis_idx: usize,
	prev_tx: &Transaction,
	prev_vout: usize,
	next_amount: Amount,
) -> Result<Transaction, &'static str> {
	let item = vtxo.genesis.get(genesis_idx).expect("genesis_idx out of range");

	let prev_txout = prev_tx.output.get(prev_vout).ok_or_else(|| "output idx out of range")?;

	let next_output = vtxo.genesis.get(genesis_idx + 1).map(|item| {
		item.transition.input_txout(
			next_amount, vtxo.asp_pubkey, vtxo.expiry_height, vtxo.exit_delta,
		)
	}).unwrap_or_else(|| {
		// when we reach the end of the chain, we take the eventual output of the vtxo
		vtxo.policy.txout(vtxo.amount, vtxo.asp_pubkey, vtxo.exit_delta)
	});

	let prevout = OutPoint::new(prev_tx.compute_txid(), prev_vout as u32);
	let tx = item.tx(prevout, next_output);

	let sighash = {
		let mut shc = sighash::SighashCache::new(&tx);
		shc.taproot_key_spend_signature_hash(
			0, &sighash::Prevouts::All(&[prev_txout]), sighash::TapSighashType::Default,
		).expect("correct prevouts")
	};

	let pubkey = {
		let transition_taproot = item.transition.input_taproot(
			vtxo.asp_pubkey(), vtxo.expiry_height(), vtxo.exit_delta(),
		);
		transition_taproot.output_key().to_x_only_public_key()
	};

	let signature = match item.transition {
		GenesisTransition::Cosigned { signature, .. } => signature,
		GenesisTransition::Arkoor { signature: Some(signature), .. } => signature,
		GenesisTransition::Arkoor { signature: None, .. } => {
			return Err("missing arkoor signature");
		},
	};

	SECP.verify_schnorr(&signature, &sighash.into(), &pubkey)
		.map_err(|_| "invalid signature")?;

	Ok(tx)
}

#[inline]
fn check_transitions_cosigned_then_arkoor<'a>(
	transitions: impl Iterator<Item = &'a GenesisTransition> + Clone,
) -> Result<(), VtxoValidationError> {
	let cosigned = transitions.clone()
		.take_while(|t| matches!(t, GenesisTransition::Cosigned { .. }));
	if cosigned.count() < 1 {
		return Err(VtxoValidationError::Invalid("should start with Cosigned genesis items"));
	}
	let mut after_cosigned = transitions.clone()
		.skip_while(|t| matches!(t, GenesisTransition::Cosigned { .. }));
	if !after_cosigned.all(|t| matches!(t, GenesisTransition::Arkoor { .. })) {
		return Err(VtxoValidationError::Invalid(
			"can only have Arkoor transitions after last Cosigned",
		));
	}
	Ok(())
}

/// The last Cosigned transition should have only two pubkey: user and asp.
/// This holds for rounds and for board (where it's the only cosigned transition).
#[inline]
fn determine_cosign_pubkey<'a>(
	transitions: impl Iterator<Item = &'a GenesisTransition> + DoubleEndedIterator,
) -> Result<PublicKey, VtxoValidationError> {
	// The last Cosigned transition should have only two pubkey: user and asp.
	// This holds for rounds and for board (where it's the only cosigned transition).
	let last_cosign_pubkeys = transitions.rev().find_map(|t| match t {
		GenesisTransition::Cosigned { ref pubkeys, .. } => Some(pubkeys),
		GenesisTransition::Arkoor { .. } => None,
	}).unwrap();
	if last_cosign_pubkeys.len() != 2 {
		return Err(VtxoValidationError::Invalid("invalid last cosign genesis"));
	}
	Ok(last_cosign_pubkeys.first().copied().expect("have more than one transition"))
}

/// Validate that the [Vtxo] is valid and can be constructed from its
/// chain anchor.
pub fn validate(
	vtxo: &Vtxo,
	chain_anchor_tx: &Transaction,
) -> Result<Validation, VtxoValidationError> {
	// We start by validating the chain anchor output.
	let anchor_txout = chain_anchor_tx.output.get(vtxo.chain_anchor().vout as usize)
		.ok_or(VtxoValidationError::Invalid("chain anchor vout out of range"))?;
	let onchain_amount = vtxo.amount() + vtxo.genesis.iter().map(|i| {
		i.other_outputs.iter().map(|o| o.value).sum()
	}).sum();
	let expected_anchor_txout = vtxo.genesis.get(0).unwrap().transition.input_txout(
		onchain_amount, vtxo.asp_pubkey(), vtxo.expiry_height(), vtxo.exit_delta(),
	);
	if *anchor_txout != expected_anchor_txout {
		return Err(VtxoValidationError::IncorrectChainAnchor { expected: expected_anchor_txout });
	}

	// Then let's go over each transition.
	let transitions = vtxo.genesis.iter().map(|i| &i.transition);

	// Every VTXO should have one or more `Cosigned` transitions, followed by 0 or more
	// `Arkoor` transitions.
	if vtxo.genesis.is_empty() {
		return Err(VtxoValidationError::Invalid("no genesis items"));
	}
	check_transitions_cosigned_then_arkoor(transitions.clone())?;

	let cosign_pubkey = determine_cosign_pubkey(transitions.clone())?;

	let mut prev = (Cow::Borrowed(chain_anchor_tx), vtxo.chain_anchor().vout as usize, onchain_amount);
	for (idx, item) in vtxo.genesis.iter().enumerate() {
		// We need to check that for all Cosigned transitions, the cosign pubkey is included.
		if let GenesisTransition::Cosigned { ref pubkeys, .. } = item.transition {
			if !pubkeys.contains(&cosign_pubkey) {
				return Err(VtxoValidationError::InconsistentCosignPubkeys {
					cosign_pubkey: cosign_pubkey,
					genesis_item_idx: idx,
				});
			}
		}

		// All outputs have to be standard otherwise we can't relay.
		if let Some(out_idx) = item.other_outputs.iter().position(|o| !o.is_standard()) {
			return Err(VtxoValidationError::NonStandardTxOut {
				genesis_item_idx: idx,
				other_output_idx: out_idx,
			});
		}

		let next_amount = prev.2.checked_sub(item.other_outputs.iter().map(|o| o.value).sum())
			.ok_or(VtxoValidationError::Invalid("insufficient onchain amount"))?;
		let next_tx = verify_transition(&vtxo, idx, prev.0.as_ref(), prev.1, next_amount)
			.map_err(|e| VtxoValidationError::transition(idx, e))?;
		prev = (Cow::Owned(next_tx), item.output_idx as usize, next_amount);
	}

	Ok(if transitions.clone().all(|t| matches!(t, GenesisTransition::Cosigned { .. })) {
		Validation::Trusted { cosign_pubkey }
	} else {
		Validation::Arkoor
	})
}

#[cfg(test)]
mod test {
	use crate::vtxo::test::VTXO_VECTORS;

	#[test]
	pub fn validate_vtxos() {
		let vtxos = &*VTXO_VECTORS;

		let err = vtxos.board_vtxo.validate(&vtxos.anchor_tx).err();
		assert!(err.is_none(), "err: {err:?}");

		let err = vtxos.arkoor_htlc_out_vtxo.validate(&vtxos.anchor_tx).err();
		assert!(err.is_none(), "err: {err:?}");

		let err = vtxos.arkoor2_vtxo.validate(&vtxos.anchor_tx).err();
		assert!(err.is_none(), "err: {err:?}");

		let err = vtxos.round1_vtxo.validate(&vtxos.round_tx).err();
		assert!(err.is_none(), "err: {err:?}");

		let err = vtxos.round2_vtxo.validate(&vtxos.round_tx).err();
		assert!(err.is_none(), "err: {err:?}");

		let err = vtxos.arkoor3_vtxo.validate(&vtxos.round_tx).err();
		assert!(err.is_none(), "err: {err:?}");
	}
}

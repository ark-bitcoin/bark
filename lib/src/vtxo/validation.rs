
use std::borrow::Cow;

use bitcoin::{Amount, OutPoint, Transaction, TxOut};

use crate::vtxo::{Vtxo, VtxoPolicyKind};
use crate::vtxo::genesis::{GenesisTransition, TransitionKind};

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[error("VTXO validation error")]
pub enum VtxoValidationError {
	#[error("the VTXO is invalid: {0}")]
	Invalid(&'static str),
	#[error("the chain anchor output doesn't match the VTXO; expected: {expected:?}, got: {got:?}")]
	IncorrectChainAnchor {
		expected: TxOut,
		got: TxOut,
	},
	#[error("Cosigned genesis transitions don't have any common pubkeys")]
	InconsistentCosignPubkeys,
	#[error("error verifying one of the genesis transitions \
		(idx={genesis_idx}/{genesis_len} type={transition_kind}): {error}")]
	GenesisTransition {
		error: &'static str,
		genesis_idx: usize,
		genesis_len: usize,
		// NB we use str here because we don't want to expose the kind enum
		transition_kind: &'static str,
	},
	#[error("invalid arkoor policy of type {policy}: {msg}")]
	InvalidArkoorPolicy {
		policy: VtxoPolicyKind,
		msg: &'static str,
	},
}

impl VtxoValidationError {
	/// Constructor for [VtxoValidationError::GenesisTransition].
	fn transition(
		genesis_idx: usize,
		genesis_len: usize,
		transition_kind: TransitionKind,
		error: &'static str,
	) -> Self {
		let transition_kind = transition_kind.as_str();
		VtxoValidationError::GenesisTransition { error, genesis_idx, genesis_len, transition_kind }
	}
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
			next_amount, vtxo.server_pubkey, vtxo.expiry_height, vtxo.exit_delta,
		)
	}).unwrap_or_else(|| {
		// when we reach the end of the chain, we take the eventual output of the vtxo
		vtxo.policy.txout(vtxo.amount, vtxo.server_pubkey, vtxo.exit_delta, vtxo.expiry_height)
	});

	let prevout = OutPoint::new(prev_tx.compute_txid(), prev_vout as u32);
	let tx = item.tx(prevout, next_output, vtxo.server_pubkey, vtxo.expiry_height);

	match &item.transition {
		GenesisTransition::Cosigned(inner) => {
			inner.validate_sigs(&tx, 0, prev_txout, vtxo.server_pubkey, vtxo.expiry_height)?
		}
		GenesisTransition::Arkoor(inner) => {
			inner.validate_sigs(&tx, 0, prev_txout, vtxo.server_pubkey())?
		}
		GenesisTransition::HashLockedCosigned(inner) => {
			inner.validate_sigs(&tx, 0, prev_txout, vtxo.server_pubkey, vtxo.expiry_height)?
		}
	};

	#[cfg(test)]
	{
		if let Err(e) = crate::test_util::verify_tx(&[prev_txout.clone()], 0, &tx) {
			// just print error because this is unit test context
			println!("TX VALIDATION FAILED: invalid tx in genesis of vtxo {}: idx={}: {}",
				vtxo.id(), genesis_idx, e,
			);
			return Err("transaction validation failed");
		}
	}

	Ok(tx)
}

/// Validate that the [Vtxo] is valid and can be constructed from its
/// chain anchor.
///
/// General checks and chain-anchor related checks are performed first,
/// transitions are checked last.
pub fn validate(
	vtxo: &Vtxo,
	chain_anchor_tx: &Transaction,
) -> Result<(), VtxoValidationError> {
	// We start by validating the chain anchor output.
	let anchor_txout = chain_anchor_tx.output.get(vtxo.chain_anchor().vout as usize)
		.ok_or(VtxoValidationError::Invalid("chain anchor vout out of range"))?;
	let onchain_amount = vtxo.amount() + vtxo.genesis.iter().map(|i| {
		i.other_outputs.iter().map(|o| o.value).sum()
	}).sum();
	let expected_anchor_txout = vtxo.genesis.get(0).unwrap().transition.input_txout(
		onchain_amount, vtxo.server_pubkey(), vtxo.expiry_height(), vtxo.exit_delta(),
	);
	if *anchor_txout != expected_anchor_txout {
		return Err(VtxoValidationError::IncorrectChainAnchor {
			expected: expected_anchor_txout,
			got: anchor_txout.clone(),
		});
	}

	// Every VTXO should have one or more `Cosigned` transitions, followed by 0 or more
	// `Arkoor` transitions.
	if vtxo.genesis.is_empty() {
		return Err(VtxoValidationError::Invalid("no genesis items"));
	}

	let mut prev = (Cow::Borrowed(chain_anchor_tx), vtxo.chain_anchor().vout as usize, onchain_amount);
	for (idx, item) in vtxo.genesis.iter().enumerate() {
		let next_amount = prev.2.checked_sub(item.other_outputs.iter().map(|o| o.value).sum())
			.ok_or(VtxoValidationError::Invalid("insufficient onchain amount"))?;
		let next_tx = verify_transition(&vtxo, idx, prev.0.as_ref(), prev.1, next_amount)
			.map_err(|e| VtxoValidationError::transition(
				idx, vtxo.genesis.len(), item.transition.kind(), e,
			))?;
		prev = (Cow::Owned(next_tx), item.output_idx as usize, next_amount);
	}

	// Verify the point field matches the computed exit outpoint
	let expected_point = OutPoint::new(prev.0.compute_txid(), prev.1 as u32);
	if vtxo.point != expected_point {
		return Err(VtxoValidationError::Invalid("point doesn't match computed exit outpoint"));
	}

	Ok(())
}

#[cfg(test)]
mod test {
	use crate::test_util::VTXO_VECTORS;

	#[test]
	pub fn validate_vtxos() {
		let vtxos = &*VTXO_VECTORS;

		assert!(vtxos.board_vtxo.is_standard());
		let err = vtxos.board_vtxo.validate(&vtxos.anchor_tx).err();
		assert!(err.is_none(), "err: {err:?}");

		assert!(vtxos.arkoor_htlc_out_vtxo.is_standard());
		let err = vtxos.arkoor_htlc_out_vtxo.validate(&vtxos.anchor_tx).err();
		assert!(err.is_none(), "err: {err:?}");

		assert!(vtxos.arkoor2_vtxo.is_standard());
		let err = vtxos.arkoor2_vtxo.validate(&vtxos.anchor_tx).err();
		assert!(err.is_none(), "err: {err:?}");

		assert!(vtxos.round1_vtxo.is_standard());
		let err = vtxos.round1_vtxo.validate(&vtxos.round_tx).err();
		assert!(err.is_none(), "err: {err:?}");

		assert!(vtxos.round2_vtxo.is_standard());
		let err = vtxos.round2_vtxo.validate(&vtxos.round_tx).err();
		assert!(err.is_none(), "err: {err:?}");

		assert!(vtxos.arkoor3_vtxo.is_standard());
		let err = vtxos.arkoor3_vtxo.validate(&vtxos.round_tx).err();
		assert!(err.is_none(), "err: {err:?}");
	}
}

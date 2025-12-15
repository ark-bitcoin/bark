
use std::borrow::Cow;

use bitcoin::{sighash, Amount, OutPoint, TapLeafHash, Transaction, TxOut};

use bitcoin_ext::TxOutExt;

use crate::tree::signed::unlock_clause;
use crate::{musig, SECP};
use crate::vtxo::{GenesisTransition, TransitionKind, Vtxo, VtxoPolicyKind};


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
	#[error("non-standard output on genesis item #{genesis_item_idx} other \
		output #{other_output_idx}")]
	NonStandardTxOut {
		genesis_item_idx: usize,
		other_output_idx: usize,
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

	let sighash = match item.transition {
		GenesisTransition::HashLockedCosigned { user_pubkey, unlock, .. } => {
			let mut shc = sighash::SighashCache::new(&tx);
			let agg_pk = musig::combine_keys([user_pubkey, vtxo.server_pubkey]);
			let script = unlock_clause(agg_pk, unlock.hash());
			let leaf = TapLeafHash::from_script(&script, bitcoin::taproot::LeafVersion::TapScript);
			shc.taproot_script_spend_signature_hash(
				0, &sighash::Prevouts::All(&[prev_txout]), leaf, sighash::TapSighashType::Default,
			).expect("correct prevouts")
		},
		GenesisTransition::Cosigned { .. } | GenesisTransition::Arkoor { .. } => {
			let mut shc = sighash::SighashCache::new(&tx);
			shc.taproot_key_spend_signature_hash(
				0, &sighash::Prevouts::All(&[prev_txout]), sighash::TapSighashType::Default,
			).expect("correct prevouts")
		},
	};

	let pubkey = {
		let taproot = item.transition.input_taproot(
			vtxo.server_pubkey(), vtxo.expiry_height(), vtxo.exit_delta(),
		);
		match item.transition {
			GenesisTransition::Cosigned { .. } | GenesisTransition::Arkoor { .. } => {
				taproot.output_key().to_x_only_public_key()
			},
			// hark transition is script-spend that uses internal key
			GenesisTransition::HashLockedCosigned { .. } => taproot.internal_key(),
		}
	};

	let signature = match item.transition {
		GenesisTransition::Cosigned { signature, .. } => signature,
		GenesisTransition::HashLockedCosigned { signature: Some(sig), .. } => sig,
		GenesisTransition::HashLockedCosigned { signature: None, .. } => {
			return Err("missing signature of hash-locked cosign leaf");
		},
		GenesisTransition::Arkoor { signature: Some(signature), .. } => signature,
		GenesisTransition::Arkoor { signature: None, .. } => {
			return Err("missing arkoor signature");
		},
	};

	SECP.verify_schnorr(&signature, &sighash.into(), &pubkey)
		.map_err(|_| "invalid signature")?;

	#[cfg(test)]
	{
		if let Err(e) = crate::test::verify_tx(&[prev_txout.clone()], 0, &tx) {
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
	let mut iter = vtxo.genesis.iter().enumerate().peekable();
	while let Some((idx, item)) = iter.next() {
		// transition-dependent validation
		match &item.transition {
			GenesisTransition::Cosigned { .. } => {},
			GenesisTransition::HashLockedCosigned { .. } => {
				// can only be followed by arkoor
				if let Some((_idx, next)) = iter.peek() {
					match &next.transition {
						GenesisTransition::Arkoor { .. } => {},
						GenesisTransition::Cosigned { .. }
						| GenesisTransition::HashLockedCosigned { .. } => {
							return Err(VtxoValidationError::transition(
								idx, vtxo.genesis.len(), item.transition.kind(),
								"hash-locked cosigned transition must \
									be followed by arkoor transitions",
							));
						},
					}
				}
			},
			GenesisTransition::Arkoor { policy, .. } => {
				if policy.arkoor_pubkey().is_none() {
					return Err(VtxoValidationError::InvalidArkoorPolicy {
						policy: policy.policy_type(),
						msg: "arkoor transition without arkoor pubkey",
					});
				}

				// can only be followed by more arkoor
				if let Some((_idx, next)) = iter.peek() {
					match &next.transition {
						GenesisTransition::Arkoor { .. } => {},
						GenesisTransition::Cosigned { .. }
						| GenesisTransition::HashLockedCosigned { .. } => {
							return Err(VtxoValidationError::transition(
								idx, vtxo.genesis.len(), item.transition.kind(),
								"Arkoor transition must be followed by arkoor transitions",
							));
						},
					}
				}
			},
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
			.map_err(|e| VtxoValidationError::transition(
				idx, vtxo.genesis.len(), item.transition.kind(), e,
			))?;
		prev = (Cow::Owned(next_tx), item.output_idx as usize, next_amount);
	}

	Ok(())
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

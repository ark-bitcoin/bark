use std::fmt;

use bitcoin::secp256k1::{schnorr, PublicKey};
use bitcoin::taproot;

use bitcoin::{Amount, OutPoint, Sequence, ScriptBuf, Transaction, TxIn, TxOut, Witness};
use bitcoin::hashes::{sha256, Hash};
use bitcoin::taproot::LeafVersion;
use bitcoin_ext::{fee, BlockDelta, BlockHeight, TaprootSpendInfoExt};

use crate::musig;
use crate::tree::signed::{cosign_taproot, leaf_cosign_taproot, unlock_clause};
use crate::vtxo::{VtxoPolicy, MaybePreimage};

/// Represents the kind of [GenesisTransition]
pub(crate) enum TransitionKind {
	Cosigned,
	HashLockedCosigned,
	Arkoor,
}

impl TransitionKind {
	pub fn as_str(&self) -> &'static str {
		match self {
			Self::Cosigned => "cosigned",
			Self::HashLockedCosigned => "hash-locked-cosigned",
			Self::Arkoor => "arkoor",
		}
	}
}

impl fmt::Display for TransitionKind {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str(self.as_str())
	}
}

impl fmt::Debug for TransitionKind {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		fmt::Display::fmt(self, f)
	}
}

/// A transition from one genesis tx to the next.
///
/// See private module-level documentation for more info.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum GenesisTransition {
	/// A transition based on a cosignature.
	///
	/// This can be either the result of a cosigned "clArk" tree branch transition
	/// or a board which is cosigned just with the server.
	Cosigned {
		/// All the cosign pubkeys signing the node.
		///
		/// Has to include server's cosign pubkey because it differs
		/// from its regular pubkey.
		pubkeys: Vec<PublicKey>,
		signature: schnorr::Signature,
	},
	/// A transition based on a cosignature and a hash lock
	///
	/// This is the transition type for hArk leaf policy outputs,
	/// that spend into the leaf transaction.
	///
	/// Refraining from any optimizations, this type is implemented the naive way:
	/// - the keyspend path is currently unused, could be used later
	/// - witness will always contain the cosignature and preimage in the script spend
	HashLockedCosigned {
		/// User pubkey that is combined with the server pubkey
		user_pubkey: PublicKey,
		/// The script-spend signature
		signature: Option<schnorr::Signature>,
		/// The unlock preimage or the unlock hash
		unlock: MaybePreimage,
	},
	/// A regular arkoor spend, using the co-signed p2tr key-spend path.
	Arkoor {
		policy: VtxoPolicy,
		signature: Option<schnorr::Signature>,
	},
}

impl GenesisTransition {
	/// Taproot that this transition is satisfying.
	pub(crate) fn input_taproot(
		&self,
		server_pubkey: PublicKey,
		expiry_height: BlockHeight,
		exit_delta: BlockDelta,
	) -> taproot::TaprootSpendInfo {
		match self {
			Self::Cosigned { pubkeys, .. } => {
				let agg_pk = musig::combine_keys(pubkeys.iter().copied());
				cosign_taproot(agg_pk, server_pubkey, expiry_height)
			},
			Self::HashLockedCosigned { user_pubkey, unlock, .. } => {
				leaf_cosign_taproot(*user_pubkey, server_pubkey, expiry_height, unlock.hash())
			},
			Self::Arkoor { policy, .. } => policy.taproot(server_pubkey, exit_delta, expiry_height),
		}
	}

	/// Output that this transition is spending.
	pub(crate) fn input_txout(
		&self,
		amount: Amount,
		server_pubkey: PublicKey,
		expiry_height: BlockHeight,
		exit_delta: BlockDelta,
	) -> TxOut {
		let taproot = self.input_taproot(server_pubkey, expiry_height, exit_delta);
		TxOut {
			value: amount,
			script_pubkey: taproot.script_pubkey(),
		}
	}

	/// The transaction witness for this transition.
	pub(crate) fn witness(
		&self,
		server_pubkey: PublicKey,
		expiry_height: BlockHeight,
	) -> Witness {
		match self {
			Self::Cosigned { signature, .. } => Witness::from_slice(&[&signature[..]]),
			Self::HashLockedCosigned {
				user_pubkey,
				signature: Some(sig),
				unlock: MaybePreimage::Preimage(preimage),
			} => {
				let unlock_hash = sha256::Hash::hash(preimage);
				let taproot = leaf_cosign_taproot(
					*user_pubkey, server_pubkey, expiry_height, unlock_hash,
				);
				let clause = unlock_clause(taproot.internal_key(), unlock_hash);
				let script_leaf = (clause, LeafVersion::TapScript);
				let cb = taproot.control_block(&script_leaf)
					.expect("unlock clause not found in hArk taproot");
				Witness::from_slice(&[
					&sig.serialize()[..],
					&preimage[..],
					&script_leaf.0.as_bytes(),
					&cb.serialize()[..],
				])
			},
			Self::HashLockedCosigned { .. } => {
				// without preimage or signature this transition is unfulfilled
				Witness::new()
			},
			Self::Arkoor { signature: Some(sig), .. } => Witness::from_slice(&[&sig[..]]),
			Self::Arkoor { signature: None, .. } => Witness::new(),
		}
	}


	/// Whether the transition is fully signed
	pub(crate) fn is_fully_signed(&self) -> bool {
		match self {
			Self::Cosigned { .. } => true,
			Self::HashLockedCosigned {
				unlock: MaybePreimage::Preimage(_),
				signature: Some(_),
				..
			} => true,
			Self::HashLockedCosigned { .. } => false,
			Self::Arkoor { signature, .. } => signature.is_some(),
		}
	}

	/// String of the transition kind, for error reporting
	pub(crate) fn kind(&self) -> TransitionKind {
		match self {
			Self::Cosigned { .. } => TransitionKind::Cosigned,
			Self::HashLockedCosigned { .. } => TransitionKind::HashLockedCosigned,
			Self::Arkoor { .. } => TransitionKind::Arkoor,
		}
	}
}

/// An item in a VTXO's genesis.
///
/// See private module-level documentation for more info.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GenesisItem {
	/// The transition from the previous tx to this one.
	pub(crate) transition: GenesisTransition,
	/// The output index ("vout") of the output going to the next genesis item.
	pub(crate) output_idx: u8,
	/// The other outputs to construct the exit tx.
	// NB empty for the first item
	pub(crate) other_outputs: Vec<TxOut>,
}

impl GenesisItem {
	/// Construct the exit transaction at this level of the genesis.
	pub(crate) fn tx(&self,
		prev: OutPoint,
		next: TxOut,
		server_pubkey: PublicKey,
		expiry_height: BlockHeight,
	) -> Transaction {
		Transaction {
			version: bitcoin::transaction::Version(3),
			lock_time: bitcoin::absolute::LockTime::ZERO,
			input: vec![TxIn {
				previous_output: prev,
				script_sig: ScriptBuf::new(),
				sequence: Sequence::ZERO,
				witness: self.transition.witness(server_pubkey, expiry_height),
			}],
			output: {
				let mut out = Vec::with_capacity(self.other_outputs.len() + 2);
				out.extend(self.other_outputs.iter().take(self.output_idx as usize).cloned());
				out.push(next);
				out.extend(self.other_outputs.iter().skip(self.output_idx as usize).cloned());
				out.push(fee::fee_anchor());
				out
			},
		}
	}
}

use std::fmt;

use bitcoin::secp256k1::{schnorr, PublicKey};
use bitcoin::{Amount, OutPoint, Sequence, ScriptBuf, Transaction, TxIn, TxOut, Witness};
use bitcoin::hashes::{sha256, Hash};
use bitcoin::key::TweakedPublicKey;
use bitcoin::sighash;
use bitcoin::taproot::{self, TapLeafHash, LeafVersion, TapTweakHash};

use bitcoin_ext::{fee, BlockDelta, BlockHeight, TaprootSpendInfoExt};

use crate::SECP;
use crate::musig;
use crate::tree::signed::{cosign_taproot, leaf_cosign_taproot, unlock_clause};
use crate::vtxo::MaybePreimage;

/// Represents the kind of [GenesisTransition]
pub enum TransitionKind {
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CosignedGenesis {
	/// All the cosign pubkeys signing the node.
	///
	/// Has to include server's cosign pubkey because it differs
	/// from its regular pubkey.
	pub pubkeys: Vec<PublicKey>,
	pub signature: schnorr::Signature,
}

impl CosignedGenesis {

	/// Taproot that this transition is satisfying.
	pub fn input_taproot(
		&self,
		server_pubkey: PublicKey,
		expiry_height: BlockHeight,
	) -> taproot::TaprootSpendInfo {
		let agg_pk = musig::combine_keys(self.pubkeys.iter().copied());
		cosign_taproot(agg_pk, server_pubkey, expiry_height)
	}

	pub fn input_txout(
		&self,
		amount: Amount,
		server_pubkey: PublicKey,
		expiry_height: BlockHeight,
	) -> TxOut {
		TxOut {
			value: amount,
			script_pubkey: self.input_taproot(server_pubkey, expiry_height).script_pubkey(),
		}
	}

	pub fn witness(&self) -> Witness {
		Witness::from_slice(&[&self.signature[..]])
	}

	pub fn is_fully_signed(&self) -> bool {
		true
	}

	pub fn validate_sigs(
		&self,
		tx: &Transaction,
		input_idx: usize,
		prev_txout: &TxOut,
		server_pubkey: PublicKey,
		expiry_height: BlockHeight,
	) -> Result<(), &'static str> {
		let mut shc = sighash::SighashCache::new(tx);

		let tapsighash = shc.taproot_key_spend_signature_hash(
			input_idx,
			&sighash::Prevouts::All(&[prev_txout]),
			sighash::TapSighashType::Default
		).expect("correct prevouts");

		let pubkey = self.input_taproot(server_pubkey, expiry_height)
			.output_key()
			.to_x_only_public_key();

		SECP.verify_schnorr(&self.signature, &tapsighash.into(), &pubkey)
			.map_err(|_| "invalid signature")
	}
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashLockedCosignedGenesis {
	/// User pubkey that is combined with the server pubkey
	pub user_pubkey: PublicKey,
	/// The script-spend signature
	pub signature: Option<schnorr::Signature>,
	/// The unlock preimage or the unlock hash
	pub unlock: MaybePreimage,
}

impl HashLockedCosignedGenesis {
	pub fn input_taproot(
		&self,
		server_pubkey: PublicKey,
		expiry_height: BlockHeight,
	) -> taproot::TaprootSpendInfo {
		leaf_cosign_taproot(self.user_pubkey, server_pubkey, expiry_height, self.unlock.hash())
	}

	pub fn input_txout(
		&self,
		amount: Amount,
		server_pubkey: PublicKey,
		expiry_height: BlockHeight,
	) -> TxOut {
		TxOut {
			value: amount,
			script_pubkey: self.input_taproot(server_pubkey, expiry_height).script_pubkey(),
		}
	}

	pub fn witness(
		&self,
		server_pubkey: PublicKey,
		expiry_height: BlockHeight,
	) -> Witness {
		// No witness if the preimage or sig is missing
		let preimage = match self.unlock {
			MaybePreimage::Preimage(p) => p,
			MaybePreimage::Hash(_) => return Witness::new(),
		};

		let sig = match self.signature {
			Some(sig) => sig,
			None => return Witness::new(),
		};

		let unlock_hash = sha256::Hash::hash(&preimage);
		let taproot = leaf_cosign_taproot(
			self.user_pubkey, server_pubkey, expiry_height, unlock_hash,
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
	}

	pub fn is_fully_signed(&self) -> bool {
		// Not fully signed if we don't know the preimage
		match self.unlock {
			MaybePreimage::Preimage(_) => {},
			MaybePreimage::Hash(_) => return false,
		};

		match self.signature {
			Some(_) => true,
			None => false,
		}
	}

	pub fn validate_sigs(
		&self,
		tx: &Transaction,
		input_idx: usize,
		prev_txout: &TxOut,
		server_pubkey: PublicKey,
		expiry_height: BlockHeight,
	) -> Result<(), &'static str> {
		match self.unlock {
			MaybePreimage::Preimage(_) => {},
			MaybePreimage::Hash(_) => return Err("missing preimage")
		};

		let mut shc = sighash::SighashCache::new(tx);
		let agg_pk = musig::combine_keys([self.user_pubkey, server_pubkey]);
		let script = unlock_clause(agg_pk, self.unlock.hash());
		let leaf = TapLeafHash::from_script(&script, bitcoin::taproot::LeafVersion::TapScript);
		let tapsighash = shc.taproot_script_spend_signature_hash(
			input_idx, &sighash::Prevouts::All(&[prev_txout]), leaf, sighash::TapSighashType::Default,
		).expect("correct prevouts");

		let pk = self.input_taproot(server_pubkey, expiry_height)
			.internal_key();

		match self.signature {
			None => return Err("missing signature"),
			Some(sig) => {
				SECP.verify_schnorr(&sig, &tapsighash.into(), &pk)
				.map_err(|_| "invalid signature")
			}
		}
	}
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArkoorGenesis {
	/// The keys that are use dfor cosiging the keyspend.
	/// This excludes the server_pubkey
	pub client_cosigners: Vec<PublicKey>,
	pub tap_tweak: taproot::TapTweakHash,
	pub signature: Option<schnorr::Signature>,
}

impl ArkoorGenesis {
	pub fn client_cosigners(&self) -> impl Iterator<Item = PublicKey> + '_ {
		self.client_cosigners.iter().copied()
	}

	pub fn cosigners<'a>(&'a self, server_pubkey: PublicKey) -> impl Iterator<Item = PublicKey> + 'a {
		self.client_cosigners.iter().cloned().chain([server_pubkey])
	}

	pub fn input_txout(&self, amount: Amount, server_pubkey: PublicKey) -> TxOut {
		TxOut {
			value: amount,
			script_pubkey: ScriptBuf::new_p2tr_tweaked(self.output_key(server_pubkey))
		}
	}

	pub fn output_key(&self, server_pubkey: PublicKey) -> TweakedPublicKey {
		let (_, agg_pk) = musig::tweaked_key_agg(self.cosigners(server_pubkey), self.tap_tweak.to_byte_array());
		TweakedPublicKey::dangerous_assume_tweaked(agg_pk.x_only_public_key().0)
	}

	pub fn witness(&self) -> Witness {
		match self.signature {
			Some(sig) => Witness::from_slice(&[&sig[..]]),
			None => Witness::new(),
		}
	}

	pub fn is_fully_signed(&self) -> bool {
		self.signature.is_some()
	}

	pub fn validate_sigs(
		&self,
		tx: &Transaction,
		input_idx: usize,
		prev_txout: &TxOut,
		server_pubkey: PublicKey,
	) -> Result<(), &'static str> {
		let signature = match self.signature {
			Some(sig) => sig,
			None => return Err("missing signature"),
		};

		let mut shc = sighash::SighashCache::new(tx);

		let tapsighash = shc.taproot_key_spend_signature_hash(
			input_idx,
			&sighash::Prevouts::All(&[prev_txout]),
			sighash::TapSighashType::Default
		).expect("correct prevouts");


		SECP.verify_schnorr(
			&signature,
			&tapsighash.into(),
			&self.output_key(server_pubkey).to_x_only_public_key(),
		).map_err(|_| "invalid signature")
	}
}

/// A transition from one genesis tx to the next.
///
/// See private module-level documentation for more info.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GenesisTransition {
	/// A transition based on a cosignature.
	///
	/// This can be either the result of a cosigned "clArk" tree branch transition
	/// or a board which is cosigned just with the server.
	Cosigned(CosignedGenesis),
	/// A transition based on a cosignature and a hash lock
	///
	/// This is the transition type for hArk leaf policy outputs,
	/// that spend into the leaf transaction.
	///
	/// Refraining from any optimizations, this type is implemented the naive way:
	/// - the keyspend path is currently unused, could be used later
	/// - witness will always contain the cosignature and preimage in the script spend
	HashLockedCosigned(HashLockedCosignedGenesis),
	/// A regular arkoor spend, using the co-signed p2tr key-spend path.
	Arkoor(ArkoorGenesis),
}

impl GenesisTransition {
	pub fn new_cosigned(pubkeys: Vec<PublicKey>, signature: schnorr::Signature) -> Self {
		Self::Cosigned(CosignedGenesis { pubkeys, signature })
	}

	pub fn new_hash_locked_cosigned(
		user_pubkey: PublicKey,
		signature: Option<schnorr::Signature>,
		unlock: MaybePreimage
	) -> Self {
		Self::HashLockedCosigned(
			HashLockedCosignedGenesis { user_pubkey, signature, unlock }
		)
	}


	pub fn new_arkoor(
		cosigners: Vec<PublicKey>,
		tap_tweak: TapTweakHash,
		signature: Option<schnorr::Signature>
	) -> Self {
		Self::Arkoor(ArkoorGenesis { client_cosigners: cosigners, tap_tweak, signature })
	}

	/// Output that this transition is spending.
	pub fn input_txout(
		&self,
		amount: Amount,
		server_pubkey: PublicKey,
		expiry_height: BlockHeight,
		_exit_delta: BlockDelta,
	) -> TxOut {
		match self {
			Self::Cosigned(inner) => inner.input_txout(amount, server_pubkey, expiry_height),
			Self::HashLockedCosigned(inner) => inner.input_txout(amount, server_pubkey, expiry_height),
			Self::Arkoor(inner) => inner.input_txout(amount, server_pubkey),
		}
	}

	/// The transaction witness for this transition.
	pub fn witness(
		&self,
		server_pubkey: PublicKey,
		expiry_height: BlockHeight,
	) -> Witness {
		match self {
			Self::Cosigned(inner) => inner.witness(),
			Self::HashLockedCosigned(inner) => inner.witness(server_pubkey, expiry_height),
			Self::Arkoor(inner) => inner.witness(),
		}
	}


	/// Whether the transition is fully signed
	pub fn is_fully_signed(&self) -> bool {
		match self {
			Self::Cosigned(inner) => inner.is_fully_signed(),
			Self::HashLockedCosigned(inner) => inner.is_fully_signed(),
			Self::Arkoor(inner) => inner.is_fully_signed(),
		}
	}

	/// String of the transition kind, for error reporting
	pub fn kind(&self) -> TransitionKind {
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
pub struct GenesisItem {
	/// The transition from the previous tx to this one.
	pub transition: GenesisTransition,
	/// The output index ("vout") of the output going to the next genesis item.
	pub output_idx: u8,
	/// The other outputs to construct the exit tx.
	// NB empty for the first item
	pub other_outputs: Vec<TxOut>,
}

impl GenesisItem {
	/// Construct the exit transaction at this level of the genesis.
	pub fn tx(&self,
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

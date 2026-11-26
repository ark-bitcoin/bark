use std::fmt;

use bitcoin::absolute::LockTime;
use bitcoin::secp256k1::{schnorr, PublicKey};
use bitcoin::{
	Amount, OutPoint, Sequence, ScriptBuf, Transaction, TxIn, TxOut, Witness, XOnlyPublicKey,
};
use bitcoin::hashes::{sha256, Hash};
use bitcoin::key::{TapTweak, TweakedPublicKey};
use bitcoin::sighash;
use bitcoin::taproot::{
	self, ControlBlock, LeafVersion, TapLeafHash, TapNodeHash, TapTweakHash, TaprootMerkleBranch,
};
use miniscript::{Miniscript, Tap};
use miniscript::interpreter::{Interpreter, KeySigPair, SatisfiedConstraint};

use bitcoin_ext::{fee, BlockDelta, BlockHeight, TaprootSpendInfoExt};

use crate::SECP;
use crate::musig;
use crate::tree::signed::{
	cosign_taproot, leaf_cosign_taproot, leaf_cosign_taproot_v0, unlock_clause, unlock_clause_v0,
};
use crate::vtxo::MaybePreimage;

/// Represents the kind of [GenesisTransition]
pub enum TransitionKind {
	Cosigned,
	HashLockedCosigned,
	#[allow(non_camel_case_types)]
	HashLockedCosigned_v0,
	Arkoor,
	ScriptArkoor,
}

impl TransitionKind {
	pub const fn as_str(&self) -> &'static str {
		match self {
			Self::Cosigned => "cosigned",
			Self::HashLockedCosigned => "hash-locked-cosigned-v1",
			Self::HashLockedCosigned_v0 => "hash-locked-cosigned",
			Self::Arkoor => "arkoor",
			Self::ScriptArkoor => "script-arkoor",
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
	pub signature: Option<schnorr::Signature>,
}

impl CosignedGenesis {

	/// Taproot that this transition is satisfying.
	pub fn input_taproot(
		&self,
		server_pubkey: PublicKey,
		expiry_height: BlockHeight,
	) -> taproot::TaprootSpendInfo {
		let agg_pk = musig::combine_keys(self.pubkeys.iter().copied())
			.x_only_public_key().0;
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
		match self.signature {
			Some(ref sig) => Witness::from_slice(&[&sig[..]]),
			None => Witness::new(),
		}
	}

	/// Whether all transaction witnesses are present
	pub fn has_all_witnesses(&self) -> bool {
		self.signature.is_some()
	}

	pub fn validate_sigs(
		&self,
		tx: &Transaction,
		input_idx: usize,
		prev_txout: &TxOut,
		server_pubkey: PublicKey,
		expiry_height: BlockHeight,
	) -> Result<(), &'static str> {
		let signature = match self.signature {
			Some(sig) => sig,
			None => return Err("missing cosigned signature"),
		};

		let mut shc = sighash::SighashCache::new(tx);

		let tapsighash = shc.taproot_key_spend_signature_hash(
			input_idx,
			&sighash::Prevouts::All(&[prev_txout]),
			sighash::TapSighashType::Default
		).expect("correct prevouts");

		let pubkey = self.input_taproot(server_pubkey, expiry_height)
			.output_key()
			.to_x_only_public_key();

		SECP.verify_schnorr(&signature, &tapsighash.into(), &pubkey)
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

	/// Whether all transaction witnesses are present
	pub fn has_all_witnesses(&self) -> bool {
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
		let agg_pk = musig::combine_keys([self.user_pubkey, server_pubkey])
			.x_only_public_key().0;
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
#[allow(non_camel_case_types)]
pub struct HashLockedCosignedGenesis_v0 {
	/// User pubkey that is combined with the server pubkey
	pub user_pubkey: PublicKey,
	/// The script-spend signature
	pub signature: Option<schnorr::Signature>,
	/// The unlock preimage or the unlock hash
	pub unlock: MaybePreimage,
}

impl HashLockedCosignedGenesis_v0 {
	pub fn input_taproot(
		&self,
		server_pubkey: PublicKey,
		expiry_height: BlockHeight,
	) -> taproot::TaprootSpendInfo {
		leaf_cosign_taproot_v0(self.user_pubkey, server_pubkey, expiry_height, self.unlock.hash())
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
		let taproot = leaf_cosign_taproot_v0(
			self.user_pubkey, server_pubkey, expiry_height, unlock_hash,
		);

		let clause = unlock_clause_v0(taproot.internal_key(), unlock_hash);
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

	/// Whether all transaction witnesses are present
	pub fn has_all_witnesses(&self) -> bool {
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
		let agg_pk = musig::combine_keys([self.user_pubkey, server_pubkey])
			.x_only_public_key().0;
		let script = unlock_clause_v0(agg_pk, self.unlock.hash());
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
	/// The keys that are used for cosiging the keyspend.
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

	// Not fully signed if we don't know the preimage
	pub fn has_all_witnesses(&self) -> bool {
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

/// The maximum size in bytes of the tapscript of a [ScriptArkoorGenesis].
pub const MAX_SCRIPT_ARKOOR_SCRIPT_SIZE: usize = 10_000;

/// The maximum size in bytes of a witness argument of a
/// [ScriptArkoorGenesis].
pub const MAX_SCRIPT_ARKOOR_WITNESS_ARG_SIZE: usize = 520;

/// The maximum number of witness arguments of a [ScriptArkoorGenesis].
pub const MAX_SCRIPT_ARKOOR_WITNESS_ARGS: usize = 100;

/// An arkoor spend through a tapscript leaf that the server cosigned.
///
/// This transition is not specific to a VTXO policy. It holds only the spent
/// leaf and its merkle path, so a wallet can validate a spend of a policy
/// that it does not know. The leaf must be sane miniscript and the cosign
/// key (the aggregate of the client cosigners and the server) must sign it.
///
/// The other leaves and the internal key of the spent output stay unknown.
/// The receiver trusts the server to cosign only leaves of policies that it
/// knows, like it does for the tap tweak of an [ArkoorGenesis].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptArkoorGenesis {
	/// The keys that cosign the leaf together with the server.
	/// This excludes the server_pubkey
	pub client_cosigners: Vec<PublicKey>,
	/// The spent tapscript leaf.
	pub script: ScriptBuf,
	/// The taproot internal key of the spent output.
	pub internal_key: XOnlyPublicKey,
	/// The merkle path from the leaf to the taproot root.
	pub merkle_branch: TaprootMerkleBranch,
	/// The witness stack items of the leaf without the signature, for
	/// example a preimage.
	pub witness_args: Vec<Vec<u8>>,
	/// The position of the signature in the witness stack.
	///
	/// The signature goes before the witness argument with this index, so
	/// this is at most the number of witness arguments.
	pub signature_index: u8,
	/// The locktime of the spending transaction.
	pub locktime: LockTime,
	/// The cosignature
	pub signature: Option<schnorr::Signature>,
}

impl ScriptArkoorGenesis {
	pub fn client_cosigners(&self) -> impl Iterator<Item = PublicKey> + '_ {
		self.client_cosigners.iter().copied()
	}

	/// The aggregate key of the client cosigners and the server, which must
	/// sign the leaf.
	pub fn cosign_pubkey(&self, server_pubkey: PublicKey) -> XOnlyPublicKey {
		musig::combine_keys(self.client_cosigners().chain([server_pubkey]))
			.x_only_public_key().0
	}

	/// The taproot merkle root of the spent output.
	pub fn merkle_root(&self) -> TapNodeHash {
		let leaf = TapNodeHash::from_script(&self.script, LeafVersion::TapScript);
		self.merkle_branch.iter().fold(leaf, |node, sibling| {
			TapNodeHash::from_node_hashes(node, *sibling)
		})
	}

	/// The control block that proves that the leaf is in the spent output.
	pub fn control_block(&self) -> ControlBlock {
		let (_, parity) = self.internal_key.tap_tweak(&SECP, Some(self.merkle_root()));
		ControlBlock {
			leaf_version: LeafVersion::TapScript,
			output_key_parity: parity,
			internal_key: self.internal_key,
			merkle_branch: self.merkle_branch.clone(),
		}
	}

	pub fn input_txout(&self, amount: Amount) -> TxOut {
		TxOut {
			value: amount,
			script_pubkey: ScriptBuf::new_p2tr(&SECP, self.internal_key, Some(self.merkle_root())),
		}
	}

	pub fn witness(&self) -> Witness {
		let sig = match self.signature {
			Some(sig) => sig,
			None => return Witness::new(),
		};

		let sig_idx = usize::from(self.signature_index);
		if sig_idx > self.witness_args.len() {
			return Witness::new();
		}

		let mut ret = Witness::new();
		for arg in &self.witness_args[..sig_idx] {
			ret.push(arg);
		}
		ret.push(&sig[..]);
		for arg in &self.witness_args[sig_idx..] {
			ret.push(arg);
		}
		ret.push(self.script.as_bytes());
		ret.push(self.control_block().serialize());
		ret
	}

	/// Whether all transaction witnesses are present
	pub fn has_all_witnesses(&self) -> bool {
		self.signature.is_some()
			&& usize::from(self.signature_index) <= self.witness_args.len()
	}

	/// Validate the script spend of the given input.
	///
	/// This checks the following:
	/// - the leaf is sane miniscript,
	/// - the witness satisfies the leaf, including hash locks and timelocks,
	/// - the locktime equals the absolute timelock of the leaf, or is zero
	///   when the leaf has none,
	/// - the cosign key signed the transaction.
	pub fn validate_sigs(
		&self,
		tx: &Transaction,
		input_idx: usize,
		prev_txout: &TxOut,
		server_pubkey: PublicKey,
	) -> Result<(), &'static str> {
		if self.signature.is_none() {
			return Err("missing signature");
		}
		if usize::from(self.signature_index) > self.witness_args.len() {
			return Err("signature index out of range");
		}

		// The interpreter also accepts miniscript that is not sane, for
		// example a leaf that needs no signature.
		Miniscript::<XOnlyPublicKey, Tap>::parse(&self.script)
			.map_err(|_| "tapscript is not sane miniscript")?;

		let input = tx.input.get(input_idx).ok_or("input idx out of range")?;
		let witness = self.witness();
		let script_sig = ScriptBuf::new();
		// This also checks that the leaf is committed to in the spent output.
		let interpreter = Interpreter::from_txdata(
			&prev_txout.script_pubkey, &script_sig, &witness, input.sequence, tx.lock_time,
		).map_err(|_| "invalid tapscript spend")?;

		let cosign_pubkey = self.cosign_pubkey(server_pubkey);
		let prevouts = [prev_txout];
		let prevouts = sighash::Prevouts::All(&prevouts);
		let mut cosigned = false;
		// Sane miniscript doesn't mix height and time locks, so comparing
		// the consensus values is fine.
		let mut timelock = None::<LockTime>;
		for constraint in interpreter.iter(&*SECP, tx, input_idx, &prevouts) {
			match constraint.map_err(|_| "tapscript is not satisfied")? {
				SatisfiedConstraint::PublicKey { key_sig: KeySigPair::Schnorr(pubkey, _) } => {
					if pubkey == cosign_pubkey {
						cosigned = true;
					}
				},
				SatisfiedConstraint::AbsoluteTimelock { n } => {
					if timelock.map_or(true, |t| n.to_consensus_u32() > t.to_consensus_u32()) {
						timelock = Some(n);
					}
				},
				_ => {},
			}
		}

		if !cosigned {
			return Err("tapscript is not signed by the cosign key");
		}
		if self.locktime != timelock.unwrap_or(LockTime::ZERO) {
			return Err("locktime doesn't match the tapscript timelock");
		}
		Ok(())
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
	/// A transition based on a cosignature and a hash lock
	///
	/// This is the transition type for hArk leaf policy outputs,
	/// that spend into the leaf transaction.
	#[allow(non_camel_case_types)]
	HashLockedCosigned_v0(HashLockedCosignedGenesis_v0),
	/// A regular arkoor spend, using the co-signed p2tr key-spend path.
	Arkoor(ArkoorGenesis),
	/// An arkoor spend using a tapscript leaf that the server cosigned.
	ScriptArkoor(ScriptArkoorGenesis),
}

impl GenesisTransition {
	pub fn new_cosigned(pubkeys: Vec<PublicKey>, signature: Option<schnorr::Signature>) -> Self {
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

	pub fn new_hash_locked_cosigned_v0(
		user_pubkey: PublicKey,
		signature: Option<schnorr::Signature>,
		unlock: MaybePreimage
	) -> Self {
		Self::HashLockedCosigned_v0(
			HashLockedCosignedGenesis_v0 { user_pubkey, signature, unlock }
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
			Self::HashLockedCosigned_v0(inner) => inner.input_txout(amount, server_pubkey, expiry_height),
			Self::Arkoor(inner) => inner.input_txout(amount, server_pubkey),
			Self::ScriptArkoor(inner) => inner.input_txout(amount),
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
			Self::HashLockedCosigned_v0(inner) => inner.witness(server_pubkey, expiry_height),
			Self::Arkoor(inner) => inner.witness(),
			Self::ScriptArkoor(inner) => inner.witness(),
		}
	}

	/// The locktime required on the transaction spending this transition.
	///
	/// Returns [None] when the spent clause has no absolute timelock.
	pub fn locktime(&self) -> Option<LockTime> {
		match self {
			Self::Cosigned(..) => None,
			Self::HashLockedCosigned(..) => None,
			Self::HashLockedCosigned_v0(..) => None,
			Self::Arkoor(..) => None,
			Self::ScriptArkoor(inner) => Some(inner.locktime),
		}
	}

	/// Whether the transition is fully signed
	pub fn has_all_witnesses(&self) -> bool {
		match self {
			Self::Cosigned(inner) => inner.has_all_witnesses(),
			Self::HashLockedCosigned(inner) => inner.has_all_witnesses(),
			Self::HashLockedCosigned_v0(inner) => inner.has_all_witnesses(),
			Self::Arkoor(inner) => inner.has_all_witnesses(),
			Self::ScriptArkoor(inner) => inner.has_all_witnesses(),
		}
	}

	/// String of the transition kind, for error reporting
	pub fn kind(&self) -> TransitionKind {
		match self {
			Self::Cosigned { .. } => TransitionKind::Cosigned,
			Self::HashLockedCosigned { .. } => TransitionKind::HashLockedCosigned,
			Self::HashLockedCosigned_v0 { .. } => TransitionKind::HashLockedCosigned_v0,
			Self::Arkoor { .. } => TransitionKind::Arkoor,
			Self::ScriptArkoor { .. } => TransitionKind::ScriptArkoor,
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
	pub other_outputs: Vec<TxOut>,
	/// The fee to apply to the P2A (pay-to-anchor) output of the exit tx. Likely to be a value of
	/// zero, however, fees for certain operations such as boarding can go here if applicable.
	pub fee_amount: Amount,
}

impl GenesisItem {
	/// Construct the P2A (pay-to-anchor) output for the exit tx.
	pub fn fee_anchor(&self) -> TxOut {
		fee::fee_anchor_with_amount(self.fee_amount)
	}

	/// The total sum of sibling tx outputs including the P2A fee output.
	pub fn other_output_sum(&self) -> Option<Amount> {
		let mut result = self.fee_amount;
		for o in &self.other_outputs {
			result = result.checked_add(o.value)?;
		}
		Some(result)
	}

	/// Construct the exit transaction at this level of the genesis.
	pub fn tx(&self,
		prev: OutPoint,
		next: TxOut,
		server_pubkey: PublicKey,
		expiry_height: BlockHeight,
	) -> Transaction {
		Transaction {
			version: bitcoin::transaction::Version(3),
			lock_time: self.transition.locktime().unwrap_or(LockTime::ZERO),
			input: vec![TxIn {
				previous_output: prev,
				script_sig: ScriptBuf::new(),
				sequence: Sequence::ZERO,
				witness: self.transition.witness(server_pubkey, expiry_height),
			}],
			output: {
				let mut out = Vec::with_capacity(self.other_outputs.len().saturating_add(2));
				out.extend(self.other_outputs.iter().take(self.output_idx as usize).cloned());
				out.push(next);
				out.extend(self.other_outputs.iter().skip(self.output_idx as usize).cloned());
				out.push(self.fee_anchor());
				out
			},
		}
	}
}

#[cfg(test)]
mod test {
	use bitcoin::Txid;
	use bitcoin::hashes::ripemd160;
	use bitcoin::key::Keypair;
	use bitcoin::opcodes;
	use bitcoin::taproot::TaprootBuilder;

	use crate::scripts;
	use crate::test_util::verify_tx;
	use crate::test_util::dummy::{DUMMY_SERVER_KEY, DUMMY_USER_KEY};

	use super::*;

	const PREIMAGE: [u8; 32] = [7u8; 32];
	const TIMELOCK: u32 = 100_000;

	fn cosign_pubkey() -> XOnlyPublicKey {
		musig::combine_keys([DUMMY_USER_KEY.public_key(), DUMMY_SERVER_KEY.public_key()])
			.x_only_public_key().0
	}

	fn hash_script() -> ScriptBuf {
		scripts::hash_and_sign(sha256::Hash::hash(&PREIMAGE), cosign_pubkey())
	}

	/// The miniscript `and_v(v:after(TIMELOCK),pk(cosign_pubkey))`.
	fn timelock_script() -> ScriptBuf {
		bitcoin::Script::builder()
			.push_int(TIMELOCK as i64)
			.push_opcode(opcodes::all::OP_CLTV)
			.push_opcode(opcodes::all::OP_VERIFY)
			.push_x_only_key(&cosign_pubkey())
			.push_opcode(opcodes::all::OP_CHECKSIG)
			.into_script()
	}

	/// Sign the message with the aggregate key of the user and the server.
	fn cosign(sighash: [u8; 32]) -> schnorr::Signature {
		let user_key = &*DUMMY_USER_KEY;
		let server_key = &*DUMMY_SERVER_KEY;
		let (user_sec_nonce, user_pub_nonce) = musig::nonce_pair(user_key);
		let (server_pub_nonce, server_part_sig) = musig::deterministic_partial_sign(
			server_key, [user_key.public_key()], &[&user_pub_nonce], sighash, None,
		);
		let agg_nonce = musig::nonce_agg(&[&user_pub_nonce, &server_pub_nonce]);
		let (_, sig) = musig::partial_sign(
			[user_key.public_key(), server_key.public_key()],
			agg_nonce,
			user_key,
			user_sec_nonce,
			sighash,
			None,
			Some(&[&server_part_sig]),
		);
		sig.expect("should have final signature")
	}

	/// Create an output with the given tapscript and one other leaf, and a
	/// transaction that spends it through the given tapscript. The given
	/// function creates the signature for the sighash.
	fn script_spend(
		script: ScriptBuf,
		witness_args: Vec<Vec<u8>>,
		locktime: LockTime,
		sign: impl FnOnce([u8; 32]) -> schnorr::Signature,
	) -> (ScriptArkoorGenesis, Transaction, TxOut) {
		script_spend_with_sig_idx(script, witness_args, 0, locktime, sign)
	}

	/// Like [script_spend], with the signature at the given position in the
	/// witness stack.
	fn script_spend_with_sig_idx(
		script: ScriptBuf,
		witness_args: Vec<Vec<u8>>,
		signature_index: u8,
		locktime: LockTime,
		sign: impl FnOnce([u8; 32]) -> schnorr::Signature,
	) -> (ScriptArkoorGenesis, Transaction, TxOut) {
		let other_leaf = scripts::delayed_sign(BlockDelta::new(12), cosign_pubkey());
		let taproot = TaprootBuilder::new()
			.add_leaf(1, script.clone()).unwrap()
			.add_leaf(1, other_leaf).unwrap()
			.finalize(&SECP, cosign_pubkey()).unwrap();
		let control_block = taproot.control_block(&(script.clone(), LeafVersion::TapScript))
			.expect("script is in taproot");

		let mut genesis = ScriptArkoorGenesis {
			client_cosigners: vec![DUMMY_USER_KEY.public_key()],
			script: script.clone(),
			internal_key: control_block.internal_key,
			merkle_branch: control_block.merkle_branch,
			witness_args,
			signature_index,
			locktime,
			signature: None,
		};
		let prev_txout = genesis.input_txout(Amount::from_sat(100_000));
		assert_eq!(prev_txout.script_pubkey, taproot.script_pubkey());

		let mut tx = Transaction {
			version: bitcoin::transaction::Version(3),
			lock_time: locktime,
			input: vec![TxIn {
				previous_output: OutPoint::new(Txid::all_zeros(), 0),
				script_sig: ScriptBuf::new(),
				sequence: Sequence::ZERO,
				witness: Witness::new(),
			}],
			output: vec![
				TxOut { value: Amount::from_sat(100_000), script_pubkey: ScriptBuf::new() },
				fee::fee_anchor(),
			],
		};
		let leaf_hash = TapLeafHash::from_script(&script, LeafVersion::TapScript);
		let sighash = sighash::SighashCache::new(&tx).taproot_script_spend_signature_hash(
			0,
			&sighash::Prevouts::All(&[&prev_txout]),
			leaf_hash,
			sighash::TapSighashType::Default,
		).expect("correct prevouts");
		genesis.signature = Some(sign(sighash.to_byte_array()));
		tx.input[0].witness = genesis.witness();

		(genesis, tx, prev_txout)
	}

	fn validate(
		genesis: &ScriptArkoorGenesis,
		tx: &Transaction,
		prev_txout: &TxOut,
	) -> Result<(), &'static str> {
		genesis.validate_sigs(tx, 0, prev_txout, DUMMY_SERVER_KEY.public_key())
	}

	#[test]
	fn script_arkoor_valid_spends() {
		let (genesis, tx, prev_txout) = script_spend(
			hash_script(), vec![PREIMAGE.to_vec()], LockTime::ZERO, cosign,
		);
		validate(&genesis, &tx, &prev_txout).expect("valid hash lock spend");
		verify_tx(&[prev_txout], 0, &tx).expect("invalid transaction");

		let locktime = LockTime::from_consensus(TIMELOCK);
		let (genesis, tx, prev_txout) = script_spend(timelock_script(), vec![], locktime, cosign);
		validate(&genesis, &tx, &prev_txout).expect("valid timelock spend");
		verify_tx(&[prev_txout], 0, &tx).expect("invalid transaction");
	}

	#[test]
	fn script_arkoor_signature_index() {
		// A leaf with the key check before the hash lock, so the signature
		// comes after the preimage in the witness stack.
		let hash160 = ripemd160::Hash::hash(&sha256::Hash::hash(&PREIMAGE)[..]);
		let script = bitcoin::Script::builder()
			.push_x_only_key(&cosign_pubkey())
			.push_opcode(opcodes::all::OP_CHECKSIGVERIFY)
			.push_opcode(opcodes::all::OP_SIZE)
			.push_int(32)
			.push_opcode(opcodes::all::OP_EQUALVERIFY)
			.push_opcode(opcodes::all::OP_HASH160)
			.push_slice(hash160.as_byte_array())
			.push_opcode(opcodes::all::OP_EQUAL)
			.into_script();
		let (mut genesis, tx, prev_txout) = script_spend_with_sig_idx(
			script, vec![PREIMAGE.to_vec()], 1, LockTime::ZERO, cosign,
		);
		assert_eq!(genesis.witness().nth(0), Some(&PREIMAGE[..]));
		validate(&genesis, &tx, &prev_txout).expect("valid spend");
		verify_tx(&[prev_txout.clone()], 0, &tx).expect("invalid transaction");

		genesis.signature_index = 0;
		assert_eq!(validate(&genesis, &tx, &prev_txout), Err("tapscript is not satisfied"));

		genesis.signature_index = 2;
		assert!(!genesis.has_all_witnesses());
		assert!(genesis.witness().is_empty());
		assert_eq!(validate(&genesis, &tx, &prev_txout), Err("signature index out of range"));
	}

	#[test]
	fn script_arkoor_rejects_missing_signature() {
		let (mut genesis, tx, prev_txout) = script_spend(
			hash_script(), vec![PREIMAGE.to_vec()], LockTime::ZERO, cosign,
		);
		genesis.signature = None;
		assert_eq!(validate(&genesis, &tx, &prev_txout), Err("missing signature"));
	}

	#[test]
	fn script_arkoor_rejects_wrong_preimage() {
		let (mut genesis, tx, prev_txout) = script_spend(
			hash_script(), vec![PREIMAGE.to_vec()], LockTime::ZERO, cosign,
		);
		genesis.witness_args = vec![vec![8u8; 32]];
		assert_eq!(validate(&genesis, &tx, &prev_txout), Err("tapscript is not satisfied"));

		genesis.witness_args = vec![];
		validate(&genesis, &tx, &prev_txout).expect_err("missing preimage");
	}

	#[test]
	fn script_arkoor_rejects_locktime_below_timelock() {
		// The signature is valid for the transaction, but the transaction
		// does not satisfy the timelock of the leaf.
		let locktime = LockTime::from_consensus(TIMELOCK - 1);
		let (genesis, tx, prev_txout) = script_spend(timelock_script(), vec![], locktime, cosign);
		assert_eq!(validate(&genesis, &tx, &prev_txout), Err("tapscript is not satisfied"));
		verify_tx(&[prev_txout], 0, &tx).expect_err("transaction is valid");
	}

	#[test]
	fn script_arkoor_rejects_locktime_above_timelock() {
		let locktime = LockTime::from_consensus(TIMELOCK + 1);
		let (genesis, tx, prev_txout) = script_spend(timelock_script(), vec![], locktime, cosign);
		verify_tx(&[prev_txout.clone()], 0, &tx).expect("invalid transaction");
		assert_eq!(
			validate(&genesis, &tx, &prev_txout),
			Err("locktime doesn't match the tapscript timelock"),
		);
	}

	#[test]
	fn script_arkoor_rejects_locktime_without_timelock() {
		let locktime = LockTime::from_consensus(1);
		let (genesis, tx, prev_txout) = script_spend(
			hash_script(), vec![PREIMAGE.to_vec()], locktime, cosign,
		);
		verify_tx(&[prev_txout.clone()], 0, &tx).expect("invalid transaction");
		assert_eq!(
			validate(&genesis, &tx, &prev_txout),
			Err("locktime doesn't match the tapscript timelock"),
		);
	}

	#[test]
	fn script_arkoor_rejects_other_signer() {
		// A valid spend of a leaf with a key that is not the aggregate key
		// of the client cosigners and the server.
		let other_key = Keypair::new(&SECP, &mut bitcoin::secp256k1::rand::thread_rng());
		let script = scripts::hash_and_sign(
			sha256::Hash::hash(&PREIMAGE), other_key.x_only_public_key().0,
		);
		let (genesis, tx, prev_txout) = script_spend(
			script, vec![PREIMAGE.to_vec()], LockTime::ZERO,
			|sighash| SECP.sign_schnorr(
				&bitcoin::secp256k1::Message::from_digest(sighash), &other_key,
			),
		);
		verify_tx(&[prev_txout.clone()], 0, &tx).expect("invalid transaction");
		assert_eq!(
			validate(&genesis, &tx, &prev_txout),
			Err("tapscript is not signed by the cosign key"),
		);

		// The same when the leaf has the cosign key but the transition
		// names other client cosigners.
		let (mut genesis, tx, prev_txout) = script_spend(
			hash_script(), vec![PREIMAGE.to_vec()], LockTime::ZERO, cosign,
		);
		genesis.client_cosigners = vec![other_key.public_key()];
		assert_eq!(
			validate(&genesis, &tx, &prev_txout),
			Err("tapscript is not signed by the cosign key"),
		);
	}

	#[test]
	fn script_arkoor_rejects_invalid_signature() {
		let (genesis, tx, prev_txout) = script_spend(
			hash_script(), vec![PREIMAGE.to_vec()], LockTime::ZERO,
			|_| cosign([1u8; 32]),
		);
		assert_eq!(validate(&genesis, &tx, &prev_txout), Err("tapscript is not satisfied"));
	}

	#[test]
	fn script_arkoor_rejects_non_miniscript() {
		// A valid spend of a leaf that is not miniscript.
		let script = scripts::timelock_sign(BlockHeight::new(TIMELOCK), cosign_pubkey());
		let locktime = LockTime::from_consensus(TIMELOCK);
		let (genesis, tx, prev_txout) = script_spend(script, vec![], locktime, cosign);
		verify_tx(&[prev_txout.clone()], 0, &tx).expect("invalid transaction");
		assert_eq!(
			validate(&genesis, &tx, &prev_txout),
			Err("tapscript is not sane miniscript"),
		);

		// A valid spend of a miniscript leaf that needs no signature.
		let hash160 = ripemd160::Hash::hash(&sha256::Hash::hash(&PREIMAGE)[..]);
		let script = bitcoin::Script::builder()
			.push_opcode(opcodes::all::OP_SIZE)
			.push_int(32)
			.push_opcode(opcodes::all::OP_EQUALVERIFY)
			.push_opcode(opcodes::all::OP_HASH160)
			.push_slice(hash160.as_byte_array())
			.push_opcode(opcodes::all::OP_EQUAL)
			.into_script();
		let (mut genesis, mut tx, prev_txout) = script_spend(
			script.clone(), vec![PREIMAGE.to_vec()], LockTime::ZERO, cosign,
		);
		let mut witness = Witness::new();
		witness.push(&PREIMAGE[..]);
		witness.push(script.as_bytes());
		witness.push(genesis.control_block().serialize());
		tx.input[0].witness = witness;
		verify_tx(&[prev_txout.clone()], 0, &tx).expect("invalid transaction");
		genesis.witness_args = vec![PREIMAGE.to_vec()];
		assert_eq!(
			validate(&genesis, &tx, &prev_txout),
			Err("tapscript is not sane miniscript"),
		);
	}

	#[test]
	fn script_arkoor_rejects_wrong_merkle_branch() {
		let (mut genesis, tx, prev_txout) = script_spend(
			hash_script(), vec![PREIMAGE.to_vec()], LockTime::ZERO, cosign,
		);
		genesis.merkle_branch = TaprootMerkleBranch::try_from(
			vec![TapNodeHash::from_byte_array([1u8; 32])],
		).unwrap();
		assert_eq!(validate(&genesis, &tx, &prev_txout), Err("invalid tapscript spend"));

		genesis.merkle_branch = TaprootMerkleBranch::default();
		assert_eq!(validate(&genesis, &tx, &prev_txout), Err("invalid tapscript spend"));
	}
}

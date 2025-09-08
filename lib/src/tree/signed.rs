

use std::{cmp, fmt, io, iter};
use std::collections::{HashMap, VecDeque};

use bitcoin::hashes::Hash;
use bitcoin::{
	taproot, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Weight, Witness,
};
use bitcoin::secp256k1::{schnorr, Keypair, PublicKey, XOnlyPublicKey};
use bitcoin::sighash::{self, SighashCache, TapSighash, TapSighashType};
use secp256k1_musig::musig::{AggregatedNonce, PartialSignature, PublicNonce, SecretNonce};

use bitcoin_ext::{fee, BlockHeight, TaprootSpendInfoExt, TransactionExt, TxOutExt};

use crate::error::IncorrectSigningKeyError;
use crate::{musig, scripts, SECP, SignedVtxoRequest, Vtxo, VtxoPolicy, VtxoRequest};
use crate::encode::{ProtocolDecodingError, ProtocolEncoding, ReadExt, WriteExt};
use crate::tree::{self, Tree};
use crate::vtxo::{self, GenesisItem, GenesisTransition};


/// The upper bound witness weight to spend a node transaction.
pub const NODE_SPEND_WEIGHT: Weight = Weight::from_wu(140);

/// The expiry clause hidden in the node taproot as only script.
pub fn expiry_clause(server_pubkey: PublicKey, expiry_height: BlockHeight) -> ScriptBuf {
	let pk = server_pubkey.x_only_public_key().0;
	scripts::timelock_sign(expiry_height, pk)
}

pub fn cosign_taproot(
	agg_pk: XOnlyPublicKey,
	server_pubkey: PublicKey,
	expiry_height: BlockHeight,
) -> taproot::TaprootSpendInfo {
	taproot::TaprootBuilder::new()
		.add_leaf(0, expiry_clause(server_pubkey, expiry_height)).unwrap()
		.finalize(&SECP, agg_pk).unwrap()
}

/// All the information that uniquely specifies a VTXO tree before it has been signed.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct VtxoTreeSpec {
	pub vtxos: Vec<SignedVtxoRequest>,
	pub expiry_height: BlockHeight,
	pub server_pubkey: PublicKey,
	pub exit_delta: u16,
	pub global_cosign_pubkeys: Vec<PublicKey>,
}

impl VtxoTreeSpec {
	pub fn new(
		vtxos: Vec<SignedVtxoRequest>,
		server_pubkey: PublicKey,
		expiry_height: BlockHeight,
		exit_delta: u16,
		global_cosign_pubkeys: Vec<PublicKey>,
	) -> VtxoTreeSpec {
		assert_ne!(vtxos.len(), 0);
		VtxoTreeSpec { vtxos, server_pubkey, expiry_height, exit_delta, global_cosign_pubkeys }
	}

	pub fn nb_leaves(&self) -> usize {
		self.vtxos.len()
	}

	pub fn nb_nodes(&self) -> usize {
		Tree::nb_nodes_for_leaves(self.nb_leaves())
	}

	pub fn iter_vtxos(&self) -> impl Iterator<Item = &SignedVtxoRequest> {
		self.vtxos.iter()
	}

	/// Get the leaf index of the given vtxo request.
	pub fn leaf_idx_of(&self, vtxo_request: &SignedVtxoRequest) -> Option<usize> {
		self.vtxos.iter().position(|e| e == vtxo_request)
	}

	/// Calculate the total value needed in the tree.
	///
	/// This accounts for
	/// - all vtxos getting their value
	pub fn total_required_value(&self) -> Amount {
		self.vtxos.iter().map(|d| d.vtxo.amount).sum::<Amount>()
	}

	/// Calculate the cosign taproot at a given node.
	pub fn cosign_taproot(&self, agg_pk: XOnlyPublicKey) -> taproot::TaprootSpendInfo {
		cosign_taproot(agg_pk, self.server_pubkey, self.expiry_height)
	}

	/// The cosign pubkey used on the vtxo output of the tx funding the tree
	///
	/// In Ark rounds this will be the round tx scriptPubkey.
	pub fn funding_tx_cosign_pubkey(&self) -> XOnlyPublicKey {
		let keys = self.vtxos.iter()
			.filter_map(|v| v.cosign_pubkey)
			.chain(self.global_cosign_pubkeys.iter().copied());
		musig::combine_keys(keys)
	}

	/// The scriptPubkey used on the vtxo output of the tx funding the tree
	///
	/// In Ark rounds this will be the round tx scriptPubkey.
	pub fn funding_tx_script_pubkey(&self) -> ScriptBuf {
		let agg_pk = self.funding_tx_cosign_pubkey();
		self.cosign_taproot(agg_pk).script_pubkey()
	}

	/// The output of the tx funding the tree
	///
	/// In Ark rounds this will be the round tx scriptPubkey.
	pub fn funding_tx_txout(&self) -> TxOut {
		TxOut {
			script_pubkey: self.funding_tx_script_pubkey(),
			value: self.total_required_value(),
		}
	}

	fn node_tx<'a>(&self, children: impl Iterator<Item=(&'a Transaction, &'a XOnlyPublicKey)>) -> Transaction {
		Transaction {
			version: bitcoin::transaction::Version(3),
			lock_time: bitcoin::absolute::LockTime::ZERO,
			input: vec![TxIn {
				previous_output: OutPoint::null(), // we will fill this later
				sequence: Sequence::ZERO,
				script_sig: ScriptBuf::new(),
				witness: Witness::new(),
			}],
			output: children.map(|(tx, agg_pk)| {
				let taproot = self.cosign_taproot(*agg_pk);
				TxOut {
					script_pubkey: taproot.script_pubkey(),
					value: tx.output_value(),
				}
			}).chain(Some(fee::fee_anchor())).collect(),
		}
	}

	fn leaf_tx(&self, vtxo: &VtxoRequest) -> Transaction {
		let txout = TxOut {
			value: vtxo.amount,
			script_pubkey: vtxo.policy.script_pubkey(self.server_pubkey, self.exit_delta),
		};

		vtxo::create_exit_tx(OutPoint::null(), txout, None)
	}

	/// Calculate all the aggregate cosign pubkeys by aggregating the leaf and server pubkeys.
	///
	/// Pubkeys expected and returned ordered from leaves to root.
	pub fn cosign_agg_pks(&self)
		-> impl Iterator<Item = XOnlyPublicKey> + iter::DoubleEndedIterator + iter::ExactSizeIterator + '_
	{
		Tree::new(self.nb_leaves()).into_iter().map(|node| {
			musig::combine_keys(
				node.leaves().filter_map(|i| self.vtxos[i].cosign_pubkey)
					.chain(self.global_cosign_pubkeys.iter().copied())
			)
		})
	}

	/// Return unsigned transactions for all nodes from leaves to root.
	pub fn unsigned_transactions(&self, utxo: OutPoint) -> Vec<Transaction> {
		let tree = Tree::new(self.nb_leaves());

		let cosign_agg_pks = self.cosign_agg_pks().collect::<Vec<_>>();

		let mut txs = Vec::with_capacity(tree.nb_nodes());
		for node in tree.iter() {
			let tx = if node.is_leaf() {
				self.leaf_tx(&self.vtxos[node.idx()].vtxo).clone()
			} else {
				let mut buf = [None; tree::RADIX];
				for (idx, child) in node.children().enumerate() {
					buf[idx] = Some((&txs[child], &cosign_agg_pks[child]));
				}
				self.node_tx(buf.iter().filter_map(|x| *x))
			};
			txs.push(tx.clone());
		};

		// set the prevouts
		txs.last_mut().unwrap().input[0].previous_output = utxo;
		for node in tree.iter().rev() {
			let txid = txs[node.idx()].compute_txid();
			for (i, child) in node.children().enumerate() {
				let point = OutPoint::new(txid, i as u32);
				txs[child].input[0].previous_output = point;
			}
		}

		txs
	}

	/// Return all signed transactions for all nodes from leaves to root.
	pub fn signed_transactions(
		&self,
		utxo: OutPoint,
		signatures: &[schnorr::Signature],
	) -> Vec<Transaction> {
		let mut txs = self.unsigned_transactions(utxo);
		for (tx, sig) in txs.iter_mut().zip(signatures) {
			tx.input[0].witness.push(&sig[..]);
		}
		txs
	}

	/// Calculate all the aggregate cosign nonces by aggregating the leaf and server nonces.
	///
	/// Nonces expected and returned ordered from leaves to root.
	pub fn calculate_cosign_agg_nonces(
		&self,
		leaf_cosign_nonces: &HashMap<PublicKey, Vec<PublicNonce>>,
		global_signer_cosign_nonces: &[impl AsRef<[PublicNonce]>],
	) -> Result<Vec<AggregatedNonce>, String> {
		if global_signer_cosign_nonces.len() != self.global_cosign_pubkeys.len() {
			return Err("missing global signer nonces".into());
		}

		Tree::new(self.nb_leaves()).iter().enumerate().map(|(idx, node)| {
			let mut nonces = Vec::new();
			for pk in node.leaves().filter_map(|i| self.vtxos[i].cosign_pubkey) {
				nonces.push(leaf_cosign_nonces.get(&pk)
					.ok_or_else(|| format!("missing nonces for leaf pk {}", pk))?
					// note that we skip some nonces for some leaves that are at the edges
					// and skip some levels
					.get(node.level())
					.ok_or_else(|| format!("not enough nonces for leaf_pk {}", pk))?
				);
			}
			for glob in global_signer_cosign_nonces {
				nonces.push(glob.as_ref().get(idx).ok_or("not enough global cosign nonces")?);
			}
			Ok(musig::nonce_agg(&nonces))
		}).collect()
	}

	/// Convert this spec into an unsigned tree by providing the
	/// root outpoint and the nodes' aggregate nonces.
	///
	/// Nonces expected ordered from leaves to root.
	pub fn into_unsigned_tree(
		self,
		utxo: OutPoint,
	) -> UnsignedVtxoTree {
		UnsignedVtxoTree::new(self, utxo)
	}
}

/// A VTXO tree ready to be signed.
///
/// This type contains various cached values required to sign the tree.
#[derive(Debug, Clone)]
pub struct UnsignedVtxoTree {
	pub spec: VtxoTreeSpec,
	pub utxo: OutPoint,

	// the following fields are calculated from the above

	/// Aggregate pubkeys for the inputs to all nodes, leaves to root.
	pub cosign_agg_pks: Vec<XOnlyPublicKey>,
	/// Transactions for all nodes, leaves to root.
	pub txs: Vec<Transaction>,
	/// Sighashes for the only input of the tx for all nodes, leaves to root.
	pub sighashes: Vec<TapSighash>,

	tree: Tree,
}

impl UnsignedVtxoTree {
	pub fn new(
		spec: VtxoTreeSpec,
		utxo: OutPoint,
	) -> UnsignedVtxoTree {
		let tree = Tree::new(spec.nb_leaves());

		let cosign_agg_pks = spec.cosign_agg_pks().collect::<Vec<_>>();
		let txs = spec.unsigned_transactions(utxo);

		let root_txout = spec.funding_tx_txout();
		let sighashes = tree.iter().map(|node| {
			let prev = if let Some((parent, sibling_idx)) = tree.parent_idx_of_with_sibling_idx(node.idx()) {
				assert!(!node.is_root());
				&txs[parent].output[sibling_idx]
			} else {
				assert!(node.is_root());
				&root_txout
			};
			SighashCache::new(&txs[node.idx()]).taproot_key_spend_signature_hash(
				0, // input idx is always 0
				&sighash::Prevouts::All(&[prev]),
				TapSighashType::Default,
			).expect("sighash error")
		}).collect();

		UnsignedVtxoTree { spec, utxo, txs, sighashes, cosign_agg_pks, tree }
	}

	pub fn nb_leaves(&self) -> usize {
		self.tree.nb_leaves()
	}

	pub fn nb_nodes(&self) -> usize {
		self.tree.nb_nodes()
	}

	/// Generate partial musig signatures for the nodes in the tree branch of the given
	/// vtxo request.
	///
	/// Note that the signatures are indexed by their place in the tree and thus do not
	/// necessarily match up with the indices in the secret nonces vector.
	///
	/// Aggregate nonces expected for all nodes, ordered from leaves to root.
	/// Secret nonces expected for branch, ordered from leaf to root.
	///
	/// Returns [None] if the vtxo request is not part of the tree.
	/// Returned signatures over the branch from leaf to root.
	//TODO(stevenroose) streamline indices of nonces and sigs
	pub fn cosign_branch(
		&self,
		cosign_agg_nonces: &[AggregatedNonce],
		leaf_idx: usize,
		cosign_key: &Keypair,
		cosign_sec_nonces: Vec<SecretNonce>,
	) -> Result<Vec<PartialSignature>, IncorrectSigningKeyError> {
		let req = self.spec.vtxos.get(leaf_idx).expect("leaf idx out of bounds");
		if Some(cosign_key.public_key()) != req.cosign_pubkey {
			return Err(IncorrectSigningKeyError {
				required: req.cosign_pubkey,
				provided: cosign_key.public_key(),
			});
		}

		let mut nonce_iter = cosign_sec_nonces.into_iter().enumerate();
		let mut ret = Vec::with_capacity(self.tree.root().level() + 1);
		for node in self.tree.iter_branch(leaf_idx) {
			// Since we can skip a level, we sometimes have to skip a nonce.
			// NB We can't just use the index into the sec_nonces vector, because
			// musig requires us to use the owned SecNonce type to prevent footgun
			// by reusing secret nonces.
			let sec_nonce = loop {
				let next = nonce_iter.next().expect("level overflow");
				if next.0 == node.level() {
					break next.1;
				}
			};

			let cosign_pubkeys = node.leaves().filter_map(|i| self.spec.vtxos[i].cosign_pubkey)
				.chain(self.spec.global_cosign_pubkeys.iter().copied());
			let sighash = self.sighashes[node.idx()];

			let agg_pk = self.cosign_agg_pks[node.idx()];
			let sig = musig::partial_sign(
				cosign_pubkeys,
				cosign_agg_nonces[node.idx()],
				&cosign_key,
				sec_nonce,
				sighash.to_byte_array(),
				Some(self.spec.cosign_taproot(agg_pk).tap_tweak().to_byte_array()),
				None,
			).0;
			ret.push(sig);
		}

		Ok(ret)
	}

	/// Generate partial musig signatures for all nodes in the tree.
	///
	/// Nonces expected for all nodes, ordered from leaves to root.
	///
	/// Returns [None] if the vtxo request is not part of the tree.
	pub fn cosign_tree(
		&self,
		cosign_agg_nonces: &[AggregatedNonce],
		keypair: &Keypair,
		cosign_sec_nonces: Vec<SecretNonce>,
	) -> Vec<PartialSignature> {
		assert_eq!(cosign_agg_nonces.len(), self.nb_nodes());
		assert_eq!(cosign_sec_nonces.len(), self.nb_nodes());

		self.tree.iter().zip(cosign_sec_nonces.into_iter()).map(|(node, sec_nonce)| {
			let cosign_pubkeys = node.leaves().filter_map(|i| self.spec.vtxos[i].cosign_pubkey)
				.chain(self.spec.global_cosign_pubkeys.iter().copied());
			let sighash = self.sighashes[node.idx()];

			let agg_pk = self.cosign_agg_pks[node.idx()];
			debug_assert_eq!(agg_pk, musig::combine_keys(cosign_pubkeys.clone()));
			musig::partial_sign(
				cosign_pubkeys,
				cosign_agg_nonces[node.idx()],
				&keypair,
				sec_nonce,
				sighash.to_byte_array(),
				Some(self.spec.cosign_taproot(agg_pk).tap_tweak().to_byte_array()),
				None,
			).0
		}).collect()
	}

	/// Verify partial cosign signature of a single node.
	fn verify_node_cosign_partial_sig(
		&self,
		node: &tree::Node,
		pk: PublicKey,
		agg_nonces: &[AggregatedNonce],
		part_sig: PartialSignature,
		pub_nonce: PublicNonce,
	) -> Result<(), CosignSignatureError> {
		let cosign_pubkeys = node.leaves().filter_map(|i| self.spec.vtxos[i].cosign_pubkey)
			.chain(self.spec.global_cosign_pubkeys.iter().copied());
		let sighash = self.sighashes[node.idx()];

		let taptweak = self.spec.cosign_taproot(self.cosign_agg_pks[node.idx()]).tap_tweak();
		let key_agg = musig::tweaked_key_agg(cosign_pubkeys, taptweak.to_byte_array()).0;
		let session = musig::Session::new(
			&musig::SECP,
			&key_agg,
			*agg_nonces.get(node.idx()).ok_or(CosignSignatureError::NotEnoughNonces)?,
			&sighash.to_byte_array(),
		);
		let success = session.partial_verify(
			&musig::SECP,
			&key_agg,
			&part_sig,
			&pub_nonce,
			musig::pubkey_to(pk),
		);
		if !success {
			return Err(CosignSignatureError::invalid_sig(pk));
		}
		Ok(())
	}

	/// Verify the partial cosign signatures from one of the leaves.
	///
	/// Nonces and partial signatures expected ordered from leaves to root.
	pub fn verify_branch_cosign_partial_sigs(
		&self,
		cosign_agg_nonces: &[AggregatedNonce],
		request: &SignedVtxoRequest,
		cosign_pub_nonces: &[PublicNonce],
		cosign_part_sigs: &[PartialSignature],
	) -> Result<(), String> {
		assert_eq!(cosign_agg_nonces.len(), self.nb_nodes());

		let cosign_pubkey = request.cosign_pubkey.ok_or("no cosign pubkey for request")?;
		let leaf_idx = self.spec.leaf_idx_of(request).ok_or("request not in tree")?;
		// quickly check if the number of sigs is sane
		match self.tree.iter_branch(leaf_idx).count().cmp(&cosign_part_sigs.len()) {
			cmp::Ordering::Less => return Err("too few partial signatures".into()),
			cmp::Ordering::Greater => return Err("too many partial signatures".into()),
			cmp::Ordering::Equal => {},
		}

		let mut part_sigs_iter = cosign_part_sigs.iter();
		let mut pub_nonce_iter = cosign_pub_nonces.iter().enumerate();
		for node in self.tree.iter_branch(leaf_idx) {
			let pub_nonce = loop {
				let next = pub_nonce_iter.next().ok_or("not enough pub nonces")?;
				if next.0 == node.level() {
					break next.1;
				}
			};
			self.verify_node_cosign_partial_sig(
				node,
				cosign_pubkey,
				cosign_agg_nonces,
				part_sigs_iter.next().ok_or("not enough sigs")?.clone(),
				*pub_nonce,
			).map_err(|e| format!("part sig verification failed: {}", e))?;
		}

		Ok(())
	}

	/// Verify the partial cosign signatures for all nodes.
	///
	/// Nonces and partial signatures expected ordered from leaves to root.
	pub fn verify_global_cosign_partial_sigs(
		&self,
		pk: PublicKey,
		agg_nonces: &[AggregatedNonce],
		pub_nonces: &[PublicNonce],
		part_sigs: &[PartialSignature],
	) -> Result<(), CosignSignatureError> {
		for node in self.tree.iter() {
			self.verify_node_cosign_partial_sig(
				node,
				pk,
				agg_nonces,
				*part_sigs.get(node.idx()).ok_or_else(|| CosignSignatureError::missing_sig(pk))?,
				*pub_nonces.get(node.idx()).ok_or_else(|| CosignSignatureError::NotEnoughNonces)?,
			)?;
		}

		Ok(())
	}

	/// Combine all partial cosign signatures.
	///
	/// Nonces expected ordered from leaves to root.
	/// Leaf signatures expected over leaf branch ordered from leaf to root.
	/// server signatures expected ordered from leaves to root.
	pub fn combine_partial_signatures(
		&self,
		cosign_agg_nonces: &[AggregatedNonce],
		leaf_part_sigs: &HashMap<PublicKey, Vec<PartialSignature>>,
		global_signer_part_sigs: &[impl AsRef<[PartialSignature]>],
	) -> Result<Vec<schnorr::Signature>, CosignSignatureError> {
		// to ease implementation, we're reconstructing the part sigs map with dequeues
		let mut leaf_part_sigs = leaf_part_sigs.iter()
			.map(|(pk, sigs)| (pk, sigs.iter().collect()))
			.collect::<HashMap<_, VecDeque<_>>>();

		if global_signer_part_sigs.len() != self.spec.global_cosign_pubkeys.len() {
			return Err(CosignSignatureError::Invalid(
				"invalid nb of global cosigner partial signatures",
			));
		}
		for (pk, sigs) in self.spec.global_cosign_pubkeys.iter().zip(global_signer_part_sigs) {
			if sigs.as_ref().len() != self.nb_nodes() {
				return Err(CosignSignatureError::MissingSignature { pk: *pk });
			}
		}

		let max_level = self.tree.root().level();
		self.tree.iter().enumerate().map(|(idx, node)| {
			let mut cosign_pks = Vec::with_capacity(max_level + 1);
			let mut part_sigs = Vec::with_capacity(max_level + 1);
			for leaf in node.leaves() {
				if let Some(cosign_pk) = self.spec.vtxos[leaf].cosign_pubkey {
					let part_sig = leaf_part_sigs.get_mut(&cosign_pk)
						.ok_or(CosignSignatureError::missing_sig(cosign_pk))?
						.pop_front()
						.ok_or(CosignSignatureError::missing_sig(cosign_pk))?;
					cosign_pks.push(cosign_pk);
					part_sigs.push(part_sig);
				}
			}
			// add global signers
			cosign_pks.extend(&self.spec.global_cosign_pubkeys);
			for sigs in global_signer_part_sigs {
				part_sigs.push(sigs.as_ref().get(idx).expect("checked before"));
			}

			let agg_pk = self.cosign_agg_pks[node.idx()];
			Ok(musig::combine_partial_signatures(
				cosign_pks,
				*cosign_agg_nonces.get(node.idx()).ok_or(CosignSignatureError::NotEnoughNonces)?,
				self.sighashes[node.idx()].to_byte_array(),
				Some(self.spec.cosign_taproot(agg_pk).tap_tweak().to_byte_array()),
				&part_sigs
			))
		}).collect()
	}

	/// Verify the signatures of all the node txs.
	///
	/// Signatures expected ordered from leaves to root.
	pub fn verify_cosign_sigs(
		&self,
		signatures: &[schnorr::Signature],
	) -> Result<(), XOnlyPublicKey> {
		for node in self.tree.iter() {
			let sighash = self.sighashes[node.idx()];
			let agg_pk = &self.cosign_agg_pks[node.idx()];
			let pk = self.spec.cosign_taproot(*agg_pk).output_key().to_x_only_public_key();
			let sig = signatures.get(node.idx()).ok_or_else(|| pk)?;
			if SECP.verify_schnorr(sig, &sighash.into(), &pk).is_err() {
				return Err(pk);
			}
		}
		Ok(())
	}

	/// Convert into a [SignedVtxoTreeSpec] by providing the signatures.
	///
	/// Signatures expected ordered from leaves to root.
	pub fn into_signed_tree(
		self,
		signatures: Vec<schnorr::Signature>,
	) -> SignedVtxoTreeSpec {
		SignedVtxoTreeSpec {
			spec: self.spec,
			utxo: self.utxo,
			cosign_sigs: signatures,
		}
	}
}

/// Error returned from cosigning a VTXO tree.
#[derive(PartialEq, Eq, thiserror::Error)]
pub enum CosignSignatureError {
	#[error("missing cosign signature from pubkey {pk}")]
	MissingSignature { pk: PublicKey },
	#[error("invalid cosign signature from pubkey {pk}")]
	InvalidSignature { pk: PublicKey },
	#[error("not enough nonces")]
	NotEnoughNonces,
	#[error("invalid cosign signatures: {0}")]
	Invalid(&'static str),
}

impl fmt::Debug for CosignSignatureError {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
	    fmt::Display::fmt(self, f)
	}
}

impl CosignSignatureError {
	fn missing_sig(cosign_pk: PublicKey) -> CosignSignatureError {
		CosignSignatureError::MissingSignature { pk: cosign_pk }
	}
	fn invalid_sig(cosign_pk: PublicKey) -> CosignSignatureError {
		CosignSignatureError::InvalidSignature { pk: cosign_pk }
	}
}

/// All the information needed to uniquely specify a fully signed VTXO tree.
#[derive(Debug, Clone, PartialEq)]
pub struct SignedVtxoTreeSpec {
	pub spec: VtxoTreeSpec,
	pub utxo: OutPoint,
	/// The signatures for the txs from leaves to root.
	pub cosign_sigs: Vec<schnorr::Signature>,
}

impl SignedVtxoTreeSpec {
	/// Signatures expected ordered from leaves to root.
	pub fn new(
		spec: VtxoTreeSpec,
		utxo: OutPoint,
		signatures: Vec<schnorr::Signature>,
	) -> SignedVtxoTreeSpec {
		SignedVtxoTreeSpec { spec, utxo, cosign_sigs: signatures }
	}

	pub fn nb_leaves(&self) -> usize {
		self.spec.nb_leaves()
	}

	/// Construct the exit branch starting from the root ending in the leaf.
	pub fn exit_branch(&self, leaf_idx: usize) -> Option<Vec<Transaction>> {
		let txs = self.all_signed_txs();

		if leaf_idx >= self.spec.nb_leaves() {
			return None;
		}

		let tree = Tree::new(self.spec.nb_leaves());
		let mut ret = tree.iter_branch(leaf_idx)
			.map(|n| txs[n.idx()].clone())
			.collect::<Vec<_>>();
		ret.reverse();
		Some(ret)
	}

	/// Get all signed txs in this tree, starting with the leaves, towards the root.
	pub fn all_signed_txs(&self) -> Vec<Transaction> {
		self.spec.signed_transactions(self.utxo, &self.cosign_sigs)
	}

	pub fn into_cached_tree(self) -> CachedSignedVtxoTree {
		CachedSignedVtxoTree {
			txs: self.all_signed_txs(),
			spec: self,
		}
	}
}

/// A fully signed VTXO tree, with all the transaction cached.
///
/// This is useful for cheap extraction of VTXO branches.
pub struct CachedSignedVtxoTree {
	pub spec: SignedVtxoTreeSpec,
	/// All signed txs in this tree, starting with the leaves, towards the root.
	pub txs: Vec<Transaction>,
}

impl CachedSignedVtxoTree {
	/// Construct the exit branch starting from the root ending in the leaf.
	pub fn exit_branch(&self, leaf_idx: usize) -> Option<Vec<&Transaction>> {
		if leaf_idx >= self.spec.spec.nb_leaves() {
			return None;
		}

		let tree = Tree::new(self.spec.spec.nb_leaves());
		let mut ret = tree.iter_branch(leaf_idx)
			.map(|n| &self.txs[n.idx()])
			.collect::<Vec<_>>();
		ret.reverse();
		Some(ret)
	}

	pub fn nb_leaves(&self) -> usize {
		self.spec.nb_leaves()
	}

	/// Get all signed txs in this tree, starting with the leaves, towards the root.
	pub fn all_signed_txs(&self) -> &[Transaction] {
		&self.txs
	}

	/// Construct the VTXO at the given leaf index.
	pub fn build_vtxo(&self, leaf_idx: usize) -> Option<Vtxo> {
		let req = self.spec.spec.vtxos.get(leaf_idx)?;
		let genesis = {
			let mut genesis = Vec::new();

			let mut last_node = None;
			let tree = Tree::new(self.spec.spec.nb_leaves());
			for node in tree.iter_branch(leaf_idx) {
				let transition = GenesisTransition::Cosigned {
					pubkeys: node.leaves().filter_map(|i| self.spec.spec.vtxos[i].cosign_pubkey)
						.chain(self.spec.spec.global_cosign_pubkeys.iter().copied())
						.collect(),
					signature: self.spec.cosign_sigs.get(node.idx()).cloned()
						.expect("enough sigs for all nodes"),
				};
				let output_idx = {
					if let Some(last) = last_node {
						node.children().position(|child_idx| last == child_idx)
							.expect("last node should be our child") as u8
					} else {
						// we start with the leaf, so this is the exit tx
						0
					}
				};
				let other_outputs = self.txs.get(node.idx()).expect("we have all txs")
					.output.iter().enumerate()
					.filter(|(i, o)| !o.is_p2a_fee_anchor() && *i != output_idx as usize)
					.map(|(_i, o)| o).cloned().collect();
				genesis.push(GenesisItem { transition, output_idx, other_outputs });
				last_node = Some(node.idx());
			}
			genesis.reverse();
			genesis
		};

		Some(Vtxo {
			amount: req.vtxo.amount,
			expiry_height: self.spec.spec.expiry_height,
			server_pubkey: self.spec.spec.server_pubkey,
			exit_delta: self.spec.spec.exit_delta,
			anchor_point: self.spec.utxo,
			genesis: genesis,
			policy: req.vtxo.policy.clone(),
			point: {
				let leaf_tx = self.txs.get(leaf_idx).expect("leaf idx exists");
				OutPoint::new(leaf_tx.compute_txid(), 0)
			},
		})
	}

	/// Construct all individual vtxos from this round.
	///
	/// This call is pretty wasteful.
	pub fn all_vtxos(&self) -> impl Iterator<Item = Vtxo> + ExactSizeIterator + '_ {
		(0..self.nb_leaves()).map(|idx| self.build_vtxo(idx).unwrap())
	}
}

/// The serialization version of [VtxoTreeSpec].
const VTXO_TREE_SPEC_VERSION: u8 = 0x02;

impl ProtocolEncoding for VtxoTreeSpec {
	fn encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<(), io::Error> {
		w.emit_u8(VTXO_TREE_SPEC_VERSION)?;
		w.emit_u32(self.expiry_height)?;
		self.server_pubkey.encode(w)?;
		w.emit_u16(self.exit_delta)?;
		w.emit_compact_size(self.global_cosign_pubkeys.len() as u64)?;
		for pk in &self.global_cosign_pubkeys {
			pk.encode(w)?;
		}

		w.emit_compact_size(self.vtxos.len() as u64)?;
		for vtxo in &self.vtxos {
			vtxo.vtxo.policy.encode(w)?;
			w.emit_u64(vtxo.vtxo.amount.to_sat())?;
			if let Some(pk) = vtxo.cosign_pubkey {
				pk.encode(w)?;
			} else {
				w.emit_u8(0)?;
			}
		}
		Ok(())
	}

	fn decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, crate::encode::ProtocolDecodingError> {
		let version = r.read_u8()?;

		// be compatible with old version
		if version == 0x01 {
			let expiry_height = r.read_u32()?;
			let server_pubkey = PublicKey::decode(r)?;
			let exit_delta = r.read_u16()?;
			let server_cosign_pk = PublicKey::decode(r)?;

			let nb_vtxos = r.read_u32()?;
			let mut vtxos = Vec::with_capacity(nb_vtxos as usize);
			for _ in 0..nb_vtxos {
				let output = VtxoPolicy::decode(r)?;
				let amount = Amount::from_sat(r.read_u64()?);
				let cosign_pk = PublicKey::decode(r)?;
				vtxos.push(SignedVtxoRequest {
					vtxo: VtxoRequest { policy: output, amount },
					cosign_pubkey: Some(cosign_pk),
				});
			}

			return Ok(VtxoTreeSpec {
				vtxos, expiry_height, server_pubkey, exit_delta,
				global_cosign_pubkeys: vec![server_cosign_pk],
			});
		}

		if version != VTXO_TREE_SPEC_VERSION {
			return Err(ProtocolDecodingError::invalid(format_args!(
				"invalid VtxoTreeSpec encoding version byte: {version:#x}",
			)));
		}

		let expiry_height = r.read_u32()?;
		let server_pubkey = PublicKey::decode(r)?;
		let exit_delta = r.read_u16()?;
		let nb_global_signers = r.read_compact_size()?;
		let mut global_cosign_pubkeys = Vec::with_capacity(nb_global_signers as usize);
		for _ in 0..nb_global_signers {
			global_cosign_pubkeys.push(PublicKey::decode(r)?);
		}

		let nb_vtxos = r.read_compact_size()?;
		let mut vtxos = Vec::with_capacity(nb_vtxos as usize);
		for _ in 0..nb_vtxos {
			let output = VtxoPolicy::decode(r)?;
			let amount = Amount::from_sat(r.read_u64()?);
			let cosign_pubkey = Option::<PublicKey>::decode(r)?;
			vtxos.push(SignedVtxoRequest { vtxo: VtxoRequest { policy: output, amount }, cosign_pubkey });
		}

		Ok(VtxoTreeSpec { vtxos, expiry_height, server_pubkey, exit_delta, global_cosign_pubkeys })
	}
}

/// The serialization version of [SignedVtxoTreeSpec].
const SIGNED_VTXO_TREE_SPEC_VERSION: u8 = 0x01;

impl ProtocolEncoding for SignedVtxoTreeSpec {
	fn encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<(), io::Error> {
		w.emit_u8(SIGNED_VTXO_TREE_SPEC_VERSION)?;
		self.spec.encode(w)?;
		self.utxo.encode(w)?;
		w.emit_u32(self.cosign_sigs.len() as u32)?;
		for sig in &self.cosign_sigs {
			sig.encode(w)?;
		}
		Ok(())
	}

	fn decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, crate::encode::ProtocolDecodingError> {
		let version = r.read_u8()?;
		if version != SIGNED_VTXO_TREE_SPEC_VERSION {
			return Err(ProtocolDecodingError::invalid(format_args!(
				"invalid SignedVtxoTreeSpec encoding version byte: {version:#x}",
			)));
		}
		let spec = VtxoTreeSpec::decode(r)?;
		let utxo = OutPoint::decode(r)?;
		let nb_cosign_sigs = r.read_u32()?;
		let mut cosign_sigs = Vec::with_capacity(nb_cosign_sigs as usize);
		for _ in 0..nb_cosign_sigs {
			cosign_sigs.push(schnorr::Signature::decode(r)?);
		}
		Ok(SignedVtxoTreeSpec { spec, utxo, cosign_sigs })
	}
}


#[cfg(test)]
mod test {
	use std::iter;
	use std::collections::HashMap;
	use std::str::FromStr;

	use bitcoin::hashes::{siphash24, sha256, Hash, HashEngine};
	use bitcoin::secp256k1::{self, rand, Keypair};
	use rand::SeedableRng;

	use crate::encode::test::json_roundtrip;
	use crate::encode::{self, test::encoding_roundtrip};
	use crate::VtxoPolicy;
	use super::*;

	fn test_tree_amounts(
		tree: &UnsignedVtxoTree,
		root_value: Amount,
	) {
		let map = tree.txs.iter().map(|tx| (tx.compute_txid(), tx)).collect::<HashMap<_, _>>();

		// skip the root
		for (idx, tx) in tree.txs.iter().take(tree.txs.len() - 1).enumerate() {
			println!("tx #{idx}: {}", bitcoin::consensus::encode::serialize_hex(tx));
			let input = tx.input.iter().map(|i| {
				let prev = i.previous_output;
				map.get(&prev.txid).expect(&format!("tx {} not found", prev.txid))
					.output[prev.vout as usize].value
			}).sum::<Amount>();
			let output = tx.output_value();
			assert!(input >= output);
			assert_eq!(input, output);
		}

		// check the root
		let root = tree.txs.last().unwrap();
		assert_eq!(root_value, root.output_value());
	}

	#[test]
	fn vtxo_tree() {
		let secp = secp256k1::Secp256k1::new();
		let mut rand = rand::rngs::StdRng::seed_from_u64(42);
		let random_sig = {
			let key = Keypair::new(&secp, &mut rand);
			let sha = sha256::Hash::from_str("4bf5122f344554c53bde2ebb8cd2b7e3d1600ad631c385a5d7cce23c7785459a").unwrap();
			let msg = secp256k1::Message::from_digest(sha.to_byte_array());
			secp.sign_schnorr(&msg, &key)
		};

		let server_key = Keypair::new(&secp, &mut rand);
		let server_cosign_key = Keypair::new(&secp, &mut rand);

		struct Req {
			key: Keypair,
			cosign_key: Keypair,
			amount: Amount,
		}
		impl Req {
			fn to_vtxo(&self) -> SignedVtxoRequest {
				SignedVtxoRequest {
					vtxo: VtxoRequest {
						amount: self.amount,
						policy: VtxoPolicy::new_pubkey(self.key.public_key()),
					},
					cosign_pubkey: Some(self.cosign_key.public_key()),
				}
			}
		}

		let nb_leaves = 27;
		let reqs = iter::repeat_with(|| Req {
			key: Keypair::new(&secp, &mut rand),
			cosign_key:  Keypair::new(&secp, &mut rand),
			amount: Amount::from_sat(100_000),
		}).take(nb_leaves).collect::<Vec<_>>();
		let point = "0000000000000000000000000000000000000000000000000000000000000001:1".parse().unwrap();

		let spec = VtxoTreeSpec::new(
			reqs.iter().map(|r| r.to_vtxo()).collect(),
			server_key.public_key(),
			101_000,
			2016,
			vec![server_cosign_key.public_key()],
		);
		assert_eq!(spec.nb_leaves(), nb_leaves);
		assert_eq!(spec.total_required_value().to_sat(), 2700000);
		let nb_nodes = spec.nb_nodes();

		encoding_roundtrip(&spec);

		let unsigned = spec.into_unsigned_tree(point);

		test_tree_amounts(&unsigned, unsigned.spec.total_required_value());

		let sighashes_hash = {
			let mut eng = siphash24::Hash::engine();
			unsigned.sighashes.iter().for_each(|h| eng.input(&h[..]));
			siphash24::Hash::from_engine(eng)
		};
		assert_eq!(sighashes_hash.to_string(), "44c13179cd19569f");

		let signed = unsigned.into_signed_tree(vec![random_sig; nb_nodes]);

		encoding_roundtrip(&signed);

		#[derive(Debug, PartialEq, Serialize, Deserialize)]
		struct JsonSignedVtxoTreeSpec {
			#[serde(with = "encode::serde")]
			pub spec: SignedVtxoTreeSpec,
		}

		json_roundtrip(&JsonSignedVtxoTreeSpec { spec: signed.clone() });

		for l in 0..nb_leaves {
			let exit = signed.exit_branch(l).unwrap();

			// Assert it's a valid chain.
			let mut iter = exit.iter().enumerate().peekable();
			while let Some((i, cur)) = iter.next() {
				if let Some((_, next)) = iter.peek() {
					assert_eq!(next.input[0].previous_output.txid, cur.compute_txid(), "{}", i);
				}
			}
		}

		let cached = signed.into_cached_tree();
		for vtxo in cached.all_vtxos() {
			encoding_roundtrip(&vtxo);
		}
	}
}

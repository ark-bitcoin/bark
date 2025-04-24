

use std::collections::{HashMap, VecDeque};
use std::{cmp, fmt, iter};

use bitcoin::hashes::Hash;
use bitcoin::{
	taproot, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Weight, Witness,
};
use bitcoin::secp256k1::{schnorr, Keypair, PublicKey, XOnlyPublicKey};
use bitcoin::sighash::{self, SighashCache, TapSighash, TapSighashType};
use secp256k1_musig::musig::{MusigAggNonce, MusigPartialSignature, MusigPubNonce, MusigSecNonce};

use bitcoin_ext::{fee, P2WSH_DUST, BlockHeight, TransactionExt};

use crate::util::{Decodable, Encodable};
use crate::{musig, util, RoundVtxo, Vtxo, VtxoRequest, VtxoSpec};
use crate::tree::{self, Tree};
use crate::vtxo::VtxoSpkSpec;


/// The witness weight to spend a node transaction.
//NB this only works in regtest because it grows a few bytes when
//the CLTV block height scriptnum grows
pub const NODE_SPEND_WEIGHT: Weight = Weight::from_wu(140);


/// All the information that uniquely specifies a VTXO tree before it has been signed.
#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
pub struct VtxoTreeSpec {
	pub vtxos: Vec<VtxoRequest>,
	pub asp_pk: PublicKey,
	pub asp_cosign_pk: PublicKey,
	pub expiry_height: u32,
	pub exit_delta: u16,
}

impl VtxoTreeSpec {
	pub fn new(
		vtxos: Vec<VtxoRequest>,
		asp_pk: PublicKey,
		asp_cosign_pk: PublicKey,
		expiry_height: BlockHeight,
		exit_delta: u16,
	) -> VtxoTreeSpec {
		assert_ne!(vtxos.len(), 0);
		VtxoTreeSpec { vtxos, asp_pk, asp_cosign_pk, expiry_height: expiry_height as u32, exit_delta }
	}

	pub fn nb_leaves(&self) -> usize {
		self.vtxos.len()
	}

	pub fn nb_nodes(&self) -> usize {
		Tree::nb_nodes_for_leaves(self.nb_leaves())
	}

	pub fn iter_vtxos(&self) -> impl Iterator<Item = &VtxoRequest> {
		self.vtxos.iter()
	}

	/// Get the leaf index of the given vtxo request.
	pub fn leaf_idx_of(&self, vtxo_request: &VtxoRequest) -> Option<usize> {
		self.vtxos.iter().position(|e| e == vtxo_request)
	}

	/// Calculate the total value needed in the tree.
	///
	/// This accounts for
	/// - all vtxos getting their value
	/// - a dust fee anchor at each node, both internal and leaves
	pub fn total_required_value(&self) -> Amount {
		self.vtxos.iter().map(|d| d.amount).sum::<Amount>()
			+ P2WSH_DUST * Tree::nb_nodes_for_leaves(self.nb_leaves()) as u64
	}

	/// The expiry clause hidden in the node taproot as only script.
	fn expiry_clause(&self) -> ScriptBuf {
		let pk = self.asp_pk.x_only_public_key().0;
		util::timelock_sign(self.expiry_height, pk)
	}

	pub fn cosign_taproot(&self, agg_pk: XOnlyPublicKey) -> taproot::TaprootSpendInfo {
		taproot::TaprootBuilder::new()
			.add_leaf(0, self.expiry_clause()).unwrap()
			.finalize(&util::SECP, agg_pk).unwrap()
	}

	pub fn cosign_taptweak(&self, agg_pk: XOnlyPublicKey) -> taproot::TapTweakHash {
		self.cosign_taproot(agg_pk).tap_tweak()
	}

	pub fn cosign_spk(&self, agg_pk: XOnlyPublicKey) -> ScriptBuf {
		ScriptBuf::new_p2tr_tweaked(self.cosign_taproot(agg_pk).output_key())
	}

	/// The cosign pubkey used on the vtxo output of the round tx.
	pub fn round_tx_cosign_pk(&self) -> XOnlyPublicKey {
		let keys = self.vtxos.iter()
			.map(|v| v.cosign_pk)
			.chain(Some(self.asp_cosign_pk));
		musig::combine_keys(keys)
	}

	/// The scriptPubkey used on the vtxo output of the round tx.
	pub fn round_tx_spk(&self) -> ScriptBuf {
		self.cosign_spk(self.round_tx_cosign_pk())
	}

	/// The vtxo output of the round tx.
	pub fn round_tx_txout(&self) -> TxOut {
		TxOut {
			script_pubkey: self.round_tx_spk(),
			value: self.total_required_value(),
		}
	}

	fn node_tx<'a>(&self, children: impl Iterator<Item=(&'a Transaction, &'a XOnlyPublicKey)>) -> Transaction {
		Transaction {
			version: bitcoin::transaction::Version(3),
			lock_time: bitcoin::absolute::LockTime::ZERO,
			input: vec![TxIn {
				previous_output: OutPoint::null(), // we will fill this later
				sequence: Sequence::MAX,
				script_sig: ScriptBuf::new(),
				witness: Witness::new(),
			}],
			output: children.map(|(tx, agg_pk)| {
				TxOut {
					script_pubkey: self.cosign_spk(*agg_pk),
					value: tx.output_value(),
				}
			}).chain(Some(fee::dust_anchor())).collect(),
		}
	}

	fn leaf_tx(&self, vtxo: &VtxoRequest) -> Transaction {
		let spec = VtxoSpec {
			user_pubkey: vtxo.pubkey,
			asp_pubkey: self.asp_pk,
			expiry_height: self.expiry_height,
			spk: VtxoSpkSpec::Exit { exit_delta: self.exit_delta },
			amount: vtxo.amount
		};

		crate::vtxo::create_exit_tx(
			&spec,
			OutPoint::null(),
			None,
		)
	}

	/// Calculate all the aggregate cosign pubkeys by aggregating the leaf and asp pubkeys.
	///
	/// Pubkeys expected and returned ordered from leaves to root.
	pub fn cosign_agg_pks(&self)
		-> impl Iterator<Item = XOnlyPublicKey> + iter::DoubleEndedIterator + iter::ExactSizeIterator + '_
	{
		Tree::new(self.nb_leaves()).into_iter().map(|node| {
			musig::combine_keys(
				node.leaves().map(|i| self.vtxos[i].cosign_pk).chain(Some(self.asp_cosign_pk))
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
				self.leaf_tx(&self.vtxos[node.idx()]).clone()
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

	/// Calculate all the aggregate cosign nonces by aggregating the leaf and asp nonces.
	///
	/// Nonces expected and returned ordered from leaves to root.
	pub fn calculate_cosign_agg_nonces(
		&self,
		leaf_cosign_nonces: &HashMap<PublicKey, Vec<MusigPubNonce>>,
		asp_cosign_nonces: &[MusigPubNonce],
	) -> Vec<MusigAggNonce> {
		let tree = Tree::new(self.nb_leaves());

		tree.iter().zip(asp_cosign_nonces).map(|(node, asp)| {
			let nonces = node.leaves().map(|i| self.vtxos[i].cosign_pk).map(|pk| {
				leaf_cosign_nonces.get(&pk).expect("nonces are complete")
					// note that we skip some nonces for some leaves that are at the edges
					// and skip some levels
					.get(node.level()).expect("sufficient nonces provided")
			}).chain(Some(asp)).collect::<Vec<_>>();
			musig::nonce_agg(&nonces)
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

impl Encodable for VtxoTreeSpec {}
impl Decodable for VtxoTreeSpec {}

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

		let root_txout = spec.round_tx_txout();
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
		cosign_agg_nonces: &[MusigAggNonce],
		request: &VtxoRequest,
		keypair: &Keypair,
		cosign_sec_nonces: Vec<MusigSecNonce>,
	) -> Option<Vec<MusigPartialSignature>> {
		let leaf_idx = self.spec.leaf_idx_of(request)?;
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

			let cosign_pubkeys = node.leaves().map(|i| self.spec.vtxos[i].cosign_pk)
				.chain(Some(self.spec.asp_cosign_pk));
			let sighash = self.sighashes[node.idx()];

			let sig = musig::partial_sign(
				cosign_pubkeys,
				cosign_agg_nonces[node.idx()],
				&keypair,
				sec_nonce,
				sighash.to_byte_array(),
				Some(self.spec.cosign_taptweak(self.cosign_agg_pks[node.idx()]).to_byte_array()),
				None,
			).0;
			ret.push(sig);
		}

		Some(ret)
	}

	/// Generate partial musig signatures for all nodes in the tree.
	///
	/// Nonces expected for all nodes, ordered from leaves to root.
	///
	/// Returns [None] if the vtxo request is not part of the tree.
	pub fn cosign_tree(
		&self,
		cosign_agg_nonces: &[MusigAggNonce],
		keypair: &Keypair,
		cosign_sec_nonces: Vec<MusigSecNonce>,
	) -> Vec<MusigPartialSignature> {
		assert_eq!(cosign_agg_nonces.len(), self.nb_nodes());
		assert_eq!(cosign_sec_nonces.len(), self.nb_nodes());

		self.tree.iter().zip(cosign_sec_nonces.into_iter()).map(|(node, sec_nonce)| {
			let cosign_pubkeys = node.leaves().map(|i| self.spec.vtxos[i].cosign_pk)
				.chain(Some(self.spec.asp_cosign_pk));
			let sighash = self.sighashes[node.idx()];

			musig::partial_sign(
				cosign_pubkeys,
				cosign_agg_nonces[node.idx()],
				&keypair,
				sec_nonce,
				sighash.to_byte_array(),
				Some(self.spec.cosign_taptweak(self.cosign_agg_pks[node.idx()]).to_byte_array()),
				None,
			).0
		}).collect()
	}

	/// Verify partial cosign signature of a single node.
	fn verify_node_cosign_partial_sig(
		&self,
		node: &tree::Node,
		pk: PublicKey,
		agg_nonces: &[MusigAggNonce],
		part_sig: MusigPartialSignature,
		pub_nonce: MusigPubNonce,
	) -> Result<(), CosignSignatureError> {
		let cosign_pubkeys = node.leaves().map(|i| self.spec.vtxos[i].cosign_pk)
			.chain(Some(self.spec.asp_cosign_pk));
		let sighash = self.sighashes[node.idx()];

		let taptweak = self.spec.cosign_taptweak(self.cosign_agg_pks[node.idx()]);
		let key_agg = musig::tweaked_key_agg(cosign_pubkeys, taptweak.to_byte_array()).0;
		let session = musig::MusigSession::new(
			&musig::SECP,
			&key_agg,
			*agg_nonces.get(node.idx()).ok_or(CosignSignatureError::NotEnoughNonces)?,
			musig::secpm::Message::from_digest(sighash.to_byte_array()),
		);
		let success = session.partial_verify(
			&musig::SECP,
			&key_agg,
			part_sig,
			pub_nonce,
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
		cosign_agg_nonces: &[MusigAggNonce],
		request: &VtxoRequest,
		cosign_pub_nonces: &[MusigPubNonce],
		cosign_part_sigs: &[MusigPartialSignature],
	) -> Result<(), String> {
		assert_eq!(cosign_agg_nonces.len(), self.nb_nodes());

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
				request.cosign_pk,
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
	pub fn verify_all_cosign_partial_sigs(
		&self,
		pk: PublicKey,
		agg_nonces: &[MusigAggNonce],
		pub_nonces: &[MusigPubNonce],
		part_sigs: &[MusigPartialSignature],
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
	/// ASP signatures expected ordered from leaves to root.
	pub fn combine_partial_signatures(
		&self,
		cosign_agg_nonces: &[MusigAggNonce],
		leaf_part_sigs: &HashMap<PublicKey, Vec<MusigPartialSignature>>,
		asp_sigs: Vec<MusigPartialSignature>,
	) -> Result<Vec<schnorr::Signature>, CosignSignatureError> {
		// to ease implementation, we're reconstructing the part sigs map with dequeues
		let mut leaf_part_sigs = leaf_part_sigs.iter()
			.map(|(pk, sigs)| (pk, sigs.iter().collect()))
			.collect::<HashMap<_, VecDeque<_>>>();

		if asp_sigs.len() != self.nb_nodes() {
			return Err(CosignSignatureError::MissingSignature { pk: self.spec.asp_cosign_pk });
		}

		let max_level = self.tree.root().level();
		self.tree.iter().zip(asp_sigs.into_iter()).map(|(node, asp_sig)| {
			let mut cosign_pks = Vec::with_capacity(max_level + 1);
			let mut part_sigs = Vec::with_capacity(max_level + 1);
			for leaf in node.leaves() {
				let cosign_pk = self.spec.vtxos[leaf].cosign_pk;
				let part_sig = leaf_part_sigs.get_mut(&cosign_pk)
					.ok_or(CosignSignatureError::missing_sig(cosign_pk))?
					.pop_front()
					.ok_or(CosignSignatureError::missing_sig(cosign_pk))?;
				cosign_pks.push(cosign_pk);
				part_sigs.push(part_sig);
			}
			cosign_pks.push(self.spec.asp_cosign_pk);
			part_sigs.push(&asp_sig);

			Ok(musig::combine_partial_signatures(
				cosign_pks,
				*cosign_agg_nonces.get(node.idx()).ok_or(CosignSignatureError::NotEnoughNonces)?,
				self.sighashes[node.idx()].to_byte_array(),
				Some(self.spec.cosign_taptweak(self.cosign_agg_pks[node.idx()]).to_byte_array()),
				&part_sigs
			))
		}).collect()
	}

	/// Verify the signatures of all the node txs.
	///
	/// Signatures expected ordered from leaves to root.
	pub fn verify_cosign_sigs(&self, signatures: &[schnorr::Signature]) -> Result<(), String> {
		if signatures.len() != self.tree.nb_nodes() {
			return Err("invalid number of signatures".into());
		}

		for (i, node) in self.tree.iter().enumerate() {
			let sig = &signatures[node.idx()];
			let sighash = self.sighashes[node.idx()];
			let agg_pk = &self.cosign_agg_pks[node.idx()];
			let pk = self.spec.cosign_taproot(*agg_pk).output_key().to_inner();
			util::SECP.verify_schnorr(sig, &sighash.into(), &pk)
				.map_err(|e| format!("invalid signature on node #{}: {}", i, e))?;
		}
		Ok(())
	}

	/// Convert into a [SignedVtxoTree] by providing the signatures.
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
#[derive(Debug, PartialEq, Eq)]
pub enum CosignSignatureError {
	MissingSignature { pk: PublicKey },
	InvalidSignature { pk: PublicKey },
	NotEnoughNonces,
}

impl CosignSignatureError {
	fn missing_sig(cosign_pk: PublicKey) -> CosignSignatureError {
		CosignSignatureError::MissingSignature { pk: cosign_pk }
	}
	fn invalid_sig(cosign_pk: PublicKey) -> CosignSignatureError {
		CosignSignatureError::InvalidSignature { pk: cosign_pk }
	}
}

impl fmt::Display for CosignSignatureError {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match self {
			Self::MissingSignature { pk } => {
				write!(f, "missing cosing signature for pubkey {}", pk)
			},
			Self::InvalidSignature { pk } => {
				write!(f, "invalid cosing signature for pubkey {}", pk)
			},
			Self::NotEnoughNonces => write!(f, "not enough nonces"),
		}
	}
}

impl std::error::Error for CosignSignatureError {}

/// All the information needed to uniquely specify a fully signed VTXO tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
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

impl Encodable for SignedVtxoTreeSpec {}
impl Decodable for SignedVtxoTreeSpec {}

/// A fully signed VTXO tree, with all the transaction cached.
///
/// This is useful for cheap extraction of VTXO branches.
pub struct CachedSignedVtxoTree {
	pub spec: SignedVtxoTreeSpec,
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

	/// Construct all individual vtxos from this round.
	///
	/// This call is pretty wasteful.
	pub fn all_vtxos(&self) -> impl Iterator<Item = Vtxo> + '_ {
		self.spec.spec.vtxos.iter().enumerate().map(|(idx, req)| {
			Vtxo::Round(RoundVtxo {
				spec: VtxoSpec {
					user_pubkey: req.pubkey,
					asp_pubkey: self.spec.spec.asp_pk,
					expiry_height: self.spec.spec.expiry_height,
					amount: req.amount,
					spk: VtxoSpkSpec::Exit { exit_delta: self.spec.spec.exit_delta },
				},
				leaf_idx: idx,
				exit_branch: self.exit_branch(idx).unwrap().into_iter().cloned().collect(),
			})
		})
	}
}


#[cfg(test)]
mod test {
	use super::*;

	use std::iter;
	use std::collections::HashMap;
	use std::str::FromStr;

	use bitcoin::hashes::{siphash24, sha256, Hash, HashEngine};
	use bitcoin::secp256k1::{self, rand, Keypair};
	use rand::SeedableRng;

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
		let mut rand = rand::rngs::SmallRng::seed_from_u64(42);
		let random_sig = {
			let key = Keypair::new(&secp, &mut rand); // asp
			let sha = sha256::Hash::from_str("4bf5122f344554c53bde2ebb8cd2b7e3d1600ad631c385a5d7cce23c7785459a").unwrap();
			let msg = secp256k1::Message::from_digest(sha.to_byte_array());
			secp.sign_schnorr(&msg, &key)
		};

		let asp_key = Keypair::new(&secp, &mut rand); // asp
		let asp_cosign_key = Keypair::new(&secp, &mut rand); // asp

		struct Req {
			key: Keypair,
			cosign_key: Keypair,
			amount: Amount,
		}
		impl Req {
			fn to_vtxo(&self) -> VtxoRequest {
				VtxoRequest {
					pubkey: self.key.public_key(),
					amount: self.amount,
					cosign_pk: self.cosign_key.public_key(),
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
			asp_key.public_key(),
			asp_cosign_key.public_key(),
			101_000,
			2016,
		);
		assert_eq!(spec.nb_leaves(), nb_leaves);
		assert_eq!(spec.total_required_value().to_sat(), 2711880);

		let unsigned = spec.into_unsigned_tree(point);

		test_tree_amounts(&unsigned, unsigned.spec.total_required_value());

		let sighashes_hash = {
			let mut eng = siphash24::Hash::engine();
			unsigned.sighashes.iter().for_each(|h| eng.input(&h[..]));
			siphash24::Hash::from_engine(eng)
		};
		assert_eq!(sighashes_hash.to_string(), "2179a0be7c366ef5");

		let signed = unsigned.into_signed_tree(vec![random_sig; nb_leaves]);

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
	}
}

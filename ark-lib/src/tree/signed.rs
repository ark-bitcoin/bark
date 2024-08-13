

use std::{cmp, io};

use bitcoin::{
	taproot, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Weight, Witness,
};
use bitcoin::secp256k1::{schnorr, PublicKey, XOnlyPublicKey};
use bitcoin::sighash::{self, SighashCache, TapSighash, TapSighashType};
use bitcoin::taproot::{ControlBlock, LeafVersion, TapNodeHash, TaprootBuilder};

use crate::{fee, util, VtxoSpec, VtxoRequest};
use crate::tree::Tree;


/// Size in vbytes for the leaf txs.
const LEAF_TX_WEIGHT: Weight = Weight::from_vb_unchecked(154);

/// Size in vbytes for a node tx with radix 2.
const NODE2_TX_WEIGHT: Weight = Weight::from_vb_unchecked(154);
/// Size in vbytes for a node tx with radix 3.
const NODE3_TX_WEIGHT: Weight = Weight::from_vb_unchecked(197);
/// Size in vbytes for a node tx with radix 4.
const NODE4_TX_WEIGHT: Weight = Weight::from_vb_unchecked(240);

/// Size in vbytes for a node tx with radix 2 and a fee anchor.
const NODE2_TX_WEIGHT_ANCHOR: Weight = Weight::from_vb_unchecked(197);
/// Size in vbytes for a node tx with radix 3 and a fee anchor.
const NODE3_TX_WEIGHT_ANCHOR: Weight = Weight::from_vb_unchecked(240);
/// Size in vbytes for a node tx with radix 4 and a fee anchor.
const NODE4_TX_WEIGHT_ANCHOR: Weight = Weight::from_vb_unchecked(283);

//TODO(stevenroose) write a test for this
//NB this only works in regtest because it grows a few bytes when
//the CLTV block height scriptnum grows
pub const NODE_SPEND_WEIGHT: Weight = Weight::from_wu(140);


#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
pub struct VtxoTreeSpec {
	pub vtxos: Vec<VtxoRequest>,
	pub cosign_agg_pk: XOnlyPublicKey,
	pub asp_key: PublicKey,
	pub expiry_height: u32,
	pub exit_delta: u16,
	/// Whether or not to place fee anchors on each node in the tree.
	/// NB Fee anchors are always placed on the leaves regardless of this field.
	pub node_anchors: bool,
}

impl VtxoTreeSpec {
	pub fn new(
		vtxos: Vec<VtxoRequest>,
		cosign_agg_pk: XOnlyPublicKey,
		asp_key: PublicKey,
		expiry_height: u32,
		exit_delta: u16,
		node_anchors: bool,
	) -> VtxoTreeSpec {
		VtxoTreeSpec { vtxos, cosign_agg_pk, asp_key, expiry_height, exit_delta, node_anchors }
	}

	pub fn encode(&self) -> Vec<u8> {
		let mut buf = Vec::new();
		ciborium::into_writer(self, &mut buf).unwrap();
		buf
	}

	pub fn decode(bytes: &[u8]) -> Result<Self, ciborium::de::Error<io::Error>> {
		Ok(ciborium::from_reader(bytes)?)
	}

	pub fn iter_vtxos(&self) -> impl Iterator<Item = &VtxoRequest> {
		self.vtxos.iter()
	}

	/// Calculate the total value needed in the tree.
	///
	/// This accounts for
	/// - all vtxos getting their value
	/// - a dust fee anchor at each leaf
	/// - minrelay fee for all intermediate txs
	pub fn total_required_value(&self) -> Amount {
		let dest_sum = self.vtxos.iter().map(|d| d.amount).sum::<Amount>();

		let leaf_extra =
			// one dust anchor per leaf
			fee::DUST * self.vtxos.len() as u64
			// relay fee for all txs
			+ fee::RELAY_FEERATE * (self.vtxos.len() as u64 * LEAF_TX_WEIGHT);

		// total minrelayfee requirement for all intermediate nodes
		let mut node_anchors = Amount::ZERO;
		let nodes_fee = {
			let mut weight = Weight::ZERO;
			let mut left = self.vtxos.len();
			while left > 1 {
				let radix = cmp::min(left, 4);
				left -= radix;
				if self.node_anchors {
					weight += match radix {
						2 => NODE2_TX_WEIGHT_ANCHOR,
						3 => NODE3_TX_WEIGHT_ANCHOR,
						4 => NODE4_TX_WEIGHT_ANCHOR,
						_ => unreachable!(),
					};
					node_anchors += fee::DUST;
				} else {
					weight += match radix {
						2 => NODE2_TX_WEIGHT,
						3 => NODE3_TX_WEIGHT,
						4 => NODE4_TX_WEIGHT,
						_ => unreachable!(),
					};
				}
			}
			fee::RELAY_FEERATE * weight
		};

		dest_sum + leaf_extra + nodes_fee + node_anchors
	}

	pub fn find_leaf_idxs<'a>(&'a self, dest: &'a VtxoRequest) -> impl Iterator<Item = usize> + 'a {
		self.vtxos.iter().enumerate().filter_map(move |(i, d)| {
			if d == dest {
				Some(i)
			} else {
				None
			}
		})
	}

	/// The expiry clause hidden in the node taproot as only script.
	fn expiry_clause(&self) -> ScriptBuf {
		let pk = self.asp_key.x_only_public_key().0;
		util::timelock_sign(self.expiry_height, pk)
	}

	/// The taproot scriptspend info for the expiry clause.
	pub fn expiry_scriptspend(&self) -> (ControlBlock, ScriptBuf, LeafVersion, TapNodeHash) {
		let taproot = self.cosign_taproot();
		let script = self.expiry_clause();
		let cb = taproot.control_block(&(script.clone(), LeafVersion::TapScript))
			.expect("expiry script should be in cosign taproot");
		(cb, script, LeafVersion::TapScript, taproot.merkle_root().unwrap())
	}

	pub fn cosign_taproot(&self) -> taproot::TaprootSpendInfo {
		TaprootBuilder::new()
			.add_leaf(0, self.expiry_clause()).unwrap()
			.finalize(&util::SECP, self.cosign_agg_pk).unwrap()
	}

	pub fn cosign_taptweak(&self) -> taproot::TapTweakHash {
		self.cosign_taproot().tap_tweak()
	}

	pub fn cosign_spk(&self) -> ScriptBuf {
		ScriptBuf::new_p2tr_tweaked(self.cosign_taproot().output_key())
	}

	fn node_tx(&self, children: &[&Transaction]) -> Transaction {
		Transaction {
			version: bitcoin::transaction::Version::TWO,
			lock_time: bitcoin::absolute::LockTime::ZERO,
			input: vec![TxIn {
				previous_output: OutPoint::null(),
				sequence: Sequence::MAX,
				script_sig: ScriptBuf::new(),
				witness: Witness::new(),
			}],
			output: children.iter().map(|child| {
				let is_leaf = child.output.len() == 2 && child.output[1] == fee::dust_anchor();
				let weight = if is_leaf {
					LEAF_TX_WEIGHT
				} else {
					if self.node_anchors {
						match child.output.len() {
							3 => NODE2_TX_WEIGHT_ANCHOR,
							4 => NODE3_TX_WEIGHT_ANCHOR,
							5 => NODE4_TX_WEIGHT_ANCHOR,
							n => unreachable!("node tx with {} children", n),
						}
					} else {
						match child.output.len() {
							2 => NODE2_TX_WEIGHT,
							3 => NODE3_TX_WEIGHT,
							4 => NODE4_TX_WEIGHT,
							n => unreachable!("node tx with {} children", n),
						}
					}
				};
				let fee_budget = fee::RELAY_FEERATE * weight;
				TxOut {
					script_pubkey: self.cosign_spk(),
					value: child.output.iter().map(|o| o.value).sum::<Amount>() + fee_budget,
				}
			}).chain(if self.node_anchors {
				Some(fee::dust_anchor())
			} else {
				None
			}).collect(),
		}
	}

	fn vtxo_spec(&self, vtxo: &VtxoRequest) -> VtxoSpec {
		VtxoSpec {
			user_pubkey: vtxo.pubkey,
			asp_pubkey: self.asp_key,
			expiry_height: self.expiry_height,
			exit_delta: self.exit_delta,
			amount: vtxo.amount,
		}
	}

	fn leaf_tx(&self, vtxo: &VtxoRequest) -> Transaction {
		let vtxo_spec = self.vtxo_spec(vtxo);
		Transaction {
			version: bitcoin::transaction::Version::TWO,
			lock_time: bitcoin::absolute::LockTime::ZERO,
			input: vec![TxIn {
				previous_output: OutPoint::null(),
				sequence: Sequence::MAX,
				script_sig: ScriptBuf::new(),
				witness: Witness::new(),
			}],
			output: vec![
				TxOut {
					script_pubkey: vtxo_spec.exit_spk(),
					value: vtxo.amount,
				},
				fee::dust_anchor(),
			],
		}
	}

	pub fn build_unsigned_tree(&self, utxo: OutPoint) -> Tree<Transaction> {
		let leaves = self.vtxos.iter().map(|dest| self.leaf_tx(dest));
		let mut tree = Tree::new(leaves, |children| self.node_tx(children));

		// Iterate over all nodes in reverse order and set the prevouts.
		let mut cursor = tree.nb_nodes() - 1;
		// This is the root, set to the tree's on-chain utxo.
		tree.element_at_mut(cursor).unwrap().input[0].previous_output = utxo;
		while cursor >= tree.nb_leaves() {
			let txid = tree.element_at(cursor).unwrap().compute_txid();
			let nb_children = tree.nb_children_of(cursor).unwrap();
			for i in 0..nb_children {
				let prevout = OutPoint::new(txid, i as u32);
				tree.child_of_mut(cursor, i).unwrap().input[0].previous_output = prevout;
			}
			cursor -= 1;
		}

		tree
	}

	/// Return all sighashes ordered from the root down to the leaves.
	pub fn sighashes(&self, utxo: OutPoint) -> Vec<TapSighash> {
		let tree = self.build_unsigned_tree(utxo);

		(0..tree.nb_nodes()).rev().map(|idx| {
			let prev = if let Some((parent, child_idx)) = tree.parent_of_with_idx(idx) {
				parent.output[child_idx].clone()
			} else {
				// this is the root
				TxOut {
					script_pubkey: self.cosign_spk(),
					value: self.total_required_value(),
				}
			};
			let el = tree.element_at(idx).unwrap();
			SighashCache::new(el).taproot_key_spend_signature_hash(
				0, &sighash::Prevouts::All(&[prev]), TapSighashType::Default,
			).expect("sighash error")
		}).collect()
	}
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
pub struct SignedVtxoTree {
	pub spec: VtxoTreeSpec,
	pub utxo: OutPoint,
	/// The signatures for the txs as they are layed out in the tree,
	/// from the leaves up to the root.
	signatures: Vec<schnorr::Signature>,
}

impl SignedVtxoTree {
	/// We expect the signatures from top to bottom, the root tx's first and the leaves last.
	pub fn new(spec: VtxoTreeSpec, utxo: OutPoint, mut signatures: Vec<schnorr::Signature>) -> SignedVtxoTree {
		signatures.reverse();
		SignedVtxoTree { spec, utxo, signatures }
	}

	pub fn encode(&self) -> Vec<u8> {
		let mut buf = Vec::new();
		ciborium::into_writer(self, &mut buf).unwrap();
		buf
	}

	pub fn decode(bytes: &[u8]) -> Result<Self, ciborium::de::Error<io::Error>> {
		Ok(ciborium::from_reader(bytes)?)
	}

	fn finalize_tx(tx: &mut Transaction, sig: &schnorr::Signature) {
		assert_eq!(tx.input.len(), 1);
		tx.input[0].witness.push(&sig[..]);
	}

	/// Validate the signatures.
	pub fn validate_signatures(&self) -> Result<(), String> {
		let pk = self.spec.cosign_taproot().output_key().to_inner();
		let sighashes = self.spec.sighashes(self.utxo);
		for (i, (sighash, sig)) in sighashes.into_iter().rev().zip(self.signatures.iter()).enumerate() {
			util::SECP.verify_schnorr(sig, &sighash.into(), &pk)
				.map_err(|e| format!("failed signature {}: sh {}; sig {}: {}", i, sighash, sig, e))?;
		}
		Ok(())
	}

	/// Construct the exit branch starting from the root ending in the leaf.
	pub fn exit_branch(&self, leaf_idx: usize) -> Option<Vec<Transaction>> {
		let tree = self.spec.build_unsigned_tree(self.utxo);
		if leaf_idx >= tree.nb_leaves {
			return None;
		}

		let mut branch = Vec::new();
		let mut cursor = leaf_idx;
		loop {
			let mut tx = tree.element_at(cursor).unwrap().clone();
			SignedVtxoTree::finalize_tx(&mut tx, &self.signatures[cursor]);
			branch.push(tx);
			if let Some(p) = tree.parent_idx_of(cursor) {
				cursor = p;
			} else {
				break;
			}
		}
		branch.reverse();

		Some(branch)
	}

	/// Get all signed txs in this tree, starting with the leaves, towards the root.
	pub fn all_signed_txs(&self) -> Vec<Transaction> {
		let mut ret = self.spec.build_unsigned_tree(self.utxo).into_vec();
		for (tx, sig) in ret.iter_mut().zip(self.signatures.iter()) {
			SignedVtxoTree::finalize_tx(tx, sig);
		}
		ret
	}
}

#[cfg(test)]
mod test {
	use super::*;

	use std::collections::HashMap;
	use std::str::FromStr;

	use bitcoin::hashes::{siphash24, sha256, Hash, HashEngine};
	use bitcoin::secp256k1::{self, rand, Keypair};
	use bitcoin::FeeRate;
	use rand::SeedableRng;

	use crate::musig;

	#[test]
	fn vtxo_tree_spec() {
		let secp = secp256k1::Secp256k1::new();
		let mut rand = rand::rngs::SmallRng::seed_from_u64(42);
		let key1 = Keypair::new(&secp, &mut rand); // asp
		let key2 = Keypair::new(&secp, &mut rand);
		let key3 = Keypair::new(&secp, &mut rand);
		let dest = VtxoRequest {
			pubkey: Keypair::new(&secp, &mut rand).public_key(),
			amount: Amount::from_sat(100_000),
		};
		let point = "0000000000000000000000000000000000000000000000000000000000000001:1".parse().unwrap();

		{
			let spec = VtxoTreeSpec::new(
				vec![dest.clone(); 27],
				musig::combine_keys([key1.public_key(), key2.public_key(), key3.public_key()]),
				key1.public_key(),
				100_000,
				2016,
				false,
			);
			assert_eq!(spec.total_required_value().to_sat(), 2714705);
			let sighashes_hash = {
				let mut eng = siphash24::Hash::engine();
				spec.sighashes(point).iter().for_each(|h| eng.input(&h[..]));
				siphash24::Hash::from_engine(eng)
			};
			assert_eq!(sighashes_hash.to_string(), "9d740b15a0ecc969");
		}
		{
			let spec = VtxoTreeSpec::new(
				vec![dest.clone(); 28],
				musig::combine_keys([key1.public_key(), key3.public_key(), key2.public_key()]),
				key1.public_key(),
				101_000,
				2016,
				true,
			);
			assert_eq!(spec.total_required_value().to_sat(), 2_817_843);
			let sighashes_hash = {
				let mut eng = siphash24::Hash::engine();
				spec.sighashes(point).iter().for_each(|h| eng.input(&h[..]));
				siphash24::Hash::from_engine(eng)
			};
			assert_eq!(sighashes_hash.to_string(), "30254f7773add95b");
		}
	}

	fn test_tree_amounts(
		tree: &SignedVtxoTree,
		root_value: Amount,
		fee_rate: FeeRate,
	) {
		let txs = tree.all_signed_txs();
		let map = txs.iter().map(|tx| (tx.compute_txid(), tx)).collect::<HashMap<_, _>>();
		println!("tx map: {:?}", map);

		// skip the root
		for tx in txs.iter().take(txs.len() - 1) {
			println!("tx: {}", bitcoin::consensus::encode::serialize_hex(tx));
			let input = tx.input.iter().map(|i| {
				let prev = i.previous_output;
				map.get(&prev.txid).expect("tx not found").output[prev.vout as usize].value
			}).sum::<Amount>();
			let output = tx.output.iter().map(|o| o.value).sum::<Amount>();
			assert!(input >= output);
			let weight = tx.weight();
			let fee = weight * fee_rate;
			assert_eq!(input, output + fee);
		}

		// check the root
		let root = txs.last().unwrap();
		let output = root.output.iter().map(|o| o.value).sum::<Amount>();
		let weight = root.weight();
		let fee = weight * fee_rate;
		assert_eq!(root_value, output + fee);
	}

	#[test]
	fn test_node_tx_sizes() {
		let secp = secp256k1::Secp256k1::new();
		let key1 = Keypair::new(&secp, &mut rand::thread_rng()); // asp
		let key2 = Keypair::new(&secp, &mut rand::thread_rng());
		let sha = sha256::Hash::from_str("4bf5122f344554c53bde2ebb8cd2b7e3d1600ad631c385a5d7cce23c7785459a").unwrap();
		let msg = secp256k1::Message::from_digest(sha.to_byte_array());
		let sig = secp.sign_schnorr(&msg, &key1);
		let dest = VtxoRequest {
			pubkey: Keypair::new(&secp, &mut rand::thread_rng()).public_key(),
			amount: Amount::from_sat(100_000),
		};
		let point = "0000000000000000000000000000000000000000000000000000000000000001:1".parse().unwrap();

		// WITHOUT FEE ANCHORS ON NODES

		// For 2..5 we should pass all types of radixes.
		let (mut had2, mut had3, mut had4) = (false, false, false);
		for n in 2..5 {
			let spec = VtxoTreeSpec::new(
				vec![dest.clone(); n],
				musig::combine_keys([key1.public_key(), key2.public_key()]),
				key1.public_key(),
				100_000,
				2016,
				false,
			);
			let root_value = spec.total_required_value();
			let unsigned = spec.build_unsigned_tree(point);
			assert!(unsigned.iter().all(|n| !n.element.input[0].previous_output.is_null()));
			let nb_nodes = unsigned.nb_nodes();
			let signed = SignedVtxoTree::new(spec, point, vec![sig; nb_nodes]);
			test_tree_amounts(&signed, root_value, fee::RELAY_FEERATE);
			for m in 0..n {
				let exit = signed.exit_branch(m).unwrap();

				// Assert it's a valid chain.
				let mut iter = exit.iter().enumerate().peekable();
				while let Some((i, cur)) = iter.next() {
					if let Some((_, next)) = iter.peek() {
						assert_eq!(next.input[0].previous_output.txid, cur.compute_txid(), "{}", i);
					}
				}

				// Assert the node tx sizes match our pre-computed ones.
				let mut iter = exit.iter().rev();
				let leaf = iter.next().unwrap();
				assert_eq!(leaf.weight(), LEAF_TX_WEIGHT);
				for node in iter {
					assert_eq!(
						node.input[0].witness.size(),
						crate::TAPROOT_KEYSPEND_WEIGHT,
					);
					match node.output.len() {
						2 => {
							assert_eq!(node.weight(), NODE2_TX_WEIGHT);
							had2 = true;
						},
						3 => {
							assert_eq!(node.weight(), NODE3_TX_WEIGHT);
							had3 = true;
						},
						4 => {
							assert_eq!(node.weight(), NODE4_TX_WEIGHT);
							had4 = true;
						},
						_ => unreachable!(),
					}
				}
			}
		}
		assert!(had2 && had3 && had4);

		// WITH FEE ANCHORS ON NODES

		// For 2..5 we should pass all types of radixes.
		let (mut had2, mut had3, mut had4) = (false, false, false);
		for n in 2..5 {
			let spec = VtxoTreeSpec::new(
				vec![dest.clone(); n],
				musig::combine_keys([key1.public_key(), key2.public_key()]),
				key1.public_key(),
				100_000,
				2016,
				true,
			);
			let root_value = spec.total_required_value();
			let unsigned = spec.build_unsigned_tree(point);
			assert!(unsigned.iter().all(|n| !n.element.input[0].previous_output.is_null()));
			let nb_nodes = unsigned.nb_nodes();
			let signed = SignedVtxoTree::new(spec, point, vec![sig; nb_nodes]);
			test_tree_amounts(&signed, root_value, fee::RELAY_FEERATE);
			for m in 0..n {
				let exit = signed.exit_branch(m).unwrap();

				// Assert it's a valid chain.
				let mut iter = exit.iter().enumerate().peekable();
				while let Some((i, cur)) = iter.next() {
					if let Some((_, next)) = iter.peek() {
						assert_eq!(next.input[0].previous_output.txid, cur.compute_txid(), "{}", i);
					}
				}

				// Assert the node tx sizes match our pre-computed ones.
				let mut iter = exit.iter().rev();
				let leaf = iter.next().unwrap();
				assert_eq!(leaf.weight(), LEAF_TX_WEIGHT);
				for node in iter {
					assert_eq!(
						node.input[0].witness.size(),
						crate::TAPROOT_KEYSPEND_WEIGHT,
					);
					match node.output.len() {
						3 => {
							assert_eq!(node.weight(), NODE2_TX_WEIGHT_ANCHOR);
							had2 = true;
						},
						4 => {
							assert_eq!(node.weight(), NODE3_TX_WEIGHT_ANCHOR);
							had3 = true;
						},
						5 => {
							assert_eq!(node.weight(), NODE4_TX_WEIGHT_ANCHOR);
							had4 = true;
						},
						_ => unreachable!(),
					}
				}
			}
		}
		assert!(had2 && had3 && had4);
	}
}

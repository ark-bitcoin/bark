
pub mod signed;

use std::cmp;

/// The max radix of this tree is 4.
const RADIX: usize = 4;

#[derive(Debug, Clone)]
pub struct Node {
	idx: u32,
	parent: Option<u32>,
	children: [Option<u32>; RADIX],
	/// Exclusive range of leaves, allowed to revolve back to 0.
	leaves: (u32, u32),
	nb_tree_leaves: u32,
	level: u32,
}

impl Node {
	fn new_leaf(idx: usize, nb_tree_leaves: usize) -> Node {
		let idx = idx as u32;
		Node {
			idx,
			parent: None,
			children: [None; RADIX],
			leaves: (idx, (idx+1) % nb_tree_leaves as u32),
			nb_tree_leaves: nb_tree_leaves as u32,
			level: 0,
		}
	}

	pub fn idx(&self) -> usize {
		self.idx as usize
	}

	/// The index among internal nodes, starting after the leaves
	///
	/// Panics if this node is a leaf node, if [Node::is_leaf] returns true.
	pub fn internal_idx(&self) -> usize {
		self.idx.checked_sub(self.nb_tree_leaves)
			.expect("called internal_idx on leaf node") as usize
	}

	pub fn parent(&self) -> Option<usize> {
		self.parent.map(|p| p as usize)
	}

	pub fn children(&self) -> impl Iterator<Item = usize> {
		self.children.clone().into_iter().filter_map(|c| c).map(|c| c as usize)
	}

	/// The level of the node in the tree, starting with 0 for a leaf
	pub fn level(&self) -> usize {
		self.level as usize
	}

	/// The internal level of the node in the tree
	///
	/// Panics if this node is a leaf node, if [Node::is_leaf] returns true.
	///
	/// Returns 0 for a node  that has leaves as children
	pub fn internal_level(&self) -> usize {
		self.level.checked_sub(1).expect("called internal_level on leaf node") as usize
	}

	/// An iterator over all leaf indices under this node.
	pub fn leaves(&self) -> impl Iterator<Item = usize> + Clone {
		let (first, last) = self.leaves;
		let nb = self.nb_tree_leaves;
		(first..)
			.take(nb as usize)
			.map(move |e| e % nb)
			.take_while(move |e| first == last || *e != last)
			.map(|e| e as usize)
	}

	pub fn is_leaf(&self) -> bool {
		self.children.iter().all(|o| o.is_none())
	}

	pub fn is_root(&self) -> bool {
		self.parent.is_none()
	}
}

//TODO(stevenroose) consider eliminating this type in favor of straight in-line iterators
// for all nodes and for branches
/// A radix-4 tree.
#[derive(Debug, Clone)]
pub struct Tree {
	/// The nodes in the tree, starting with all the leaves
	/// and then building up towards the root.
	nodes: Vec<Node>,
	nb_leaves: usize,
}

impl Tree {
	/// Calculate the total number of nodes a tree would have
	/// for the given number of leaves.
	pub fn nb_nodes_for_leaves(nb_leaves: usize) -> usize {
		let mut ret = nb_leaves;
		let mut left = nb_leaves;
		while left > 1 {
			let radix = cmp::min(left, RADIX);
			left -= radix;
			left += 1;
			ret += 1;
		}
		ret
	}

	pub fn new(
		nb_leaves: usize,
	) -> Tree {
		assert_ne!(nb_leaves, 0, "trees can't be empty");

		let mut nodes = Vec::with_capacity(Tree::nb_nodes_for_leaves(nb_leaves));

		// First we add all the leaves to the tree.
		nodes.extend((0..nb_leaves).map(|i| Node::new_leaf(i, nb_leaves)));

		let mut cursor = 0;
		// As long as there is more than 1 element on the leftover stack,
		// we have to add more nodes.
		while cursor < nodes.len() - 1 {
			let mut children = [None; RADIX];
			let mut nb_children = 0;
			let mut max_child_level = 0;
			while cursor < nodes.len() && nb_children < RADIX {
				children[nb_children] = Some(cursor as u32);

				let new_idx = nodes.len(); // idx of next node
				let child = &mut nodes[cursor];
				child.parent = Some(new_idx as u32);

				// adjust level and leaf indices
				if child.level > max_child_level {
					max_child_level = child.level;
				}

				cursor += 1;
				nb_children += 1;
			}
			nodes.push(Node {
				idx: nodes.len() as u32,
				leaves: (
					nodes[children.first().unwrap().unwrap() as usize].leaves.0,
					nodes[children.iter().filter_map(|c| *c).last().unwrap() as usize].leaves.1,
				),
				children,
				level: max_child_level + 1,
				parent: None,
				nb_tree_leaves: nb_leaves as u32,
			});
		}

		Tree { nodes, nb_leaves }
	}

	pub fn nb_leaves(&self) -> usize {
		self.nb_leaves
	}

	pub fn nb_nodes(&self) -> usize {
		self.nodes.len()
	}

	/// The number of internal nodes
	pub fn nb_internal_nodes(&self) -> usize {
		self.nodes.len().checked_sub(self.nb_leaves)
			.expect("tree can't have less nodes than leaves")
	}

	pub fn node_at(&self, node_idx: usize) -> &Node {
		self.nodes.get(node_idx).expect("node_idx out of bounds")
	}

	pub fn root(&self) -> &Node {
		self.nodes.last().expect("no empty trees")
	}

	/// Iterate over all nodes, starting with the leaves, towards the root.
	pub fn iter(&self) -> std::slice::Iter<'_, Node> {
		self.nodes.iter()
	}

	/// Iterate over all internal nodes, starting with the ones
	/// right beyond the leaves, towards the root.
	pub fn iter_internal(&self) -> std::slice::Iter<'_, Node> {
		self.nodes[self.nb_leaves..].iter()
	}

	/// Iterate over all nodes, starting with the leaves, towards the root.
	pub fn into_iter(self) -> std::vec::IntoIter<Node> {
		self.nodes.into_iter()
	}

	/// Iterate nodes over a branch starting at the leaf
	/// with index `leaf_idx` ending in the root.
	pub fn iter_branch(&self, leaf_idx: usize) -> BranchIter<'_> {
		assert!(leaf_idx < self.nodes.len());
		BranchIter {
			tree: &self,
			cursor: Some(leaf_idx),
		}
	}

	/// Iterate over ancestors of a node with child indices.
	///
	/// Starting from `node_idx`, walks up towards the root. The starting node
	/// is excluded from iteration. Each returned tuple `(ancestor_idx, child_idx)`
	/// indicates that `child_idx` is the child position that leads back down
	/// towards `node_idx`.
	///
	/// # Example
	///
	/// For a node 12 with children `[4, 5, 6, 7]`:
	/// ```text
	/// iter_branch_with_output(6) yields (12, 2), ..., (root_idx, ...)
	/// ```
	/// Node 6 is at child index 2 (0-indexed) of node 12.
	pub fn iter_branch_with_output(&self, node_idx: usize) -> BranchWithOutputIter<'_> {
		assert!(node_idx < self.nodes.len());
		BranchWithOutputIter {
			tree: self,
			prev_idx: node_idx,
			cursor: self.nodes[node_idx].parent(),
		}
	}

	pub fn parent_idx_of(&self, idx: usize) -> Option<usize> {
		self.nodes.get(idx).and_then(|n| n.parent.map(|c| c as usize))
	}

	/// Returns index of the the parent of the node with given `idx`,
	/// and the index of the node among its siblings.
	pub fn parent_idx_of_with_sibling_idx(&self, idx: usize) -> Option<(usize, usize)> {
		self.nodes.get(idx).and_then(|n| n.parent).map(|parent_idx| {
			let child_idx = self.nodes[parent_idx as usize].children.iter()
				.position(|c| *c == Some(idx as u32))
				.expect("broken tree");
			(self.nodes[parent_idx as usize].idx as usize, child_idx as usize)
		})
	}

}

/// Iterates a tree branch.
#[derive(Clone)]
pub struct BranchIter<'a> {
	tree: &'a Tree,
	cursor: Option<usize>,
}

impl<'a> Iterator for BranchIter<'a> {
	type Item = &'a Node;
	fn next(&mut self) -> Option<Self::Item> {
		if let Some(cursor) = self.cursor {
			let ret = &self.tree.nodes[cursor];
			self.cursor = ret.parent();
			Some(ret)
		} else {
			None
		}
	}
}

/// Iterates ancestors of a node, returning (node_idx, child_idx) tuples.
#[derive(Clone)]
pub struct BranchWithOutputIter<'a> {
	tree: &'a Tree,
	prev_idx: usize,
	cursor: Option<usize>,
}

impl<'a> Iterator for BranchWithOutputIter<'a> {
	type Item = (usize, usize);
	fn next(&mut self) -> Option<Self::Item> {
		let cursor = self.cursor?;
		let node = &self.tree.nodes[cursor];
		let child_idx = node.children()
			.position(|c| c == self.prev_idx)
			.expect("broken tree");
		self.prev_idx = cursor;
		self.cursor = node.parent();
		Some((cursor, child_idx))
	}
}

#[cfg(test)]
mod test {
	use std::collections::HashSet;

use super::*;

	#[test]
	fn test_simple_tree() {
		for n in 1..100 {
			let tree = Tree::new(n);

			assert!(tree.nodes.iter().rev().skip(1).all(|n| n.parent.is_some()));
			assert!(tree.nodes.iter().enumerate().skip(tree.nb_leaves).all(|(i, n)| {
				n.children.iter().filter_map(|v| *v)
					.all(|c| tree.nodes[c as usize].parent == Some(i as u32))
			}));
			assert!(tree.nodes.iter().enumerate().rev().skip(1).all(|(i, n)| {
				let parent_idx = n.parent.unwrap() as usize;
				tree.nodes[parent_idx].children.iter().find(|c| **c == Some(i as u32)).is_some()
			}));
			assert_eq!(Tree::nb_nodes_for_leaves(n), tree.nb_nodes(), "leaves: {}", n);
		}
	}

	#[test]
	fn test_leaves_range() {
		for n in 1..42 {
			let tree = Tree::new(n);

			for node in &tree.nodes[0..tree.nb_leaves()] {
				assert_eq!(node.leaves().collect::<Vec<_>>(), vec![node.idx()]);
			}
			for node in tree.iter() {
				if !node.is_leaf() {
					assert_eq!(
						node.leaves().count(),
						node.children().map(|c| tree.nodes[c].leaves().count()).sum::<usize>(),
						"idx: {}", node.idx(),
					);
				}
				assert!(node.leaves().all(|l| l < tree.nb_leaves()));
				assert_eq!(
					node.leaves().count(),
					node.leaves().collect::<HashSet<_>>().len(),
				);
			}
			println!("n={n} ok");
		}
	}

	#[test]
	fn test_iter_branch_with_output() {
		for n in 1..100 {
			let tree = Tree::new(n);

			for start_idx in 0..tree.nb_nodes() {
				let results: Vec<_> = tree.iter_branch_with_output(start_idx).collect();

				// 1. Verify the iterator excludes the starting node
				assert!(results.iter().all(|(idx, _)| *idx != start_idx));

				// 2. Verify each returned node is an ancestor of the previous
				let mut expected_parent = tree.nodes[start_idx].parent();
				for (ancestor_idx, _) in &results {
					assert_eq!(Some(*ancestor_idx), expected_parent);
					expected_parent = tree.nodes[*ancestor_idx].parent();
				}

				// 3. Verify child_idx actually points back down the branch
				let mut prev = start_idx;
				for (ancestor_idx, child_idx) in &results {
					let child = tree.nodes[*ancestor_idx].children().nth(*child_idx).unwrap();
					assert_eq!(child, prev);
					prev = *ancestor_idx;
				}

				// 4. Verify the last node is the root (has no parent)
				if let Some((last_idx, _)) = results.last() {
					assert!(tree.nodes[*last_idx].is_root());
				}

				// 5. Verify consistency with iter_branch (same path, minus starting node)
				let branch_len = tree.iter_branch(start_idx).skip(1).count();
				assert_eq!(results.len(), branch_len);
			}
		}
	}
}



pub mod signed;





#[derive(Debug)]
pub struct Node<T> {
	elem: T,
	parent: Option<usize>,
	children: [Option<usize>; 4],
}

impl<T> Node<T> {
	fn new(elem: T) -> Node<T> {
		Node {
			elem: elem,
			parent: None,
			children: [None; 4],
		}
	}
}

/// Type used when iterator over the nodes of a tree.
#[derive(Debug)]
pub struct IterNode<'a, T> {
	pub element: &'a T,
	pub parent: Option<&'a T>,
	pub children: [Option<&'a T>; 4],
}

impl<'a, T> IterNode<'a, T> {
	pub fn is_leaf(&self) -> bool {
		self.children.iter().all(|o| o.is_none())
	}

	pub fn is_root(&self) -> bool {
		self.parent.is_none()
	}
}

/// Type used when iterator over the nodes of a tree.
#[derive(Debug)]
pub struct IterNodeMut<'a, T> {
	pub element: &'a mut T,
	pub parent: Option<&'a mut T>,
	pub children: [Option<&'a mut T>; 4],
}

impl<'a, T> IterNodeMut<'a, T> {
	pub fn is_leaf(&self) -> bool {
		self.children.iter().all(|o| o.is_none())
	}

	pub fn is_root(&self) -> bool {
		self.parent.is_none()
	}
}

pub struct ChildrenIterMut<'a, T> {
	tree: &'a mut Tree<T>,
	idxs: [Option<usize>; 4],
	inner_idx: usize,
}

impl<'a, T> ChildrenIterMut<'a, T> {
	pub fn get(&'a mut self) -> Option<&'a mut T> {
		self.idxs.get(self.inner_idx).and_then(|o| o.map(|idx| &mut self.tree.nodes[idx].elem))
	}

	pub fn next(&mut self) -> bool {
		self.inner_idx += 1;
		self.inner_idx < 4
	}
}

pub struct NodeIterMut<'a, T> {
	tree: &'a mut Tree<T>,
	idx: usize,
}

impl<'a, T> NodeIterMut<'a, T> {
	pub fn next(&mut self) -> bool {
		if self.idx >= self.tree.nodes.len() {
			return false;
		}
		self.idx += 1;
		true
	}

	pub fn prev(&mut self) -> bool {
		if self.idx == 0 {
			return false;
		}
		self.idx -= 1;
		true
	}

	pub fn seek_to_last(&mut self) {
		self.idx = self.tree.nodes.len() - 1;
	}

	pub fn element(&mut self) -> &mut T {
		&mut self.tree.nodes[self.idx].elem
	}

	fn node(&self) -> &Node<T> {
		&self.tree.nodes[self.idx]
	}

	pub fn is_leaf(&self) -> bool {
		self.node().children.iter().all(|o| o.is_none())
	}

	pub fn is_root(&self) -> bool {
		self.node().parent.is_none()
	}

	pub fn parent(&mut self) -> Option<&mut T> {
		self.node().parent.map(|i| &mut self.tree.nodes[i].elem)
	}

	pub fn children(&mut self) -> ChildrenIterMut<T> {
		let idxs = self.node().children;
		ChildrenIterMut { idxs, tree: &mut self.tree, inner_idx: 0 }
	}
}

/// A radix-4 "congestion control"-like tree.
#[derive(Debug)]
pub struct Tree<T> {
	nodes: Vec<Node<T>>,
	nb_leaves: usize,
}

impl<T> Tree<T> {
	pub fn new(
		leaves: impl IntoIterator<Item = T>,
		combine_f: impl Fn(&[&T]) -> T,
	) -> Tree<T> {
		let leaves = leaves.into_iter();
		let estimated_size = 2 * leaves.size_hint().1.unwrap_or(leaves.size_hint().0);
		let mut nodes = Vec::with_capacity(estimated_size);

		// First we add all the leaves to the tree.
		nodes.extend(leaves.map(|e| Node::new(e)));
		let nb_leaves = nodes.len();
		assert_ne!(nb_leaves, 0, "trees can't be empty");

		let mut cursor = 0;
		// As long as there is more than 1 element on the leftover stack,
		// we have to add more nodes.
		while cursor < nodes.len() - 1 {
			let mut children = [None; 4];
			let mut nb_children = 0;
			while cursor < nodes.len() && nb_children < 4 {
				children[nb_children] = Some(cursor);
				nodes[cursor].parent = Some(nodes.len()); // idx of next node
				cursor += 1;
				nb_children += 1;
			}
			// build a slice of references to the children elements to call the combine fn
			let mut refs = Vec::with_capacity(4); //TODO(stevenroose) try avoid this allocation
			for i in 0..nb_children {
				refs.push(&nodes[children[i].unwrap()].elem);
			}
			let elem = combine_f(&refs);
			nodes.push(Node { elem, children, parent: None });
		}

		debug_assert!(nodes.len() <= estimated_size);
		nodes.shrink_to_fit();
		Tree { nodes, nb_leaves }
	}

	pub fn nb_leaves(&self) -> usize {
		self.nb_leaves
	}

	pub fn nb_nodes(&self) -> usize {
		self.nodes.len()
	}

	pub fn element_at(&self, idx: usize) -> Option<&T> {
		self.nodes.get(idx).map(|n| &n.elem)
	}

	pub fn element_at_mut(&mut self, idx: usize) -> Option<&mut T> {
		self.nodes.get_mut(idx).map(|n| &mut n.elem)
	}

	pub fn parent_idx_of(&self, idx: usize) -> Option<usize> {
		self.nodes.get(idx).and_then(|n| n.parent)
	}

	pub fn parent_of(&self, idx: usize) -> Option<&T> {
		self.parent_idx_of(idx).map(|idx| &self.nodes[idx].elem)
	}

	pub fn parent_of_mut(&mut self, idx: usize) -> Option<&mut T> {
		self.parent_idx_of(idx).map(|idx| &mut self.nodes[idx].elem)
	}

	/// Returns the parent of the node with given `idx`, and the index of the
	/// node among its siblings.
	pub fn parent_of_with_idx(&self, idx: usize) -> Option<(&T, usize)> {
		self.parent_idx_of(idx).map(|parent_idx| {
			let child_idx = self.nodes[parent_idx].children.iter()
				.position(|c| *c == Some(idx))
				.expect("broken tree");
			(&self.nodes[parent_idx].elem, child_idx)
		})
	}

	/// Cfr [parent_of_with_idx], but returns mutable reference.
	pub fn parent_of_with_idx_mut(&mut self, idx: usize) -> Option<(&mut T, usize)> {
		self.parent_idx_of(idx).map(|parent_idx| {
			let child_idx = self.nodes[parent_idx].children.iter()
				.position(|c| *c == Some(idx))
				.expect("broken tree");
			(&mut self.nodes[parent_idx].elem, child_idx)
		})
	}

	pub fn nb_children_of(&self, idx: usize) -> Option<usize> {
		self.nodes.get(idx).map(|n| n.children.iter().filter(|c| c.is_some()).count())
	}

	pub fn child_idx_of(&self, node_idx: usize, child_idx: usize) -> Option<usize> {
		assert!(child_idx < 4);
		self.nodes.get(node_idx).and_then(|n| n.children[child_idx])
	}

	pub fn child_of(&self, node_idx: usize, child_idx: usize) -> Option<&T> {
		self.child_idx_of(node_idx, child_idx).map(|idx| &self.nodes[idx].elem)
	}

	pub fn child_of_mut(&mut self, node_idx: usize, child_idx: usize) -> Option<&mut T> {
		self.child_idx_of(node_idx, child_idx).map(|idx| &mut self.nodes[idx].elem)
	}

	pub fn into_vec(self) -> Vec<T> {
		self.nodes.into_iter().map(|n| n.elem).collect()
	}

	pub fn iter(&self) -> impl DoubleEndedIterator<Item = IterNode<T>> {
		self.nodes.iter().map(|n| {
			IterNode {
				element: &n.elem,
				parent: n.parent.map(|i| &self.nodes[i].elem),
				children: {
					let mut ret = [None; 4];
					for (i, o) in n.children.iter().enumerate() {
						ret[i] = o.map(|c| &self.nodes[c].elem);
					}
					ret
				}
			}
		})
	}

	pub fn iter_mut(&mut self) -> NodeIterMut<T> {
		NodeIterMut {
			tree: self,
			idx: 0,
		}
	}

	pub fn get_branch(&self, _leaf_idx: usize) -> Vec<T> {
		unimplemented!();
	}
}

#[cfg(test)]
mod test {
	use super::*;
	use std::iter;

	#[test]
	fn test_simple_tree() {
		for n in 1..100 {
			let tree = Tree::new(iter::repeat(()).take(n), |_| ());

			assert!(tree.nodes.iter().rev().skip(1).all(|n| n.parent.is_some()));
			assert!(tree.nodes.iter().enumerate().skip(tree.nb_leaves).all(|(i, n)| {
				n.children.iter().filter_map(|v| *v).all(|c| tree.nodes[c].parent == Some(i))
			}));
			assert!(tree.nodes.iter().enumerate().rev().skip(1).all(|(i, n)| {
				tree.nodes[n.parent.unwrap()].children.iter().find(|c| **c == Some(i)).is_some()
			}));
		}
	}
}

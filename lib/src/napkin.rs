
use std::iter;

use bitcoin::{Amount, Transaction, TxIn, TxOut, ScriptBuf, OutPoint, Txid, Witness, Script};
use bitcoin::blockdata::opcodes;
use bitcoin::hashes::Hash;


const BYTES32: [u8; 32] = [0; 32];
const BYTES64: [u8; 64] = [0; 64];

trait EncSize {
	fn size(&self) -> usize;
}

impl<T: bitcoin::consensus::Encodable> EncSize for T {
	fn size(&self) -> usize {
		bitcoin::consensus::serialize(self).len()
	}
}

fn empty_input() -> TxIn {
	TxIn {
		previous_output: OutPoint::new(Txid::from_byte_array(BYTES32), 0),
		script_sig: ScriptBuf::new(),
		sequence: Default::default(),
		witness: Witness::new(),
	}
}

fn ctv_output() -> TxOut {
	TxOut {
		value: Amount::ZERO,
		script_pubkey: Script::builder()
			.push_opcode(opcodes::all::OP_NOP4)
			.push_slice(&BYTES32)
			.into_script(),
	}
}

fn ctv_input() -> TxIn {
	empty_input()
}

fn taproot_output() -> TxOut {
	TxOut {
		value: Amount::ZERO,
		script_pubkey: Script::builder()
			.push_opcode(opcodes::all::OP_PUSHNUM_1)
			.push_slice(&BYTES32)
			.into_script(),
	}
}

fn taproot_input() -> TxIn {
	TxIn {
		previous_output: OutPoint::new(Txid::hash(&[]), 0),
		script_sig: ScriptBuf::new(),
		sequence: Default::default(),
		witness: {
			let mut ret = Witness::new();
			ret.push(&BYTES64);
			ret
		},
	}
}

fn anchor_output() -> TxOut {
	TxOut {
		value: Amount::ZERO,
		script_pubkey: Script::builder()
			.push_opcode(opcodes::OP_TRUE)
			.into_script(),
	}
}

fn anchor_input() -> TxIn {
	empty_input()
}

fn ctv_node_tx(radix: usize) -> Transaction {
	Transaction {
		version: bitcoin::transaction::Version::TWO,
		lock_time: bitcoin::locktime::absolute::LockTime::from_consensus(0),
		input: vec![ctv_input()],
		output: iter::repeat(ctv_output()).take(radix).chain(Some(anchor_output())).collect(),
	}
}

fn ctv_leaf_tx() -> Transaction {
	Transaction {
		version: bitcoin::transaction::Version::TWO,
		lock_time: bitcoin::locktime::absolute::LockTime::from_consensus(0),
		input: vec![ctv_input()],
		output: vec![taproot_output(), anchor_output()],
	}
}

fn clark_node_tx(radix: usize) -> Transaction {
	Transaction {
		version: bitcoin::transaction::Version::TWO,
		lock_time: bitcoin::locktime::absolute::LockTime::from_consensus(0),
		input: vec![taproot_input()],
		output: iter::repeat(taproot_output()).take(radix).chain(Some(anchor_output())).collect(),
	}
}

fn clark_leaf_tx() -> Transaction {
	Transaction {
		version: bitcoin::transaction::Version::TWO,
		lock_time: bitcoin::locktime::absolute::LockTime::from_consensus(0),
		input: vec![taproot_input()],
		output: vec![taproot_output(), anchor_output()],
	}
}

fn calc_exit_cost(n: usize, radix: usize) {
	let (nodes, levels) = {
		let mut n = n;
		let mut nodes = 0;
		let mut levels = 0;
		loop {
			nodes += n / radix;
			levels += 1;
			n = n / radix + n % radix;
			if n <= radix {
				nodes += 1; // in reality this is not needed if n == 1
				levels += 1;
				break;
			}
		}
		(nodes, levels)
	};

	// nb not every node will have same nb of outputs because at the
	// edge it might be less. we'll simplify this as it's not significant.
	// for exit cost the largest radix has to be taken anyway

	let exit_claim_tx = Transaction {
		version: bitcoin::transaction::Version::TWO,
		lock_time: bitcoin::locktime::absolute::LockTime::from_consensus(0),
		input: iter::repeat(anchor_input()).take(levels).chain(Some(taproot_input())).collect(),
		output: vec![taproot_output()],
	};

	println!("Calculations for n={}, radix={}: levels={}", n, radix, levels);

	let ctv_exit_cost = levels * ctv_node_tx(radix).size() + ctv_leaf_tx().size() + exit_claim_tx.size();
	println!("CTV exit cost: {}", ctv_exit_cost);
	let ctv_total_tree = nodes * ctv_node_tx(radix).size() + n * ctv_leaf_tx().size();
	println!("CTV total tree size: {}", ctv_total_tree);

	let clark_exit_cost = levels * clark_node_tx(radix).size() + clark_leaf_tx().size() + exit_claim_tx.size();
	println!("clArk exit cost: {}", clark_exit_cost);
	let clark_total_tree = nodes * clark_node_tx(radix).size() + n * clark_leaf_tx().size();
	println!("clArk total tree size: {}", clark_total_tree);
	println!();
}

#[test]
fn napkin() {
	println!("CTV node tx radix=2: {} bytes", ctv_node_tx(2).size());
	println!("CTV node tx radix=4: {} bytes", ctv_node_tx(4).size());
	println!("CTV leaf tx: {} bytes", ctv_leaf_tx().size());
	println!("clArk node tx radix=2: {} bytes", clark_node_tx(2).size());
	println!("clArk node tx radix=4: {} bytes", clark_node_tx(4).size());
	println!("clArk leaf tx: {} bytes", clark_leaf_tx().size());
	println!();
	println!();

	calc_exit_cost(4096, 2);
	calc_exit_cost(4096, 3);
	calc_exit_cost(4096, 4);
	calc_exit_cost(4096, 5);
	calc_exit_cost(4096, 6);
	calc_exit_cost(4096, 8);

	println!();

	calc_exit_cost(1_048_576, 2);
	calc_exit_cost(1_048_576, 3);
	calc_exit_cost(1_048_576, 4);
	calc_exit_cost(1_048_576, 5);
	calc_exit_cost(1_048_576, 6);
	calc_exit_cost(1_048_576, 8);
	calc_exit_cost(1_048_576, 12);

	println!();

	calc_exit_cost(10_000_000, 3);
	calc_exit_cost(10_000_000, 4);
	calc_exit_cost(10_000_000, 5);
	calc_exit_cost(10_000_000, 6);
	calc_exit_cost(100_000_000, 4);
}

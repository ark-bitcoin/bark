//! The fee and the payout of each owner VTXO of an expired tree.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{ensure, Context};
use bitcoin::{Amount, ScriptBuf};

use ark::VtxoId;

/// The fee for all the payouts of one root to one script: the higher of
/// 2,000 sats and 1%.
fn payout_fee(gross: Amount) -> Amount {
	Amount::from_sat(2_000.max(gross.to_sat().div_ceil(100)))
}

/// An owner VTXO of an expired tree: its payout script and its amount.
pub(crate) struct OwnerLeaf {
	pub id: VtxoId,
	pub script: ScriptBuf,
	pub amount: Amount,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct LeafAllocation {
	pub id: VtxoId,
	pub gross: Amount,
	pub fee: Amount,
	pub payout: Amount,
}

/// Split the payout of one root between its owner VTXOs. The VTXOs of one
/// script share one fee, which is charged in VTXO id order, so the amount
/// stored for each VTXO does not depend on the input order. The mining fee
/// is not charged to the owners.
pub(crate) fn allocate(leaves: Vec<OwnerLeaf>) -> anyhow::Result<Vec<LeafAllocation>> {
	let mut ids = BTreeSet::new();
	let mut groups = BTreeMap::<ScriptBuf, Vec<OwnerLeaf>>::new();
	for leaf in leaves {
		ensure!(ids.insert(leaf.id), "duplicate expiry payout share {}", leaf.id);
		ensure!(leaf.amount > Amount::ZERO, "empty expiry payout share {}", leaf.id);
		groups.entry(leaf.script.clone()).or_default().push(leaf);
	}

	let mut allocations = Vec::new();
	for (script, mut group) in groups {
		group.sort_by_key(|leaf| leaf.id);
		let gross = group.iter().try_fold(Amount::ZERO, |sum, leaf|
			sum.checked_add(leaf.amount).context("expiry group amount overflow"),
		)?;
		// A remainder below dust cannot be paid, so the owner forfeits it.
		let net = gross.checked_sub(payout_fee(gross)).unwrap_or(Amount::ZERO);
		let group_fee = if net < script.minimal_non_dust() { gross } else { gross - net };
		let mut remaining_fee = group_fee;
		for leaf in group {
			let fee = leaf.amount.min(remaining_fee);
			remaining_fee = remaining_fee.checked_sub(fee).context("expiry fee allocation overflow")?;
			let payout = leaf.amount.checked_sub(fee).context("expiry leaf fee exceeds principal")?;
			allocations.push(LeafAllocation { id: leaf.id, gross: leaf.amount, fee, payout });
		}
		ensure!(remaining_fee == Amount::ZERO, "expiry group fee was not allocated");
	}
	Ok(allocations)
}

#[cfg(test)]
mod tests {
	use bitcoin::hashes::Hash;
	use bitcoin::{PubkeyHash, ScriptHash, WPubkeyHash, WScriptHash};
	use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey};

	use super::*;

	fn leaf(id: u8, amount: u64, script: &ScriptBuf) -> OwnerLeaf {
		let mut bytes = [0; VtxoId::ENCODE_SIZE];
		bytes[0] = id;
		OwnerLeaf {
			id: VtxoId::from_slice(&bytes).unwrap(),
			amount: Amount::from_sat(amount),
			script: script.clone()
		}
	}

	fn wpkh() -> ScriptBuf {
		ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array([1; 20]))
	}

	#[test]
	fn payout_fee_many_small_leaves_pay_one_non_dust_output() {
		let script = wpkh();
		let plan = allocate((0..30).map(|i| leaf(i, 100, &script)).collect()).unwrap();
		assert_eq!(plan.len(), 30);
		assert_eq!(plan.iter().map(|leaf| leaf.payout).sum::<Amount>(), Amount::from_sat(1_000));
		assert_eq!(plan.iter().map(|a| a.fee.to_sat()).sum::<u64>(), 2_000);
		assert!(plan.iter().all(|a| a.fee <= a.gross));
	}

	#[test]
	fn payout_fee_remainder_below_dust_is_forfeited() {
		let secp = Secp256k1::new();
		let key = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[3; 32]).unwrap());
		for script in [
			wpkh(),
			ScriptBuf::new_p2pkh(&PubkeyHash::from_byte_array([2; 20])),
			ScriptBuf::new_p2sh(&ScriptHash::from_byte_array([4; 20])),
			ScriptBuf::new_p2wsh(&WScriptHash::from_byte_array([5; 32])),
			ScriptBuf::new_p2tr(&secp, key.x_only_public_key().0, None),
		] {
			let dust = script.minimal_non_dust().to_sat();
			let paid = allocate(vec![leaf(1, 2_000 + dust, &script)]).unwrap();
			assert_eq!(paid.iter().map(|leaf| leaf.payout).sum::<Amount>().to_sat(), dust);
			let forfeited = allocate(vec![leaf(1, 1_999 + dust, &script)]).unwrap();
			assert_eq!(forfeited[0].payout, Amount::ZERO);
			assert_eq!(forfeited[0].fee.to_sat(), 1_999 + dust);
		}
	}

	#[test]
	fn payout_fee_order_does_not_change_leaf_attribution() {
		let script = wpkh();
		let a = allocate(vec![leaf(2, 2_000, &script), leaf(1, 400, &script)]).unwrap();
		let b = allocate(vec![leaf(1, 400, &script), leaf(2, 2_000, &script)]).unwrap();
		assert_eq!(a, b);
		assert_eq!(a[0].fee.to_sat(), 400);
		assert_eq!(a[1].fee.to_sat(), 1_600);
	}

	#[test]
	fn fee_rejects_duplicate_payout_share() {
		let script = wpkh();
		assert!(allocate(vec![leaf(1, 2_000, &script), leaf(1, 2_000, &script)]).is_err());
	}

	#[test]
	fn payout_fee_conserves_each_leaf_across_policy_boundary() {
		let script = wpkh();
		for total in 1..4_000 {
			for a in allocate(vec![leaf(1, total, &script)]).unwrap() {
				assert_eq!(a.gross, a.fee + a.payout);
			}
		}
	}

	#[test]
	fn payout_fee_separate_outputs_charge_up_to_gross() {
		let script = wpkh();
		let combined = allocate(vec![leaf(1, 1_200, &script), leaf(2, 1_200, &script)]).unwrap();
		assert_eq!(combined.len(), 2);
		assert_eq!(combined.iter().map(|leaf| leaf.payout).sum::<Amount>().to_sat(), 400);
		for id in [1, 2] {
			let separate = allocate(vec![leaf(id, 1_200, &script)]).unwrap();
			assert!(separate.iter().all(|leaf| leaf.payout == Amount::ZERO));
			assert_eq!(separate[0].fee.to_sat(), 1_200);
		}
	}

	#[test]
	fn fee_is_charged_once_per_root() {
		let script = wpkh();
		// One root: two VTXOs of one owner share one fee.
		let shared = allocate(vec![leaf(1, 50_000, &script), leaf(2, 50_001, &script)]).unwrap();
		assert_eq!(shared.iter().map(|leaf| leaf.fee).sum::<Amount>().to_sat(), 2_000);
		assert_eq!(shared.iter().map(|leaf| leaf.payout).sum::<Amount>().to_sat(), 98_001);
		// Two roots at the same height: each allocation charges its own minimum.
		let first = allocate(vec![leaf(1, 50_000, &script)]).unwrap();
		let second = allocate(vec![leaf(2, 50_001, &script)]).unwrap();
		assert_eq!(first[0].fee.to_sat(), 2_000);
		assert_eq!(second[0].fee.to_sat(), 2_000);
		assert_eq!(first[0].payout.to_sat() + second[0].payout.to_sat(), 100_001 - 4_000);
	}

	#[test]
	fn percentage_fee_rounds_up_without_overflow() {
		for (gross, fee) in [(100_000, 2_000), (100_001, 2_000), (200_000, 2_000),
			(200_001, 2_001),
			(u64::MAX, u64::MAX.div_ceil(100))] {
			assert_eq!(payout_fee(Amount::from_sat(gross)).to_sat(), fee);
		}
	}
}

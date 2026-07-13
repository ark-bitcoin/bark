#[derive(Copy, Drop, Serde)]
pub struct ArkTaprootMiniscriptClaim {
    pub manifest_id_hi: u128,
    pub manifest_id_lo: u128,
    pub taproot_root_hi: u128,
    pub taproot_root_lo: u128,
    pub selected_leaf_hash_hi: u128,
    pub selected_leaf_hash_lo: u128,
    pub selected_leaf_role: felt252,
    pub taproot_path_commitment_hi: u128,
    pub taproot_path_commitment_lo: u128,
    pub taproot_path_fold: felt252,
    pub taproot_path_depth: u32,
    pub path_sibling_0_hi: u128,
    pub path_sibling_0_lo: u128,
    pub path_sibling_0_is_left: felt252,
    pub path_sibling_1_hi: u128,
    pub path_sibling_1_lo: u128,
    pub path_sibling_1_is_left: felt252,
    pub path_sibling_2_hi: u128,
    pub path_sibling_2_lo: u128,
    pub path_sibling_2_is_left: felt252,
    pub settlement_hash_hi: u128,
    pub settlement_hash_lo: u128,
    pub amount_sats: u64,
    pub exit_delay: u32,
    pub binding_commitment: felt252,
}

#[derive(Copy, Drop, Serde)]
pub struct ArkTaprootMiniscriptOutput {
    pub ok: felt252,
    pub selected_leaf_role: felt252,
    pub binding_commitment: felt252,
}

const ROLE_COOPERATIVE_ROUND: felt252 = 1;
const ROLE_OWNER_CSV_EXIT: felt252 = 2;
const ROLE_ASP_FORFEIT_GUARD: felt252 = 3;
const ROLE_DLC_VIRTUAL_CET_SETTLEMENT: felt252 = 4;
const ROLE_UTXOREF_CHALLENGE_PUBLICATION: felt252 = 5;

fn mix(left: felt252, right: felt252) -> felt252 {
    left * 31 + right * 17 + 7
}

fn mix_hash_limbs(hi: u128, lo: u128) -> felt252 {
    let hi_felt: felt252 = hi.into();
    let lo_felt: felt252 = lo.into();
    mix(hi_felt, lo_felt)
}

fn is_supported_leaf_role(role: felt252) -> bool {
    role == ROLE_COOPERATIVE_ROUND
        || role == ROLE_OWNER_CSV_EXIT
        || role == ROLE_ASP_FORFEIT_GUARD
        || role == ROLE_DLC_VIRTUAL_CET_SETTLEMENT
        || role == ROLE_UTXOREF_CHALLENGE_PUBLICATION
}

fn mix_path_branch(current: felt252, sibling: felt252, sibling_is_left: felt252) -> felt252 {
    assert(sibling_is_left == 0 || sibling_is_left == 1, 'bad path side');
    if sibling_is_left == 1 {
        mix(sibling, current)
    } else {
        mix(current, sibling)
    }
}

pub fn compute_taproot_path_fold(claim: @ArkTaprootMiniscriptClaim) -> felt252 {
    let mut current = mix_hash_limbs(*claim.selected_leaf_hash_hi, *claim.selected_leaf_hash_lo);
    if *claim.taproot_path_depth > 0 {
        let sibling_0 = mix_hash_limbs(*claim.path_sibling_0_hi, *claim.path_sibling_0_lo);
        current = mix_path_branch(current, sibling_0, *claim.path_sibling_0_is_left);
    };
    if *claim.taproot_path_depth > 1 {
        let sibling_1 = mix_hash_limbs(*claim.path_sibling_1_hi, *claim.path_sibling_1_lo);
        current = mix_path_branch(current, sibling_1, *claim.path_sibling_1_is_left);
    };
    if *claim.taproot_path_depth > 2 {
        let sibling_2 = mix_hash_limbs(*claim.path_sibling_2_hi, *claim.path_sibling_2_lo);
        current = mix_path_branch(current, sibling_2, *claim.path_sibling_2_is_left);
    };
    current
}

pub fn compute_binding(claim: @ArkTaprootMiniscriptClaim) -> felt252 {
    let amount: felt252 = (*claim.amount_sats).into();
    let delay: felt252 = (*claim.exit_delay).into();

    let manifest_id = mix_hash_limbs(*claim.manifest_id_hi, *claim.manifest_id_lo);
    let taproot_root = mix_hash_limbs(*claim.taproot_root_hi, *claim.taproot_root_lo);
    let selected_leaf_hash = mix_hash_limbs(
        *claim.selected_leaf_hash_hi, *claim.selected_leaf_hash_lo,
    );
    let taproot_path_commitment = mix_hash_limbs(
        *claim.taproot_path_commitment_hi, *claim.taproot_path_commitment_lo,
    );
    let settlement_hash = mix_hash_limbs(*claim.settlement_hash_hi, *claim.settlement_hash_lo);

    let policy_pair = mix(manifest_id, taproot_root);
    let path_pair = mix(taproot_path_commitment, *claim.taproot_path_fold);
    let leaf_pair = mix(selected_leaf_hash, *claim.selected_leaf_role);
    let policy_path = mix(policy_pair, path_pair);
    let policy_leaf = mix(policy_path, leaf_pair);
    let settlement_amount = mix(settlement_hash, amount);
    let settlement_delay = mix(settlement_amount, delay);

    mix(policy_leaf, settlement_delay)
}

pub fn verify_claim(claim: @ArkTaprootMiniscriptClaim) -> ArkTaprootMiniscriptOutput {
    assert(is_supported_leaf_role(*claim.selected_leaf_role), 'bad leaf role');
    assert(*claim.amount_sats > 0, 'amount is zero');
    assert(*claim.exit_delay > 0, 'exit delay is zero');
    assert(*claim.taproot_path_depth <= 3, 'path too deep');

    let expected_path_fold = compute_taproot_path_fold(claim);
    assert(*claim.taproot_path_fold == expected_path_fold, 'bad path fold');
    let expected_binding = compute_binding(claim);
    assert(*claim.binding_commitment == expected_binding, 'bad binding');

    ArkTaprootMiniscriptOutput {
        ok: 1, selected_leaf_role: *claim.selected_leaf_role, binding_commitment: expected_binding,
    }
}

#[executable]
fn main(claim: ArkTaprootMiniscriptClaim) -> ArkTaprootMiniscriptOutput {
    verify_claim(@claim)
}

#[cfg(test)]
mod tests {
    use super::{
        ArkTaprootMiniscriptClaim, ROLE_DLC_VIRTUAL_CET_SETTLEMENT, compute_binding,
        compute_taproot_path_fold, verify_claim,
    };

    fn sample_claim() -> ArkTaprootMiniscriptClaim {
        let mut claim = ArkTaprootMiniscriptClaim {
            manifest_id_hi: 0,
            manifest_id_lo: 0x101,
            taproot_root_hi: 0,
            taproot_root_lo: 0x202,
            selected_leaf_hash_hi: 0,
            selected_leaf_hash_lo: 0x303,
            selected_leaf_role: ROLE_DLC_VIRTUAL_CET_SETTLEMENT,
            taproot_path_commitment_hi: 0,
            taproot_path_commitment_lo: 0x505,
            taproot_path_fold: 0,
            taproot_path_depth: 0,
            path_sibling_0_hi: 0,
            path_sibling_0_lo: 0,
            path_sibling_0_is_left: 0,
            path_sibling_1_hi: 0,
            path_sibling_1_lo: 0,
            path_sibling_1_is_left: 0,
            path_sibling_2_hi: 0,
            path_sibling_2_lo: 0,
            path_sibling_2_is_left: 0,
            settlement_hash_hi: 0,
            settlement_hash_lo: 0x404,
            amount_sats: 100000,
            exit_delay: 1008,
            binding_commitment: 0,
        };
        claim.taproot_path_fold = compute_taproot_path_fold(@claim);
        claim.binding_commitment = compute_binding(@claim);
        claim
    }

    #[test]
    fn test_sample_claim_verifies() {
        let claim = sample_claim();
        let output = verify_claim(@claim);
        assert(output.ok == 1, 'claim failed');
        assert(output.binding_commitment == claim.binding_commitment, 'binding mismatch');
    }
}


//! Onboard flow:
//!
//! * User starts by using the [new_user] function that crates the user's parts.
//! * ASP does a deterministic sign and sends ASP part using [new_asp].
//! * User also signs and combines sigs using [finish] and stores vtxo.

use bitcoin::{taproot, Amount, OutPoint, ScriptBuf, Transaction, TxOut};
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::Keypair;

use bitcoin_ext::P2WSH_DUST;

use crate::{musig, util, vtxo, OnboardVtxo, VtxoSpec};


pub fn onboard_taproot(spec: &VtxoSpec) -> taproot::TaprootSpendInfo {
	let expiry = util::timelock_sign(spec.expiry_height, spec.asp_pubkey.x_only_public_key().0);
	let ret = taproot::TaprootBuilder::new()
		.add_leaf(0, expiry).unwrap()
		.finalize(&util::SECP, spec.combined_pubkey()).unwrap();
	debug_assert_eq!(
		ret.output_key().to_inner(),
		musig::tweaked_key_agg(
			[spec.user_pubkey, spec.asp_pubkey], ret.tap_tweak().to_byte_array(),
		).1.x_only_public_key().0,
		"unexpected output key",
	);
	ret
}

pub fn onboard_taptweak(spec: &VtxoSpec) -> taproot::TapTweakHash {
	onboard_taproot(spec).tap_tweak()
}

pub fn onboard_spk(spec: &VtxoSpec) -> ScriptBuf {
	ScriptBuf::new_p2tr_tweaked(onboard_taproot(spec).output_key())
}

/// The additional amount that needs to be sent into the onboard tx.
pub fn onboard_surplus() -> Amount {
	P2WSH_DUST
}

/// The amount that should be sent into the onboard output.
pub fn onboard_amount(spec: &VtxoSpec) -> Amount {
	spec.amount + onboard_surplus()
}

fn onboard_txout(spec: &VtxoSpec) -> TxOut {
	TxOut {
		script_pubkey: onboard_spk(&spec),
		//TODO(stevenroose) consider storing both leaf and input values in vtxo struct
		value: spec.amount + onboard_surplus(),
	}
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserPart {
	pub spec: VtxoSpec,
	pub utxo: OutPoint,
	#[serde(with = "musig::serde::pubnonce")]
	pub nonce: musig::MusigPubNonce,
}

impl UserPart {
	pub fn exit_tx(&self) -> Transaction {
		vtxo::create_exit_tx(
			self.spec.user_pubkey,
			self.spec.asp_pubkey,
			self.spec.exit_delta,
			self.spec.amount,
			self.utxo,
			None,
		)
	}
}

#[derive(Debug)]
pub struct PrivateUserPart {
	pub sec_nonce: musig::MusigSecNonce,
}

pub fn new_user(spec: VtxoSpec, utxo: OutPoint) -> (UserPart, PrivateUserPart) {
	let onboard_prev = onboard_txout(&spec);
	let (reveal_sighash, _tx) = vtxo::exit_tx_sighash(&spec, utxo, &onboard_prev);
	let (agg, _) = musig::tweaked_key_agg(
		[spec.user_pubkey, spec.asp_pubkey], onboard_taptweak(&spec).to_byte_array(),
	);
	let (sec_nonce, pub_nonce) = agg.nonce_gen(
		&musig::SECP,
		musig::MusigSecRand::assume_unique_per_nonce_gen(rand::random()),
		musig::pubkey_to(spec.user_pubkey),
		musig::secpm::Message::from_digest(reveal_sighash.to_byte_array()),
		None,
	).expect("non-zero session id");

	let user_part = UserPart { spec, utxo, nonce: pub_nonce };
	let private_user_part = PrivateUserPart { sec_nonce };
	(user_part, private_user_part)
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AspPart {
	#[serde(with = "musig::serde::pubnonce")]
	pub nonce: musig::MusigPubNonce,
	#[serde(with = "musig::serde::partialsig")]
	pub signature: musig::MusigPartialSignature,
}

impl AspPart {
	/// Validate the ASP's partial signature.
	pub fn verify_partial_sig(&self, user_part: &UserPart) -> bool {
		let onboard_prev = onboard_txout(&user_part.spec);
		let (reveal_sighash, _tx) = vtxo::exit_tx_sighash(
			&user_part.spec,
			user_part.utxo,
			&onboard_prev,
		);
		let agg_nonce = musig::nonce_agg(&[&user_part.nonce, &self.nonce]);
		let agg_pk = musig::tweaked_key_agg(
			[user_part.spec.user_pubkey, user_part.spec.asp_pubkey],
			onboard_taptweak(&user_part.spec).to_byte_array(),
		).0;

		let session = musig::MusigSession::new(
			&musig::SECP,
			&agg_pk,
			agg_nonce,
			musig::secpm::Message::from_digest(reveal_sighash.to_byte_array()),
		);
		session.partial_verify(
			&musig::SECP,
			&agg_pk,
			self.signature,
			self.nonce,
			musig::pubkey_to(user_part.spec.asp_pubkey),
		)
	}
}

pub fn new_asp(user: &UserPart, key: &Keypair) -> AspPart {
	let onboard_prev = onboard_txout(&user.spec);
	let (reveal_sighash, _tx) = vtxo::exit_tx_sighash(&user.spec, user.utxo, &onboard_prev);
	let msg = reveal_sighash.to_byte_array();
	let tweak = onboard_taptweak(&user.spec);
	let (pub_nonce, sig) = musig::deterministic_partial_sign(
		key, [user.spec.user_pubkey], &[&user.nonce], msg, Some(tweak.to_byte_array()),
	);
	AspPart {
		nonce: pub_nonce,
		signature: sig,
	}
}

pub fn finish(
	user: UserPart,
	asp: AspPart,
	private: PrivateUserPart,
	key: &Keypair,
) -> OnboardVtxo {
	let onboard_prev = onboard_txout(&user.spec);
	let (reveal_sighash, _tx) = vtxo::exit_tx_sighash(&user.spec, user.utxo, &onboard_prev);
	let agg_nonce = musig::nonce_agg(&[&user.nonce, &asp.nonce]);
	let (_user_sig, final_sig) = musig::partial_sign(
		[user.spec.user_pubkey, user.spec.asp_pubkey],
		agg_nonce,
		key,
		private.sec_nonce,
		reveal_sighash.to_byte_array(),
		Some(onboard_taptweak(&user.spec).to_byte_array()),
		Some(&[&asp.signature]),
	);
	let final_sig = final_sig.expect("we provided the other sig");
	debug_assert!(util::SECP.verify_schnorr(
		&final_sig,
		&reveal_sighash.into(),
		&onboard_taproot(&user.spec).output_key().to_inner(),
	).is_ok(), "invalid onboard exit tx signature produced");

	OnboardVtxo {
		spec: user.spec,
		onchain_output: user.utxo,
		exit_tx_signature: final_sig,
	}
}

#[cfg(test)]
mod test {
	use super::*;

	#[test]
	fn test_flow_assertions() {
		//! Passes through the entire flow so that all assertions
		//! inside the code are ran at least once.

		let key = Keypair::new(&util::SECP, &mut rand::thread_rng());
		let utxo = "0000000000000000000000000000000000000000000000000000000000000001:1".parse().unwrap();
		let spec = VtxoSpec {
			user_pubkey: key.public_key(),
			asp_pubkey: key.public_key(),
			expiry_height: 100_000,
			exit_delta: 2016,
			amount: Amount::from_btc(1.5).unwrap(),
		};
		let (user, upriv) = new_user(spec, utxo);
		let asp = new_asp(&user, &key);
		let vtxo = finish(user, asp, upriv, &key);
		let _exit_tx = vtxo.exit_tx(); // does some assertion inside
	}
}

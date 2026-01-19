

use bitcoin::{OutPoint, ScriptBuf, Sequence, TapLeafHash, Transaction, TxIn, TxOut, Witness};
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{schnorr, Keypair, PublicKey};
use bitcoin::sighash::{self, SighashCache, TapSighash, TapSighashType};
use bitcoin::taproot::{self, LeafVersion, TaprootSpendInfo};

use bitcoin_ext::{fee, TaprootSpendInfoExt, P2TR_DUST};

use crate::{musig, Vtxo, VtxoId, SECP};
use crate::connectors::ConnectorChain;
use crate::encode::{ProtocolDecodingError, ProtocolEncoding, ReadExt, WriteExt};
use crate::tree::signed::{unlock_clause, UnlockHash, UnlockPreimage};
use crate::vtxo::exit_clause;


/// The taproot for the policy of the output of the hArk forfeit tx
///
/// This policy allows the server to spend by revealing the unlock preimage,
/// but still has a timeout to the user after exit delta.
#[inline]
pub fn hark_forfeit_claim_taproot(
	vtxo: &Vtxo,
	unlock_hash: UnlockHash,
) -> TaprootSpendInfo {
	let agg_pk = vtxo.forfeit_agg_pubkey();
	taproot::TaprootBuilder::new()
		.add_leaf(1, exit_clause(vtxo.user_pubkey(), vtxo.exit_delta())).unwrap()
		.add_leaf(1, unlock_clause(agg_pk, unlock_hash)).unwrap()
		.finalize(&SECP, agg_pk).unwrap()
}

/// Construct the first tx in the hArk forfeit protocol
#[inline]
pub fn create_hark_forfeit_tx(
	vtxo: &Vtxo,
	unlock_hash: UnlockHash,
	signature: Option<&schnorr::Signature>,
) -> Transaction {
	let claim_taproot = hark_forfeit_claim_taproot(vtxo, unlock_hash);
	Transaction {
		version: bitcoin::transaction::Version(3),
		lock_time: bitcoin::absolute::LockTime::ZERO,
		input: vec![
			TxIn {
				previous_output: vtxo.point(),
				sequence: Sequence::MAX,
				script_sig: ScriptBuf::new(),
				witness: signature.map(|s| Witness::from_slice(&[&s[..]])).unwrap_or_default(),
			},
		],
		output: vec![
			TxOut {
				value: vtxo.amount(),
				script_pubkey: claim_taproot.script_pubkey(),
			},
			fee::fee_anchor(),
		],
	}
}

/// Construct the second tx in the hArk forfeit protocol
#[inline]
pub fn create_hark_forfeit_claim_tx(
	vtxo: &Vtxo,
	forfeit_point: OutPoint,
	unlock_hash: UnlockHash,
	witness: Option<(&schnorr::Signature, UnlockPreimage)>,
) -> Transaction {
	Transaction {
		version: bitcoin::transaction::Version(3),
		lock_time: bitcoin::absolute::LockTime::ZERO,
		input: vec![
			TxIn {
				previous_output: forfeit_point,
				sequence: Sequence::MAX,
				script_sig: ScriptBuf::new(),
				witness: witness.map(|(signature, unlock_preimage)| {
					let taproot = hark_forfeit_claim_taproot(vtxo, unlock_hash);
					let agg_pk = taproot.internal_key();
					debug_assert_eq!(agg_pk, vtxo.forfeit_agg_pubkey());
					let clause = unlock_clause(agg_pk, unlock_hash);
					let script_leaf = (clause, LeafVersion::TapScript);
					let cb = taproot.control_block(&script_leaf)
						.expect("unlock clause not found in hArk forfeit claim taproot");
					Witness::from_slice(&[
						&signature.serialize()[..],
						&unlock_preimage[..],
						&script_leaf.0.as_bytes(),
						&cb.serialize()[..],
					])
				}).unwrap_or_default(),
			},
		],
		output: vec![
			TxOut {
				value: vtxo.amount(),
				script_pubkey: ScriptBuf::new_p2tr(&SECP, vtxo.server_pubkey().into(), None),
			},
			fee::fee_anchor(),
		],
	}
}

#[inline]
pub fn hark_forfeit_sighash(
	vtxo: &Vtxo,
	unlock_hash: UnlockHash,
) -> (TapSighash, Transaction) {
	let exit_prevout = vtxo.txout();
	let tx = create_hark_forfeit_tx(vtxo, unlock_hash, None);
	let sighash = SighashCache::new(&tx).taproot_key_spend_signature_hash(
		0, &sighash::Prevouts::All(&[exit_prevout]), TapSighashType::Default,
	).expect("sighash error");
	(sighash, tx)
}

#[inline]
pub fn hark_forfeit_claim_sighash(
	vtxo: &Vtxo,
	forfeit_point: OutPoint,
	unlock_hash: UnlockHash,
) -> (TapSighash, Transaction) {
	let claim_taproot = hark_forfeit_claim_taproot(vtxo, unlock_hash);
	let claim_txout = TxOut {
		script_pubkey: claim_taproot.script_pubkey(),
		value: vtxo.amount(),
	};
	let tx = create_hark_forfeit_claim_tx(vtxo, forfeit_point, unlock_hash, None);
	let agg_pk = claim_taproot.internal_key();
	debug_assert_eq!(agg_pk, vtxo.forfeit_agg_pubkey());
	let clause = unlock_clause(agg_pk, unlock_hash);
	let leaf = TapLeafHash::from_script(&clause, LeafVersion::TapScript);
	let sighash = SighashCache::new(&tx).taproot_script_spend_signature_hash(
		0, &sighash::Prevouts::All(&[claim_txout]), leaf, TapSighashType::Default,
	).expect("sighash error");
	(sighash, tx)
}

/// Set of nonces for a hArk forfeit
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashLockedForfeitNonces {
	pub forfeit_tx_nonce: musig::PublicNonce,
	pub forfeit_claim_tx_nonce: musig::PublicNonce,
}

impl ProtocolEncoding for HashLockedForfeitNonces {
	fn encode<W: std::io::Write + ?Sized>(&self, w: &mut W) -> Result<(), std::io::Error> {
		self.forfeit_tx_nonce.encode(w)?;
		self.forfeit_claim_tx_nonce.encode(w)?;
		Ok(())
	}

	fn decode<R: std::io::Read + ?Sized>(r: &mut R) -> Result<Self, ProtocolDecodingError> {
		Ok(Self {
			forfeit_tx_nonce: ProtocolEncoding::decode(r)?,
			forfeit_claim_tx_nonce: ProtocolEncoding::decode(r)?,
		})
	}
}

/// A bundle of signatures that forfeits a user's VTXO
/// conditional on the server revealing a secret preimage
///
/// In hArk, the forfeit protocol actually consists of two steps.
/// First there is a tx that sends the money to an output that the
/// server can claim if he provides the preimage, but that still
/// has a timeout back to the user, to force the server to actually
/// reveal the preimage before the new hArk VTXO expires.
/// This output policy also has to contain the user's pubkey, so the
/// user that forfeits will have to provide a partial signature for
/// both the spend from his VTXO to the forfeit tx and on a tx that
/// spends the forfeit tx to the server's wallet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashLockedForfeitBundle {
	pub vtxo_id: VtxoId,
	pub unlock_hash: UnlockHash,
	pub user_nonces: HashLockedForfeitNonces,
	/// User's partial signature on the forfeit tx
	pub forfeit_tx_part_sig: musig::PartialSignature,
	/// User's partial signature on the forfeit claim tx
	pub forfeit_claim_tx_part_sig: musig::PartialSignature,
}

impl HashLockedForfeitBundle {
	/// Create a new [HashLockedForfeitBundle] for the given VTXO
	pub fn forfeit_vtxo(
		vtxo: &Vtxo,
		unlock_hash: UnlockHash,
		user_key: &Keypair,
		server_nonces: &HashLockedForfeitNonces,
	) -> Self {
		let vtxo_exit_taproot = vtxo.output_taproot();
		let (ff_sighash, ff_tx) = hark_forfeit_sighash(vtxo, unlock_hash);
		let (ff_sec_nonce, ff_pub_nonce) = musig::nonce_pair_with_msg(
			user_key, &ff_sighash.to_byte_array(),
		);
		let ff_agg_nonce = musig::nonce_agg(&[&ff_pub_nonce, &server_nonces.forfeit_tx_nonce]);
		let ff_point = OutPoint::new(ff_tx.compute_txid(), 0);
		let (ff_part_sig, _sig) = musig::partial_sign(
			[vtxo.user_pubkey(), vtxo.server_pubkey()],
			ff_agg_nonce,
			user_key,
			ff_sec_nonce,
			ff_sighash.to_byte_array(),
			Some(vtxo_exit_taproot.tap_tweak().to_byte_array()),
			None,
		);

		let (claim_sighash, _tx) = hark_forfeit_claim_sighash(vtxo, ff_point, unlock_hash);
		let (claim_sec_nonce, claim_pub_nonce) = musig::nonce_pair_with_msg(
			user_key, &claim_sighash.to_byte_array(),
		);
		let claim_agg_nonce = musig::nonce_agg(
			&[&claim_pub_nonce, &server_nonces.forfeit_claim_tx_nonce],
		);
		let (claim_part_sig, _sig) = musig::partial_sign(
			[vtxo.user_pubkey(), vtxo.server_pubkey()],
			claim_agg_nonce,
			user_key,
			claim_sec_nonce,
			claim_sighash.to_byte_array(),
			None,
			None,
		);

		Self {
			vtxo_id: vtxo.id(),
			unlock_hash: unlock_hash,
			user_nonces: HashLockedForfeitNonces {
				forfeit_tx_nonce: ff_pub_nonce,
				forfeit_claim_tx_nonce: claim_pub_nonce,
			},
			forfeit_tx_part_sig: ff_part_sig,
			forfeit_claim_tx_part_sig: claim_part_sig,
		}
	}

	/// Used by the server to verify if the partial signatures in the bundle are
	/// valid
	pub fn verify(
		&self,
		vtxo: &Vtxo,
		server_nonces: &HashLockedForfeitNonces,
	) -> Result<(), &'static str> {
		if vtxo.id() != self.vtxo_id {
			return Err("VTXO mismatch");
		}

		let ff_agg_nonce = musig::nonce_agg(
			&[&self.user_nonces.forfeit_tx_nonce, &server_nonces.forfeit_tx_nonce],
		);
		let vtxo_exit_taproot = vtxo.output_taproot();
		let (ff_sighash, ff_tx) = hark_forfeit_sighash(vtxo, self.unlock_hash);
		let (ff_key_agg, _) = musig::tweaked_key_agg(
			[vtxo.user_pubkey(), vtxo.server_pubkey()],
			vtxo_exit_taproot.tap_tweak().to_byte_array(),
		);
		let ff_point = OutPoint::new(ff_tx.compute_txid(), 0);
		let ff_session = musig::Session::new(
			&ff_key_agg,
			ff_agg_nonce,
			&ff_sighash.to_byte_array(),
		);
		let success = ff_session.partial_verify(
			&ff_key_agg,
			&self.forfeit_tx_part_sig,
			&self.user_nonces.forfeit_tx_nonce,
			musig::pubkey_to(vtxo.user_pubkey()),
		);
		if !success {
			return Err("invalid partial sig for forfeit tx");
		}

		let claim_agg_nonce = musig::nonce_agg(
			&[&self.user_nonces.forfeit_claim_tx_nonce, &server_nonces.forfeit_claim_tx_nonce],
		);
		let (claim_sighash, _tx) = hark_forfeit_claim_sighash(vtxo, ff_point, self.unlock_hash);
		let claim_key_agg = musig::key_agg([vtxo.user_pubkey(), vtxo.server_pubkey()]);
		let claim_session = musig::Session::new(
			&claim_key_agg,
			claim_agg_nonce,
			&claim_sighash.to_byte_array(),
		);
		let success = claim_session.partial_verify(
			&claim_key_agg,
			&self.forfeit_claim_tx_part_sig,
			&self.user_nonces.forfeit_claim_tx_nonce,
			musig::pubkey_to(vtxo.user_pubkey()),
		);
		if !success {
			return Err("invalid partial sig for forfeit claim tx");
		}
		Ok(())
	}

	/// Used by the server to finish the forfeit signatures using its own
	/// nonces.
	///
	/// NB users don't need to know these signatures.
	pub fn finish(
		&self,
		vtxo: &Vtxo,
		server_pub_nonces: &HashLockedForfeitNonces,
		[ff_sec_nonce, claim_sec_nonce]: [musig::SecretNonce; 2],
		server_key: &Keypair,
	) -> [schnorr::Signature; 2] {
		assert_eq!(vtxo.id(), self.vtxo_id);

		let ff_agg_nonce = musig::nonce_agg(
			&[&self.user_nonces.forfeit_tx_nonce, &server_pub_nonces.forfeit_tx_nonce],
		);
		let vtxo_exit_taproot = vtxo.output_taproot();
		let (ff_sighash, ff_tx) = hark_forfeit_sighash(vtxo, self.unlock_hash);
		let ff_point = OutPoint::new(ff_tx.compute_txid(), 0);
		let (_ff_part_sig, ff_sig) = musig::partial_sign(
			[vtxo.user_pubkey(), vtxo.server_pubkey()],
			ff_agg_nonce,
			server_key,
			ff_sec_nonce,
			ff_sighash.to_byte_array(),
			Some(vtxo_exit_taproot.tap_tweak().to_byte_array()),
			Some(&[&self.forfeit_tx_part_sig]),
		);
		let ff_sig = ff_sig.expect("forfeit tx sig error");
		debug_assert!({
			let (ff_key_agg, _) = musig::tweaked_key_agg(
				[vtxo.user_pubkey(), vtxo.server_pubkey()],
				vtxo_exit_taproot.tap_tweak().to_byte_array(),
			);
			let ff_session = musig::Session::new(
				&ff_key_agg,
				ff_agg_nonce,
				&ff_sighash.to_byte_array(),
			);
			ff_session.partial_verify(
				&ff_key_agg,
				&_ff_part_sig,
				&server_pub_nonces.forfeit_tx_nonce,
				musig::pubkey_to(vtxo.server_pubkey()),
			)
		});
		debug_assert_eq!(Ok(()), SECP.verify_schnorr(
			&ff_sig, &ff_sighash.into(), &vtxo_exit_taproot.output_key().to_x_only_public_key(),
		));

		let claim_agg_nonce = musig::nonce_agg(
			&[&self.user_nonces.forfeit_claim_tx_nonce, &server_pub_nonces.forfeit_claim_tx_nonce],
		);
		let claim_taproot = hark_forfeit_claim_taproot(vtxo, self.unlock_hash);
		let (claim_sighash, _tx) = hark_forfeit_claim_sighash(vtxo, ff_point, self.unlock_hash);
		let (_claim_part_sig, claim_sig) = musig::partial_sign(
			[vtxo.user_pubkey(), vtxo.server_pubkey()],
			claim_agg_nonce,
			server_key,
			claim_sec_nonce,
			claim_sighash.to_byte_array(),
			None,
			Some(&[&self.forfeit_claim_tx_part_sig]),
		);
		let claim_sig = claim_sig.expect("forfeit claim tx sig error");
		debug_assert!({
			let claim_key_agg = musig::key_agg([vtxo.user_pubkey(), vtxo.server_pubkey()]);
			let claim_session = musig::Session::new(
				&claim_key_agg,
				claim_agg_nonce,
				&claim_sighash.to_byte_array(),
			);
			claim_session.partial_verify(
				&claim_key_agg,
				&_claim_part_sig,
				&server_pub_nonces.forfeit_claim_tx_nonce,
				musig::pubkey_to(vtxo.server_pubkey()),
			)
		});
		debug_assert_eq!(Ok(()), SECP.verify_schnorr(
			&claim_sig, &claim_sighash.into(), &claim_taproot.internal_key(),
		));

		[ff_sig, claim_sig]
	}
}

/// The serialization version of [HashLockedForfeitBundle].
const HASH_LOCKED_FORFEIT_BUNDLE_VERSION: u8 = 0x00;

impl ProtocolEncoding for HashLockedForfeitBundle {
	fn encode<W: std::io::Write + ?Sized>(&self, w: &mut W) -> Result<(), std::io::Error> {
		w.emit_u8(HASH_LOCKED_FORFEIT_BUNDLE_VERSION)?;
		self.vtxo_id.encode(w)?;
		self.unlock_hash.encode(w)?;
		self.user_nonces.encode(w)?;
		self.forfeit_tx_part_sig.encode(w)?;
		self.forfeit_claim_tx_part_sig.encode(w)?;
		Ok(())
	}

	fn decode<R: std::io::Read + ?Sized>(r: &mut R) -> Result<Self, ProtocolDecodingError> {
		let ver = r.read_u8()?;
		if ver != HASH_LOCKED_FORFEIT_BUNDLE_VERSION {
			return Err(ProtocolDecodingError::invalid("unknown encoding version"));
		}
		Ok(Self {
			vtxo_id: ProtocolEncoding::decode(r)?,
			unlock_hash: ProtocolEncoding::decode(r)?,
			user_nonces: ProtocolEncoding::decode(r)?,
			forfeit_tx_part_sig: ProtocolEncoding::decode(r)?,
			forfeit_claim_tx_part_sig: ProtocolEncoding::decode(r)?,
		})
	}
}

#[inline]
pub fn create_connector_forfeit_tx(
	vtxo: &Vtxo,
	connector: OutPoint,
	forfeit_sig: Option<&schnorr::Signature>,
	connector_sig: Option<&schnorr::Signature>,
) -> Transaction {
	Transaction {
		version: bitcoin::transaction::Version(3),
		lock_time: bitcoin::absolute::LockTime::ZERO,
		input: vec![
			TxIn {
				previous_output: vtxo.point(),
				sequence: Sequence::ZERO,
				script_sig: ScriptBuf::new(),
				witness: forfeit_sig.map(|s| Witness::from_slice(&[&s[..]])).unwrap_or_default(),
			},
			TxIn {
				previous_output: connector,
				sequence: Sequence::ZERO,
				script_sig: ScriptBuf::new(),
				witness: connector_sig.map(|s| Witness::from_slice(&[&s[..]])).unwrap_or_default(),
			},
		],
		output: vec![
			TxOut {
				value: vtxo.amount(),
				script_pubkey: ScriptBuf::new_p2tr(&SECP, vtxo.server_pubkey().into(), None),
			},
			// We throw the connector dust value into the fee anchor
			// because we can't have zero-value anchors and a non-zero fee.
			fee::fee_anchor_with_amount(P2TR_DUST),
		],
	}
}

#[inline]
fn connector_forfeit_input_sighash(
	vtxo: &Vtxo,
	connector: OutPoint,
	connector_pk: PublicKey,
	input_idx: usize,
) -> (TapSighash, Transaction) {
	let exit_prevout = vtxo.txout();
	let connector_prevout = TxOut {
		script_pubkey: ConnectorChain::output_script(connector_pk),
		value: P2TR_DUST,
	};
	let tx = create_connector_forfeit_tx(vtxo, connector, None, None);
	let sighash = SighashCache::new(&tx).taproot_key_spend_signature_hash(
		input_idx,
		&sighash::Prevouts::All(&[exit_prevout, connector_prevout]),
		TapSighashType::Default,
	).expect("sighash error");
	(sighash, tx)
}

/// The sighash of the exit tx input of a forfeit tx.
#[inline]
pub fn connector_forfeit_sighash_exit(
	vtxo: &Vtxo,
	connector: OutPoint,
	connector_pk: PublicKey,
) -> (TapSighash, Transaction) {
	connector_forfeit_input_sighash(vtxo, connector, connector_pk, 0)
}

/// The sighash of the connector input of a forfeit tx.
#[inline]
pub fn connector_forfeit_sighash_connector(
	vtxo: &Vtxo,
	connector: OutPoint,
	connector_pk: PublicKey,
) -> (TapSighash, Transaction) {
	connector_forfeit_input_sighash(vtxo, connector, connector_pk, 1)
}

#[cfg(test)]
mod test {
	use bitcoin::hex::{DisplayHex, FromHex};
	use crate::{test::verify_tx, vtxo::test::VTXO_VECTORS};
	use super::*;

	fn verify_hark_forfeits(
		vtxo: &Vtxo,
		unlock_preimage: UnlockPreimage,
		server_sec_nonces: [musig::SecretNonce; 2],
		server_pub_nonces: &HashLockedForfeitNonces,
		bundle: HashLockedForfeitBundle,
	) {
		let unlock_hash = UnlockHash::hash(&unlock_preimage);
		assert_eq!(Ok(()), bundle.verify(vtxo, server_pub_nonces));

		// finish it which triggers debug asserts on partial sigs
		let sigs = bundle.finish(vtxo, server_pub_nonces, server_sec_nonces, &VTXO_VECTORS.server_key);

		let (ff_sighash, ff_tx) = hark_forfeit_sighash(vtxo, unlock_hash);
		SECP.verify_schnorr(
			&sigs[0],
			&ff_sighash.into(),
			&vtxo.output_taproot().output_key().to_x_only_public_key(),
		).expect("forfeit tx sig check failed");
		let ff_point = OutPoint::new(ff_tx.compute_txid(), 0);
		let claim_taproot = hark_forfeit_claim_taproot(vtxo, unlock_hash);
		let (claim_sighash, _tx) = hark_forfeit_claim_sighash(vtxo, ff_point, unlock_hash);
		SECP.verify_schnorr(
			&sigs[1],
			&claim_sighash.into(),
			&claim_taproot.internal_key(),
		).expect("forfeit claim tx sig check failed");

		// validate the actual txs
		let ff_input = vtxo.txout();
		let ff_tx = create_hark_forfeit_tx(vtxo, unlock_hash, Some(&sigs[0]));
		verify_tx(&[ff_input], 0, &ff_tx).expect("forfeit tx error");
		assert_eq!(ff_tx.compute_txid(), ff_point.txid);

		let claim_input = ff_tx.output[0].clone();
		let claim_tx = create_hark_forfeit_claim_tx(
			vtxo, ff_point, unlock_hash, Some((&sigs[1], unlock_preimage)),
		);
		verify_tx(&[claim_input], 0, &claim_tx).expect("claim tx error");
	}

	#[test]
	fn test_hark_forfeits() {
		let server_ff_nonces = musig::nonce_pair(&VTXO_VECTORS.server_key);
		let server_claim_nonces = musig::nonce_pair(&VTXO_VECTORS.server_key);
		// we need to go through some hoops to print the secret nonces
		let server_ff_sec_bytes = server_ff_nonces.0.dangerous_into_bytes();
		let server_claim_sec_bytes = server_claim_nonces.0.dangerous_into_bytes();
		println!("server ff sec nonce: {}", server_ff_sec_bytes.as_hex());
		println!("server claim sec nonce: {}", server_claim_sec_bytes.as_hex());
		let server_sec_nonces = [
			musig::SecretNonce::dangerous_from_bytes(server_ff_sec_bytes),
			musig::SecretNonce::dangerous_from_bytes(server_claim_sec_bytes),
		];
		let server_nonces = HashLockedForfeitNonces {
			forfeit_tx_nonce: server_ff_nonces.1,
			forfeit_claim_tx_nonce: server_claim_nonces.1,
		};
		println!("server pub nonces: {}", server_nonces.serialize_hex());

		let vtxo = &VTXO_VECTORS.arkoor3_vtxo;
		let unlock_preimage = UnlockPreimage::from_hex("c65f29e65dbc6cbad3e7f35c41986487c74ed513aeb37778354d42f3b0714645").unwrap();
		let unlock_hash = UnlockHash::hash(&unlock_preimage);
		let bundle = HashLockedForfeitBundle::forfeit_vtxo(
			vtxo,
			unlock_hash,
			&VTXO_VECTORS.arkoor3_user_key,
			&server_nonces,
		);

		// test encoding round trip
		let encoded = bundle.serialize();
		println!("bundle: {}", encoded.as_hex());
		let decoded = HashLockedForfeitBundle::deserialize(&encoded).unwrap();
		assert_eq!(bundle, decoded);
		let bundle = decoded;

		println!("verifying generated forfeits");
		verify_hark_forfeits(
			vtxo, unlock_preimage, server_sec_nonces, &server_nonces, bundle.clone(),
		);

		let (_sec, bad_nonce) = musig::nonce_pair(&VTXO_VECTORS.server_key);
		assert_eq!(
			bundle.verify(vtxo, &HashLockedForfeitNonces {
				forfeit_tx_nonce: server_nonces.forfeit_tx_nonce,
				forfeit_claim_tx_nonce: bad_nonce,
			}),
			Err("invalid partial sig for forfeit claim tx"),
		);
		assert_eq!(
			bundle.verify(vtxo, &HashLockedForfeitNonces {
				forfeit_tx_nonce: bad_nonce,
				forfeit_claim_tx_nonce: server_nonces.forfeit_claim_tx_nonce,
			}),
			Err("invalid partial sig for forfeit tx"),
		);


		// verify a hard-coded example from a previous run of this test
		let server_sec_nonces = [
			musig::SecretNonce::dangerous_from_bytes(FromHex::from_hex("220edcf1da44b6cc84c3c65258e6ed9c8d2c55550e9f6609b6193343b16f13ab6f63adc9d562325233121e80861822c63f408895e78a2f1ed0fedd7c1ffdc3fea4240c8c622bf70a8243580d1879746ffe940588c5ad9d478d1b46e2bb9318743312a8657f684b47f963f7a0e95927b2c71005112d8edc5821a3f6f0f7bd6354947ff8ac").unwrap()),
			musig::SecretNonce::dangerous_from_bytes(FromHex::from_hex("220edcf1e588918982400caaf3aeef938bb1e2347ca666bd69ca150fc87fc6fdd536a4f574addbb6924d46214f0e1ba6e89a30360d0f8ea6d521cc778758aa90ed7c28e7622bf70a8243580d1879746ffe940588c5ad9d478d1b46e2bb9318743312a8657f684b47f963f7a0e95927b2c71005112d8edc5821a3f6f0f7bd6354947ff8ac").unwrap()),
		];
		let server_nonces = HashLockedForfeitNonces::deserialize_hex("030ca8be9e96f5ae3625b61c31d548243ef3b3bba7dd7e578118eaee24c273c8e20329b9def95225f95618972590dac83154b0b21d1b1eccf1988e923e12d2f926e102c465f28ddc1f864686d897be9fc3a4476fec1a43c359509bea8bd70ddbd4b6f3035dd60b80b10401fbc2457dbad40451ce6f67c38b0fa9ef805b92d2f3256d8df4").unwrap();
		let bundle = HashLockedForfeitBundle::deserialize_hex("00016422a562a4826f26ff351ecb5b1122e0d27958053fd6595a9424a0305fad07000000003d5491373df6a016f78b3f46d65a4fc6948824c43a59620404e8719cfee05d1a02b35f8a030a5b7bbee5509390ae25165b713f6b99caf052f52d0d4711871f43d7032e97b05b0699059d162d335f5c5cc8a62b67e47ab73c396da4559b816bf76338025c210c3e6febfcaf673abc5310fbbd3c3e1bb33e5013e7798732fd67e89f3bcc02bf0437c4adccd3aa39189a21c862fddfd007c905d52f41d1794a8480bc78f9d42d824cd6825ec2ff4fd88b1a4eb963c284683ec93fe4992c788886393138f3f7b5cb2fa7368bb44f6a75f3721b33fe57734f1aa8ec3b3daf6c2151ad6d0103c9").unwrap();

		println!("verifying hard-coded forfeits");
		verify_hark_forfeits(vtxo, unlock_preimage, server_sec_nonces, &server_nonces, bundle);
	}
}

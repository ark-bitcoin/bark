

use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness};
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{schnorr, Keypair, PublicKey};
use bitcoin::sighash::{self, SighashCache, TapSighash, TapSighashType};
use bitcoin::taproot::{self, TaprootSpendInfo};

use bitcoin_ext::{fee, TaprootSpendInfoExt, P2TR_DUST};

use crate::vtxo::genesis::ArkoorGenesis;
use crate::{musig, ServerVtxo, ServerVtxoPolicy, Vtxo, VtxoId, SECP};
use crate::connectors::ConnectorChain;
use crate::encode::{ProtocolDecodingError, ProtocolEncoding, ReadExt, WriteExt};
use crate::tree::signed::{unlock_clause, UnlockHash};
use crate::vtxo::{exit_clause, GenesisItem, GenesisTransition};


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
		.add_leaf(1, unlock_clause(vtxo.server_pubkey().x_only_public_key().0, unlock_hash)).unwrap()
		.finalize(&SECP, agg_pk).unwrap()
}

/// Construct the forfeit tx in the hArk forfeit protocol
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

#[inline]
fn hark_forfeit_sighash(
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

/// Construct the internal VTXO that represents the forfeit output
///
/// The `forfeit_txid` argument is optional and will be calculated if not present.
#[inline]
fn build_internal_forfeit_vtxo(
	vtxo: &Vtxo,
	unlock_hash: UnlockHash,
	forfeit_tx_sig: schnorr::Signature,
	forfeit_txid: Option<Txid>,
) -> ServerVtxo {
	let ff_txid = forfeit_txid.unwrap_or_else(|| {
		create_hark_forfeit_tx(vtxo, unlock_hash, None).compute_txid()
	});
	debug_assert_eq!(ff_txid, create_hark_forfeit_tx(vtxo, unlock_hash, None).compute_txid());

	Vtxo {
		point: OutPoint::new(ff_txid, 0),
		policy: ServerVtxoPolicy::new_hark_forfeit(vtxo.user_pubkey(), unlock_hash),
		genesis: vtxo.genesis.iter().cloned().chain([
			GenesisItem {
				transition: GenesisTransition::Arkoor(ArkoorGenesis {
					client_cosigners: vec![vtxo.user_pubkey()],
					tap_tweak: vtxo.output_taproot().tap_tweak(),
					signature: Some(forfeit_tx_sig),
				}),
				output_idx: 0,
				other_outputs: vec![],
				fee_amount: Amount::ZERO,
			}
		]).collect(),

		amount: vtxo.amount,
		expiry_height: vtxo.expiry_height,
		server_pubkey: vtxo.server_pubkey,
		exit_delta: vtxo.exit_delta,
		anchor_point: vtxo.anchor_point,
	}
}

/// A bundle of a signature and metadata that forfeits a user's VTXO
/// conditional on the server revealing a secret preimage
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashLockedForfeitBundle {
	pub vtxo_id: VtxoId,
	pub unlock_hash: UnlockHash,
	pub user_nonce: musig::PublicNonce,
	/// User's partial signature on the forfeit tx
	pub part_sig: musig::PartialSignature,
}

impl HashLockedForfeitBundle {
	/// Create a new [HashLockedForfeitBundle] for the given VTXO
	///
	/// This is used to forfeit the VTXO to the server conditional on receiving
	/// the unlock preimage corresponding to the given unlock hash.
	pub fn new(
		vtxo: &Vtxo,
		unlock_hash: UnlockHash,
		user_key: &Keypair,
		server_nonce: &musig::PublicNonce,
	) -> Self {
		let vtxo_exit_taproot = vtxo.output_taproot();
		let (ff_sighash, _) = hark_forfeit_sighash(vtxo, unlock_hash);
		let (ff_sec_nonce, ff_pub_nonce) = musig::nonce_pair_with_msg(
			user_key, &ff_sighash.to_byte_array(),
		);
		let ff_agg_nonce = musig::nonce_agg(&[&ff_pub_nonce, &server_nonce]);
		let (ff_part_sig, _sig) = musig::partial_sign(
			[vtxo.user_pubkey(), vtxo.server_pubkey()],
			ff_agg_nonce,
			user_key,
			ff_sec_nonce,
			ff_sighash.to_byte_array(),
			Some(vtxo_exit_taproot.tap_tweak().to_byte_array()),
			None,
		);

		Self {
			vtxo_id: vtxo.id(),
			unlock_hash: unlock_hash,
			user_nonce: ff_pub_nonce,
			part_sig: ff_part_sig,
		}
	}

	/// Used by the server to verify if the partial signature in the bundle
	/// is valid
	pub fn verify(
		&self,
		vtxo: &Vtxo,
		server_nonce: &musig::PublicNonce,
	) -> Result<(), &'static str> {
		if vtxo.id() != self.vtxo_id {
			return Err("VTXO mismatch");
		}

		let ff_agg_nonce = musig::nonce_agg(
			&[&self.user_nonce, &server_nonce],
		);
		let vtxo_exit_taproot = vtxo.output_taproot();
		let (ff_sighash, _) = hark_forfeit_sighash(vtxo, self.unlock_hash);
		let (ff_key_agg, _) = musig::tweaked_key_agg(
			[vtxo.user_pubkey(), vtxo.server_pubkey()],
			vtxo_exit_taproot.tap_tweak().to_byte_array(),
		);
		let ff_session = musig::Session::new(
			&ff_key_agg,
			ff_agg_nonce,
			&ff_sighash.to_byte_array(),
		);
		let success = ff_session.partial_verify(
			&ff_key_agg, &self.part_sig, &self.user_nonce, musig::pubkey_to(vtxo.user_pubkey()),
		);
		if !success {
			return Err("invalid partial sig for forfeit tx");
		}
		Ok(())
	}

	/// Used by the server to finish the forfeit signature using its own
	/// nonce
	///
	/// NB users don't need to know this signature
	pub fn finish(
		&self,
		vtxo: &Vtxo,
		server_pub_nonce: &musig::PublicNonce,
		server_sec_nonce: musig::SecretNonce,
		server_key: &Keypair,
	) -> (schnorr::Signature, Transaction, ServerVtxo) {
		assert_eq!(vtxo.id(), self.vtxo_id);

		let ff_agg_nonce = musig::nonce_agg(
			&[&self.user_nonce, &server_pub_nonce],
		);
		let vtxo_exit_taproot = vtxo.output_taproot();
		let (ff_sighash, mut ff_tx) = hark_forfeit_sighash(vtxo, self.unlock_hash);
		let (_ff_part_sig, ff_sig) = musig::partial_sign(
			[vtxo.user_pubkey(), vtxo.server_pubkey()],
			ff_agg_nonce,
			server_key,
			server_sec_nonce,
			ff_sighash.to_byte_array(),
			Some(vtxo_exit_taproot.tap_tweak().to_byte_array()),
			Some(&[&self.part_sig]),
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
				&server_pub_nonce,
				musig::pubkey_to(vtxo.server_pubkey()),
			)
		});
		debug_assert_eq!(Ok(()), SECP.verify_schnorr(
			&ff_sig, &ff_sighash.into(), &vtxo_exit_taproot.output_key().to_x_only_public_key(),
		));

		// fill in the signature in the tx
		ff_tx.input[0].witness = Witness::from_slice(&[&ff_sig[..]]);
		debug_assert_eq!(ff_tx, create_hark_forfeit_tx(vtxo, self.unlock_hash, Some(&ff_sig)));

		let ff_txid = ff_tx.compute_txid();
		let ff_vtxo = build_internal_forfeit_vtxo(vtxo, self.unlock_hash, ff_sig, Some(ff_txid));

		(ff_sig, ff_tx, ff_vtxo)
	}
}

/// The serialization version of [HashLockedForfeitBundle].
const HASH_LOCKED_FORFEIT_BUNDLE_VERSION: u8 = 0x01;

impl ProtocolEncoding for HashLockedForfeitBundle {
	fn encode<W: std::io::Write + ?Sized>(&self, w: &mut W) -> Result<(), std::io::Error> {
		w.emit_u8(HASH_LOCKED_FORFEIT_BUNDLE_VERSION)?;
		self.vtxo_id.encode(w)?;
		self.unlock_hash.encode(w)?;
		self.user_nonce.encode(w)?;
		self.part_sig.encode(w)?;
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
			user_nonce: ProtocolEncoding::decode(r)?,
			part_sig: ProtocolEncoding::decode(r)?,
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
	use std::str::FromStr;
	use bitcoin::hex::{DisplayHex, FromHex};
	use crate::test_util::{verify_tx, VTXO_VECTORS};
	use crate::tree::signed::UnlockPreimage;
	use super::*;

	fn verify_hark_forfeits(
		vtxo: &Vtxo,
		unlock_preimage: UnlockPreimage,
		server_sec_nonce: musig::SecretNonce,
		server_pub_nonce: &musig::PublicNonce,
		bundle: HashLockedForfeitBundle,
	) {
		let unlock_hash = UnlockHash::hash(&unlock_preimage);
		assert_eq!(Ok(()), bundle.verify(vtxo, server_pub_nonce));

		// finish it which triggers debug asserts on partial sigs
		let (sig, tx, _vtxo) = bundle.finish(vtxo, server_pub_nonce, server_sec_nonce, &VTXO_VECTORS.server_key);

		let (ff_sighash, ff_tx) = hark_forfeit_sighash(vtxo, unlock_hash);
		SECP.verify_schnorr(
			&sig,
			&ff_sighash.into(),
			&vtxo.output_taproot().output_key().to_x_only_public_key(),
		).expect("forfeit tx sig check failed");
		let ff_point = OutPoint::new(ff_tx.compute_txid(), 0);

		// validate the actual txs
		let ff_input = vtxo.txout();
		let ff_tx_expected = create_hark_forfeit_tx(vtxo, unlock_hash, Some(&sig));
		assert_eq!(ff_tx_expected, tx);
		verify_tx(&[ff_input], 0, &ff_tx_expected).expect("forfeit tx error");
		assert_eq!(ff_tx_expected.compute_txid(), ff_point.txid);
	}

	#[test]
	fn test_hark_forfeits() {
		let (server_sec_nonce, server_pub_nonce) = musig::nonce_pair(&VTXO_VECTORS.server_key);
		// we need to go through some hoops to print the secret nonces
		let server_sec_bytes = server_sec_nonce.dangerous_into_bytes();
		println!("server ff sec nonce: {}", server_sec_bytes.as_hex());
		let server_sec_nonce = musig::SecretNonce::dangerous_from_bytes(server_sec_bytes);
		println!("server pub nonces: {}", server_pub_nonce.serialize_hex());

		let vtxo = &VTXO_VECTORS.arkoor3_vtxo;
		let unlock_preimage = UnlockPreimage::from_hex("c65f29e65dbc6cbad3e7f35c41986487c74ed513aeb37778354d42f3b0714645").unwrap();
		let unlock_hash = UnlockHash::hash(&unlock_preimage);
		let bundle = HashLockedForfeitBundle::new(
			vtxo,
			unlock_hash,
			&VTXO_VECTORS.arkoor3_user_key,
			&server_pub_nonce,
		);

		// test encoding round trip
		let encoded = bundle.serialize();
		println!("bundle: {}", encoded.as_hex());
		let decoded = HashLockedForfeitBundle::deserialize(&encoded).unwrap();
		assert_eq!(bundle, decoded);
		let bundle = decoded;

		println!("verifying generated forfeits");
		verify_hark_forfeits(
			vtxo, unlock_preimage, server_sec_nonce, &server_pub_nonce, bundle.clone(),
		);

		let (_sec, bad_nonce) = musig::nonce_pair(&VTXO_VECTORS.server_key);
		assert_eq!(
			bundle.verify(vtxo, &bad_nonce),
			Err("invalid partial sig for forfeit tx"),
		);


		// verify a hard-coded example from a previous run of this test
		let server_sec_nonce = musig::SecretNonce::dangerous_from_bytes(FromHex::from_hex(
			"220edcf12f794b5d53011980f30395d02c65805b7aac1e6e5c25e894b8554530c226cd931c096f6ee6fb3619f60ff9c1ff84d4e8df94204ca08ac77abd6a4cfc0f30609a622bf70a8243580d1879746ffe940588c5ad9d478d1b46e2bb9318743312a8657f684b47f963f7a0e95927b2c71005112d8edc5821a3f6f0f7bd6354947ff8ac",
		).unwrap());
		let server_pub_nonce = musig::PublicNonce::from_str("02856551afd4ccdc7f5748fb6b41a51837a95d7f239c2a4cabaa82a09c8f2a43bc038f0b2826a264f0bb12825e997abcb02c0ab6a6acbd96d4567abd57a75b68f9b9").unwrap();
		let bundle = HashLockedForfeitBundle::deserialize_hex("01016422a562a4826f26ff351ecb5b1122e0d27958053fd6595a9424a0305fad07000000003d5491373df6a016f78b3f46d65a4fc6948824c43a59620404e8719cfee05d1a02048e8b6aa30a6cd9fb8860b86c3cd9b0705769d049207dec0835056eee9e0857036f62d32ebcb8426ac8092a63f33dfb8bbe4e5ad8403f9b67d70bd326ee7a6e3120b75e5638f4d5fe4a47b0240293e045078da800ba4e24bd2d3b9879c6f534d6").unwrap();

		println!("verifying hard-coded forfeits");
		verify_hark_forfeits(vtxo, unlock_preimage, server_sec_nonce, &server_pub_nonce, bundle);
	}
}

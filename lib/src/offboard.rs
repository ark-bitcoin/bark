
use std::borrow::Borrow;

use bitcoin::hashes::Hash;
use bitcoin::{
	Amount, FeeRate, OutPoint, Script, ScriptBuf, Sequence, TapSighashType, Transaction, TxIn,
	TxOut, Weight, Witness,
};
use bitcoin::hex::DisplayHex;
use bitcoin::secp256k1::{Keypair, schnorr};
use bitcoin::sighash::{Prevouts, SighashCache};

use bitcoin_ext::{fee, KeypairExt, TxOutExt, P2TR_DUST};

use crate::connectors::construct_multi_connector_tx;
use crate::{musig, Vtxo, VtxoId, SECP};


/// The output index of the offboard output in the offboard tx
pub const OFFBOARD_TX_OFFBOARD_VOUT: usize = 0;
/// The output index of the connector output in the offboard tx
pub const OFFBOARD_TX_CONNECTOR_VOUT: usize = 1;


#[derive(Debug, Clone, PartialEq, Eq, Hash, thiserror::Error)]
#[error("invalid offboard request: {0}")]
pub struct InvalidOffboardRequestError(&'static str);

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
pub struct OffboardRequest {
	#[serde(with = "bitcoin_ext::serde::encodable")]
	pub script_pubkey: ScriptBuf,
	#[serde(rename = "amount_sat", with = "bitcoin::amount::serde::as_sat")]
	pub amount: Amount,
}

impl OffboardRequest {
	/// Calculate the fee we have to charge for adding an output
	/// with the given scriptPubkey to a transaction.
	///
	/// Use the `fixed_weight_charged` argument to add the fixed fee part that the
	/// server charges. This will be added to the offboard's output size
	/// and multiplied with the given fee rate.
	///
	/// Returns `None` in the calculation overflows because of insane
	/// scriptPubkey or fee rate.
	pub fn calculate_fee(
		script_pubkey: &Script,
		fee_rate: FeeRate,
		fixed_weight_charged: Weight,
	) -> Option<Amount> {
		let total = Weight::from_vb(script_pubkey.len() as u64)?
			.checked_add(fixed_weight_charged)?;
		Some(fee_rate.checked_mul_by_weight(total)?)
	}

	/// Validate that the offboard has a valid script.
	pub fn validate(&self) -> Result<(), InvalidOffboardRequestError> {
		if self.to_txout().is_standard() {
			Ok(())
		} else {
			Err(InvalidOffboardRequestError("non-standard output"))
		}
	}

	/// Convert into a tx output.
	pub fn to_txout(&self) -> TxOut {
		TxOut {
			script_pubkey: self.script_pubkey.clone(),
			value: self.amount,
		}
	}

	/// Returns the fee charged for the user to make this offboard given the fee rate
	///
	///
	/// Use the `fixed_weight_charged` argument to add the fixed fee part that the
	/// server charges. This will be added to the offboard's output size
	/// and multiplied with the given fee rate.
	///
	/// Returns `None` in the calculation overflows because of insane
	/// scriptPubkey or fee rate.
	pub fn fee(
		&self,
		fee_rate: FeeRate,
		fixed_weight_charged: Weight,
	) -> Option<Amount> {
		Self::calculate_fee(&self.script_pubkey, fee_rate, fixed_weight_charged)
	}
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, thiserror::Error)]
#[error("invalid offboard transaction: {0}")]
pub struct InvalidOffboardTxError(String);

impl<S: Into<String>> From<S> for InvalidOffboardTxError {
	fn from(v: S) -> Self {
	    Self(v.into())
	}
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, thiserror::Error)]
#[error("invalid partial signature for VTXO {vtxo}")]
pub struct InvalidUserPartialSignatureError {
	pub vtxo: VtxoId,
}

pub struct OffboardForfeitSignatures {
	pub public_nonces: Vec<musig::PublicNonce>,
	pub partial_signatures: Vec<musig::PartialSignature>,
}

pub struct OffboardForfeitContext<'a, V> {
	input_vtxos: &'a [V],
	offboard_tx: &'a Transaction,
}

impl<'a, V> OffboardForfeitContext<'a, V>
where
	V: AsRef<Vtxo>,
{
	/// Create a new [OffboardForfeitContext] with given input VTXOs and offboard tx
	///
	/// Number of input VTXOs must not be zero.
	pub fn new(input_vtxos: &'a [V], offboard_tx: &'a Transaction) -> Self {
		assert_ne!(input_vtxos.len(), 0, "no input VTXOs");
		Self { input_vtxos, offboard_tx }
	}

	/// Validate offboard tx matches offboard request
	pub fn validate_offboard_tx(
		&self,
		req: &OffboardRequest,
	) -> Result<(), InvalidOffboardTxError> {
		let offb_txout = self.offboard_tx.output.get(OFFBOARD_TX_OFFBOARD_VOUT)
			.ok_or("missing offboard output")?;
		let exp_txout = req.to_txout();

		if exp_txout.script_pubkey != offb_txout.script_pubkey {
			return Err(format!(
				"offboard output scriptPubkey doesn't match: got={}, expected={}",
				offb_txout.script_pubkey.as_bytes().as_hex(),
				exp_txout.script_pubkey.as_bytes().as_hex(),
			).into());
		}
		if exp_txout.value != offb_txout.value {
			return Err(format!(
				"offboard output amount doesn't match: got={}, expected={}",
				offb_txout.value, exp_txout.value,
			).into());
		}

		// for the user we only need to check that there are enough connectors
		let conn_txout = self.offboard_tx.output.get(OFFBOARD_TX_CONNECTOR_VOUT)
			.ok_or("missing connector output")?;
		let required_conn_value = P2TR_DUST * self.input_vtxos.len() as u64;
		if conn_txout.value != required_conn_value {
			return Err(format!(
				"insufficient connector amount: got={}, need={}",
				conn_txout.value, required_conn_value,
			).into());
		}

		Ok(())
	}

	/// Sign forfeit transactions for all input VTXOs
	///
	/// Provide the keys for the VTXO pubkeys in order of the input VTXOs.
	///
	/// Panics if wrong number of keys or nonces, or if [Self::validate_offboard_tx]
	/// would have returned an error. The caller should call that method first.
	pub fn user_sign_forfeits(
		&self,
		keys: &[impl Borrow<Keypair>],
		server_nonces: &[musig::PublicNonce],
	) -> OffboardForfeitSignatures {
		assert_eq!(self.input_vtxos.len(), keys.len(), "wrong number of keys");
		assert_eq!(self.input_vtxos.len(), server_nonces.len(), "wrong number of nonces");
		assert_ne!(self.input_vtxos.len(), 0, "no inputs");

		let mut pub_nonces = Vec::with_capacity(self.input_vtxos.len());
		let mut part_sigs = Vec::with_capacity(self.input_vtxos.len());
		let offboard_txid = self.offboard_tx.compute_txid();
		let connector_prev = OutPoint::new(offboard_txid, OFFBOARD_TX_CONNECTOR_VOUT as u32);
		let connector_txout = self.offboard_tx.output.get(OFFBOARD_TX_CONNECTOR_VOUT)
			.expect("invalid offboard tx");

		if self.input_vtxos.len() == 1 {
			let (nonce, sig) = user_sign_vtxo_forfeit_input(
				self.input_vtxos[0].as_ref(),
				keys[0].borrow(),
				connector_prev,
				connector_txout,
				&server_nonces[0],
			);
			pub_nonces.push(nonce);
			part_sigs.push(sig);
		} else {
			// here we will create a deterministic intermediate connector tx and
			// sign forfeit txs with the outputs of that tx

			let connector_tx = construct_multi_connector_tx(
				connector_prev, self.input_vtxos.len(), &connector_txout.script_pubkey,
			);
			let connector_txid = connector_tx.compute_txid();

			// NB all connector txouts are identical, we copy the one from the offboard tx
			let iter = self.input_vtxos.iter().zip(keys).zip(server_nonces);
			for (i, ((vtxo, key), server_nonce)) in iter.enumerate() {
				let connector = OutPoint::new(connector_txid, i as u32);
				let (nonce, sig) = user_sign_vtxo_forfeit_input(
					vtxo.as_ref(), key.borrow(), connector, connector_txout, server_nonce,
				);
				pub_nonces.push(nonce);
				part_sigs.push(sig);
			}
		}

		OffboardForfeitSignatures {
			public_nonces: pub_nonces,
			partial_signatures: part_sigs,
		}
	}

	/// Check the user's partial signatures and finalize the forfeit txs
	///
	/// Panics if wrong number of secret nonces or partial signatures, or if [Self::validate_offboard_tx]
	/// would have returned an error. The caller should call that method first.
	pub fn check_finalize_transactions(
		&self,
		server_key: &Keypair,
		connector_key: &Keypair,
		server_pub_nonces: &[musig::PublicNonce],
		server_sec_nonces: Vec<musig::SecretNonce>,
		user_pub_nonces: &[musig::PublicNonce],
		user_partial_sigs: &[musig::PartialSignature],
	) -> Result<Vec<Transaction>, InvalidUserPartialSignatureError> {
		assert_eq!(self.input_vtxos.len(), server_pub_nonces.len());
		assert_eq!(self.input_vtxos.len(), server_sec_nonces.len());
		assert_eq!(self.input_vtxos.len(), user_pub_nonces.len());
		assert_eq!(self.input_vtxos.len(), user_partial_sigs.len());
		assert_ne!(self.input_vtxos.len(), 0, "no inputs");

		let offboard_txid = self.offboard_tx.compute_txid();
		let connector_prev = OutPoint::new(offboard_txid, OFFBOARD_TX_CONNECTOR_VOUT as u32);
		let connector_txout = self.offboard_tx.output.get(OFFBOARD_TX_CONNECTOR_VOUT)
			.expect("invalid offboard tx");
		let tweaked_connector_key = connector_key.for_keyspend(&*SECP);

		let mut ret = Vec::with_capacity(self.input_vtxos.len());
		if self.input_vtxos.len() == 1 {
			let vtxo = self.input_vtxos[0].as_ref();
			let tx = server_check_finalize_forfeit_tx(
				vtxo,
				server_key,
				&tweaked_connector_key,
				connector_prev,
				connector_txout,
				(&server_pub_nonces[0], server_sec_nonces.into_iter().next().unwrap()),
				&user_pub_nonces[0],
				&user_partial_sigs[0],
			).ok_or_else(|| InvalidUserPartialSignatureError { vtxo: vtxo.id() })?;
			ret.push(tx);
		} else {
			// here we will create a deterministic intermediate connector tx and
			// sign forfeit txs with the outputs of that tx

			let connector_tx = construct_multi_connector_tx(
				connector_prev, self.input_vtxos.len(), &connector_txout.script_pubkey,
			);
			let connector_txid = connector_tx.compute_txid();

			// NB all connector txouts are identical, we copy the one from the offboard tx
			let iter = self.input_vtxos.iter()
				.zip(server_pub_nonces)
				.zip(server_sec_nonces)
				.zip(user_pub_nonces)
				.zip(user_partial_sigs);
			for (i, ((((vtxo, server_pub), server_sec), user_pub), user_part)) in iter.enumerate() {
				let connector = OutPoint::new(connector_txid, i as u32);
				match server_check_finalize_forfeit_tx(
					vtxo.as_ref(),
					server_key,
					&tweaked_connector_key,
					connector,
					connector_txout,
					(server_pub, server_sec),
					user_pub,
					user_part,
				) {
					Some(tx) => ret.push(tx),
					None => return Err(InvalidUserPartialSignatureError {
						vtxo: vtxo.as_ref().id(),
					}),
				}
			}
		}

		Ok(ret)
	}
}

fn user_sign_vtxo_forfeit_input(
	vtxo: &Vtxo,
	key: &Keypair,
	connector: OutPoint,
	connector_txout: &TxOut,
	server_nonce: &musig::PublicNonce,
) -> (musig::PublicNonce, musig::PartialSignature) {
	let tx = create_offboard_forfeit_tx(vtxo, connector, None, None);
	let mut shc = SighashCache::new(&tx);
	let prevouts = [&vtxo.txout(), &connector_txout];
	let sighash = shc.taproot_key_spend_signature_hash(
		0, &Prevouts::All(&prevouts), TapSighashType::Default,
	).expect("provided all prevouts");
	let tweak = vtxo.output_taproot().tap_tweak().to_byte_array();
	let (pub_nonce, partial_sig) = musig::deterministic_partial_sign(
		key,
		[vtxo.server_pubkey()],
		&[server_nonce],
		sighash.to_byte_array(),
		Some(tweak),
	);
	debug_assert!({
		let (key_agg, _) = musig::tweaked_key_agg(
			[vtxo.user_pubkey(), vtxo.server_pubkey()], tweak,
		);
		let agg_nonce = musig::nonce_agg(&[&pub_nonce, server_nonce]);
		let ff_session = musig::Session::new(
			&key_agg,
			agg_nonce,
			&sighash.to_byte_array(),
		);
		ff_session.partial_verify(
			&key_agg,
			&partial_sig,
			&pub_nonce,
			musig::pubkey_to(vtxo.user_pubkey()),
		)
	}, "invalid partial offboard forfeit signature");

	(pub_nonce, partial_sig)
}

/// Check the user's partial signature, then finalize the forfeit tx
///
/// Returns `None` only if the user's partial signature is invalid.
fn server_check_finalize_forfeit_tx(
	vtxo: &Vtxo,
	server_key: &Keypair,
	tweaked_connector_key: &Keypair,
	connector: OutPoint,
	connector_txout: &TxOut,
	server_nonces: (&musig::PublicNonce, musig::SecretNonce),
	user_nonce: &musig::PublicNonce,
	user_partial_sig: &musig::PartialSignature,
) -> Option<Transaction> {
	let mut tx = create_offboard_forfeit_tx(vtxo, connector, None, None);
	let mut shc = SighashCache::new(&tx);
	let prevouts = [&vtxo.txout(), &connector_txout];
	let vtxo_sig = {
		let sighash = shc.taproot_key_spend_signature_hash(
			0, &Prevouts::All(&prevouts), TapSighashType::Default,
		).expect("provided all prevouts");
		let vtxo_taproot = vtxo.output_taproot();
		let tweak = vtxo_taproot.tap_tweak().to_byte_array();
		let agg_nonce = musig::nonce_agg(&[user_nonce, server_nonces.0]);

		// NB it is cheaper to check final schnorr signature than partial sig, so
		// it is customary to do that insted

		let (_our_part_sig, final_sig) = musig::partial_sign(
			[vtxo.user_pubkey(), vtxo.server_pubkey()],
			agg_nonce,
			server_key,
			server_nonces.1,
			sighash.to_byte_array(),
			Some(tweak),
			Some(&[user_partial_sig]),
		);
		debug_assert!({
			let (key_agg, _) = musig::tweaked_key_agg(
				[vtxo.user_pubkey(), vtxo.server_pubkey()], tweak,
			);
			let ff_session = musig::Session::new(
				&key_agg,
				agg_nonce,
				&sighash.to_byte_array(),
			);
			ff_session.partial_verify(
				&key_agg,
				&_our_part_sig,
				server_nonces.0,
				musig::pubkey_to(vtxo.server_pubkey()),
			)
		}, "invalid partial offboard forfeit signature");
		let final_sig = final_sig.expect("we provided other sigs");
		SECP.verify_schnorr(
			&final_sig, &sighash.into(), vtxo_taproot.output_key().as_x_only_public_key(),
		).ok()?;
		final_sig
	};

	let conn_sig = {
		let sighash = shc.taproot_key_spend_signature_hash(
			1, &Prevouts::All(&prevouts), TapSighashType::Default,
		).expect("provided all prevouts");
		SECP.sign_schnorr_with_aux_rand(&sighash.into(), tweaked_connector_key, &rand::random())
	};

	tx.input[0].witness = Witness::from_slice(&[&vtxo_sig[..]]);
	tx.input[1].witness = Witness::from_slice(&[&conn_sig[..]]);
	debug_assert_eq!(tx,
		create_offboard_forfeit_tx(vtxo, connector, Some(&vtxo_sig), Some(&conn_sig)),
	);

	#[cfg(test)]
	{
		let prevs = [vtxo.txout(), connector_txout.clone()];
		if let Err(e) = crate::test::verify_tx(&prevs, 0, &tx) {
			println!("forfeit tx for VTXO {} failed: {}", vtxo.id(), e);
			panic!("forfeit tx for VTXO {} failed: {}", vtxo.id(), e);
		}
	}

	Some(tx)
}

fn create_offboard_forfeit_tx(
	vtxo: &Vtxo,
	connector: OutPoint,
	vtxo_sig: Option<&schnorr::Signature>,
	conn_sig: Option<&schnorr::Signature>,
) -> Transaction {
	Transaction {
		version: bitcoin::transaction::Version(3),
		lock_time: bitcoin::absolute::LockTime::ZERO,
		input: vec![
			TxIn {
				previous_output: vtxo.point(),
				sequence: Sequence::MAX,
				script_sig: ScriptBuf::new(),
				witness: vtxo_sig.map(|s| Witness::from_slice(&[&s[..]])).unwrap_or_default(),
			},
			TxIn {
				previous_output: connector,
				sequence: Sequence::MAX,
				script_sig: ScriptBuf::new(),
				witness: conn_sig.map(|s| Witness::from_slice(&[&s[..]])).unwrap_or_default(),
			},
		],
		output: vec![
			TxOut {
				// also accumulate the connector dust
				value: vtxo.amount() + P2TR_DUST,
				script_pubkey: ScriptBuf::new_p2tr(
					&*SECP, vtxo.server_pubkey().x_only_public_key().0, None,
				),
			},
			fee::fee_anchor(),
		],
	}
}

#[cfg(test)]
mod test {
	use std::str::FromStr;
	use bitcoin::hex::FromHex;
	use bitcoin::secp256k1::PublicKey;
	use crate::test::dummy::{random_utxo, DummyTestVtxoSpec};
	use super::*;

	#[test]
	fn test_offboard_forfeit() {
		let server_key = Keypair::new(&*SECP, &mut bitcoin::secp256k1::rand::thread_rng());

		let req_pk = PublicKey::from_str(
			"02271fba79f590251099b07fa0393b4c55d5e50cd8fca2e2822b619f8aabf93b74",
		).unwrap();
		let req = OffboardRequest {
			script_pubkey: ScriptBuf::new_p2tr(&*SECP, req_pk.x_only_public_key().0, None),
			amount: Amount::ONE_BTC,
		};

		let input1_key = Keypair::new(&*SECP, &mut bitcoin::secp256k1::rand::thread_rng());
		let (_, input1) = DummyTestVtxoSpec {
			user_keypair: input1_key,
			server_keypair: server_key,
			..Default::default()
		}.build();
		let input2_key = Keypair::new(&*SECP, &mut bitcoin::secp256k1::rand::thread_rng());
		let (_, input2) = DummyTestVtxoSpec {
			user_keypair: input2_key,
			server_keypair: server_key,
			..Default::default()
		}.build();

		let conn_key = Keypair::new(&*SECP, &mut bitcoin::secp256k1::rand::thread_rng());
		let conn_spk = ScriptBuf::new_p2tr(
			&*SECP, conn_key.public_key().x_only_public_key().0, None,
		);

		let change_amt = Amount::ONE_BTC * 2;
		let offboard_tx = Transaction {
			version: bitcoin::transaction::Version(3),
			lock_time: bitcoin::absolute::LockTime::ZERO,
			input: vec![
				TxIn {
					previous_output: random_utxo(),
					sequence: Sequence::MAX,
					script_sig: ScriptBuf::new(),
					witness: Witness::new(),
				},
			],
			output: vec![
				// the delivery goes first
				req.to_txout(),
				// then a connector
				TxOut {
					script_pubkey: conn_spk.clone(),
					value: P2TR_DUST * 2,
				},
				// then maybe change
				TxOut {
					script_pubkey: ScriptBuf::from_bytes(Vec::<u8>::from_hex(
						"512077243a077f583b197d36caac516b0c7e4319c7b6a2316c25972f44dfbf20fd09"
					).unwrap()),
					value: change_amt,
				},
			],
		};

		let inputs = [&input1, &input2];
		let ctx = OffboardForfeitContext::new(&inputs, &offboard_tx);
		ctx.validate_offboard_tx(&req).unwrap();

		let (server_sec_nonces, server_pub_nonces) = (0..2).map(|_| {
			musig::nonce_pair(&server_key)
		}).collect::<(Vec<_>, Vec<_>)>();

		let user_sigs = ctx.user_sign_forfeits(&[&input1_key, &input2_key], &server_pub_nonces);

		ctx.check_finalize_transactions(
			&server_key,
			&conn_key,
			&server_pub_nonces,
			server_sec_nonces,
			&user_sigs.public_nonces,
			&user_sigs.partial_signatures,
		).unwrap();
	}
}

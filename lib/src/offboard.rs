//!
//! # Offboard mechanism using connector-swaps
//!
//!
//! ## Connector VTXOs
//!
//! Connector outputs are plain key-spend p2tr outputs for the server key, so
//! the watchman can sweep their dust once they are no longer needed. We create
//! internal "ServerVtxo"s for them. Because they must not be swept before they
//! are no longer required (i.e. when the input VTXO expires) — spending a
//! connector invalidates the forfeit tx it belongs to, forgoing the full input
//! VTXO amount, not just the dust — we use the expiry height on the VTXO to
//! indicate when they can be swept.
//!

use std::borrow::Borrow;

use bitcoin::{
	Amount, FeeRate, OutPoint, ScriptBuf, Sequence, TapSighashType, Transaction, TxIn, TxOut, Txid,
	Witness,
};
use bitcoin::hashes::Hash;
use bitcoin::hex::DisplayHex;
use bitcoin::secp256k1::{schnorr, Keypair, PublicKey};
use bitcoin::sighash::{Prevouts, SighashCache};

use bitcoin_ext::{fee, BlockDelta, BlockHeight, KeypairExt, NonStandardOutput, TxOutExt, P2TR_DUST};

use crate::{musig, ServerVtxo, ServerVtxoPolicy, Vtxo, VtxoId, SECP};
use crate::connectors::construct_multi_connector_fanout_tx;
use crate::vtxo::{Bare, Full};


/// The output index of the offboard output in the offboard tx
pub const OFFBOARD_TX_OFFBOARD_VOUT: usize = 0;
/// The output index of the connector output in the offboard tx
pub const OFFBOARD_TX_CONNECTOR_VOUT: usize = 1;

/// Additional number of blocks after the input VTXO expiry we wait to sweep connectors
const CONNECTOR_EXPIRY_DELTA: BlockDelta = 144;


#[derive(Debug, Clone, PartialEq, Eq, Hash, thiserror::Error)]
#[error("invalid offboard request: {0}")]
pub struct InvalidOffboardRequestError(String);

impl From<NonStandardOutput> for InvalidOffboardRequestError {
	fn from(err: NonStandardOutput) -> Self {
		Self(format!("{:#}", err))
	}
}

/// Contains information regarding an offboard that a client would like to perform.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
pub struct OffboardRequest {
	/// The destination for the [TxOut].
	#[serde(with = "bitcoin_ext::serde::encodable")]
	pub script_pubkey: ScriptBuf,
	/// The target amount in sats.
	#[serde(rename = "amount_sat", with = "bitcoin::amount::serde::as_sat")]
	pub net_amount: Amount,
	/// Determines whether fees should be added onto the given amount or deducted from the gross
	/// amount.
	pub deduct_fees_from_gross_amount: bool,
	/// What fee rate was used when calculating the fee for the offboard.
	#[serde(rename = "fee_rate_kwu")]
	pub fee_rate: FeeRate,
}

impl OffboardRequest {
	/// Validate that the offboard has a valid script.
	pub fn validate(&self) -> Result<(), InvalidOffboardRequestError> {
		Ok(self.to_txout().check_standard()?)
	}

	/// Convert into a tx output.
	pub fn to_txout(&self) -> TxOut {
		TxOut {
			script_pubkey: self.script_pubkey.clone(),
			value: self.net_amount,
		}
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

impl From<InvalidOffboardRequestError> for InvalidOffboardTxError {
	fn from(e: InvalidOffboardRequestError) -> Self {
		InvalidOffboardTxError(format!("invalid offboard request: {:#}", e))
	}
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, thiserror::Error)]
#[error("invalid partial signature for VTXO {vtxo}")]
pub struct InvalidUserPartialSignatureError {
	pub vtxo: VtxoId,
}

/// Something is wrong with what was handed to an [OffboardForfeitContext].
///
/// Every variant is a condition the counterparty can cause: a server picks
/// how many cosign nonces it sends and what offboard tx it builds, a client
/// picks how many nonces and partial signatures it sends. None of them may
/// panic, because the side rejecting a malformed message would be the side
/// that goes down.
#[derive(Debug, Clone, PartialEq, Eq, Hash, thiserror::Error)]
pub enum OffboardForfeitError {
	/// There is nothing to forfeit. Every offboard spends at least one VTXO.
	#[error("offboard has no input VTXOs")]
	NoInputs,
	/// A vector holding one entry per input VTXO has a different length.
	#[error("wrong number of {vector}: expected {expected}, received {received}")]
	WrongCount {
		/// Names the vector that was the wrong length.
		vector: &'static str,
		/// How many entries were needed: one per input VTXO.
		expected: usize,
		/// How many entries were actually supplied.
		received: usize,
	},
	/// The offboard tx has no connector output for the forfeits to spend.
	/// [OffboardForfeitContext::validate_offboard_tx] reports this in more
	/// detail; it shows up here only if that check was skipped.
	#[error("offboard tx has no connector output")]
	MissingConnectorOutput,
	#[error(transparent)]
	InvalidUserPartialSignature(#[from] InvalidUserPartialSignatureError),
}

impl OffboardForfeitError {
	/// Returns [Self::WrongCount] unless `received` is exactly `expected`.
	///
	/// `vector` names what was counted, for the error message.
	pub fn check_count(
		vector: &'static str,
		expected: usize,
		received: usize,
	) -> Result<(), OffboardForfeitError> {
		if expected == received {
			Ok(())
		} else {
			Err(OffboardForfeitError::WrongCount { vector, expected, received })
		}
	}
}

pub struct OffboardForfeitSignatures {
	pub public_nonces: Vec<musig::PublicNonce>,
	pub partial_signatures: Vec<musig::PartialSignature>,
}

pub struct OffboardForfeitResult {
	pub forfeit_txs: Vec<Transaction>,
	pub forfeit_vtxos: Vec<ServerVtxo>,
	pub connector_tx: Option<Transaction>,
	pub connector_vtxos: Vec<ServerVtxo>,
}

impl OffboardForfeitResult {
	pub fn spend_info<'a>(
		&'a self,
		inputs: impl Iterator<Item = VtxoId> + 'a,
		offboard_txid: Txid,
	) -> impl Iterator<Item = (VtxoId, Txid)> + 'a {
		// We need:
		// - each input vtxo spent by forfeit
		// for not single:
		// - connector root output spent by connector tx

		let vtxos_to_ff = inputs.zip(self.forfeit_txs.iter().map(|t| t.compute_txid()));

		let connector = if let Some(ref conn_tx) = self.connector_tx {
			Some((OutPoint::new(offboard_txid, 1).into(), conn_tx.compute_txid()))
		} else {
			None
		};

		vtxos_to_ff.chain(connector)
	}
}

pub struct OffboardForfeitContext<'a, V> {
	input_vtxos: &'a [V],
	offboard_tx: &'a Transaction,
}

/// Construction and validation work with any VTXO representation: they
/// only need the number of inputs, so the client can validate a prepared
/// offboard tx with bare wallet vtxos. Only signing and finishing need
/// the full form; those methods are bounded on `AsRef<Vtxo<Full>>` below.
impl<'a, V> OffboardForfeitContext<'a, V> {
	/// Create a new [OffboardForfeitContext] with given input VTXOs and offboard tx
	///
	/// Fails with [OffboardForfeitError::NoInputs] if there are no input
	/// VTXOs. Every other method relies on that, so this is the only place
	/// it has to be checked.
	pub fn new(
		input_vtxos: &'a [V],
		offboard_tx: &'a Transaction,
	) -> Result<Self, OffboardForfeitError> {
		if input_vtxos.is_empty() {
			return Err(OffboardForfeitError::NoInputs);
		}
		Ok(Self { input_vtxos, offboard_tx })
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
}

impl<'a, V> OffboardForfeitContext<'a, V>
where
	V: AsRef<Vtxo<Full>>,
{
	/// Sign forfeit transactions for all input VTXOs
	///
	/// Provide the keys for the VTXO pubkeys in order of the input VTXOs.
	///
	/// `server_nonces` comes from the server, so a wrong count is an error and
	/// not a panic: the caller can't keep a peer from sending a malformed
	/// response, only reject it.
	///
	/// Call [Self::validate_offboard_tx] first; it reports a malformed
	/// offboard tx in full detail, where this only names what it needed.
	pub fn user_sign_forfeits(
		&self,
		keys: &[impl Borrow<Keypair>],
		server_nonces: &[musig::PublicNonce],
	) -> Result<OffboardForfeitSignatures, OffboardForfeitError> {
		OffboardForfeitError::check_count("keys", self.input_vtxos.len(), keys.len())?;
		OffboardForfeitError::check_count(
			"forfeit cosign nonces", self.input_vtxos.len(), server_nonces.len(),
		)?;

		let mut pub_nonces = Vec::with_capacity(self.input_vtxos.len());
		let mut part_sigs = Vec::with_capacity(self.input_vtxos.len());
		let offboard_txid = self.offboard_tx.compute_txid();
		let connector_fanout_prev = OutPoint::new(offboard_txid, OFFBOARD_TX_CONNECTOR_VOUT as u32);
		let connector_fanout_txout = self.offboard_tx.output.get(OFFBOARD_TX_CONNECTOR_VOUT)
			.ok_or(OffboardForfeitError::MissingConnectorOutput)?;

		if self.input_vtxos.len() == 1 {
			let (nonce, sig) = user_sign_vtxo_forfeit_input(
				self.input_vtxos[0].as_ref(),
				keys[0].borrow(),
				connector_fanout_prev,
				connector_fanout_txout,
				&server_nonces[0],
			);
			pub_nonces.push(nonce);
			part_sigs.push(sig);
		} else {
			// here we will create a deterministic intermediate connector tx and
			// sign forfeit txs with the outputs of that tx

			let connector_tx = construct_multi_connector_fanout_tx(
				connector_fanout_prev,
				self.input_vtxos.len(),
				&connector_fanout_txout.script_pubkey,
			);
			let connector_txid = connector_tx.compute_txid();

			// The forfeit txs spend the connector tx's outputs, which carry a
			// single dust each; the offboard tx's connector output carries the
			// combined sum. The sighash commits to the prevout values, so we
			// must use the actual connector tx output here.
			let connector_txout = TxOut {
				script_pubkey: connector_fanout_txout.script_pubkey.clone(),
				value: P2TR_DUST,
			};
			let iter = self.input_vtxos.iter().zip(keys).zip(server_nonces);
			for (i, ((vtxo, key), server_nonce)) in iter.enumerate() {
				let connector = OutPoint::new(connector_txid, u32::try_from(i).expect("connector index fits in u32"));
				let (nonce, sig) = user_sign_vtxo_forfeit_input(
					vtxo.as_ref(), key.borrow(), connector, &connector_txout, server_nonce,
				);
				pub_nonces.push(nonce);
				part_sigs.push(sig);
			}
		}

		Ok(OffboardForfeitSignatures {
			public_nonces: pub_nonces,
			partial_signatures: part_sigs,
		})
	}

	/// Check the user's partial signatures and finalize the forfeit txs
	///
	/// `user_pub_nonces` and `user_partial_sigs` come from the user, so wrong
	/// counts are errors and not panics: the server has to be able to reject a
	/// malformed request without going down.
	///
	/// Call [Self::validate_offboard_tx] first; it reports a malformed
	/// offboard tx in full detail, where this only names what it needed.
	pub fn finish(
		&self,
		server_key: &Keypair,
		server_pub_nonces: &[musig::PublicNonce],
		server_sec_nonces: Vec<musig::SecretNonce>,
		user_pub_nonces: &[musig::PublicNonce],
		user_partial_sigs: &[musig::PartialSignature],
	) -> Result<OffboardForfeitResult, OffboardForfeitError> {
		let inputs = self.input_vtxos.len();
		OffboardForfeitError::check_count("server public nonces", inputs, server_pub_nonces.len())?;
		OffboardForfeitError::check_count("server secret nonces", inputs, server_sec_nonces.len())?;
		OffboardForfeitError::check_count("user public nonces", inputs, user_pub_nonces.len())?;
		OffboardForfeitError::check_count("user partial signatures", inputs, user_partial_sigs.len())?;

		let offboard_txid = self.offboard_tx.compute_txid();
		let connector_fanout_prev = OutPoint::new(offboard_txid, OFFBOARD_TX_CONNECTOR_VOUT as u32);
		let connector_fanout_txout = self.offboard_tx.output.get(OFFBOARD_TX_CONNECTOR_VOUT)
			.ok_or(OffboardForfeitError::MissingConnectorOutput)?;
		let tweaked_connector_key = server_key.for_keyspend_only(&*SECP);

		let mut ret = OffboardForfeitResult {
			forfeit_txs: Vec::with_capacity(self.input_vtxos.len()),
			forfeit_vtxos: Vec::with_capacity(self.input_vtxos.len()),
			connector_tx: None,
			connector_vtxos: Vec::new(),
		};

		if self.input_vtxos.len() == 1 {
			let vtxo = self.input_vtxos[0].as_ref();
			let tx = server_check_finalize_forfeit_tx(
				vtxo,
				server_key,
				&tweaked_connector_key,
				connector_fanout_prev,
				connector_fanout_txout,
				(&server_pub_nonces[0], server_sec_nonces.into_iter().next().unwrap()),
				&user_pub_nonces[0],
				&user_partial_sigs[0],
			).ok_or_else(|| InvalidUserPartialSignatureError { vtxo: vtxo.id() })?;
			ret.forfeit_vtxos = vec![construct_forfeit_vtxo(vtxo, &tx)];
			ret.forfeit_txs.push(tx);
			ret.connector_vtxos = vec![construct_connector_vtxo_single(vtxo, offboard_txid)];
		} else {
			// here we will create a deterministic intermediate connector tx and
			// sign forfeit txs with the outputs of that tx

			let connector_tx = {
				let mut tx = construct_multi_connector_fanout_tx(
					connector_fanout_prev,
					self.input_vtxos.len(),
					&connector_fanout_txout.script_pubkey,
				);

				// The connector fanout tx spends the offboard's connector output, a
				// key-path-only p2tr for the server key. Sign it; otherwise it would
				// be stored/broadcast with an empty witness and rejected by the mempool.
				let sighash = SighashCache::new(&tx).taproot_key_spend_signature_hash(
					0, &Prevouts::All(&[connector_fanout_txout]), TapSighashType::Default,
				).expect("provided the connector prevout");
				let sig = SECP.sign_schnorr_with_aux_rand(
					&sighash.into(), &tweaked_connector_key, &rand::random(),
				);
				tx.input[0].witness = Witness::from_slice(&[&sig[..]]);

				tx
			};
			let connector_txid = connector_tx.compute_txid();

			ret.connector_tx = Some(connector_tx);
			ret.connector_vtxos = Vec::with_capacity(self.input_vtxos.len().saturating_add(1));
			ret.connector_vtxos.push(construct_connector_vtxo_fanout_root(
				offboard_txid,
				self.input_vtxos.iter().map(|v| v.as_ref().expiry_height()).max().unwrap(),
				self.input_vtxos[0].as_ref().server_pubkey(), // should be the same, any will do
				self.input_vtxos.len(),
			));

			// The forfeit txs spend the connector tx's outputs, which carry a
			// single dust each; the offboard tx's connector output carries the
			// combined sum. The sighash commits to the prevout values, so we
			// must use the actual connector tx output here.
			let connector_txout = TxOut {
				script_pubkey: connector_fanout_txout.script_pubkey.clone(),
				value: P2TR_DUST,
			};
			let iter = self.input_vtxos.iter()
				.zip(server_pub_nonces)
				.zip(server_sec_nonces)
				.zip(user_pub_nonces)
				.zip(user_partial_sigs);
			for (i, ((((vtxo, server_pub), server_sec), user_pub), user_part)) in iter.enumerate() {
				let vtxo = vtxo.as_ref();
				let connector = OutPoint::new(connector_txid, u32::try_from(i).expect("connector index fits in u32"));
				let tx = server_check_finalize_forfeit_tx(
					vtxo,
					server_key,
					&tweaked_connector_key,
					connector,
					&connector_txout,
					(server_pub, server_sec),
					user_pub,
					user_part,
				).ok_or_else(|| InvalidUserPartialSignatureError { vtxo: vtxo.as_ref().id() })?;

				ret.forfeit_vtxos.push(construct_forfeit_vtxo(vtxo, &tx));
				ret.forfeit_txs.push(tx);
				ret.connector_vtxos.push(construct_connector_vtxo_fanout_leaf(
					vtxo, i, offboard_txid, connector_txid,
				));
			}
		}

		Ok(ret)
	}
}

fn construct_forfeit_vtxo<G>(
	input: &Vtxo<G>,
	forfeit_tx: &Transaction,
) -> ServerVtxo<Bare> {
	ServerVtxo {
		point: OutPoint::new(forfeit_tx.compute_txid(), 0),
		policy: ServerVtxoPolicy::ServerOwned,
		// the forfeit tx output accumulates the connector dust on
		// top of the input amount
		amount: forfeit_tx.output[0].value,
		anchor_point: input.anchor_point,
		server_pubkey: input.server_pubkey,
		expiry_height: input.expiry_height,
		exit_delta: input.exit_delta,
		genesis: Bare,
	}
}

/// Create the connector VTXO for the connector used to offboard a single VTXO
///
/// This connector is just a single 330 sat output on the offboard tx.
fn construct_connector_vtxo_single<G>(
	input: &Vtxo<G>,
	offboard_txid: Txid,
) -> ServerVtxo<Bare> {
	let point = OutPoint::new(offboard_txid, 1);
	ServerVtxo {
		// NB they are the same here because this VTXO goes straight onchain
		anchor_point: point.clone(),
		point: point,
		policy: ServerVtxoPolicy::ServerOwned,
		amount: P2TR_DUST,
		server_pubkey: input.server_pubkey,
		expiry_height: input.expiry_height.checked_add(CONNECTOR_EXPIRY_DELTA as u32)
			.expect("expiry_height + CONNECTOR_EXPIRY_DELTA fits in u32 by MAX_BLOCK_HEIGHT invariant"),
		exit_delta: 0,
		genesis: Bare,
	}
}

/// Create the connector VTXO for the fanout output into multi connector tx
///
/// This connector is the fanout output on the offboard tx and is spent by the fanout
/// tx that creates a connector for each input.
fn construct_connector_vtxo_fanout_root(
	offboard_txid: Txid,
	max_expiry_height: BlockHeight,
	server_pubkey: PublicKey,
	nb_vtxos: usize,
) -> ServerVtxo<Bare> {
	let point = OutPoint::new(offboard_txid, 1);
	ServerVtxo {
		// NB they are the same here because this VTXO goes straight onchain
		anchor_point: point.clone(),
		point: point,
		policy: ServerVtxoPolicy::ServerOwned,
		amount: P2TR_DUST.checked_mul(nb_vtxos as u64)
			.expect("P2TR_DUST * nb_vtxos fits in u64 by VTXO-count and dust bounds"),
		server_pubkey: server_pubkey,
		expiry_height: max_expiry_height.checked_add(CONNECTOR_EXPIRY_DELTA as u32)
			.expect("max_expiry_height + CONNECTOR_EXPIRY_DELTA fits in u32 by MAX_BLOCK_HEIGHT invariant"),
		exit_delta: 0,
		genesis: Bare,
	}
}

/// Create the connector VTXO on the connector fanout tx
///
/// This connector is an output of the connector fanout tx.
fn construct_connector_vtxo_fanout_leaf<G>(
	input: &Vtxo<G>,
	input_idx: usize,
	offboard_txid: Txid,
	connector_txid: Txid,
) -> ServerVtxo<Bare> {
	ServerVtxo {
		point: OutPoint::new(connector_txid, u32::try_from(input_idx).expect("input index fits in u32")),
		anchor_point: OutPoint::new(offboard_txid, 1),
		policy: ServerVtxoPolicy::ServerOwned,
		amount: P2TR_DUST,
		server_pubkey: input.server_pubkey,
		expiry_height: input.expiry_height.checked_add(CONNECTOR_EXPIRY_DELTA as u32)
			.expect("expiry_height + CONNECTOR_EXPIRY_DELTA fits in u32 by MAX_BLOCK_HEIGHT invariant"),
		exit_delta: 0,
		genesis: Bare,
	}
}

fn user_sign_vtxo_forfeit_input<G: Sync + Send>(
	vtxo: &Vtxo<G>,
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
fn server_check_finalize_forfeit_tx<G: Sync + Send>(
	vtxo: &Vtxo<G>,
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
		if let Err(e) = crate::test_util::verify_tx(&prevs, 0, &tx) {
			println!("forfeit tx for VTXO {} failed: {}", vtxo.id(), e);
			panic!("forfeit tx for VTXO {} failed: {}", vtxo.id(), e);
		}
	}

	Some(tx)
}

fn create_offboard_forfeit_tx<G: Sync + Send>(
	vtxo: &Vtxo<G>,
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
	use crate::test_util::dummy::{random_utxo, DummyTestVtxoSpec};
	use super::*;

	#[test]
	fn test_offboard_forfeit() {
		let server_key = Keypair::new(&*SECP, &mut bitcoin::secp256k1::rand::thread_rng());

		let req_pk = PublicKey::from_str(
			"02271fba79f590251099b07fa0393b4c55d5e50cd8fca2e2822b619f8aabf93b74",
		).unwrap();
		let req = OffboardRequest {
			script_pubkey: ScriptBuf::new_p2tr(&*SECP, req_pk.x_only_public_key().0, None),
			net_amount: Amount::ONE_BTC,
			deduct_fees_from_gross_amount: true,
			fee_rate: FeeRate::from_sat_per_kwu(100),
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

		// connectors pay a plain keyspend of the server key
		let conn_spk = ScriptBuf::new_p2tr(
			&*SECP, server_key.public_key().x_only_public_key().0, None,
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
		let ctx = OffboardForfeitContext::new(&inputs, &offboard_tx).unwrap();
		ctx.validate_offboard_tx(&req).unwrap();

		// An offboard with nothing to forfeit is refused at construction, so
		// no other method has to cope with it.
		assert_eq!(
			OffboardForfeitContext::new(&[] as &[&Vtxo<Full>], &offboard_tx).err(),
			Some(OffboardForfeitError::NoInputs),
		);

		let (server_sec_nonces, server_pub_nonces) = (0..2).map(|_| {
			musig::nonce_pair(&server_key)
		}).collect::<(Vec<_>, Vec<_>)>();

		let keys = [&input1_key, &input2_key];

		// A server that sends the wrong number of nonces is rejected, not
		// signed for: the caller must be able to survive a malformed response.
		assert_eq!(
			ctx.user_sign_forfeits(&keys, &server_pub_nonces[..1]).err(),
			Some(OffboardForfeitError::WrongCount {
				vector: "forfeit cosign nonces", expected: 2, received: 1,
			}),
		);
		assert_eq!(
			ctx.user_sign_forfeits(&keys, &[]).err(),
			Some(OffboardForfeitError::WrongCount {
				vector: "forfeit cosign nonces", expected: 2, received: 0,
			}),
		);

		let user_sigs = ctx.user_sign_forfeits(&keys, &server_pub_nonces).unwrap();

		// Same in the other direction: a user sending the wrong number of
		// partial signatures must not be able to take the server down.
		let (spare_sec_nonces, spare_pub_nonces) = (0..2).map(|_| {
			musig::nonce_pair(&server_key)
		}).collect::<(Vec<_>, Vec<_>)>();
		assert_eq!(
			ctx.finish(
				&server_key,
				&spare_pub_nonces,
				spare_sec_nonces,
				&user_sigs.public_nonces,
				&user_sigs.partial_signatures[..1],
			).err(),
			Some(OffboardForfeitError::WrongCount {
				vector: "user partial signatures", expected: 2, received: 1,
			}),
		);

		let result = ctx.finish(
			&server_key,
			&server_pub_nonces,
			server_sec_nonces,
			&user_sigs.public_nonces,
			&user_sigs.partial_signatures,
		).unwrap();

		// The forfeit txs must be valid against the prevouts that will actually
		// exist on-chain: each spends an output of the connector fanout tx,
		// which carries a single dust, not the combined fanout root output on
		// the offboard tx. Taproot sighashes commit to all prevout amounts, so
		// signing against the wrong value makes the forfeits consensus-invalid.
		let connector_tx = result.connector_tx.as_ref()
			.expect("multi-input offboard must have a connector fanout tx");
		let connector_txid = connector_tx.compute_txid();
		for (i, (vtxo, forfeit_tx)) in inputs.iter().zip(&result.forfeit_txs).enumerate() {
			assert_eq!(
				forfeit_tx.input[1].previous_output,
				OutPoint::new(connector_txid, i as u32),
				"forfeit tx {} doesn't spend its fanout connector", i,
			);
			let real_prevouts = [vtxo.txout(), connector_tx.output[i].clone()];
			crate::test_util::verify_tx(&real_prevouts, 0, forfeit_tx)
				.expect(&format!("forfeit tx {} vtxo input invalid against real connector prevout", i));
			crate::test_util::verify_tx(&real_prevouts, 1, forfeit_tx)
				.expect(&format!("forfeit tx {} connector input invalid against real connector prevout", i));

			// The recorded forfeit vtxo must describe the actual forfeit tx
			// output, or the watchman can never sweep it.
			assert_eq!(result.forfeit_vtxos[i].txout(), forfeit_tx.output[0],
				"forfeit vtxo {} doesn't match its forfeit tx output", i,
			);
		}
	}
}

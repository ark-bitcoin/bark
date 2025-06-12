//!
//! Board flow:
//!
//! * user creates a builder using [BoardBuilder::new]
//! * user creates the funding tx which pays to [BoardBuilder::funding_script_pubkey]
//! * user sets the funding output in [BoardBuilder::set_funding_utxo]
//! * user generates signing nonces using [BoardBuilder::generate_user_nonces]
//! * user sends all board info to the server
//! * server creates a builder using [BoardBuilder::new_for_cosign]
//! * server cosigns using [BoardBuilder::server_cosign] and sends cosign response to user
//! * user validates cosign response using [BoardBuilder::verify_partial_sig]
//! * user finishes the vtxos by cross-signing using [BoardBuilder::build_vtxo]

use std::marker::PhantomData;

use bitcoin::sighash::{self, SighashCache};
use bitcoin::taproot::TaprootSpendInfo;
use bitcoin::{taproot, Amount, OutPoint, ScriptBuf, TapSighash, Transaction, TxOut};
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{schnorr, Keypair, PublicKey};
use bitcoin_ext::{BlockHeight, TaprootSpendInfoExt};

use crate::{musig, Vtxo, VtxoId};
use crate::util::{self, SECP};
use crate::vtxo::{self, exit_taproot, VtxoSpec, VtxoSpkSpec};

use self::state::BuilderState;


/// The output index of the board vtxo in the board tx.
pub const BOARD_FUNDING_TX_VTXO_VOUT: u32 = 0;


/// The taproot info for the output of the board funding tx (i.e. the onchain tx
/// made by the user).
pub fn funding_taproot(
	user_pubkey: PublicKey,
	expiry_height: BlockHeight,
	asp_pubkey: PublicKey,
) -> taproot::TaprootSpendInfo {
	let expiry = util::timelock_sign(expiry_height, asp_pubkey.x_only_public_key().0);
	let combined_pubkey = musig::combine_keys([user_pubkey, asp_pubkey]);
	let ret = taproot::TaprootBuilder::new()
		.add_leaf(0, expiry).unwrap()
		.finalize(&util::SECP, combined_pubkey)
		.unwrap();
	debug_assert_eq!(
		ret.output_key().to_x_only_public_key(),
		musig::tweaked_key_agg(
			[user_pubkey, asp_pubkey], ret.tap_tweak().to_byte_array(),
		).1.x_only_public_key().0,
		"unexpected output key",
	);
	ret
}

fn exit_tx_sighash(
	prev_utxo: &TxOut,
	utxo: OutPoint,
	output: TxOut,
) -> (TapSighash, Transaction) {
	let exit_tx = vtxo::create_exit_tx(utxo, output, None);
	let sighash = SighashCache::new(&exit_tx).taproot_key_spend_signature_hash(
		0, &sighash::Prevouts::All(&[prev_utxo]), sighash::TapSighashType::Default,
	).expect("matching prevouts");
	(sighash, exit_tx)
}

/// Partial signature the server responds to a board request.
#[derive(Debug)]
pub struct BoardCosignResponse {
	pub pub_nonce: musig::MusigPubNonce,
	pub partial_signature: musig::MusigPartialSignature,
}

pub mod state {
	mod sealed {
		/// Just a trait to seal the BuilderState trait.
		pub trait Sealed {}
		impl Sealed for super::Preparing {}
		impl Sealed for super::CanGenerateNonces {}
		impl Sealed for super::ServerCanCosign {}
		impl Sealed for super::CanBuild {}
	}

	/// A marker trait used as a generic for [super::BoardBuilder].
	pub trait BuilderState: sealed::Sealed {}

	/// The user is preparing the board tx.
	pub struct Preparing;
	impl BuilderState for Preparing {}

	/// The UTXO that will be used to fund the board is known, so the
	/// user's signing nonces can be generated.
	pub struct CanGenerateNonces;
	impl BuilderState for CanGenerateNonces {}

	/// All the information for the server to cosign the VTXO is known.
	pub struct ServerCanCosign;
	impl BuilderState for ServerCanCosign {}

	/// The user is ready to build the VTXO as soon as it has
	/// a cosign response from the user.
	pub struct CanBuild;
	impl BuilderState for CanBuild {}

	/// Trait to capture all states that have sufficient information
	/// for either party to create signatures.
	pub trait CanSign: BuilderState {}
	impl CanSign for ServerCanCosign {}
	impl CanSign for CanBuild {}
}

/// A request for the server to cosign an onboard vtxo.
///
/// An object of this type is created by the user, sent to the server who will
/// cosign the request and return his partial signature (along with public nonce)
/// back to the user so that the user can finish the request and create a [Vtxo].
///
/// Currently you can only create VTXOs with [VtxoSpkSpec::Exit].
#[derive(Debug)]
pub struct BoardBuilder<S: BuilderState> {
	pub amount: Amount,
	pub user_pubkey: PublicKey,
	pub expiry_height: BlockHeight,
	pub asp_pubkey: PublicKey,
	pub exit_delta: u16,

	utxo: Option<OutPoint>,
	user_pub_nonce: Option<musig::MusigPubNonce>,
	user_sec_nonce: Option<musig::MusigSecNonce>,
	_state: PhantomData<S>,
}

impl<S: BuilderState> BoardBuilder<S> {
	/// The scriptPubkey to send the board funds to.
	pub fn funding_script_pubkey(&self) -> ScriptBuf {
		funding_taproot(self.user_pubkey, self.expiry_height, self.asp_pubkey).script_pubkey()
	}
}

impl BoardBuilder<state::Preparing> {
	/// Create a new builder to construct a board vtxo.
	///
	/// See module-level documentation for an overview of the board flow.
	pub fn new(
		amount: Amount,
		user_pubkey: PublicKey,
		expiry_height: BlockHeight,
		asp_pubkey: PublicKey,
		exit_delta: u16,
	) -> BoardBuilder<state::Preparing> {
		BoardBuilder {
			amount, user_pubkey, expiry_height, asp_pubkey, exit_delta,
			utxo: None,
			user_pub_nonce: None,
			user_sec_nonce: None,
			_state: PhantomData,
		}
	}

	/// Set the UTXO where the board will be funded.
	pub fn set_funding_utxo(self, utxo: OutPoint) -> BoardBuilder<state::CanGenerateNonces> {
		BoardBuilder {
			utxo: Some(utxo),
			// copy the rest
			amount: self.amount,
			user_pubkey: self.user_pubkey,
			expiry_height: self.expiry_height,
			asp_pubkey: self.asp_pubkey,
			exit_delta: self.exit_delta,
			user_pub_nonce: self.user_pub_nonce,
			user_sec_nonce: self.user_sec_nonce,
			_state: PhantomData,
		}
	}
}

impl BoardBuilder<state::CanGenerateNonces> {
	/// Generate user nonces.
	pub fn generate_user_nonces(self) -> BoardBuilder<state::CanBuild> {
		let funding_taproot = funding_taproot(self.user_pubkey, self.expiry_height, self.asp_pubkey);
		let funding_txout = TxOut {
			script_pubkey: funding_taproot.script_pubkey(),
			value: self.amount,
		};

		let exit_taproot = exit_taproot(self.user_pubkey, self.asp_pubkey, self.exit_delta);
		let exit_txout = TxOut {
			value: self.amount,
			script_pubkey: exit_taproot.script_pubkey(),
		};

		let utxo = self.utxo.expect("state invariant");
		let (reveal_sighash, _tx) = exit_tx_sighash(&funding_txout, utxo, exit_txout);
		let (agg, _) = musig::tweaked_key_agg(
			[self.user_pubkey, self.asp_pubkey],
			funding_taproot.tap_tweak().to_byte_array(),
		);
		let (sec_nonce, pub_nonce) = agg.nonce_gen(
			&musig::SECP,
			musig::MusigSecRand::assume_unique_per_nonce_gen(rand::random()),
			musig::pubkey_to(self.user_pubkey),
			musig::secpm::Message::from_digest(reveal_sighash.to_byte_array()),
			None,
		).expect("non-zero session id");

		BoardBuilder {
			user_pub_nonce: Some(pub_nonce),
			user_sec_nonce: Some(sec_nonce),
			// copy the rest
			amount: self.amount,
			user_pubkey: self.user_pubkey,
			expiry_height: self.expiry_height,
			asp_pubkey: self.asp_pubkey,
			exit_delta: self.exit_delta,
			utxo: self.utxo,
			_state: PhantomData,
		}
	}
}

impl<S: state::CanSign> BoardBuilder<S> {
	pub fn user_pub_nonce(&self) -> musig::MusigPubNonce {
		self.user_pub_nonce.expect("state invariant")
	}

	/// The signature hash to sign the exit tx and the taproot info used to calcualte it.
	fn exit_tx_sighash_data(&self) -> (TapSighash, TaprootSpendInfo) {
		let funding_taproot = funding_taproot(
			self.user_pubkey, self.expiry_height, self.asp_pubkey,
		);
		let funding_txout = TxOut {
			value: self.amount,
			script_pubkey: funding_taproot.script_pubkey(),
		};

		let exit_taproot = exit_taproot(self.user_pubkey, self.asp_pubkey, self.exit_delta);
		let exit_txout = TxOut {
			value: self.amount,
			script_pubkey: exit_taproot.script_pubkey(),
		};

		let utxo = self.utxo.expect("state invariant");
		let (sighash, _tx) = exit_tx_sighash(&funding_txout, utxo, exit_txout);
		(sighash, funding_taproot)
	}
}

impl BoardBuilder<state::ServerCanCosign> {
	/// This constructor is to be used by the server with the information provided
	/// by the user.
	pub fn new_for_cosign(
		amount: Amount,
		user_pubkey: PublicKey,
		expiry_height: BlockHeight,
		asp_pubkey: PublicKey,
		exit_delta: u16,
		utxo: OutPoint,
		user_pub_nonce: musig::MusigPubNonce,
	) -> BoardBuilder<state::ServerCanCosign> {
		BoardBuilder {
			amount, user_pubkey, expiry_height, asp_pubkey, exit_delta,
			utxo: Some(utxo),
			user_pub_nonce: Some(user_pub_nonce),
			user_sec_nonce: None,
			_state: PhantomData,
		}
	}

	/// This method is used by the server to cosign the board request.
	///
	/// Returns `None` if utxo or user_pub_nonce field is not provided.
	pub fn server_cosign(&self, key: &Keypair) -> BoardCosignResponse {
		let (sighash, taproot) = self.exit_tx_sighash_data();
		let (pub_nonce, partial_signature) = musig::deterministic_partial_sign(
			key,
			[self.user_pubkey],
			&[&self.user_pub_nonce()],
			sighash.to_byte_array(),
			Some(taproot.tap_tweak().to_byte_array()),
		);
		BoardCosignResponse { pub_nonce, partial_signature }
	}
}

impl BoardBuilder<state::CanBuild> {
	/// Validate the server's partial signature.
	///
	/// Returns `None` if utxo or user_pub_nonce field is not provided.
	pub fn verify_partial_sig(
		&self,
		server_cosign: &BoardCosignResponse,
	) -> bool {
		let (sighash, taproot) = self.exit_tx_sighash_data();
		let agg_nonce = musig::nonce_agg(&[&self.user_pub_nonce(), &server_cosign.pub_nonce]);
		let agg_pk = musig::tweaked_key_agg(
			[self.user_pubkey, self.asp_pubkey],
			taproot.tap_tweak().to_byte_array(),
		).0;

		let session = musig::MusigSession::new(
			&musig::SECP,
			&agg_pk,
			agg_nonce,
			musig::secpm::Message::from_digest(sighash.to_byte_array()),
		);
		session.partial_verify(
			&musig::SECP,
			&agg_pk,
			server_cosign.partial_signature,
			server_cosign.pub_nonce,
			musig::pubkey_to(self.asp_pubkey),
		)
	}

	/// Finishes the board request and create a vtxo.
	pub fn build_vtxo(
		mut self,
		server_cosign: &BoardCosignResponse,
		user_key: &Keypair,
	) -> Vtxo {
		let (sighash, taproot) = self.exit_tx_sighash_data();

		let agg_nonce = musig::nonce_agg(&[&self.user_pub_nonce(), &server_cosign.pub_nonce]);
		let (_user_sig, final_sig) = musig::partial_sign(
			[self.user_pubkey, self.asp_pubkey],
			agg_nonce,
			user_key,
			self.user_sec_nonce.take().expect("state invariant"),
			sighash.to_byte_array(),
			Some(taproot.tap_tweak().to_byte_array()),
			Some(&[&server_cosign.partial_signature]),
		);
		let final_sig = final_sig.expect("we provided the other sig");
		debug_assert!(SECP.verify_schnorr(
			&final_sig,
			&sighash.into(),
			&taproot.output_key().to_x_only_public_key(),
		).is_ok(), "invalid board exit tx signature produced");

		Vtxo::Board(BoardVtxo {
			spec: VtxoSpec {
				user_pubkey: self.user_pubkey,
				expiry_height: self.expiry_height,
				asp_pubkey: self.asp_pubkey,
				exit_delta: self.exit_delta,
				spk: VtxoSpkSpec::Exit,
				amount: self.amount,
			},
			onchain_output: self.utxo.expect("state invariant"),
			exit_tx_signature: final_sig,
		})
	}
}

#[derive(Debug, Clone, thiserror::Error)]
#[error("board funding tx validation error: {0}")]
pub struct BoardFundingTxValidationError(String);

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BoardVtxo {
	pub spec: VtxoSpec,
	/// The output of the board. This will be the input to the exit tx.
	pub onchain_output: OutPoint,
	pub exit_tx_signature: schnorr::Signature,
}

impl BoardVtxo {
	pub fn exit_tx(&self) -> Transaction {
		let ret = vtxo::create_exit_tx(
			self.onchain_output,
			self.spec.txout(),
			Some(&self.exit_tx_signature),
		);
		assert_eq!(ret.weight(), crate::vtxo::EXIT_TX_WEIGHT);
		ret
	}

	pub fn point(&self) -> OutPoint {
		//TODO(stevenroose) consider caching this so that we don't have to calculate it
		OutPoint::new(self.exit_tx().compute_txid(), 0)
	}

	pub fn id(&self) -> VtxoId {
		self.point().into()
	}

	pub fn amount(&self) -> Amount {
		self.spec.amount
	}

	pub fn validate_funding_tx(
		&self,
		funding_tx: &Transaction,
	) -> Result<(), BoardFundingTxValidationError> {
		let id = self.id();
		if self.onchain_output.txid != funding_tx.compute_txid() {
			return Err(BoardFundingTxValidationError(format!(
				"onchain tx and vtxo board txid don't match",
			)));
		}

		// Check that the output actually has the right script.
		let output_idx = self.onchain_output.vout as usize;
		if funding_tx.output.len() < output_idx {
			return Err(BoardFundingTxValidationError(format!(
				"non-existing point {} in tx {}", self.onchain_output, self.onchain_output.txid,
			)));
		}
		let funding_spk = funding_taproot(
			self.spec.user_pubkey, self.spec.expiry_height, self.spec.asp_pubkey,
		).script_pubkey();
		if funding_tx.output[output_idx].script_pubkey != funding_spk {
			return Err(BoardFundingTxValidationError(format!(
				"vtxo {} has incorrect board script: {}",
				id, funding_tx.output[output_idx].script_pubkey,
			)));
		}
		let amount = funding_tx.output[output_idx].value;
		if amount != self.spec.amount {
			return Err(BoardFundingTxValidationError(format!(
				"vtxo {} has incorrect board amount: {}", id, amount,
			)));
		}
		Ok(())
	}
}


#[cfg(test)]
mod test {
	use bitcoin::Amount;

	use super::*;

	#[test]
	fn test_flow_assertions() {
		//! Passes through the entire flow so that all assertions
		//! inside the code are ran at least once.

		let user_key = Keypair::new(&SECP, &mut bitcoin::secp256k1::rand::thread_rng());
		let asp_key = Keypair::new(&SECP, &mut bitcoin::secp256k1::rand::thread_rng());
		let utxo = "0000000000000000000000000000000000000000000000000000000000000001:1".parse().unwrap();

		// user
		let amount = Amount::from_btc(1.5).unwrap();
		let expiry = 100_000;
		let asp_pubkey = asp_key.public_key();
		let exit_delta = 24;
		let builder = BoardBuilder::new(
			amount, user_key.public_key(), expiry, asp_pubkey, exit_delta,
		)
			.set_funding_utxo(utxo)
			.generate_user_nonces();

		// server
		let cosign = {
			let server_builder = BoardBuilder::new_for_cosign(
				amount, builder.user_pubkey, expiry, asp_pubkey, exit_delta, utxo, builder.user_pub_nonce(),
			);
			server_builder.server_cosign(&asp_key)
		};

		// user
		assert!(builder.verify_partial_sig(&cosign));
		let _vtxo = builder.build_vtxo(&cosign, &user_key);
		//TODO(stevenroose) check serialization roundtrip
	}
}

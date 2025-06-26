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
//! * user validates cosign response using [BoardBuilder::verify_cosign_response]
//! * user finishes the vtxos by cross-signing using [BoardBuilder::build_vtxo]

use std::marker::PhantomData;

use bitcoin::sighash::{self, SighashCache};
use bitcoin::taproot::TaprootSpendInfo;
use bitcoin::{Amount, OutPoint, ScriptBuf, TapSighash, Transaction, TxOut, Txid};
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{Keypair, PublicKey};
use bitcoin_ext::{BlockHeight, TaprootSpendInfoExt};

use crate::error::IncorrectSigningKeyError;
use crate::{musig, Vtxo, VtxoPolicy};
use crate::tree::signed::cosign_taproot;
use crate::util::{verify_partial_sig, SECP};
use crate::vtxo::{self, exit_taproot, GenesisItem, GenesisTransition};

use self::state::BuilderState;


/// The output index of the board vtxo in the board tx.
pub const BOARD_FUNDING_TX_VTXO_VOUT: u32 = 0;

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
	pub pub_nonce: musig::PublicNonce,
	pub partial_signature: musig::PartialSignature,
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
/// Currently you can only create VTXOs with [VtxoPolicy::PublicKey].
#[derive(Debug)]
pub struct BoardBuilder<S: BuilderState> {
	pub amount: Amount,
	pub user_pubkey: PublicKey,
	pub expiry_height: BlockHeight,
	pub asp_pubkey: PublicKey,
	pub exit_delta: u16,

	utxo: Option<OutPoint>,
	user_pub_nonce: Option<musig::PublicNonce>,
	user_sec_nonce: Option<musig::SecretNonce>,
	_state: PhantomData<S>,
}

impl<S: BuilderState> BoardBuilder<S> {
	/// The scriptPubkey to send the board funds to.
	pub fn funding_script_pubkey(&self) -> ScriptBuf {
		let combined_pubkey = musig::combine_keys([self.user_pubkey, self.asp_pubkey]);
		cosign_taproot(combined_pubkey, self.asp_pubkey, self.expiry_height).script_pubkey()
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
		let combined_pubkey = musig::combine_keys([self.user_pubkey, self.asp_pubkey]);
		let funding_taproot = cosign_taproot(combined_pubkey, self.asp_pubkey, self.expiry_height);
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
		//TODO(stevenroose) consider trying to move this to musig module
		let (sec_nonce, pub_nonce) = agg.nonce_gen(
			&musig::SECP,
			musig::SessionSecretRand::assume_unique_per_nonce_gen(rand::random()),
			musig::pubkey_to(self.user_pubkey),
			&reveal_sighash.to_byte_array(),
			None,
		);

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
	pub fn user_pub_nonce(&self) -> &musig::PublicNonce {
		self.user_pub_nonce.as_ref().expect("state invariant")
	}

	/// The signature hash to sign the exit tx and the taproot info
	/// (of the funding tx) used to calcualte it and the exit tx's txid.
	fn exit_tx_sighash_data(&self) -> (TapSighash, TaprootSpendInfo, Txid) {
		let combined_pubkey = musig::combine_keys([self.user_pubkey, self.asp_pubkey]);
		let funding_taproot = cosign_taproot(combined_pubkey, self.asp_pubkey, self.expiry_height);
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
		let (sighash, tx) = exit_tx_sighash(&funding_txout, utxo, exit_txout);
		(sighash, funding_taproot, tx.compute_txid())
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
		user_pub_nonce: musig::PublicNonce,
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
		let (sighash, taproot, _txid) = self.exit_tx_sighash_data();
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
	pub fn verify_cosign_response(&self, server_cosign: &BoardCosignResponse) -> bool {
		let (sighash, taproot, _txid) = self.exit_tx_sighash_data();
		verify_partial_sig(
			sighash,
			taproot.tap_tweak(),
			(self.asp_pubkey, &server_cosign.pub_nonce),
			(self.user_pubkey, self.user_pub_nonce()),
			&server_cosign.partial_signature
		)
	}

	/// Finishes the board request and create a vtxo.
	pub fn build_vtxo(
		mut self,
		server_cosign: &BoardCosignResponse,
		user_key: &Keypair,
	) -> Result<Vtxo, IncorrectSigningKeyError> {
		if user_key.public_key() != self.user_pubkey {
			return Err(IncorrectSigningKeyError {
				required: self.user_pubkey,
				provided: user_key.public_key(),
			});
		}

		let (sighash, taproot, exit_txid) = self.exit_tx_sighash_data();

		let agg_nonce = musig::nonce_agg(&[&self.user_pub_nonce(), &server_cosign.pub_nonce]);
		let (user_sig, final_sig) = musig::partial_sign(
			[self.user_pubkey, self.asp_pubkey],
			agg_nonce,
			user_key,
			self.user_sec_nonce.take().expect("state invariant"),
			sighash.to_byte_array(),
			Some(taproot.tap_tweak().to_byte_array()),
			Some(&[&server_cosign.partial_signature]),
		);
		debug_assert!(
			verify_partial_sig(
				sighash,
				taproot.tap_tweak(),
				(self.user_pubkey, self.user_pub_nonce()),
				(self.asp_pubkey, &server_cosign.pub_nonce),
				&user_sig,
			),
			"invalid board partial exit tx signature produced",
		);

		let final_sig = final_sig.expect("we provided the other sig");
		debug_assert!(
			SECP.verify_schnorr(
				&final_sig, &sighash.into(), &taproot.output_key().to_x_only_public_key(),
			).is_ok(),
			"invalid board exit tx signature produced",
		);

		Ok(Vtxo {
			amount: self.amount,
			expiry_height: self.expiry_height,
			asp_pubkey: self.asp_pubkey,
			exit_delta: self.exit_delta,
			anchor_point: self.utxo.expect("state invariant"),
			genesis: vec![GenesisItem {
				transition: GenesisTransition::Cosigned {
					pubkeys: vec![self.user_pubkey, self.asp_pubkey],
					signature: final_sig,
				},
				output_idx: 0,
				other_outputs: vec![],
			}],
			policy: VtxoPolicy::new_pubkey(self.user_pubkey),
			point: OutPoint::new(exit_txid, BOARD_FUNDING_TX_VTXO_VOUT),
		})
	}
}

#[derive(Debug, Clone, thiserror::Error)]
#[error("board funding tx validation error: {0}")]
pub struct BoardFundingTxValidationError(String);


#[cfg(test)]
mod test {
	use bitcoin::Amount;

	use crate::encode::test::encoding_roundtrip;

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
				amount, builder.user_pubkey, expiry, asp_pubkey, exit_delta, utxo, *builder.user_pub_nonce(),
			);
			server_builder.server_cosign(&asp_key)
		};

		// user
		assert!(builder.verify_cosign_response(&cosign));
		let vtxo = builder.build_vtxo(&cosign, &user_key).unwrap();

		encoding_roundtrip(&vtxo);
	}
}

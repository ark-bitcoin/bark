//!
//! Board flow:
//!
//! * user creates a builder using [BoardBuilder::new]
//! * user creates the funding tx which pays to [BoardBuilder::funding_script_pubkey]
//! * user sets the funding output in [BoardBuilder::set_funding_details]
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
use bitcoin_ext::{BlockDelta, BlockHeight, TaprootSpendInfoExt};

use crate::error::IncorrectSigningKeyError;
use crate::{musig, scripts, SECP};
use crate::tree::signed::cosign_taproot;
use crate::vtxo::{self, Vtxo, VtxoId, VtxoPolicy, ServerVtxo, ServerVtxoPolicy, GenesisItem, GenesisTransition};

use self::state::BuilderState;


/// The output index of the board vtxo in the board tx.
pub const BOARD_FUNDING_TX_VTXO_VOUT: u32 = 0;

/// Cached data computed from the exit transaction.
#[derive(Debug)]
struct ExitData {
	sighash: TapSighash,
	funding_taproot: TaprootSpendInfo,
	tx: Transaction,
	txid: Txid,
}

fn compute_exit_data(
	user_pubkey: PublicKey,
	server_pubkey: PublicKey,
	expiry_height: BlockHeight,
	exit_delta: BlockDelta,
	amount: Amount,
	utxo: OutPoint,
) -> ExitData {
	let combined_pubkey = musig::combine_keys([user_pubkey, server_pubkey]);
	let funding_taproot = cosign_taproot(combined_pubkey, server_pubkey, expiry_height);
	let funding_txout = TxOut {
		value: amount,
		script_pubkey: funding_taproot.script_pubkey(),
	};

	let exit_taproot = VtxoPolicy::new_pubkey(user_pubkey)
		.taproot(server_pubkey, exit_delta, expiry_height);
	let exit_txout = TxOut {
		value: amount,
		script_pubkey: exit_taproot.script_pubkey(),
	};

	let tx = vtxo::create_exit_tx(utxo, exit_txout, None);
	let sighash = SighashCache::new(&tx).taproot_key_spend_signature_hash(
		0, &sighash::Prevouts::All(&[funding_txout]), sighash::TapSighashType::Default,
	).expect("matching prevouts");

	let txid = tx.compute_txid();
	ExitData { sighash, funding_taproot, tx, txid }
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum BoardFromVtxoError {
	#[error("funding txid mismatch: expected {expected}, got {got}")]
	FundingTxMismatch {
		expected: Txid,
		got: Txid,
	},
	#[error("server pubkey mismatch: expected {expected}, got {got}")]
	ServerPubkeyMismatch {
		expected: PublicKey,
		got: PublicKey,
	},
	#[error("vtxo id mismatch: expected {expected}, got {got}")]
	VtxoIdMismatch {
		expected: OutPoint,
		got: OutPoint,
	},
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
		impl Sealed for super::CanFinish {}
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
	/// a cosign response from the server.
	pub struct CanFinish;
	impl BuilderState for CanFinish {}

	/// Trait to capture all states that have sufficient information
	/// for either party to create signatures.
	pub trait CanSign: BuilderState {}
	impl CanSign for ServerCanCosign {}
	impl CanSign for CanFinish {}

	/// Trait for once the funding details are known
	pub trait HasFundingDetails: BuilderState {}
	impl HasFundingDetails for CanGenerateNonces {}
	impl HasFundingDetails for ServerCanCosign {}
	impl HasFundingDetails for CanFinish {}
}

/// A request for the server to cosign an board vtxo.
///
/// An object of this type is created by the user, sent to the server who will
/// cosign the request and return his partial signature (along with public nonce)
/// back to the user so that the user can finish the request and create a [Vtxo].
///
/// Currently you can only create VTXOs with [VtxoPolicy::Pubkey].
#[derive(Debug)]
pub struct BoardBuilder<S: BuilderState> {
	pub user_pubkey: PublicKey,
	pub expiry_height: BlockHeight,
	pub server_pubkey: PublicKey,
	pub exit_delta: BlockDelta,

	amount: Option<Amount>,
	utxo: Option<OutPoint>,

	user_pub_nonce: Option<musig::PublicNonce>,
	user_sec_nonce: Option<musig::SecretNonce>,

	// Cached exit tx data (computed when funding details are set)
	exit_data: Option<ExitData>,

	_state: PhantomData<S>,
}

impl<S: BuilderState> BoardBuilder<S> {
	/// The scriptPubkey to send the board funds to.
	pub fn funding_script_pubkey(&self) -> ScriptBuf {
		let combined_pubkey = musig::combine_keys([self.user_pubkey, self.server_pubkey]);
		cosign_taproot(combined_pubkey, self.server_pubkey, self.expiry_height).script_pubkey()
	}

	fn to_state<S2: BuilderState>(self) -> BoardBuilder<S2> {
		BoardBuilder {
			user_pubkey: self.user_pubkey,
			expiry_height: self.expiry_height,
			server_pubkey: self.server_pubkey,
			exit_delta: self.exit_delta,
			amount: self.amount,
			utxo: self.utxo,
			user_pub_nonce: self.user_pub_nonce,
			user_sec_nonce: self.user_sec_nonce,
			exit_data: self.exit_data,
			_state: PhantomData,
		}
	}
}

impl BoardBuilder<state::Preparing> {
	/// Create a new builder to construct a board vtxo.
	///
	/// See module-level documentation for an overview of the board flow.
	pub fn new(
		user_pubkey: PublicKey,
		expiry_height: BlockHeight,
		server_pubkey: PublicKey,
		exit_delta: BlockDelta,
	) -> BoardBuilder<state::Preparing> {
		BoardBuilder {
			user_pubkey, expiry_height, server_pubkey, exit_delta,
			amount: None,
			utxo: None,
			user_pub_nonce: None,
			user_sec_nonce: None,
			exit_data: None,
			_state: PhantomData,
		}
	}

	/// Set the UTXO where the board will be funded and the board amount.
	pub fn set_funding_details(
		mut self,
		amount: Amount,
		utxo: OutPoint,
	) -> BoardBuilder<state::CanGenerateNonces> {
		let exit_data = compute_exit_data(
			self.user_pubkey, self.server_pubkey, self.expiry_height,
			self.exit_delta, amount, utxo,
		);

		self.amount = Some(amount);
		self.utxo = Some(utxo);
		self.exit_data = Some(exit_data);

		self.to_state()
	}
}

impl BoardBuilder<state::CanGenerateNonces> {
	/// Generate user nonces.
	pub fn generate_user_nonces(mut self) -> BoardBuilder<state::CanFinish> {
		let exit_data = self.exit_data.as_ref().expect("state invariant");
		let funding_taproot = &exit_data.funding_taproot;
		let exit_sighash = exit_data.sighash;

		let (agg, _) = musig::tweaked_key_agg(
			[self.user_pubkey, self.server_pubkey],
			funding_taproot.tap_tweak().to_byte_array(),
		);
		//TODO(stevenroose) consider trying to move this to musig module
		let (sec_nonce, pub_nonce) = agg.nonce_gen(
			musig::SessionSecretRand::assume_unique_per_nonce_gen(rand::random()),
			musig::pubkey_to(self.user_pubkey),
			&exit_sighash.to_byte_array(),
			None,
		);

		self.user_pub_nonce = Some(pub_nonce);
		self.user_sec_nonce = Some(sec_nonce);
		self.to_state()
	}

	/// Constructs a BoardBuilder from a vtxo
	///
	/// This is used to validate that a vtxo is a board
	/// that originates from the provided server.
	///
	/// This call assumes the [Vtxo] is valid. The caller
	/// has to call [Vtxo::validate] before using this
	/// constructor.
	pub fn new_from_vtxo(
		vtxo: &Vtxo,
		funding_tx: &Transaction,
		server_pubkey: PublicKey,
	) -> Result<Self, BoardFromVtxoError> {
		if vtxo.chain_anchor().txid != funding_tx.compute_txid() {
			return Err(BoardFromVtxoError::FundingTxMismatch {
				expected: vtxo.chain_anchor().txid,
				got: funding_tx.compute_txid(),
			})
		}

		if vtxo.server_pubkey() != server_pubkey {
			return Err(BoardFromVtxoError::ServerPubkeyMismatch {
				expected: server_pubkey,
				got: vtxo.server_pubkey(),
			})
		}

		let exit_data = compute_exit_data(
			vtxo.user_pubkey(),
			server_pubkey,
			vtxo.expiry_height,
			vtxo.exit_delta,
			vtxo.amount(),
			vtxo.chain_anchor(),
		);

		// We compute the vtxo_id again from all reconstructed data
		// It must match exactly
		let expected_vtxo_id = OutPoint::new(exit_data.txid, BOARD_FUNDING_TX_VTXO_VOUT);
		if vtxo.point() != expected_vtxo_id {
			return Err(BoardFromVtxoError::VtxoIdMismatch {
				expected: expected_vtxo_id,
				got: vtxo.point(),
			})
		}

		Ok(Self {
			user_pub_nonce: None,
			user_sec_nonce: None,
			amount: Some(vtxo.amount()),
			user_pubkey: vtxo.user_pubkey(),
			server_pubkey,
			expiry_height: vtxo.expiry_height,
			exit_delta: vtxo.exit_delta,
			utxo: Some(vtxo.chain_anchor()),
			exit_data: Some(exit_data),
			_state: PhantomData,
		})
	}

	/// Returns a reference to the exit transaction.
	///
	/// The exit transaction spends the board's funding UTXO and creates
	/// the VTXO output.
	pub fn exit_tx(&self) -> &Transaction {
		&self.exit_data.as_ref().expect("state invariant").tx
	}

	/// Returns the txid of the exit transaction.
	pub fn exit_txid(&self) -> Txid {
		self.exit_data.as_ref().expect("state invariant").txid
	}

	/// Builds the internal unsigned VTXOs created by this board operation.
	///
	/// Returns two VTXOs:
	/// 1. An expiry VTXO with empty genesis (for server tracking)
	/// 2. A pubkey VTXO with an arkoor genesis transition
	pub fn build_internal_unsigned_vtxos(&self) -> Vec<ServerVtxo> {
		let exit_data = self.exit_data.as_ref().expect("state invariant");
		let exit_txid = exit_data.txid;
		let tap_tweak = exit_data.funding_taproot.tap_tweak();

		let expiry_policy = ServerVtxoPolicy::new_expiry(self.user_pubkey.x_only_public_key().0);
		vec![
			Vtxo {
				policy: expiry_policy,
				amount: self.amount.expect("state invariant"),
				expiry_height: self.expiry_height,
				server_pubkey: self.server_pubkey,
				exit_delta: self.exit_delta,
				anchor_point: self.utxo.expect("state invariant"),
				genesis: vec![],
				point: self.utxo.expect("state invariant"),
			},
			Vtxo {
				policy: ServerVtxoPolicy::User(VtxoPolicy::new_pubkey(self.user_pubkey)),
				amount: self.amount.expect("state invariant"),
				expiry_height: self.expiry_height,
				server_pubkey: self.server_pubkey,
				exit_delta: self.exit_delta,
				anchor_point: self.utxo.expect("state invariant"),
				genesis: vec![
					GenesisItem {
						transition: GenesisTransition::new_arkoor(
							vec![self.user_pubkey],
							tap_tweak,
							None,
						),
						output_idx: 0,
						other_outputs: vec![],
					}
				],
				point: OutPoint::new(exit_txid, BOARD_FUNDING_TX_VTXO_VOUT),
			},
		]
	}

	/// Returns spend information mapping input VTXO IDs to spending transaction IDs.
	pub fn spend_info(&self) -> Vec<(VtxoId, Txid)> {
		let exit_txid = self.exit_data.as_ref().expect("state invariant").txid;
		vec![(self.utxo.expect("state invariant").into(), exit_txid)]
	}
}

impl<S: state::CanSign> BoardBuilder<S> {
	pub fn user_pub_nonce(&self) -> &musig::PublicNonce {
		self.user_pub_nonce.as_ref().expect("state invariant")
	}
}

impl BoardBuilder<state::ServerCanCosign> {
	/// This constructor is to be used by the server with the information provided
	/// by the user.
	pub fn new_for_cosign(
		user_pubkey: PublicKey,
		expiry_height: BlockHeight,
		server_pubkey: PublicKey,
		exit_delta: BlockDelta,
		amount: Amount,
		utxo: OutPoint,
		user_pub_nonce: musig::PublicNonce,
	) -> BoardBuilder<state::ServerCanCosign> {
		let exit_data = compute_exit_data(
			user_pubkey, server_pubkey, expiry_height, exit_delta, amount, utxo,
		);

		BoardBuilder {
			user_pubkey, expiry_height, server_pubkey, exit_delta,
			amount: Some(amount),
			utxo: Some(utxo),
			user_pub_nonce: Some(user_pub_nonce),
			user_sec_nonce: None,
			exit_data: Some(exit_data),
			_state: PhantomData,
		}
	}

	/// This method is used by the server to cosign the board request.
	///
	/// Returns `None` if utxo or user_pub_nonce field is not provided.
	pub fn server_cosign(&self, key: &Keypair) -> BoardCosignResponse {
		let exit_data = self.exit_data.as_ref().expect("state invariant");
		let sighash = exit_data.sighash;
		let taproot = &exit_data.funding_taproot;
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

impl BoardBuilder<state::CanFinish> {
	/// Validate the server's partial signature.
	pub fn verify_cosign_response(&self, server_cosign: &BoardCosignResponse) -> bool {
		let exit_data = self.exit_data.as_ref().expect("state invariant");
		let sighash = exit_data.sighash;
		let taproot = &exit_data.funding_taproot;
		scripts::verify_partial_sig(
			sighash,
			taproot.tap_tweak(),
			(self.server_pubkey, &server_cosign.pub_nonce),
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
				required: Some(self.user_pubkey),
				provided: user_key.public_key(),
			});
		}

		let exit_data = self.exit_data.as_ref().expect("state invariant");
		let sighash = exit_data.sighash;
		let taproot = &exit_data.funding_taproot;
		let exit_txid = exit_data.txid;

		let agg_nonce = musig::nonce_agg(&[&self.user_pub_nonce(), &server_cosign.pub_nonce]);
		let (user_sig, final_sig) = musig::partial_sign(
			[self.user_pubkey, self.server_pubkey],
			agg_nonce,
			user_key,
			self.user_sec_nonce.take().expect("state invariant"),
			sighash.to_byte_array(),
			Some(taproot.tap_tweak().to_byte_array()),
			Some(&[&server_cosign.partial_signature]),
		);
		debug_assert!(
			scripts::verify_partial_sig(
				sighash,
				taproot.tap_tweak(),
				(self.user_pubkey, self.user_pub_nonce()),
				(self.server_pubkey, &server_cosign.pub_nonce),
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
			amount: self.amount.expect("state invariant"),
			expiry_height: self.expiry_height,
			server_pubkey: self.server_pubkey,
			exit_delta: self.exit_delta,
			anchor_point: self.utxo.expect("state invariant"),
			genesis: vec![GenesisItem {
				transition: GenesisTransition::new_cosigned(
					vec![self.user_pubkey, self.server_pubkey],
					Some(final_sig),
				),
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
	use std::str::FromStr;

	use bitcoin::{absolute, transaction, Amount};

	use crate::test_util::encoding_roundtrip;

	use super::*;

	#[test]
	fn test_board_builder() {
		//! Passes through the entire flow so that all assertions
		//! inside the code are ran at least once.

		let user_key = Keypair::from_str("5255d132d6ec7d4fc2a41c8f0018bb14343489ddd0344025cc60c7aa2b3fda6a").unwrap();
		let server_key = Keypair::from_str("1fb316e653eec61de11c6b794636d230379509389215df1ceb520b65313e5426").unwrap();

		// user
		let amount = Amount::from_btc(1.5).unwrap();
		let expiry = 100_000;
		let server_pubkey = server_key.public_key();
		let exit_delta = 24;
		let builder = BoardBuilder::new(
			user_key.public_key(), expiry, server_pubkey, exit_delta,
		);
		let funding_tx = Transaction {
			version: transaction::Version::TWO,
			lock_time: absolute::LockTime::ZERO,
			input: vec![],
			output: vec![TxOut {
				value: amount,
				script_pubkey: builder.funding_script_pubkey(),
			}],
		};
		let utxo = OutPoint::new(funding_tx.compute_txid(), 0);
		assert_eq!(utxo.to_string(), "8c4b87af4ce8456bbd682859959ba64b95d5425d761a367f4f20b8ffccb1bde0:0");
		let builder = builder.set_funding_details(amount, utxo).generate_user_nonces();

		// server
		let cosign = {
			let server_builder = BoardBuilder::new_for_cosign(
				builder.user_pubkey, expiry, server_pubkey, exit_delta, amount, utxo, *builder.user_pub_nonce(),
			);
			server_builder.server_cosign(&server_key)
		};

		// user
		assert!(builder.verify_cosign_response(&cosign));
		let vtxo = builder.build_vtxo(&cosign, &user_key).unwrap();

		encoding_roundtrip(&vtxo);

		vtxo.validate(&funding_tx).unwrap();
	}

	/// Helper to create a valid vtxo and funding tx for testing new_from_vtxo
	fn create_board_vtxo() -> (Vtxo, Transaction, Keypair, Keypair) {
		let user_key = Keypair::from_str("5255d132d6ec7d4fc2a41c8f0018bb14343489ddd0344025cc60c7aa2b3fda6a").unwrap();
		let server_key = Keypair::from_str("1fb316e653eec61de11c6b794636d230379509389215df1ceb520b65313e5426").unwrap();

		let amount = Amount::from_btc(1.5).unwrap();
		let expiry = 100_000;
		let server_pubkey = server_key.public_key();
		let exit_delta = 24;

		let builder = BoardBuilder::new(
			user_key.public_key(), expiry, server_pubkey, exit_delta,
		);
		let funding_tx = Transaction {
			version: transaction::Version::TWO,
			lock_time: absolute::LockTime::ZERO,
			input: vec![],
			output: vec![TxOut {
				value: amount,
				script_pubkey: builder.funding_script_pubkey(),
			}],
		};
		let utxo = OutPoint::new(funding_tx.compute_txid(), 0);
		let builder = builder.set_funding_details(amount, utxo).generate_user_nonces();

		let cosign = {
			let server_builder = BoardBuilder::new_for_cosign(
				builder.user_pubkey, expiry, server_pubkey, exit_delta, amount, utxo, *builder.user_pub_nonce(),
			);
			server_builder.server_cosign(&server_key)
		};

		let vtxo = builder.build_vtxo(&cosign, &user_key).unwrap();
		(vtxo, funding_tx, user_key, server_key)
	}

	#[test]
	fn test_new_from_vtxo_success() {
		let (vtxo, funding_tx, _, server_key) = create_board_vtxo();

		// Should succeed with correct inputs
		let builder = BoardBuilder::new_from_vtxo(&vtxo, &funding_tx, server_key.public_key())
			.expect("Is valid");

		let server_vtxos = builder.build_internal_unsigned_vtxos();
		assert_eq!(server_vtxos.len(), 2);
		assert!(matches!(server_vtxos[0].policy(), ServerVtxoPolicy::Expiry(..)));
		assert!(matches!(server_vtxos[1].policy(), ServerVtxoPolicy::User(VtxoPolicy::Pubkey{..})));
	}

	#[test]
	fn test_new_from_vtxo_txid_mismatch() {
		let (vtxo, funding_tx, _, server_key) = create_board_vtxo();

		// Create a different funding tx with wrong txid
		let wrong_funding_tx = Transaction {
			version: transaction::Version::TWO,
			lock_time: absolute::LockTime::ZERO,
			input: vec![],
			output: vec![TxOut {
				value: Amount::from_btc(2.0).unwrap(), // Different amount = different txid
				script_pubkey: funding_tx.output[0].script_pubkey.clone(),
			}],
		};

		let result = BoardBuilder::new_from_vtxo(&vtxo, &wrong_funding_tx, server_key.public_key());
		assert!(matches!(
			result,
			Err(BoardFromVtxoError::FundingTxMismatch { expected, got })
			if expected == vtxo.chain_anchor().txid && got == wrong_funding_tx.compute_txid()
		));
	}

	#[test]
	fn test_new_from_vtxo_server_pubkey_mismatch() {
		let (vtxo, funding_tx, _, _) = create_board_vtxo();

		// Use a different server pubkey
		let wrong_server_key = Keypair::from_str("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap();

		let result = BoardBuilder::new_from_vtxo(&vtxo, &funding_tx, wrong_server_key.public_key());
		assert!(matches!(
			result,
			Err(BoardFromVtxoError::ServerPubkeyMismatch { expected, got })
			if expected == wrong_server_key.public_key() && got == vtxo.server_pubkey()
		));
	}

	#[test]
	fn test_new_from_vtxo_vtxoid_mismatch() {
		// This test verifies that BoardBuilder::new_from_vtxo detects when the
		// vtxo's point doesn't match the computed exit tx output.
		//
		// Note: It is not the responsibility of new_from_vtxo to validate that
		// the vtxo's point is correct in the first place. That validation
		// happens in Vtxo::validate. This check ensures internal consistency
		// when reconstructing the board from a vtxo.
		let (mut vtxo, funding_tx, _, server_key) = create_board_vtxo();

		// Tamper with the vtxo's point to cause a mismatch
		let original_point = vtxo.point;
		vtxo.point = OutPoint::new(vtxo.point.txid, vtxo.point.vout + 1);

		let result = BoardBuilder::new_from_vtxo(&vtxo, &funding_tx, server_key.public_key());
		assert!(matches!(
			result,
			Err(BoardFromVtxoError::VtxoIdMismatch { expected, got })
			if expected == original_point && got == vtxo.point
		));
	}
}


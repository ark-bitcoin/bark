//! Utilities to create out-of-round transactions using
//! checkpoint transactions.
//!
//! # Checkpoints keep users and the server safe
//!
//! When an Ark transaction is spent out-of-round a new
//! transaction is added on top of that. In the naive
//! approach we just keep adding transactions and the
//! chain becomes longer.
//!
//! A first problem is that this can become unsafe for the server.
//! If a client performs a partial exit attack the server
//! will have to broadcast a long chain of transactions
//! to get the forfeit published.
//!
//! A second problem is that if one user exits it affects everyone.
//! In their chunk of the tree. The server cannot sweep the funds
//! anymore and all other users are forced to collect their funds
//! from the chain (which can be expensive).
//!
//! # How do they work
//!
//! The core idea is that each out-of-round spent will go through
//! a checkpoint transaction. The checkpoint transaction has the policy
//! `A + S or S after expiry`.
//!
//! Note, that the `A+S` path is fast and will always take priority.
//! Users will still be able to exit their funds at any time.
//! But if a partial exit occurs, the server can just broadcast
//! a single checkpoint transaction and continue like nothing happened.
//!
//! Other users will be fully unaffected by this. Their [Vtxo] will now
//! be anchored in the checkpoint which can be swept after expiry.
//!
//! # Usage
//!
//! This module creates a checkpoint transaction that originates
//! from a single [Vtxo]. It is a low-level construct and the developer
//! has to compute the paid amount, change and fees themselves.
//!
//! The core construct is [CheckpointedArkoorBuilder] which can be
//! used to build arkoor transactions. The struct is designed to be
//! used by both the client and the server.
//!
//! [CheckpointedArkoorBuilder::new]  is a constructor that validates
//! the intended transaction. At this point, all transactions that
//! will be constructed are fully designed. You can
//! use [CheckpointedArkoorBuilder::build_unsigned_vtxos] to construct the
//! vtxos but they will still lack signatures.
//!
//! Constructing the signatures is an interactive process in which the
//! client signs first.
//!
//! The client will call [CheckpointedArkoorBuilder::generate_user_nonces]
//! which will update the builder-state to  [state::UserGeneratedNonces].
//! The client will create a [CosignRequest] which contains the details
//! about the arkoor payment including the user nonces. The server will
//! respond with a [CosignResponse] which can be used to finalize all
//! signatures. At the end the client can call [CheckpointedArkoorBuilder::build_signed_vtxos]
//! to get their fully signed VTXOs.
//!
//! The server will also use [CheckpointedArkoorBuilder::from_cosign_request]
//! to construct a builder. The [CheckpointedArkoorBuilder::server_cosign]
//! will construct the [CosignResponse] which is sent to the client.
//!

use std::borrow::Cow;
use std::marker::PhantomData;

use bitcoin::hashes::Hash;
use bitcoin::{Amount, OutPoint, TapSighash, Transaction, Txid, TxIn, TxOut, ScriptBuf, Sequence, Witness};
use bitcoin::taproot::TapTweakHash;
use bitcoin::secp256k1::{schnorr, Keypair, PublicKey};
use bitcoin_ext::{fee, P2TR_DUST, TxOutExt};
use secp256k1_musig::musig::PublicNonce;

use crate::vtxo::{GenesisItem, GenesisTransition};
use crate::arkoor::arkoor_sighash;
use crate::{Vtxo, VtxoId};
use crate::VtxoRequest;
use crate::scripts;
use crate::musig;
use crate::vtxo::VtxoPolicy;

#[derive(Debug, Clone, PartialEq, Eq, Hash, thiserror::Error)]
pub enum ArkoorConstructionError {
	#[error("Input amount of {input} does not match output amount of {output}")]
	Unbalanced {
		input: Amount,
		output: Amount,
	},
	#[error("An output is below the dust threshold")]
	Dust,
	#[error("Too many inputs provided")]
	TooManyInputs,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, thiserror::Error)]
pub enum ArkoorSigningError {
	#[error("An error occurred while building arkoor: {0}")]
	ArkoorConstructionError(ArkoorConstructionError),
	#[error("Wrong number of user nonces provided. Expected {expected}, got {got}")]
	InvalidNbUserNonces {
		expected: usize,
		got: usize,
	},
	#[error("Wrong number of server nonces provided. Expected {expected}, got {got}")]
	InvalidNbServerNonces {
		expected: usize,
		got: usize,
	},
	#[error("Incorrect signing key provided. Expected {expected}, got {got}")]
	IncorrectKey {
		expected: PublicKey,
		got: PublicKey,
	},
	#[error("Wrong number of server partial sigs. Expected {expected}, got {got}")]
	InvalidNbServerPartialSigs {
		expected: usize,
		got: usize
	},
	#[error("Invalid partial signature at index {index}")]
	InvalidPartialSignature {
		index: usize,
	},
	#[error("Wrong number of packages. Expected {expected}, got {got}")]
	InvalidNbPackages {
		expected: usize,
		got: usize,
	},
	#[error("Wrong number of keypairs. Expected {expected}, got {got}")]
	InvalidNbKeypairs {
		expected: usize,
		got: usize,
	},
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CosignResponse {
	pub server_pub_nonces: Vec<musig::PublicNonce>,
	pub server_partial_sigs: Vec<musig::PartialSignature>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CosignRequest<'a> {
	pub user_pub_nonces: Vec<musig::PublicNonce>,
	pub input: std::borrow::Cow<'a, Vtxo>,
	pub outputs: Vec<VtxoRequest>,
}

pub mod state {
	/// There are two paths that a can be followed
	///
	/// 1. [Initial] -> [UserGeneratedNonces] -> [UserSigned]
	/// 2. [Initial] -> [ServerCanCosign] -> [ServerSigned]
	///
	/// The first option is taken by the user and the second by the server

	mod sealed {
		pub trait Sealed {}
		impl Sealed for super::Initial {}
		impl Sealed for super::UserGeneratedNonces {}
		impl Sealed for super::UserSigned {}
		impl Sealed for super::ServerCanCosign {}
		impl Sealed for super::ServerSigned {}
	}

	pub trait BuilderState: sealed::Sealed {}

	// The initial state of the builder
	pub struct Initial;
	impl BuilderState for Initial {}

	// The user has generated their nonces
	pub struct UserGeneratedNonces;
	impl BuilderState for UserGeneratedNonces {}

	// The user can sign
	pub struct UserSigned;
	impl BuilderState for UserSigned {}

	// The server can cosign
	pub struct ServerCanCosign;
	impl BuilderState for ServerCanCosign {}


	/// The server has signed and knows the partial signatures
	pub struct ServerSigned;
	impl BuilderState for ServerSigned {}
}

pub struct CheckpointedArkoorBuilder<'a, S: state::BuilderState> {
	// These variables are provided by the user
	/// The input vtxo to be spent
	input: &'a Vtxo,
	/// `n` [VtxoRequest]s that the user wants to receive
	outputs: Vec<VtxoRequest>,

	// These can be computed in the constructor
	/// The unsigned checkpoint transaction
	unsigned_checkpoint_tx: Transaction,
	/// The unsigned arkoor transactions
	unsigned_arkoor_txs: Vec<Transaction>,
	/// The sighashes that must be signed
	sighashes: Vec<TapSighash>,
	/// The taptweak to sign the checkpoint tx
	checkpoint_taptweak: TapTweakHash,
	/// The taptweak to sign the arkoor tx
	arkoor_taptweak: TapTweakHash,
	/// The [VtxoId]s of all new [Vtxo]s that will be created
	new_vtxo_ids: Vec<VtxoId>,

	//  These variables are filled in when the state progresses
	/// We need 1 signature for the checkpoint transaction
	/// We need n signatures. This is one for each arkoor tx
	/// `1+n` public nonces created by the user
	user_pub_nonces: Option<Vec<musig::PublicNonce>>,
	/// `1+n` secret nonces created by the user
	user_sec_nonces: Option<Vec<musig::SecretNonce>>,
	/// `1+n` public nonces created by the server
	server_pub_nonces: Option<Vec<musig::PublicNonce>>,
	/// `1+n` partial signatures created by the server
	server_partial_sigs: Option<Vec<musig::PartialSignature>>,
	/// `1+n` signatures that are signed by the user and server
	full_signatures: Option<Vec<schnorr::Signature>>,

	_state: PhantomData<S>,
}

impl<'a, S: state::BuilderState> CheckpointedArkoorBuilder<'a, S> {

	fn vtxo_at(
		&self,
		output_idx: usize,
		checkpoint_sig: Option<schnorr::Signature>,
		arkoor_sig: Option<schnorr::Signature>,
	) -> Vtxo {
		let output = &self.outputs[output_idx];
		let checkpoint_policy = VtxoPolicy::new_checkpoint(self.input.user_pubkey());

		Vtxo {
			amount: output.amount,
			policy: output.policy.clone(),
			expiry_height: self.input.expiry_height,
			server_pubkey: self.input.server_pubkey,
			exit_delta: self.input.exit_delta,
			anchor_point: self.input.anchor_point,
			genesis: self.input.genesis.iter().cloned().chain([
				GenesisItem {
					transition: GenesisTransition::Arkoor { policy: self.input.policy.clone(), signature: checkpoint_sig },
					output_idx: output_idx as u8,
					other_outputs: self.unsigned_checkpoint_tx.output
						.iter().enumerate()
						.filter_map(|(iii, txout)| if iii == (output_idx as usize) || txout.is_p2a_fee_anchor() { None } else { Some(txout.clone()) })
						.collect(),
				},
				GenesisItem {
					transition: GenesisTransition::Arkoor { policy: checkpoint_policy, signature: arkoor_sig },
					output_idx: 0,
					other_outputs: vec![]
				}
			]).collect(),
			point: self.new_vtxo_ids[output_idx].utxo()
		}
	}


	fn nb_sigs(&self) -> usize {
		self.outputs.len() + 1
	}

	fn nb_outputs(&self) -> usize {
		self.outputs.len()
	}

	/// Construct all unsigned vtxos that will be created by this builder.
	pub fn build_unsigned_vtxos(&self) -> Vec<Vtxo> {
		(0..self.nb_outputs()).map(|i| self.vtxo_at(i, None, None)).collect()
	}

	fn taptweak_at(&self, idx: usize) -> TapTweakHash {
		if idx == 0 {
			self.checkpoint_taptweak
		}
		else {
			self.arkoor_taptweak
		}

	}

	fn user_pubkey(&self) -> PublicKey {
		self.input.user_pubkey()
	}

	fn server_pubkey(&self) -> PublicKey {
		self.input.server_pubkey()
	}

	fn construct_unsigned_checkpoint_tx(
		input: &Vtxo,
		outputs: &[VtxoRequest],
	) -> Transaction {
		// All outputs on the checkpoint transaction will use exactly the same policy.
		let output_policy = VtxoPolicy::new_checkpoint(input.user_pubkey());
		let checkpoint_spk = output_policy.script_pubkey(input.server_pubkey(), input.exit_delta(), input.expiry_height());

		Transaction {
			version: bitcoin::transaction::Version(3),
			lock_time: bitcoin::absolute::LockTime::ZERO,
			input: vec![TxIn {
				previous_output: input.point(),
				script_sig: ScriptBuf::new(),
				sequence: Sequence::ZERO,
				witness: Witness::new(),
			}],
			output: outputs.iter().map(|o| {
				TxOut {
					value: o.amount,
					script_pubkey: checkpoint_spk.clone(),
				}
			}).chain(Some(fee::fee_anchor())).collect()
		}
	}

	fn construct_unsigned_arkoor_txs(
		input: &Vtxo,
		outputs: &[VtxoRequest],
		checkpoint_txid: Txid,
	) -> Vec<Transaction> {
		let mut arkoor_txs = Vec::with_capacity(outputs.len());

		for (vout, output) in outputs.iter().enumerate() {
			let transaction = Transaction {
				version: bitcoin::transaction::Version(3),
				lock_time: bitcoin::absolute::LockTime::ZERO,
				input: vec![TxIn {
					previous_output: OutPoint::new(checkpoint_txid, vout as u32),
					script_sig: ScriptBuf::new(),
					sequence: Sequence::ZERO,
					witness: Witness::new(),
				}],
				output: vec![
					output.policy.txout(output.amount, input.server_pubkey(), input.exit_delta(), input.expiry_height()),
					fee::fee_anchor(),
				]
			};
			arkoor_txs.push(transaction);
		}

		arkoor_txs
	}

	fn validate_amounts(input: &Vtxo, outputs: &[VtxoRequest]) -> Result<(), ArkoorConstructionError> {
		// Check if inputs and outputs are balanced
		// We need to build transactions that pay exactly 0 in onchain fees
		// to ensure our transaction with an ephemeral anchor is standard.
		// We need `==` for standardness and we can't be lenient
		let input_amount = input.amount();
		let output_amount = outputs.iter().map(|o| o.amount).sum::<Amount>();
		if input_amount != output_amount {
			return Err(ArkoorConstructionError::Unbalanced {
				input: input_amount,
				output: output_amount,
			})
		}

		// Check if we have any subdust outputs
		if outputs.iter().any(|o| o.amount < P2TR_DUST) {
			return Err(ArkoorConstructionError::Dust)
		}

		Ok(())
	}


	fn to_state<S2: state::BuilderState>(self) -> CheckpointedArkoorBuilder<'a, S2> {
		CheckpointedArkoorBuilder {
			input: self.input,
			outputs: self.outputs,
			unsigned_checkpoint_tx: self.unsigned_checkpoint_tx,
			unsigned_arkoor_txs: self.unsigned_arkoor_txs,
			new_vtxo_ids: self.new_vtxo_ids,
			sighashes: self.sighashes,
			checkpoint_taptweak: self.checkpoint_taptweak,
			arkoor_taptweak: self.arkoor_taptweak,
			user_pub_nonces: self.user_pub_nonces,
			user_sec_nonces: self.user_sec_nonces,
			server_pub_nonces: self.server_pub_nonces,
			server_partial_sigs: self.server_partial_sigs,
			full_signatures: self.full_signatures,
			_state: PhantomData,
		}
	}
}

impl<'a> CheckpointedArkoorBuilder<'a, state::Initial> {

	/// Create a new checkpointed arkoor builder
	pub fn new(input: &'a Vtxo, outputs: Vec<VtxoRequest>) -> Result<Self, ArkoorConstructionError> {
		// Do some validation on the amounts
		Self::validate_amounts(input, &outputs)?;

		// Construct the checkpoint and arkoor transactions
		let unsigned_checkpoint_tx = Self::construct_unsigned_checkpoint_tx(input, &outputs);
		let unsigned_arkoor_txs = Self::construct_unsigned_arkoor_txs(input, &outputs, unsigned_checkpoint_tx.compute_txid());

		// Compute all vtx-ids
		let new_vtxo_ids = unsigned_arkoor_txs.iter()
			.map(|tx| OutPoint::new(tx.compute_txid(), 0))
			.map(|outpoint| VtxoId::from(outpoint))
			.collect();

		// Compute all sighashes
		let mut sighashes = Vec::with_capacity(outputs.len() + 1);
		sighashes.push(arkoor_sighash(&input.txout(), &unsigned_checkpoint_tx));
		for vout in 0..outputs.len() {
			let prevout = unsigned_checkpoint_tx.output[vout].clone();
			sighashes.push(arkoor_sighash(&prevout, &unsigned_arkoor_txs[vout]));
		}

		// For the checkpoint
		let checkpoint_taptweak = input.output_taproot().tap_tweak();
		let policy = VtxoPolicy::new_checkpoint(input.user_pubkey());
		let arkoor_taptweak = policy.taproot(input.server_pubkey(), input.exit_delta(), input.expiry_height()).tap_tweak();

		Ok(Self {
			input: input,
			outputs: outputs,
			sighashes: sighashes,
			checkpoint_taptweak: checkpoint_taptweak,
			arkoor_taptweak: arkoor_taptweak,
			unsigned_checkpoint_tx: unsigned_checkpoint_tx,
			unsigned_arkoor_txs: unsigned_arkoor_txs,
			new_vtxo_ids: new_vtxo_ids,
			user_pub_nonces: None,
			user_sec_nonces: None,
			server_pub_nonces: None,
			server_partial_sigs: None,
			full_signatures: None,
			_state: PhantomData,
		})
	}

	/// Generates the user nonces and moves the builder to the [state::UserGeneratedNonces] state
	/// This is the path that is used by the user
	pub fn generate_user_nonces(mut self, user_keypair: Keypair) -> CheckpointedArkoorBuilder<'a, state::UserGeneratedNonces> {
		let mut user_pub_nonces = Vec::with_capacity(self.nb_sigs());
		let mut user_sec_nonces = Vec::with_capacity(self.nb_sigs());

		for idx in 0..self.nb_sigs() {
			let sighash = &self.sighashes[idx].to_byte_array();
			let (sec_nonce, pub_nonce) = musig::nonce_pair_with_msg(&user_keypair, sighash);

			user_pub_nonces.push(pub_nonce);
			user_sec_nonces.push(sec_nonce);
		}

		self.user_pub_nonces = Some(user_pub_nonces);
		self.user_sec_nonces = Some(user_sec_nonces);

		self.to_state::<state::UserGeneratedNonces>()
	}

	/// Sets the pub nonces that a user has generated.
	/// When this has happened the server can cosign.
	///
	/// If you are implementing a client, use [Self::generate_user_nonces] instead.
	/// If you are implementing a server you should look at [CheckpointedArkoorBuilder::from_cosign_request]
	fn set_user_pub_nonces(mut self, user_pub_nonces: Vec<musig::PublicNonce>) -> Result<CheckpointedArkoorBuilder<'a, state::ServerCanCosign>, ArkoorSigningError> {
		if user_pub_nonces.len() != self.nb_sigs() {
			return Err(ArkoorSigningError::InvalidNbUserNonces {
				expected: self.nb_sigs(),
				got: user_pub_nonces.len()
			})
		}

		self.user_pub_nonces = Some(user_pub_nonces);
		Ok(self.to_state::<state::ServerCanCosign>())
	}
}

impl<'a> CheckpointedArkoorBuilder<'a, state::ServerCanCosign> {

	pub fn from_cosign_request(cosign_request: &'a CosignRequest) -> Result<CheckpointedArkoorBuilder<'a, state::ServerCanCosign>, ArkoorSigningError> {
		CheckpointedArkoorBuilder::new(
				&cosign_request.input,
				cosign_request.outputs.clone())
			.map_err(ArkoorSigningError::ArkoorConstructionError)?
			.set_user_pub_nonces(cosign_request.user_pub_nonces.clone())

	}

	pub fn server_cosign(mut self, server_keypair: Keypair) -> Result<CheckpointedArkoorBuilder<'a, state::ServerSigned>, ArkoorSigningError> {
		// Verify that the provided keypair is correct
		if server_keypair.public_key() != self.input.server_pubkey() {
			return Err(ArkoorSigningError::IncorrectKey {
				expected: self.input.server_pubkey(),
				got: server_keypair.public_key(),
			});
		}

		let mut server_pub_nonces = Vec::with_capacity(self.outputs.len() + 1);
		let mut server_partial_sigs = Vec::with_capacity(self.outputs.len() + 1);

		for idx in 0..self.nb_sigs() {
			let (server_pub_nonce, server_partial_sig) = musig::deterministic_partial_sign(
				&server_keypair,
				[self.input.user_pubkey()],
				&[&self.user_pub_nonces.as_ref().expect("state-invariant")[idx]],
				self.sighashes[idx].to_byte_array(),
				Some(self.taptweak_at(idx).to_byte_array()),
			);

			server_pub_nonces.push(server_pub_nonce);
			server_partial_sigs.push(server_partial_sig);
		};

		self.server_pub_nonces = Some(server_pub_nonces);
		self.server_partial_sigs = Some(server_partial_sigs);
		Ok(self.to_state::<state::ServerSigned>())
	}

}

impl<'a> CheckpointedArkoorBuilder<'a, state::ServerSigned> {

	pub fn user_pub_nonces(&self) -> Vec<musig::PublicNonce> {
		self.user_pub_nonces.as_ref().expect("state invariant").clone()
	}

	pub fn server_partial_signatures(&self) -> Vec<musig::PartialSignature> {
		self.server_partial_sigs.as_ref().expect("state invariant").clone()
	}

	pub fn cosign_response(&self) -> CosignResponse {
		CosignResponse {
			server_pub_nonces: self.server_pub_nonces.as_ref().expect("state invariant").clone(),
			server_partial_sigs: self.server_partial_sigs.as_ref().expect("state invariant").clone(),
		}
	}
}

impl<'a> CheckpointedArkoorBuilder<'a, state::UserGeneratedNonces> {

	pub fn user_pub_nonces(&self) -> &[PublicNonce] {
		self.user_pub_nonces.as_ref().expect("State invariant")
	}

	pub fn cosign_request(&'a self) -> CosignRequest<'a> {
		CosignRequest {
			user_pub_nonces: self.user_pub_nonces.as_ref().expect("state invariant").clone(),
			input: Cow::Borrowed(self.input),
			outputs: self.outputs.clone(),
		}
	}

	fn validate_server_cosign_response(
		&self,
		data: &CosignResponse,
	) -> Result<(), ArkoorSigningError> {

		// Check if the correct number of nonces is provided
		if data.server_pub_nonces.len() != self.nb_sigs() {
			return Err(ArkoorSigningError::InvalidNbServerNonces {
				expected: self.nb_sigs(),
				got: data.server_pub_nonces.len(),
			});
		}

		if data.server_partial_sigs.len() != self.nb_sigs() {
			return Err(ArkoorSigningError::InvalidNbServerPartialSigs {
				expected: self.nb_sigs(),
				got: data.server_partial_sigs.len(),
			})
		}

		// Check if the partial signatures is valid
		for idx in 0..self.nb_sigs() {
			let is_valid_sig = scripts::verify_partial_sig(
				self.sighashes[idx],
				self.taptweak_at(idx),
				(self.input.server_pubkey(), &data.server_pub_nonces[idx]),
				(self.input.user_pubkey(), &self.user_pub_nonces()[idx]),
				&data.server_partial_sigs[idx]
			);

			if !is_valid_sig {
				return Err(ArkoorSigningError::InvalidPartialSignature {
					index: idx,
				});
			}
		}
		Ok(())
	}

	pub fn user_cosign(
		mut self,
		user_keypair: &Keypair,
		server_cosign_data: &CosignResponse,
	) -> Result<CheckpointedArkoorBuilder<'a, state::UserSigned>, ArkoorSigningError> {
		// Verify that the correct user keypair is provided
		if user_keypair.public_key() != self.input.user_pubkey() {
			return Err(ArkoorSigningError::IncorrectKey {
				expected: self.input.user_pubkey(),
				got: user_keypair.public_key(),
			});
		}

		// Verify that the server cosign data is valid
		self.validate_server_cosign_response(&server_cosign_data)?;

		let mut sigs = Vec::with_capacity(self.nb_sigs());

		// Takes the secret nonces out of the [CheckpointedArkoorBuilder].
		// Note, that we can't clone nonces so we can only sign once
		let user_sec_nonces = self.user_sec_nonces.take().expect("state invariant");

		for (idx, user_sec_nonce) in user_sec_nonces.into_iter().enumerate() {
			let user_pub_nonce = self.user_pub_nonces()[idx];
			let server_pub_nonce = server_cosign_data.server_pub_nonces[idx];
			let agg_nonce = musig::nonce_agg(&[&user_pub_nonce, &server_pub_nonce]);

			let (_partial, maybe_sig) = musig::partial_sign(
				[self.user_pubkey(), self.server_pubkey()],
				agg_nonce,
				&user_keypair,
				user_sec_nonce,
				self.sighashes[idx].to_byte_array(),
				Some(self.taptweak_at(idx).to_byte_array()),
				Some(&[&server_cosign_data.server_partial_sigs[idx]])
			);

			let sig = maybe_sig.expect("The full signature exists. The server did sign first");
			sigs.push(sig);
		}


		self.full_signatures = Some(sigs);

		Ok(self.to_state::<state::UserSigned>())
	}
}


impl<'a> CheckpointedArkoorBuilder<'a, state::UserSigned> {

	pub fn build_signed_vtxos(&self) -> Vec<Vtxo> {
		let checkpoint_sig = self.full_signatures.as_ref().expect("state invariant")[0];
		let arkoor_sigs = &self.full_signatures.as_ref().expect("state invariant")[1..];

		(0..self.nb_outputs()).map(|i| {
			self.vtxo_at(i, Some(checkpoint_sig), Some(arkoor_sigs[i]))
		}).collect()
	}
}

impl<'a, S: state::BuilderState> CheckpointedArkoorBuilder<'a, S> {
}




#[cfg(test)]
mod test {
	use super::*;

	use bitcoin::Amount;
	use bitcoin::secp256k1::Keypair;
	use bitcoin::secp256k1::rand;

	use crate::SECP;
	use crate::VtxoRequest;
	use crate::test::dummy::DummyTestVtxoSpec;


	#[test]
	fn build_checkpointed_arkoor() {
		let alice_keypair = Keypair::new(&SECP, &mut rand::thread_rng());
		let bob_keypair = Keypair::new(&SECP, &mut rand::thread_rng());
		let server_keypair = Keypair::new(&SECP, &mut rand::thread_rng());

		println!("Alice keypair: {}", alice_keypair.public_key());
		println!("Bob keypair: {}", bob_keypair.public_key());
		println!("Server keypair: {}", server_keypair.public_key());
		println!("-----------------------------------------------");

		let (funding_tx, alice_vtxo) = DummyTestVtxoSpec {
			amount: Amount::from_sat(100_000),
			expiry_height: 1000,
			exit_delta : 128,
			user_keypair: alice_keypair.clone(),
			server_keypair: server_keypair.clone()
		}.build();

		// Validate Alice her vtxo
		alice_vtxo.validate(&funding_tx).expect("The unsigned vtxo is valid");

		let vtxo_request = vec![
			VtxoRequest {
				amount: Amount::from_sat(96_000),
				policy: VtxoPolicy::new_pubkey(bob_keypair.public_key())
			},
			VtxoRequest {
				amount: Amount::from_sat(4_000),
				policy: VtxoPolicy::new_pubkey(alice_keypair.public_key())
			}
		];

		// The user generates their nonces
		let user_builder = CheckpointedArkoorBuilder::new(
			&alice_vtxo,
			vtxo_request.clone(),
		).expect("Valid arkoor request");

		// At this point all out-of-round transactions are fully defined.
		// They are just missing the required signatures.
		// We are already able to compute the vtxos and validate them
		let _unsigned_vtxos = user_builder.build_unsigned_vtxos();


		// The user generates their nonces
		let user_builder =user_builder.generate_user_nonces(alice_keypair);
		let cosign_request = user_builder.cosign_request();

		// The server will cosign the request
		let server_builder = CheckpointedArkoorBuilder::from_cosign_request(&cosign_request).expect("Invalid cosign request")
			.server_cosign(server_keypair).expect("Incorrect key");

		let cosign_data = server_builder.cosign_response();

		// The user will cosign the request and construct their vtxos
		let vtxos = user_builder
			.user_cosign(&alice_keypair, &cosign_data)
			.expect("Valid cosign data and correct key")
			.build_signed_vtxos();

		for vtxo in vtxos.into_iter() {
			// Check if the vtxo is considered valid
			vtxo.validate(&funding_tx).expect("Invalid VTXO");

			// Check all transactions using libbitcoin-kernel
			let mut prev_tx = funding_tx.clone();
			for tx in vtxo.transactions().map(|item| item.tx) {
				let prev_outpoint: OutPoint = tx.input[0].previous_output;
				let prev_txout: TxOut = prev_tx.output[prev_outpoint.vout as usize].clone();
				crate::test::verify_tx(&[prev_txout], 0, &tx).expect("Valid transaction");
				prev_tx = tx;
			}
		}

	}
}

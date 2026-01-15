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
//! server signs first.
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

use std::marker::PhantomData;

use bitcoin::hashes::Hash;
use bitcoin::{Amount, OutPoint, TapSighash, Transaction, Txid, TxIn, TxOut, ScriptBuf, Sequence, Witness};
use bitcoin::taproot::TapTweakHash;
use bitcoin::secp256k1::{schnorr, Keypair, PublicKey};
use bitcoin_ext::{P2TR_DUST, TxOutExt, fee};
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
pub struct CosignRequest<V> {
	pub user_pub_nonces: Vec<musig::PublicNonce>,
	pub input: V,
	pub outputs: Vec<VtxoRequest>,
	pub dust_outputs: Vec<VtxoRequest>,
	pub use_checkpoint: bool,
}

impl<V> CosignRequest<V> {
	pub fn new(
		user_pub_nonces: Vec<musig::PublicNonce>,
		input: V,
		outputs: Vec<VtxoRequest>,
		dust_outputs: Vec<VtxoRequest>,
		use_checkpoint: bool,
	) -> Self {
		Self {
			user_pub_nonces,
			input,
			outputs,
			dust_outputs,
			use_checkpoint,
		}
	}
}

impl CosignRequest<VtxoId> {
	pub fn with_vtxo(self, vtxo: Vtxo) -> Result<CosignRequest<Vtxo>, &'static str> {
		if self.input != vtxo.id() {
			return Err("Input vtxo id does not match the provided vtxo id")
		}

		Ok(CosignRequest::new(
			self.user_pub_nonces,
			vtxo,
			self.outputs,
			self.dust_outputs,
			self.use_checkpoint,
		))
	}
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

pub struct CheckpointedArkoorBuilder<S: state::BuilderState> {
	// These variables are provided by the user
	/// The input vtxo to be spent
	input: Vtxo,
	/// regular output [VtxoRequest]s that the user wants to receive
	/// if the input is dust, these can be dust
	outputs: Vec<VtxoRequest>,
	/// dusty [VtxoRequest]s that the user wants to receive (< P2TR_DUST)
	dust_outputs: Vec<VtxoRequest>,

	/// Data on the checkpoint tx, if checkpoints are enabled
	///
	/// - the unsigned checkpoint transaction
	/// - the taptweak to sign the checkpoint tx
	checkpoint_data: Option<(Transaction, Txid, TapTweakHash)>,
	/// The unsigned arkoor transactions (one per non-dust output)
	unsigned_arkoor_txs: Vec<Transaction>,
	/// The unsigned dust fanout transaction (only when dust isolation is needed)
	/// Splits the combined dust checkpoint output into k outputs with checkpoint policy
	unsigned_dust_fanout_tx: Option<Transaction>,
	/// The unsigned exit transactions (only when dust isolation is needed)
	/// One per dust output, creates final vtxo with user's requested policy
	unsigned_dust_exit_txs: Option<Vec<Transaction>>,
	/// The sighashes that must be signed
	sighashes: Vec<TapSighash>,
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

impl<S: state::BuilderState> CheckpointedArkoorBuilder<S> {
	fn checkpoint_vtxo_at(
		&self,
		output_idx: usize,
		checkpoint_sig: Option<schnorr::Signature>
	) -> Vtxo {
		let output = &self.outputs[output_idx];
		let (checkpoint_tx, checkpoint_txid, _tweak) = self.checkpoint_data.as_ref()
			.expect("called checkpoint_vtxo_at in context without checkpoints");

		Vtxo {
			amount: output.amount,
			policy: VtxoPolicy::new_checkpoint(self.input.user_pubkey()),
			expiry_height: self.input.expiry_height,
			server_pubkey: self.input.server_pubkey,
			exit_delta: self.input.exit_delta,
			point: OutPoint::new(*checkpoint_txid, output_idx as u32),
			anchor_point: self.input.anchor_point,
			genesis: self.input.genesis.clone().into_iter().chain([
				GenesisItem {
					transition: GenesisTransition::Arkoor {
						policy: self.input.policy.clone(),
						signature: checkpoint_sig,
					},
					output_idx: output_idx as u8,
					other_outputs: checkpoint_tx.output
						.iter().enumerate()
						.filter_map(|(i, txout)| {
							if i == (output_idx as usize) || txout.is_p2a_fee_anchor() {
								None
							} else {
								Some(txout.clone())
							}
						})
						.collect(),
				},
			]).collect(),
		}
	}

	fn vtxo_at(
		&self,
		output_idx: usize,
		checkpoint_sig: Option<schnorr::Signature>,
		arkoor_sig: Option<schnorr::Signature>,
	) -> Vtxo {
		let output = &self.outputs[output_idx];

		if let Some((checkpoint_tx, _txid, _tweak)) = &self.checkpoint_data {
			// Two-transition genesis: Input → Checkpoint → Arkoor
			let checkpoint_policy = VtxoPolicy::new_checkpoint(self.input.user_pubkey());

			Vtxo {
				amount: output.amount,
				policy: output.policy.clone(),
				expiry_height: self.input.expiry_height,
				server_pubkey: self.input.server_pubkey,
				exit_delta: self.input.exit_delta,
				point: self.new_vtxo_ids[output_idx].utxo(),
				anchor_point: self.input.anchor_point,
				genesis: self.input.genesis.iter().cloned().chain([
					GenesisItem {
						transition: GenesisTransition::Arkoor {
							policy: self.input.policy.clone(),
							signature: checkpoint_sig,
						},
						output_idx: output_idx as u8,
						other_outputs: checkpoint_tx.output
							.iter().enumerate()
							.filter_map(|(i, txout)| {
								if i == (output_idx as usize) || txout.is_p2a_fee_anchor() {
									None
								} else {
									Some(txout.clone())
								}
							})
							.collect(),
					},
					GenesisItem {
						transition: GenesisTransition::Arkoor {
							policy: checkpoint_policy,
							signature: arkoor_sig,
						},
						output_idx: 0,
						other_outputs: vec![]
					}
				]).collect(),
			}
		} else {
			// Single-transition genesis: Input → Arkoor
			let arkoor_tx = &self.unsigned_arkoor_txs[0];

			Vtxo {
				amount: output.amount,
				policy: output.policy.clone(),
				expiry_height: self.input.expiry_height,
				server_pubkey: self.input.server_pubkey,
				exit_delta: self.input.exit_delta,
				point: OutPoint::new(arkoor_tx.compute_txid(), output_idx as u32),
				anchor_point: self.input.anchor_point,
				genesis: self.input.genesis.iter().cloned().chain([
					GenesisItem {
						transition: GenesisTransition::Arkoor {
							policy: self.input.policy.clone(),
							signature: arkoor_sig,
						},
						output_idx: output_idx as u8,
						other_outputs: arkoor_tx.output
							.iter().enumerate()
							.filter_map(|(idx, txout)| {
								if idx == output_idx || txout.is_p2a_fee_anchor() {
									None
								} else {
									Some(txout.clone())
								}
							})
							.collect(),
					}
				]).collect(),
			}
		}
	}

	/// Build a dust vtxo at the given index (into dust_outputs)
	///
	/// Only used when dust isolation is active.
	///
	/// The `pre_fanout_tx_sig` is either
	/// - the arkoor tx signature when no checkpoint tx is used, or
	/// - the checkpoint tx signature when a checkpoint tx is used
	fn construct_dust_vtxo_at(
		&self,
		dust_idx: usize,
		pre_fanout_tx_sig: Option<schnorr::Signature>,
		dust_fanout_tx_sig: Option<schnorr::Signature>,
		exit_tx_sig: Option<schnorr::Signature>,
	) -> Vtxo {
		let output = &self.dust_outputs[dust_idx];
		let checkpoint_policy = VtxoPolicy::new_checkpoint(self.input.user_pubkey());

		let fanout_tx = self.unsigned_dust_fanout_tx.as_ref()
			.expect("construct_dust_vtxo_at called without dust isolation");
		let exit_txs = self.unsigned_dust_exit_txs.as_ref()
			.expect("construct_dust_vtxo_at called without dust isolation");

		// The combined dust output is at index outputs.len()
		let dust_isolation_output_idx = self.outputs.len();

		if let Some((checkpoint_tx, _txid, _tweak)) = &self.checkpoint_data {
			// Three transitions: Input → Checkpoint → Dust Fanout → Exit
			Vtxo {
				amount: output.amount,
				policy: output.policy.clone(),
				expiry_height: self.input.expiry_height,
				server_pubkey: self.input.server_pubkey,
				exit_delta: self.input.exit_delta,
				point: OutPoint::new(exit_txs[dust_idx].compute_txid(), 0),
				anchor_point: self.input.anchor_point,
				genesis: self.input.genesis.iter().cloned().chain([
					// Transition 1: input -> checkpoint
					GenesisItem {
						transition: GenesisTransition::Arkoor {
							policy: self.input.policy.clone(),
							signature: pre_fanout_tx_sig,
						},
						output_idx: dust_isolation_output_idx as u8,
						// other outputs are the non-dust outputs
						// (we skip our combined dust output and fee anchor)
						other_outputs: checkpoint_tx.output
							.iter().enumerate()
							.filter_map(|(idx, txout)| {
								if idx == dust_isolation_output_idx || txout.is_p2a_fee_anchor() {
									None
								} else {
									Some(txout.clone())
								}
							})
							.collect(),
					},
					// Transition 2: checkpoint -> dust fanout tx
					GenesisItem {
						transition: GenesisTransition::Arkoor {
							policy: checkpoint_policy.clone(),
							signature: dust_fanout_tx_sig,
						},
						output_idx: dust_idx as u8,
						// other outputs are the other dust outputs
						// (we skip our output and fee anchor)
						other_outputs: fanout_tx.output
							.iter().enumerate()
							.filter_map(|(idx, txout)| {
								if idx == dust_idx || txout.is_p2a_fee_anchor() {
									None
								} else {
									Some(txout.clone())
								}
							})
							.collect(),
					},
					// Transition 3: dust fanout tx -> exit_tx (final vtxo)
					GenesisItem {
						transition: GenesisTransition::Arkoor {
							policy: checkpoint_policy,
							signature: exit_tx_sig,
						},
						output_idx: 0,
						other_outputs: vec![]
					}
				]).collect(),
			}
		} else {
			// Three transitions: Input → Arkoor (with isolation output) → Dust Fanout → Exit
			let arkoor_tx = &self.unsigned_arkoor_txs[0];

			Vtxo {
				amount: output.amount,
				policy: output.policy.clone(),
				expiry_height: self.input.expiry_height,
				server_pubkey: self.input.server_pubkey,
				exit_delta: self.input.exit_delta,
				point: OutPoint::new(exit_txs[dust_idx].compute_txid(), 0),
				anchor_point: self.input.anchor_point,
				genesis: self.input.genesis.iter().cloned().chain([
					// Transition 1: input -> arkoor tx (which includes isolation output)
					GenesisItem {
						transition: GenesisTransition::Arkoor {
							policy: self.input.policy.clone(),
							signature: pre_fanout_tx_sig,  // Note: In build_signed_vtxos, this is the arkoor_sig
						},
						output_idx: dust_isolation_output_idx as u8,
						other_outputs: arkoor_tx.output
							.iter().enumerate()
							.filter_map(|(idx, txout)| {
								if idx == dust_isolation_output_idx || txout.is_p2a_fee_anchor() {
									None
								} else {
									Some(txout.clone())
								}
							})
							.collect(),
					},
					// Transition 2: isolation output -> dust fanout
					GenesisItem {
						transition: GenesisTransition::Arkoor {
							policy: checkpoint_policy.clone(),
							signature: dust_fanout_tx_sig,
						},
						output_idx: dust_idx as u8,
						other_outputs: fanout_tx.output
							.iter().enumerate()
							.filter_map(|(idx, txout)| {
								if idx == dust_idx || txout.is_p2a_fee_anchor() {
									None
								} else {
									Some(txout.clone())
								}
							})
							.collect(),
					},
					// Transition 3: dust fanout -> exit
					GenesisItem {
						transition: GenesisTransition::Arkoor {
							policy: checkpoint_policy,
							signature: exit_tx_sig,
						},
						output_idx: 0,
						other_outputs: vec![]
					}
				]).collect(),
			}
		}
	}

	fn nb_sigs(&self) -> usize {
		let base = if self.checkpoint_data.is_some() {
			1 + self.outputs.len()  // 1 checkpoint + m arkoor txs
		} else {
			1  // 1 direct arkoor tx (regardless of output count)
		};

		if self.unsigned_dust_fanout_tx.is_some() {
			base + 1 + self.dust_outputs.len()
		} else {
			base
		}
	}

	//TODO(stevenroose) check if used and maybe add dust
	fn nb_outputs(&self) -> usize {
		self.outputs.len()
	}

	pub fn build_unsigned_vtxos<'a>(&'a self) -> impl Iterator<Item = Vtxo> + 'a {
		(0..self.nb_outputs()).map(|i| self.vtxo_at(i, None, None))
	}

	/// Build unsigned dust vtxos (only when dust isolation is active)
	pub fn build_unsigned_dust_vtxos<'a>(&'a self) -> impl Iterator<Item = Vtxo> + 'a {
		(0..self.dust_outputs.len()).map(|i| self.construct_dust_vtxo_at(i, None, None, None))
	}

	pub fn build_unsigned_checkpoint_vtxos<'a>(&'a self) -> impl Iterator<Item = Vtxo> + 'a {
		(0..self.nb_outputs()).map(|i| self.checkpoint_vtxo_at(i, None))
	}

	/// The returned [VtxoId] is spent out-of-round by [Txid]
	pub fn spend_info(&self) -> Vec<(VtxoId, Txid)> {
		let mut ret = Vec::with_capacity(1 + self.nb_outputs());

		if let Some((_tx, checkpoint_txid, _tweak)) = &self.checkpoint_data {
			// Input vtxo -> checkpoint tx
			ret.push((self.input.id(), *checkpoint_txid));

			// Non-dust checkpoint outputs -> arkoor txs
			for idx in 0..self.nb_outputs() {
				ret.push((
					VtxoId::from(OutPoint::new(*checkpoint_txid, idx as u32)),
					self.unsigned_arkoor_txs[idx].compute_txid()
				));
			}

			// dust isolation paths (if active)
			if let (Some(fanout_tx), Some(exit_txs))
				= (&self.unsigned_dust_fanout_tx, &self.unsigned_dust_exit_txs)
			{
				let fanout_txid = fanout_tx.compute_txid();

				// Combined dust checkpoint output -> dust fanout tx
				let dust_output_idx = self.outputs.len() as u32;
				ret.push((
					VtxoId::from(OutPoint::new(*checkpoint_txid, dust_output_idx)),
					fanout_txid
				));

				// dust fanout tx outputs -> exit_txs
				for (idx, exit_tx) in exit_txs.iter().enumerate() {
					ret.push((
						VtxoId::from(OutPoint::new(fanout_txid, idx as u32)),
						exit_tx.compute_txid()
					));
				}
			}
		} else {
			let arkoor_txid = self.unsigned_arkoor_txs[0].compute_txid();

			// Input vtxo -> arkoor tx
			ret.push((self.input.id(), arkoor_txid));

			// dust isolation paths (if active)
			if let (Some(fanout_tx), Some(exit_txs))
				= (&self.unsigned_dust_fanout_tx, &self.unsigned_dust_exit_txs)
			{
				let fanout_txid = fanout_tx.compute_txid();

				// Isolation output in arkoor tx -> dust fanout
				let dust_output_idx = self.outputs.len() as u32;
				ret.push((
					VtxoId::from(OutPoint::new(arkoor_txid, dust_output_idx)),
					fanout_txid
				));

				// Dust fanout outputs -> exit txs
				for (idx, exit_tx) in exit_txs.iter().enumerate() {
					ret.push((
						VtxoId::from(OutPoint::new(fanout_txid, idx as u32)),
						exit_tx.compute_txid()
					));
				}
			}
		}

		ret
	}

	/// These are the intermediate Vtxos that will be owned by the server
	///
	/// The tuples represent a [Vtxo] which is spent out-of-round
	/// by [Txid]
	pub fn checkpoint_spend_info(&self) -> Vec<(Vtxo, Txid)> {
		if self.checkpoint_data.is_none() {
			return vec![];
		}

		let mut result = Vec::with_capacity(self.nb_outputs());

		for idx in 0..self.nb_outputs() {
			let vtxo = self.checkpoint_vtxo_at(idx, None);
			result.push((vtxo, self.new_vtxo_ids[idx].utxo().txid))
		}

		result
	}

	fn taptweak_at(&self, idx: usize) -> TapTweakHash {
		if let Some((_tx, _txid, checkpoint_tweak)) = &self.checkpoint_data {
			if idx == 0 {
				*checkpoint_tweak
			} else {
				self.arkoor_taptweak
			}
		} else {
			self.arkoor_taptweak
		}
	}

	fn user_pubkey(&self) -> PublicKey {
		self.input.user_pubkey()
	}

	fn server_pubkey(&self) -> PublicKey {
		self.input.server_pubkey()
	}

	/// Construct the checkpoint transaction.
	/// When dust isolation is needed, `combined_dust_amount` should be Some with the total dust amount.
	fn construct_unsigned_checkpoint_tx(
		input: &Vtxo,
		outputs: &[VtxoRequest],
		dust_isolation_amount: Option<Amount>,
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
			})
				// add dust isolation output when required
				.chain(dust_isolation_amount.map(|amt| {
					TxOut {
						value: amt,
						script_pubkey: checkpoint_spk.clone(),
					}
				}))
				.chain([fee::fee_anchor()]).collect()
		}
	}

	fn construct_unsigned_arkoor_txs(
		input: &Vtxo,
		outputs: &[VtxoRequest],
		checkpoint_txid: Option<Txid>,
		dust_isolation_amount: Option<Amount>,
	) -> Vec<Transaction> {
		if let Some(checkpoint_txid) = checkpoint_txid {
			// Checkpoint mode: create separate arkoor tx for each output
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
		} else {
			// Direct mode: create single arkoor tx with all outputs + optional isolation output
			let checkpoint_policy = VtxoPolicy::new_checkpoint(input.user_pubkey());
			let checkpoint_spk = checkpoint_policy.script_pubkey(
				input.server_pubkey(),
				input.exit_delta(),
				input.expiry_height()
			);

			let transaction = Transaction {
				version: bitcoin::transaction::Version(3),
				lock_time: bitcoin::absolute::LockTime::ZERO,
				input: vec![TxIn {
					previous_output: input.point(),
					script_sig: ScriptBuf::new(),
					sequence: Sequence::ZERO,
					witness: Witness::new(),
				}],
				output: outputs.iter()
					.map(|o| o.policy.txout(o.amount, input.server_pubkey(), input.exit_delta(), input.expiry_height()))
					// Add isolation output if dust is present
					.chain(dust_isolation_amount.map(|amt| TxOut {
						value: amt,
						script_pubkey: checkpoint_spk.clone(),
					}))
					.chain([fee::fee_anchor()])
					.collect()
			};
			vec![transaction]
		}
	}

	/// Construct the dust isolation transaction that splits the combined
	/// dust output into individual outputs
	///
	/// Each output uses checkpoint policy (not the user's final policy).
	/// Called only when dust isolation is needed.
	///
	/// `parent_txid` is either the checkpoint txid (checkpoint mode) or arkoor txid (direct mode)
	fn construct_unsigned_dust_fanout_tx(
		input: &Vtxo,
		dust_outputs: &[VtxoRequest],
		parent_txid: Txid,  // Either checkpoint txid or arkoor txid
		dust_isolation_output_vout: u32,  // Output index containing the dust isolation output
	) -> Transaction {
		// All outputs on the dust transaction will use exactly the same policy (checkpoint).
		let output_policy = VtxoPolicy::new_checkpoint(input.user_pubkey());
		let checkpoint_spk = output_policy.script_pubkey(input.server_pubkey(), input.exit_delta(), input.expiry_height());

		let mut tx_outputs: Vec<TxOut> = dust_outputs.iter().map(|o| {
			TxOut {
				value: o.amount,
				script_pubkey: checkpoint_spk.clone(),
			}
		}).collect();

		// Add fee anchor
		tx_outputs.push(fee::fee_anchor());

		Transaction {
			version: bitcoin::transaction::Version(3),
			lock_time: bitcoin::absolute::LockTime::ZERO,
			input: vec![TxIn {
				previous_output: OutPoint::new(parent_txid, dust_isolation_output_vout),
				script_sig: ScriptBuf::new(),
				sequence: Sequence::ZERO,
				witness: Witness::new(),
			}],
			output: tx_outputs,
		}
	}

	/// Construct the exit transactions for dust isolation
	///
	/// Each exit tx takes one output from the dust fanout tx and creates
	/// the final vtxo with user's policy.
	/// Called only when dust isolation is needed.
	fn construct_unsigned_dust_exit_txs(
		input: &Vtxo,
		dust_outputs: &[VtxoRequest],
		dust_fanout_tx: &Transaction,
	) -> Vec<Transaction> {
		let fanout_txid = dust_fanout_tx.compute_txid();

		dust_outputs.iter().enumerate().map(|(vout, output)| {
			Transaction {
				version: bitcoin::transaction::Version(3),
				lock_time: bitcoin::absolute::LockTime::ZERO,
				input: vec![TxIn {
					previous_output: OutPoint::new(fanout_txid, vout as u32),
					script_sig: ScriptBuf::new(),
					sequence: Sequence::ZERO,
					witness: Witness::new(),
				}],
				output: vec![
					// Final vtxo with user's requested policy
					output.policy.txout(
						output.amount,
						input.server_pubkey(),
						input.exit_delta(),
						input.expiry_height(),
					),
					fee::fee_anchor(),
				]
			}
		}).collect()
	}

	fn validate_amounts(
		input: &Vtxo,
		outputs: &[VtxoRequest],
		isolation_outputs: &[VtxoRequest],
	) -> Result<(), ArkoorConstructionError> {
		// Check if inputs and outputs are balanced
		// We need to build transactions that pay exactly 0 in onchain fees
		// to ensure our transaction with an ephemeral anchor is standard.
		// We need `==` for standardness and we can't be lenient
		let input_amount = input.amount();
		let output_amount = outputs.iter().chain(isolation_outputs.iter())
			.map(|o| o.amount).sum::<Amount>();

		if input_amount != output_amount {
			return Err(ArkoorConstructionError::Unbalanced {
				input: input_amount,
				output: output_amount,
			})
		}

		// If dust isolation is needed (mixed outputs),
		// - we don't allow dust outputs in the normal outputs
		// - the combined dust must be >= P2TR_DUST
		if !isolation_outputs.is_empty() {
			if outputs.iter().any(|o| o.amount < P2TR_DUST) {
				return Err(ArkoorConstructionError::Dust)
			}

			let dust_sum: Amount = isolation_outputs.iter().map(|o| o.amount).sum();
			if dust_sum < P2TR_DUST {
				return Err(ArkoorConstructionError::Dust)
			}
		} else {
			// without isolation they have to either be all dust or all non-dust
			let nb_dust = outputs.iter().filter(|o| o.amount < P2TR_DUST).count();
			if !(nb_dust == 0 || nb_dust == outputs.len()) {
				return Err(ArkoorConstructionError::Dust)
			}
		}

		Ok(())
	}


	fn to_state<S2: state::BuilderState>(self) -> CheckpointedArkoorBuilder<S2> {
		CheckpointedArkoorBuilder {
			input: self.input,
			outputs: self.outputs,
			dust_outputs: self.dust_outputs,
			checkpoint_data: self.checkpoint_data,
			unsigned_arkoor_txs: self.unsigned_arkoor_txs,
			unsigned_dust_fanout_tx: self.unsigned_dust_fanout_tx,
			unsigned_dust_exit_txs: self.unsigned_dust_exit_txs,
			new_vtxo_ids: self.new_vtxo_ids,
			sighashes: self.sighashes,
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

impl CheckpointedArkoorBuilder<state::Initial> {
	/// Create builder with checkpoint transaction
	pub fn new_with_checkpoint(
		input: Vtxo,
		outputs: Vec<VtxoRequest>,
		dust_outputs: Vec<VtxoRequest>,
	) -> Result<Self, ArkoorConstructionError> {
		Self::new(input, outputs, dust_outputs, true)
	}

	/// Create builder without checkpoint transaction
	pub fn new_without_checkpoint(
		input: Vtxo,
		outputs: Vec<VtxoRequest>,
		dust_outputs: Vec<VtxoRequest>,
	) -> Result<Self, ArkoorConstructionError> {
		Self::new(input, outputs, dust_outputs, false)
	}

	fn new(
		input: Vtxo,
		mut outputs: Vec<VtxoRequest>,
		mut dust_outputs: Vec<VtxoRequest>,
		use_checkpoint: bool,
	) -> Result<Self, ArkoorConstructionError> {
		// if there is only dust outputs, we just do a dust arkoor
		if outputs.is_empty() && !dust_outputs.is_empty() {
			std::mem::swap(&mut outputs, &mut dust_outputs);
		}

		// Do some validation on the amounts
		Self::validate_amounts(&input, &outputs, &dust_outputs)?;

		// Compute combined dust amount if dust isolation is needed
		let combined_dust_amount = if !dust_outputs.is_empty() {
			Some(dust_outputs.iter().map(|o| o.amount).sum())
		} else {
			None
		};

		// Conditionally construct checkpoint transaction
		let unsigned_checkpoint_tx = if use_checkpoint {
			let tx = Self::construct_unsigned_checkpoint_tx(
				&input,
				&outputs,
				combined_dust_amount,
			);
			let txid = tx.compute_txid();
			let taptweak = input.output_taproot().tap_tweak();
			Some((tx, txid, taptweak))
		} else {
			None
		};

		// Construct arkoor transactions
		let unsigned_arkoor_txs = Self::construct_unsigned_arkoor_txs(
			&input,
			&outputs,
			unsigned_checkpoint_tx.as_ref().map(|t| t.1),
			combined_dust_amount,
		);

		// Construct dust fanout tx and exit txs if dust isolation is needed
		let (unsigned_dust_fanout_tx, unsigned_dust_exit_txs) = if !dust_outputs.is_empty() {
			// Combined dust isolation output is at index outputs.len()
			// (after all non-dust outputs)
			let dust_isolation_output_vout = outputs.len() as u32;

			let parent_txid = if let Some((_tx, txid, _tweak)) = &unsigned_checkpoint_tx {
				*txid
			} else {
				unsigned_arkoor_txs[0].compute_txid()
			};

			let fanout_tx = Self::construct_unsigned_dust_fanout_tx(
				&input,
				&dust_outputs,
				parent_txid,
				dust_isolation_output_vout,
			);
			let exit_txs = Self::construct_unsigned_dust_exit_txs(
				&input,
				&dust_outputs,
				&fanout_tx,
			);
			(Some(fanout_tx), Some(exit_txs))
		} else {
			(None, None)
		};

		// Compute all vtx-ids
		let new_vtxo_ids = unsigned_arkoor_txs.iter()
			.map(|tx| OutPoint::new(tx.compute_txid(), 0))
			.map(|outpoint| VtxoId::from(outpoint))
			.collect();

		// Compute all sighashes
		let mut sighashes = Vec::new();

		if let Some((checkpoint_tx, _txid, _tweak)) = &unsigned_checkpoint_tx {
			// Checkpoint signature
			sighashes.push(arkoor_sighash(&input.txout(), checkpoint_tx));

			// Arkoor transaction signatures (one per tx)
			for vout in 0..outputs.len() {
				let prevout = checkpoint_tx.output[vout].clone();
				sighashes.push(arkoor_sighash(&prevout, &unsigned_arkoor_txs[vout]));
			}
		} else {
			// Single direct arkoor transaction signature
			sighashes.push(arkoor_sighash(&input.txout(), &unsigned_arkoor_txs[0]));
		}

		// Add dust sighashes
		if let Some(ref tx) = unsigned_dust_fanout_tx {
			let dust_output_vout = outputs.len();  // Same for both modes
			let prevout = if let Some((checkpoint_tx, _txid, _tweak)) = &unsigned_checkpoint_tx {
				checkpoint_tx.output[dust_output_vout].clone()
			} else {
				// In direct mode, it's the isolation output from the arkoor tx
				unsigned_arkoor_txs[0].output[dust_output_vout].clone()
			};
			sighashes.push(arkoor_sighash(&prevout, tx));
		}

		// Add exit txs sighashes if dust isolation is needed
		if let (Some(fanout_tx), Some(exit_txs))
			= (&unsigned_dust_fanout_tx, &unsigned_dust_exit_txs)
		{
			for (vout, exit_tx) in exit_txs.iter().enumerate() {
				let prevout = fanout_tx.output[vout].clone();
				sighashes.push(arkoor_sighash(&prevout, exit_tx));
			}
		}

		// Compute taptweaks
		let policy = VtxoPolicy::new_checkpoint(input.user_pubkey());
		let arkoor_taptweak = if use_checkpoint {
			policy.taproot(
				input.server_pubkey(),
				input.exit_delta(),
				input.expiry_height(),
			).tap_tweak()
		} else {
			// In direct mode, arkoor uses input's policy
			input.output_taproot().tap_tweak()
		};

		Ok(Self {
			input: input,
			outputs: outputs,
			dust_outputs: dust_outputs,
			sighashes: sighashes,
			arkoor_taptweak: arkoor_taptweak,
			checkpoint_data: unsigned_checkpoint_tx,
			unsigned_arkoor_txs: unsigned_arkoor_txs,
			unsigned_dust_fanout_tx: unsigned_dust_fanout_tx,
			unsigned_dust_exit_txs: unsigned_dust_exit_txs,
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
	pub fn generate_user_nonces(mut self, user_keypair: Keypair) -> CheckpointedArkoorBuilder<state::UserGeneratedNonces> {
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
	fn set_user_pub_nonces(mut self, user_pub_nonces: Vec<musig::PublicNonce>) -> Result<CheckpointedArkoorBuilder<state::ServerCanCosign>, ArkoorSigningError> {
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

impl<'a> CheckpointedArkoorBuilder<state::ServerCanCosign> {

	pub fn from_cosign_request(
		cosign_request: CosignRequest<Vtxo>,
	) -> Result<CheckpointedArkoorBuilder<state::ServerCanCosign>, ArkoorSigningError> {
		CheckpointedArkoorBuilder::new(
			cosign_request.input,
			cosign_request.outputs,
			cosign_request.dust_outputs,
			cosign_request.use_checkpoint,
		)
			.map_err(ArkoorSigningError::ArkoorConstructionError)?
			.set_user_pub_nonces(cosign_request.user_pub_nonces.clone())
	}

	pub fn server_cosign(mut self, server_keypair: Keypair) -> Result<CheckpointedArkoorBuilder<state::ServerSigned>, ArkoorSigningError> {
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

impl CheckpointedArkoorBuilder<state::ServerSigned> {

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

impl CheckpointedArkoorBuilder<state::UserGeneratedNonces> {

	pub fn user_pub_nonces(&self) -> &[PublicNonce] {
		self.user_pub_nonces.as_ref().expect("State invariant")
	}

	pub fn cosign_request(&self) -> CosignRequest<Vtxo> {
		CosignRequest {
			user_pub_nonces: self.user_pub_nonces().to_vec(),
			input: self.input.clone(),
			outputs: self.outputs.clone(),
			dust_outputs: self.dust_outputs.clone(),
			use_checkpoint: self.checkpoint_data.is_some(),
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
	) -> Result<CheckpointedArkoorBuilder<state::UserSigned>, ArkoorSigningError> {
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


impl<'a> CheckpointedArkoorBuilder<state::UserSigned> {

	pub fn build_signed_vtxos(&self) -> Vec<Vtxo> {
		let sigs = self.full_signatures.as_ref().expect("state invariant");
		let mut ret = Vec::with_capacity(self.outputs.len() + self.dust_outputs.len());

		if self.checkpoint_data.is_some() {
			let checkpoint_sig = sigs[0];

			// Build regular vtxos (signatures 1..1+m)
			for i in 0..self.outputs.len() {
				let arkoor_sig = sigs[1 + i];
				ret.push(self.vtxo_at(i, Some(checkpoint_sig), Some(arkoor_sig)));
			}

			// Build dust vtxos if present
			if self.unsigned_dust_fanout_tx.is_some() {
				let m = self.outputs.len();
				let dust_fanout_tx_sig = sigs[1 + m];

				for i in 0..self.dust_outputs.len() {
					let exit_tx_sig = sigs[2 + m + i];
					ret.push(self.construct_dust_vtxo_at(
						i,
						Some(checkpoint_sig),
						Some(dust_fanout_tx_sig),
						Some(exit_tx_sig),
					));
				}
			}
		} else {
			// Direct mode: no checkpoint signature
			let arkoor_sig = sigs[0];

			// Build regular vtxos (all use same arkoor signature)
			for i in 0..self.outputs.len() {
				ret.push(self.vtxo_at(i, None, Some(arkoor_sig)));
			}

			// Build dust vtxos if present
			if self.unsigned_dust_fanout_tx.is_some() {
				let dust_fanout_tx_sig = sigs[1];

				for i in 0..self.dust_outputs.len() {
					let exit_tx_sig = sigs[2 + i];
					ret.push(self.construct_dust_vtxo_at(
						i,
						Some(arkoor_sig),  // In direct mode, first sig is arkoor, not checkpoint
						Some(dust_fanout_tx_sig),
						Some(exit_tx_sig),
					));
				}
			}
		}

		ret
	}
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
		let user_builder = CheckpointedArkoorBuilder::new_with_checkpoint(
			alice_vtxo.clone(),
			vtxo_request.clone(),
			vec![], // no dust outputs
		).expect("Valid arkoor request");

		// At this point all out-of-round transactions are fully defined.
		// They are just missing the required signatures.
		// We are already able to compute the vtxos and validate them
		let _unsigned_vtxos = user_builder.build_unsigned_vtxos().collect::<Vec<_>>();


		// The user generates their nonces
		let user_builder =user_builder.generate_user_nonces(alice_keypair);
		let cosign_request = user_builder.cosign_request();

		// The server will cosign the request
		let server_builder = CheckpointedArkoorBuilder::from_cosign_request(cosign_request).expect("Invalid cosign request")
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

	#[test]
	fn build_checkpointed_arkoor_with_dust_isolation() {
		// Test mixed outputs: some dust, some non-dust
		// This should activate dust isolation
		let alice_keypair = Keypair::new(&SECP, &mut rand::thread_rng());
		let bob_keypair = Keypair::new(&SECP, &mut rand::thread_rng());
		let charlie_keypair = Keypair::new(&SECP, &mut rand::thread_rng());
		let server_keypair = Keypair::new(&SECP, &mut rand::thread_rng());

		let (funding_tx, alice_vtxo) = DummyTestVtxoSpec {
			amount: Amount::from_sat(100_000),
			expiry_height: 1000,
			exit_delta : 128,
			user_keypair: alice_keypair.clone(),
			server_keypair: server_keypair.clone()
		}.build();

		// Validate Alice her vtxo
		alice_vtxo.validate(&funding_tx).expect("The unsigned vtxo is valid");

		// Non-dust outputs (>= 330 sats)
		let outputs = vec![
			VtxoRequest {
				amount: Amount::from_sat(99_600),
				policy: VtxoPolicy::new_pubkey(bob_keypair.public_key())
			},
		];

		// dust outputs (< 330 sats each, but combined >= 330)
		let dust_outputs = vec![
			VtxoRequest {
				amount: Amount::from_sat(200),  // < 330, truly dust
				policy: VtxoPolicy::new_pubkey(charlie_keypair.public_key())
			},
			VtxoRequest {
				amount: Amount::from_sat(200),  // < 330, truly dust
				policy: VtxoPolicy::new_pubkey(alice_keypair.public_key())
			}
		];

		// The user generates their nonces
		let user_builder = CheckpointedArkoorBuilder::new_with_checkpoint(
			alice_vtxo.clone(),
			outputs.clone(),
			dust_outputs.clone(),
		).expect("Valid arkoor request with dust isolation");

		// Verify dust isolation is active
		assert!(user_builder.unsigned_dust_fanout_tx.is_some(), "Dust isolation should be active");
		assert!(user_builder.unsigned_dust_exit_txs.is_some(), "Dust exit txs should be present");
		assert_eq!(user_builder.unsigned_dust_exit_txs.as_ref().unwrap().len(), 2);

		// Check signature count: 1 checkpoint + 1 arkoor + 1 dust fanout + 2 exits = 5
		assert_eq!(user_builder.nb_sigs(), 5);

		// The user generates their nonces
		let user_builder = user_builder.generate_user_nonces(alice_keypair);
		let cosign_request = user_builder.cosign_request();

		// The server will cosign the request
		let server_builder = CheckpointedArkoorBuilder::from_cosign_request(cosign_request).expect("Invalid cosign request")
			.server_cosign(server_keypair).expect("Incorrect key");

		let cosign_data = server_builder.cosign_response();

		// The user will cosign the request and construct their vtxos
		let vtxos = user_builder
			.user_cosign(&alice_keypair, &cosign_data)
			.expect("Valid cosign data and correct key")
			.build_signed_vtxos();

		// Should have 3 vtxos: 1 non-dust + 2 dust
		assert_eq!(vtxos.len(), 3);

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

	#[test]
	fn build_checkpointed_arkoor_outputs_must_be_above_dust_if_mixed() {
		// Test that outputs in the outputs list must be >= P2TR_DUST
		let alice_keypair = Keypair::new(&SECP, &mut rand::thread_rng());
		let bob_keypair = Keypair::new(&SECP, &mut rand::thread_rng());
		let server_keypair = Keypair::new(&SECP, &mut rand::thread_rng());

		let (funding_tx, alice_vtxo) = DummyTestVtxoSpec {
			amount: Amount::from_sat(1000),
			expiry_height: 1000,
			exit_delta : 128,
			user_keypair: alice_keypair.clone(),
			server_keypair: server_keypair.clone()
		}.build();

		alice_vtxo.validate(&funding_tx).expect("The unsigned vtxo is valid");

		// only dust is allowed
		CheckpointedArkoorBuilder::new_with_checkpoint(
			alice_vtxo.clone(),
			vec![
				VtxoRequest {
					amount: Amount::from_sat(100),  // < 330 sats (P2TR_DUST)
					policy: VtxoPolicy::new_pubkey(bob_keypair.public_key())
				}; 10
			],
			vec![],
		).unwrap();

		// only dust in isolation is also allowed
		CheckpointedArkoorBuilder::new_with_checkpoint(
			alice_vtxo.clone(),
			vec![],
			vec![
				VtxoRequest {
					amount: Amount::from_sat(100),  // < 330 sats (P2TR_DUST)
					policy: VtxoPolicy::new_pubkey(bob_keypair.public_key())
				}; 10
			],
		).unwrap();

		// normal case: non-dust in normal outputs and dust in isolation
		CheckpointedArkoorBuilder::new_with_checkpoint(
			alice_vtxo.clone(),
			vec![
				VtxoRequest {
					amount: Amount::from_sat(330),  // >= 330 sats
					policy: VtxoPolicy::new_pubkey(alice_keypair.public_key())
				}; 2
			],
			vec![
				VtxoRequest {
					amount: Amount::from_sat(170),
					policy: VtxoPolicy::new_pubkey(alice_keypair.public_key())
				}; 2
			],
		).unwrap();

		// can't mix dust and non-dust in normal outputs
		let res_mixed = CheckpointedArkoorBuilder::new_with_checkpoint(
			alice_vtxo.clone(),
			vec![
				VtxoRequest {
					amount: Amount::from_sat(500),
					policy: VtxoPolicy::new_pubkey(alice_keypair.public_key())
				},
				VtxoRequest {
					amount: Amount::from_sat(300),
					policy: VtxoPolicy::new_pubkey(alice_keypair.public_key())
				}
			],
			vec![
				VtxoRequest {
					amount: Amount::from_sat(100),
					policy: VtxoPolicy::new_pubkey(alice_keypair.public_key())
				}; 2
			],
		);
		match res_mixed {
			Err(ArkoorConstructionError::Dust) => {},
			_ => panic!("Expected Dust error"),
		}
	}

	#[test]
	fn build_checkpointed_arkoor_dust_sum_too_small() {
		// Test mixed with dust_sum < P2TR_DUST → error
		let alice_keypair = Keypair::new(&SECP, &mut rand::thread_rng());
		let bob_keypair = Keypair::new(&SECP, &mut rand::thread_rng());
		let server_keypair = Keypair::new(&SECP, &mut rand::thread_rng());

		let (funding_tx, alice_vtxo) = DummyTestVtxoSpec {
			amount: Amount::from_sat(100_000),
			expiry_height: 1000,
			exit_delta : 128,
			user_keypair: alice_keypair.clone(),
			server_keypair: server_keypair.clone()
		}.build();

		alice_vtxo.validate(&funding_tx).expect("The unsigned vtxo is valid");

		// Non-dust outputs
		let outputs = vec![
			VtxoRequest {
				amount: Amount::from_sat(99_900),
				policy: VtxoPolicy::new_pubkey(bob_keypair.public_key())
			},
		];

		// dust outputs with combined sum < P2TR_DUST (330)
		let dust_outputs = vec![
			VtxoRequest {
				amount: Amount::from_sat(50),
				policy: VtxoPolicy::new_pubkey(alice_keypair.public_key())
			},
			VtxoRequest {
				amount: Amount::from_sat(50),
				policy: VtxoPolicy::new_pubkey(alice_keypair.public_key())
			}
		];

		// This should fail because combined dust < P2TR_DUST
		let result = CheckpointedArkoorBuilder::new_with_checkpoint(
			alice_vtxo.clone(),
			outputs.clone(),
			dust_outputs.clone(),
		);

		match result {
			Err(ArkoorConstructionError::Dust) => {},
			_ => panic!("Expected Dust error"),
		}
	}

	#[test]
	fn spend_dust_vtxo() {
		// Test the "all dust" case: create a 200 sat vtxo and split into two 100 sat outputs
		let alice_keypair = Keypair::new(&SECP, &mut rand::thread_rng());
		let bob_keypair = Keypair::new(&SECP, &mut rand::thread_rng());
		let server_keypair = Keypair::new(&SECP, &mut rand::thread_rng());

		// Create a 200 sat input vtxo (this is dust since 200 < 330)
		let (funding_tx, alice_vtxo) = DummyTestVtxoSpec {
			amount: Amount::from_sat(200),
			expiry_height: 1000,
			exit_delta: 128,
			user_keypair: alice_keypair.clone(),
			server_keypair: server_keypair.clone()
		}.build();

		alice_vtxo.validate(&funding_tx).expect("The unsigned vtxo is valid");

		// Split into two 100 sat outputs
		// outputs is empty, all outputs go to dust_outputs
		let outputs = vec![];
		let dust_outputs = vec![
			VtxoRequest {
				amount: Amount::from_sat(100),
				policy: VtxoPolicy::new_pubkey(bob_keypair.public_key())
			},
			VtxoRequest {
				amount: Amount::from_sat(100),
				policy: VtxoPolicy::new_pubkey(alice_keypair.public_key())
			}
		];

		let user_builder = CheckpointedArkoorBuilder::new_with_checkpoint(
			alice_vtxo.clone(),
			outputs,
			dust_outputs,
		).expect("Valid arkoor request for all-dust case");

		// Verify dust isolation is NOT active (all-dust case, no mixing)
		assert!(user_builder.unsigned_dust_fanout_tx.is_none(), "Dust isolation should NOT be active");

		// Check we have 2 outputs
		assert_eq!(user_builder.nb_outputs(), 2);

		// Check signature count: 1 checkpoint + 2 arkoor = 3
		assert_eq!(user_builder.nb_sigs(), 3);

		// The user generates their nonces
		let user_builder = user_builder.generate_user_nonces(alice_keypair);
		let cosign_request = user_builder.cosign_request();

		// The server will cosign the request
		let server_builder = CheckpointedArkoorBuilder::from_cosign_request(cosign_request)
			.expect("Invalid cosign request")
			.server_cosign(server_keypair)
			.expect("Incorrect key");

		let cosign_data = server_builder.cosign_response();

		// The user will cosign the request and construct their vtxos
		let vtxos = user_builder
			.user_cosign(&alice_keypair, &cosign_data)
			.expect("Valid cosign data and correct key")
			.build_signed_vtxos();

		// Should have 2 vtxos
		assert_eq!(vtxos.len(), 2);

		for vtxo in vtxos.into_iter() {
			// Check if the vtxo is considered valid
			vtxo.validate(&funding_tx).expect("Invalid VTXO");

			// Verify amount is 100 sats
			assert_eq!(vtxo.amount(), Amount::from_sat(100));

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

	#[test]
	fn spend_nondust_vtxo_to_dust() {
		// Test: take a 500 sat vtxo (above dust) and split into two 250 sat vtxos (below dust)
		// Input is non-dust, outputs are all dust - no dust isolation needed
		let alice_keypair = Keypair::new(&SECP, &mut rand::thread_rng());
		let bob_keypair = Keypair::new(&SECP, &mut rand::thread_rng());
		let server_keypair = Keypair::new(&SECP, &mut rand::thread_rng());

		// Create a 500 sat input vtxo (this is above P2TR_DUST of 330)
		let (funding_tx, alice_vtxo) = DummyTestVtxoSpec {
			amount: Amount::from_sat(500),
			expiry_height: 1000,
			exit_delta: 128,
			user_keypair: alice_keypair.clone(),
			server_keypair: server_keypair.clone()
		}.build();

		alice_vtxo.validate(&funding_tx).expect("The unsigned vtxo is valid");

		// Split into two 250 sat outputs (each below P2TR_DUST)
		// outputs is empty, all outputs go to dust_outputs
		let outputs = vec![];
		let dust_outputs = vec![
			VtxoRequest {
				amount: Amount::from_sat(250),
				policy: VtxoPolicy::new_pubkey(bob_keypair.public_key())
			},
			VtxoRequest {
				amount: Amount::from_sat(250),
				policy: VtxoPolicy::new_pubkey(alice_keypair.public_key())
			}
		];

		let user_builder = CheckpointedArkoorBuilder::new_with_checkpoint(
			alice_vtxo.clone(),
			outputs,
			dust_outputs,
		).expect("Valid arkoor request for non-dust to dust case");

		// Verify dust isolation is NOT active (all-dust case, no mixing)
		assert!(user_builder.unsigned_dust_fanout_tx.is_none(), "Dust isolation should NOT be active");

		// Check we have 2 outputs
		assert_eq!(user_builder.nb_outputs(), 2);

		// Check signature count: 1 checkpoint + 2 arkoor = 3
		assert_eq!(user_builder.nb_sigs(), 3);

		// The user generates their nonces
		let user_builder = user_builder.generate_user_nonces(alice_keypair);
		let cosign_request = user_builder.cosign_request();

		// The server will cosign the request
		let server_builder = CheckpointedArkoorBuilder::from_cosign_request(cosign_request)
			.expect("Invalid cosign request")
			.server_cosign(server_keypair)
			.expect("Incorrect key");

		let cosign_data = server_builder.cosign_response();

		// The user will cosign the request and construct their vtxos
		let vtxos = user_builder
			.user_cosign(&alice_keypair, &cosign_data)
			.expect("Valid cosign data and correct key")
			.build_signed_vtxos();

		// Should have 2 vtxos
		assert_eq!(vtxos.len(), 2);

		for vtxo in vtxos.into_iter() {
			// Check if the vtxo is considered valid
			vtxo.validate(&funding_tx).expect("Invalid VTXO");

			// Verify amount is 250 sats
			assert_eq!(vtxo.amount(), Amount::from_sat(250));

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

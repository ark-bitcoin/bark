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
}

impl<V> CosignRequest<V> {
	pub fn new(
		user_pub_nonces: Vec<musig::PublicNonce>,
		input: V,
		outputs: Vec<VtxoRequest>,
		dust_outputs: Vec<VtxoRequest>,
	) -> Self {
		Self {
			user_pub_nonces,
			input,
			outputs,
			dust_outputs,
		}
	}
}

impl CosignRequest<VtxoId> {
	pub fn with_vtxo(self, vtxo: Vtxo) -> Result<CosignRequest<Vtxo>, &'static str> {
		if self.input != vtxo.id() {
			return Err("Input vtxo id does not match the provided vtxo id")
		}

		Ok(CosignRequest::new(self.user_pub_nonces, vtxo, self.outputs, self.dust_outputs))
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
	/// non-dust [VtxoRequest]s that the user wants to receive (>= P2TR_DUST)
	outputs: Vec<VtxoRequest>,
	/// dusty [VtxoRequest]s that the user wants to receive (< P2TR_DUST)
	dust_outputs: Vec<VtxoRequest>,

	// These can be computed in the constructor
	/// The unsigned checkpoint transaction
	unsigned_checkpoint_tx: Transaction,
	unsigned_checkpoint_txid: Txid,
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

impl<S: state::BuilderState> CheckpointedArkoorBuilder<S> {

	fn checkpoint_vtxo_at(
		&self,
		output_idx: usize,
		checkpoint_sig: Option<schnorr::Signature>
	) -> Vtxo {
		let output = &self.outputs[output_idx];
		let checkpoint_txid = self.unsigned_checkpoint_tx.compute_txid();

		Vtxo {
			amount: output.amount,
			policy: VtxoPolicy::new_checkpoint(self.input.user_pubkey()),
			expiry_height: self.input.expiry_height,
			server_pubkey: self.input.server_pubkey,
			exit_delta: self.input.exit_delta,
			point: OutPoint::new(checkpoint_txid, output_idx as u32),
			anchor_point: self.input.anchor_point,
			genesis: self.input.genesis.clone().into_iter().chain([
				GenesisItem {
					transition: GenesisTransition::Arkoor { policy: self.input.policy.clone(), signature: checkpoint_sig },
					output_idx: output_idx as u8,
					other_outputs: self.unsigned_checkpoint_tx.output
						.iter().enumerate()
						.filter_map(|(iii, txout)| if iii == (output_idx as usize) || txout.is_p2a_fee_anchor() { None } else { Some(txout.clone()) })
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
		}
	}

	/// Build a dust vtxo at the given index (into dust_outputs)
	///
	/// Only used when dust isolation is active.
	/// Genesis chain has 3 transitions:
	/// 1. input -> checkpoint (with other outputs including combined dust)
	/// 2. checkpoint -> dust fanout tx (with other dust outputs)
	/// 3. dust fanout tx -> exit tx (final vtxo)
	fn construct_dust_vtxo_at(
		&self,
		dust_idx: usize,
		checkpoint_sig: Option<schnorr::Signature>,
		dust_fanout_tx_sig: Option<schnorr::Signature>,
		exit_tx_sig: Option<schnorr::Signature>,
	) -> Vtxo {
		let output = &self.dust_outputs[dust_idx];
		let checkpoint_policy = VtxoPolicy::new_checkpoint(self.input.user_pubkey());

		let fanout_tx = self.unsigned_dust_fanout_tx.as_ref()
			.expect("construct_dust_vtxo_at called without dust isolation");
		let exit_txs = self.unsigned_dust_exit_txs.as_ref()
			.expect("construct_dust_vtxo_at called without dust isolation");

		// The combined dust output is at index outputs.len() in the checkpoint tx
		let dust_isolation_output_idx = self.outputs.len();

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
						signature: checkpoint_sig,
					},
					output_idx: dust_isolation_output_idx as u8,
					// other outputs are the non-dust outputs
					// (we skip our combined dust output and fee anchor)
					other_outputs: self.unsigned_checkpoint_tx.output
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
	}


	fn nb_sigs(&self) -> usize {
		// 1 checkpoint + m arkoor txs + (if dust isolation: + 1 dust fanout tx + k exit txs)
		let base = 1 + self.outputs.len();
		if self.unsigned_dust_fanout_tx.is_some() {
			base + 1 + self.dust_outputs.len()
		} else {
			base
		}
	}

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

		// Input vtxo -> checkpoint tx
		ret.push((self.input.id(), self.unsigned_checkpoint_txid));

		// Non-dust checkpoint outputs -> arkoor txs
		for idx in 0..self.nb_outputs() {
			ret.push((
				VtxoId::from(OutPoint::new(self.unsigned_checkpoint_txid, idx as u32)),
				self.unsigned_arkoor_txs[idx].compute_txid()
			));
		}

		// dust isolation paths (if active)
		if let (Some(fanout_tx), Some(exit_txs))
			= (&self.unsigned_dust_fanout_tx, &self.unsigned_dust_exit_txs)
		{
			ret.reserve(1 + exit_txs.len());

			let fanout_txid = fanout_tx.compute_txid();

			// Combined dust checkpoint output -> dust fanout tx
			let dust_output_idx = self.outputs.len() as u32;
			ret.push((
				VtxoId::from(OutPoint::new(self.unsigned_checkpoint_txid, dust_output_idx)),
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

		ret
	}

	/// These are the intermediate Vtxos that will be owned by the server
	///
	/// The tuples represent a [Vtxo] which is spent out-of-round
	/// by [Txid]
	pub fn checkpoint_spend_info(&self) -> Vec<(Vtxo, Txid)> {
		let mut result = Vec::with_capacity(self.nb_outputs());

		for idx in 0..self.nb_outputs() {
			let vtxo = self.checkpoint_vtxo_at(idx, None);
			result.push((vtxo, self.new_vtxo_ids[idx].utxo().txid))
		}

		result
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

	/// Construct the dust isolation transaction that splits the combined
	/// dust output into individual outputs
	///
	/// Each output uses checkpoint policy (not the user's final policy).
	/// Called only when dust isolation is needed.
	fn construct_unsigned_dust_fanout_tx(
		input: &Vtxo,
		dust_outputs: &[VtxoRequest],
		checkpoint_txid: Txid,
		dust_isolation_output_vout: u32,
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
				previous_output: OutPoint::new(checkpoint_txid, dust_isolation_output_vout),
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

	/// Returns true if dust isolation is needed.
	/// Dust isolation is only needed when there's a MIX of dust and non-dust outputs.
	fn needs_dust_isolation(outputs: &[VtxoRequest], dust_outputs: &[VtxoRequest]) -> bool {
		!outputs.is_empty() && !dust_outputs.is_empty()
	}

	fn validate_amounts(
		input: &Vtxo,
		outputs: &[VtxoRequest],
		dust_outputs: &[VtxoRequest],
	) -> Result<(), ArkoorConstructionError> {
		// Check if inputs and outputs are balanced
		// We need to build transactions that pay exactly 0 in onchain fees
		// to ensure our transaction with an ephemeral anchor is standard.
		// We need `==` for standardness and we can't be lenient
		let input_amount = input.amount();
		let output_amount = outputs.iter().chain(dust_outputs.iter())
			.map(|o| o.amount).sum::<Amount>();

		if input_amount != output_amount {
			return Err(ArkoorConstructionError::Unbalanced {
				input: input_amount,
				output: output_amount,
			})
		}

		// Check if any non-dust output is actually below dust threshold
		if outputs.iter().any(|o| o.amount < P2TR_DUST) {
			return Err(ArkoorConstructionError::Dust)
		}

		// If dust isolation is needed (mixed outputs), the combined dust must be >= P2TR_DUST
		if Self::needs_dust_isolation(outputs, dust_outputs) {
			let dust_sum: Amount = dust_outputs.iter().map(|o| o.amount).sum();
			if dust_sum < P2TR_DUST {
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
			unsigned_checkpoint_tx: self.unsigned_checkpoint_tx,
			unsigned_checkpoint_txid: self.unsigned_checkpoint_txid,
			unsigned_arkoor_txs: self.unsigned_arkoor_txs,
			unsigned_dust_fanout_tx: self.unsigned_dust_fanout_tx,
			unsigned_dust_exit_txs: self.unsigned_dust_exit_txs,
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

impl CheckpointedArkoorBuilder<state::Initial> {

	/// Create a new checkpointed arkoor builder
	pub fn new(
		input: Vtxo,
		outputs: Vec<VtxoRequest>,
		dust_outputs: Vec<VtxoRequest>,
	) -> Result<Self, ArkoorConstructionError> {
		// Do some validation on the amounts
		Self::validate_amounts(&input, &outputs, &dust_outputs)?;

		// Compute combined dust amount if dust isolation is needed
		let needs_dust_isolation = Self::needs_dust_isolation(&outputs, &dust_outputs);
		let combined_dust_amount = if needs_dust_isolation {
			Some(dust_outputs.iter().map(|o| o.amount).sum())
		} else {
			None
		};

		// Construct the checkpoint and arkoor transactions
		let unsigned_checkpoint_tx = Self::construct_unsigned_checkpoint_tx(
			&input,
			&outputs,
			combined_dust_amount,
		);
		let unsigned_checkpoint_txid = unsigned_checkpoint_tx.compute_txid();
		let unsigned_arkoor_txs = Self::construct_unsigned_arkoor_txs(
			&input,
			&outputs,
			unsigned_checkpoint_txid,
		);

		// Construct dust fanout tx and exit txs if dust isolation is needed
		let (unsigned_dust_fanout_tx, unsigned_dust_exit_txs) = if needs_dust_isolation {
			// Combined dust isolation output is at index outputs.len()
			// (after all non-dust outputs)
			let dust_isolation_output_vout = outputs.len() as u32;
			let fanout_tx = Self::construct_unsigned_dust_fanout_tx(
				&input,
				&dust_outputs,
				unsigned_checkpoint_txid,
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
		let mut sighashes = Vec::with_capacity(outputs.len() + 1);
		sighashes.push(arkoor_sighash(&input.txout(), &unsigned_checkpoint_tx));
		for vout in 0..outputs.len() {
			let prevout = unsigned_checkpoint_tx.output[vout].clone();
			sighashes.push(arkoor_sighash(&prevout, &unsigned_arkoor_txs[vout]));
		}

		// Add dust fanout tx sighash if dust isolation is needed
		if let Some(ref tx) = unsigned_dust_fanout_tx {
			let dust_output_vout = outputs.len();
			let prevout = unsigned_checkpoint_tx.output[dust_output_vout].clone();
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

		// For the checkpoint
		let checkpoint_taptweak = input.output_taproot().tap_tweak();
		let policy = VtxoPolicy::new_checkpoint(input.user_pubkey());
		let arkoor_taptweak = policy.taproot(input.server_pubkey(), input.exit_delta(), input.expiry_height()).tap_tweak();

		Ok(Self {
			input: input,
			outputs: outputs,
			dust_outputs: dust_outputs,
			sighashes: sighashes,
			checkpoint_taptweak: checkpoint_taptweak,
			arkoor_taptweak: arkoor_taptweak,
			unsigned_checkpoint_tx: unsigned_checkpoint_tx,
			unsigned_checkpoint_txid: unsigned_checkpoint_txid,
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

	pub fn from_cosign_request(cosign_request: CosignRequest<Vtxo>) -> Result<CheckpointedArkoorBuilder<state::ServerCanCosign>, ArkoorSigningError> {
		CheckpointedArkoorBuilder::new(
				cosign_request.input,
				cosign_request.outputs,
				cosign_request.dust_outputs,
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
		let checkpoint_sig = self.full_signatures.as_ref().expect("state invariant")[0];
		let arkoor_sigs = &self.full_signatures.as_ref().expect("state invariant")[1..];

		(0..self.nb_outputs()).map(|i| {
			self.vtxo_at(i, Some(checkpoint_sig), Some(arkoor_sigs[i]))
		}).collect()
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
		let user_builder = CheckpointedArkoorBuilder::new(
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
}

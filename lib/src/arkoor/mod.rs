pub mod package;
pub mod checkpoint;

use std::borrow::{Borrow, Cow};

use bitcoin::hex::DisplayHex;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Weight, Witness};
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{schnorr, Keypair};
use bitcoin::sighash::{self, SighashCache, TapSighash, TapSighashType};

use bitcoin_ext::{fee, P2TR_DUST, TAPROOT_KEYSPEND_WEIGHT};

use crate::error::IncorrectSigningKeyError;
use crate::{musig, scripts, ProtocolEncoding, Vtxo, VtxoRequest, SECP};
use crate::vtxo::{GenesisItem, GenesisTransition};

pub use package::ArkoorPackageBuilder;


#[derive(Debug, Clone, PartialEq, Eq, Hash, thiserror::Error)]
pub enum ArkoorError {
	#[error("output amount of {input} exceeds input amount of {output}")]
	Unbalanced {
		input: Amount,
		output: Amount,
	},
	#[error("arkoor output amounts cannot be below the p2tr dust threshold")]
	Dust,
	#[error("arkoor cannot have more than 2 outputs")]
	TooManyOutputs,
}

pub fn arkoor_sighash(prevout: &TxOut, arkoor_tx: &Transaction) -> TapSighash {
	let mut shc = SighashCache::new(arkoor_tx);

	shc.taproot_key_spend_signature_hash(
		0, &sighash::Prevouts::All(&[prevout]), TapSighashType::Default,
	).expect("sighash error")
}

pub fn unsigned_arkoor_tx(input: &Vtxo, outputs: &[TxOut]) -> Transaction {
	Transaction {
		version: bitcoin::transaction::Version(3),
		lock_time: bitcoin::absolute::LockTime::ZERO,
		input: vec![TxIn {
			previous_output: input.point(),
			script_sig: ScriptBuf::new(),
			sequence: Sequence::ZERO,
			witness: Witness::new(),
		}],
		output: outputs.into_iter().cloned().chain([fee::fee_anchor()]).collect(),
	}
}

/// Inner utility method to construct the arkoor vtxos.
fn build_arkoor_vtxos<T: Borrow<VtxoRequest>>(
	input: &Vtxo,
	outputs: &[T],
	txouts: &[TxOut],
	arkoor_txid: Txid,
	arkoor_signature: Option<schnorr::Signature>,
) -> Vec<Vtxo> {
	outputs.iter().enumerate().map(|(idx, output)| {
		Vtxo {
			amount: output.borrow().amount,
			expiry_height: input.expiry_height,
			server_pubkey: input.server_pubkey,
			exit_delta: input.exit_delta,
			anchor_point: input.anchor_point,
			genesis: input.genesis.iter().cloned().chain([GenesisItem {
				transition: GenesisTransition::Arkoor {
					policy: input.policy.clone(),
					signature: arkoor_signature,
				},
				output_idx: idx as u8,
				// filter out our index from the txouts
				other_outputs: txouts.iter().enumerate()
					.filter(|(i, _)| *i != idx)
					.map(|(_, o)| o).cloned().collect(),
			}]).collect(),
			policy: output.borrow().policy.clone(),
			point: OutPoint::new(arkoor_txid, idx as u32),
		}
	}).collect()
}

/// Build oor tx and signs it
///
/// ## Panic
///
/// Will panic if inputs and signatures don't have the same length,
/// or if some input witnesses are not empty
pub fn signed_arkoor_tx(
	input: &Vtxo,
	signature: schnorr::Signature,
	outputs: &[TxOut],
) -> Transaction {
	let mut tx = unsigned_arkoor_tx(input, outputs);
	scripts::fill_taproot_sigs(&mut tx, &[signature]);
	tx
}

/// The cosignature details received from the Ark server.
#[derive(Debug)]
pub struct ArkoorCosignResponse {
	pub pub_nonce: musig::PublicNonce,
	pub partial_signature: musig::PartialSignature,
}

/// This types helps both the client and server with building arkoor txs in
/// a synchronized way. It's purely a functional type, initialized with
/// the parameters that will make up the arkoor: the input vtxo to be spent
/// and the desired outputs.
///
/// The flow works as follows:
/// - sender uses the [ArkoorBuilder::new] to check the request for validity
/// - server uses the [ArkoorBuilder::new] to check the request for validity
/// - server uses [ArkoorBuilder::server_cosign] to construct a
///   [ArkoorCosignResponse] to send back to the sender
/// - sender passes the response into [ArkoorBuilder::build_vtxos] to construct
///   the signed resulting VTXOs
pub struct ArkoorBuilder<'a, T: Clone> {
	pub input: &'a Vtxo,
	pub user_nonce: &'a musig::PublicNonce,
	pub outputs: Cow<'a, [T]>,
}

impl<'a, T: Borrow<VtxoRequest> + Clone> ArkoorBuilder<'a, T> {
	/// Construct a generic arkoor builder for the given input and outputs.
	pub fn new(
		input: &'a Vtxo,
		user_nonce: &'a musig::PublicNonce,
		outputs: impl Into<Cow<'a, [T]>>,
	) -> Result<Self, ArkoorError> {
		let outputs = outputs.into();
		if outputs.iter().any(|o| o.borrow().amount < P2TR_DUST) {
			return Err(ArkoorError::Dust);
		}
		let output_amount = outputs.as_ref().iter().map(|o| o.borrow().amount).sum::<Amount>();
		if output_amount > input.amount() {
			return Err(ArkoorError::Unbalanced {
				input: input.amount(),
				output: output_amount,
			});
		}

		if outputs.len() > 2 {
			return Err(ArkoorError::TooManyOutputs);
		}

		Ok(Self {
			input,
			user_nonce,
			outputs,
		})
	}

	/// Construct the transaction outputs of the resulting arkoor tx.
	pub fn txouts(&self) -> Vec<TxOut> {
		self.outputs.iter().map(|out| {
			out.borrow().policy.txout(
				out.borrow().amount,
				self.input.server_pubkey(),
				self.input.exit_delta(),
				self.input.expiry_height(),
			)
		}).collect()
	}

	pub fn unsigned_transaction(&self) -> Transaction {
		unsigned_arkoor_tx(&self.input, &self.txouts())
	}

	pub fn sighash(&self) -> TapSighash {
		arkoor_sighash(&self.input.txout(), &self.unsigned_transaction())
	}

	pub fn total_weight(&self) -> Weight {
		let spend_weight = Weight::from_wu(TAPROOT_KEYSPEND_WEIGHT as u64);
		self.unsigned_transaction().weight() + spend_weight
	}

	/// Used by the Ark server to cosign the arkoor request.
	pub fn server_cosign(&self, keypair: &Keypair) -> ArkoorCosignResponse {
		let (pub_nonce, partial_signature) = musig::deterministic_partial_sign(
			keypair,
			[self.input.user_pubkey()],
			&[&self.user_nonce],
			self.sighash().to_byte_array(),
			Some(self.input.output_taproot().tap_tweak().to_byte_array()),
		);
		ArkoorCosignResponse { pub_nonce, partial_signature }
	}

	/// Validate the server's partial signature.
	pub fn verify_cosign_response(
		&self,
		server_cosign: &ArkoorCosignResponse,
	) -> bool {
		scripts::verify_partial_sig(
			self.sighash(),
			self.input.output_taproot().tap_tweak(),
			(self.input.server_pubkey(), &server_cosign.pub_nonce),
			(self.input.user_pubkey(), &self.user_nonce),
			&server_cosign.partial_signature,
		)
	}

	/// Construct the vtxos of the outputs of this OOR tx.
	///
	/// These vtxos are not valid vtxos because they lack the signature.
	pub fn unsigned_output_vtxos(&self) -> Vec<Vtxo> {
		let txouts = self.txouts();
		let tx = unsigned_arkoor_tx(&self.input, &txouts);
		build_arkoor_vtxos(&self.input, self.outputs.as_ref(), &txouts, tx.compute_txid(), None)
	}

	/// Finish the arkoor process.
	///
	/// Returns the resulting vtxos and the signed arkoor tx.
	pub fn build_vtxos(
		&self,
		user_sec_nonce: musig::SecretNonce,
		user_key: &Keypair,
		cosign_resp: &ArkoorCosignResponse,
	) -> Result<Vec<Vtxo>, IncorrectSigningKeyError> {
		if user_key.public_key() != self.input.user_pubkey() {
			return Err(IncorrectSigningKeyError {
				required: Some(self.input.user_pubkey()),
				provided: user_key.public_key(),
			});
		}

		let txouts = self.txouts();
		let tx = unsigned_arkoor_tx(&self.input, &txouts);
		let sighash = arkoor_sighash(&self.input.txout(), &tx);
		let taptweak = self.input.output_taproot().tap_tweak();

		let agg_nonce = musig::nonce_agg(&[&self.user_nonce, &cosign_resp.pub_nonce]);
		let (_part_sig, final_sig) = musig::partial_sign(
			[self.input.user_pubkey(), self.input.server_pubkey()],
			agg_nonce,
			user_key,
			user_sec_nonce,
			sighash.to_byte_array(),
			Some(taptweak.to_byte_array()),
			Some(&[&cosign_resp.partial_signature]),
		);
		let final_sig = final_sig.expect("we provided the other sig");
		debug_assert!(
			scripts::verify_partial_sig(
				sighash,
				taptweak,
				(self.input.user_pubkey(), &self.user_nonce),
				(self.input.server_pubkey(), &cosign_resp.pub_nonce),
				&_part_sig,
			),
			"invalid partial signature produced",
		);
		debug_assert!(
			SECP.verify_schnorr(
				&final_sig,
				&sighash.into(),
				&self.input.output_taproot().output_key().to_x_only_public_key(),
			).is_ok(),
			"invalid arkoor tx signature produced: input={}, outputs={:?}",
			self.input.serialize().as_hex(), &txouts,
		);

		Ok(build_arkoor_vtxos(
			&self.input,
			self.outputs.as_ref(),
			&txouts,
			tx.compute_txid(),
			Some(final_sig),
		))
	}
}


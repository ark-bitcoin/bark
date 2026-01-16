
use std::convert::Infallible;

use bitcoin::Txid;
use bitcoin::secp256k1::Keypair;

use crate::{Vtxo, VtxoId, VtxoPolicy, Amount};
use crate::arkoor::ArkoorDestination;
use crate::arkoor::{
	ArkoorBuilder, ArkoorConstructionError, state, ArkoorCosignResponse,
	ArkoorSigningError, ArkoorCosignRequest,
};


/// A builder struct for creating arkoor packages
///
/// A package consists out of one or more inputs and matching outputs.
/// When packages are created, the outputs can be possibly split up
/// between the inputs.
///
/// The builder always keeps input and output order.
pub struct ArkoorPackageBuilder<S: state::BuilderState> {
	builders: Vec<ArkoorBuilder<S>>,
}

#[derive(Debug, Clone)]
pub struct ArkoorPackageCosignRequest<V> {
	pub requests: Vec<ArkoorCosignRequest<V>>
}

impl<V> ArkoorPackageCosignRequest<V> {
	pub fn convert_vtxo<F, O>(self, mut f: F) -> ArkoorPackageCosignRequest<O>
		where F: FnMut(V) -> O
	{
		ArkoorPackageCosignRequest {
			requests: self.requests.into_iter().map(|r| {
				ArkoorCosignRequest {
					user_pub_nonces: r.user_pub_nonces,
					input: f(r.input),
					outputs: r.outputs,
					isolated_outputs: r.isolated_outputs,
					use_checkpoint: r.use_checkpoint,
				}

			}).collect::<Vec<_>>()
		}
	}

	pub fn inputs(&self) -> impl Iterator<Item=&V> {
		self.requests.iter()
			.map(|r| Some(&r.input))
			.flatten()
	}

	pub fn outputs(&self) -> impl Iterator<Item=&ArkoorDestination> {
		self.requests.iter()
			.map(|r| &r.outputs)
			.flatten()
	}
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, thiserror::Error)]
#[error("VTXO id mismatch. Expected {expected}, got {got}")]
pub struct InputMismatchError {
	expected: VtxoId,
	got: VtxoId,
}

impl ArkoorPackageCosignRequest<VtxoId> {
	pub fn set_vtxos(
		self,
		vtxos: impl IntoIterator<Item = Vtxo>,
	) -> Result<ArkoorPackageCosignRequest<Vtxo>, InputMismatchError> {
		let package = ArkoorPackageCosignRequest {
			requests: self.requests.into_iter().zip(vtxos).map(|(r, vtxo)| {
				if r.input != vtxo.id() {
					return Err(InputMismatchError {
						expected: r.input,
						got: vtxo.id(),
					})
				}

				Ok(ArkoorCosignRequest {
					input: vtxo,
					user_pub_nonces: r.user_pub_nonces,
					outputs: r.outputs,
					isolated_outputs: r.isolated_outputs,
					use_checkpoint: r.use_checkpoint,
				})
			}).collect::<Result<Vec<_>, _>>()?,
		};

		Ok(package)
	}
}


#[derive(Debug, Clone)]
pub struct ArkoorPackageCosignResponse {
	pub responses: Vec<ArkoorCosignResponse>
}

impl ArkoorPackageBuilder<state::Initial> {
	/// Allocate outputs to inputs with splitting support
	///
	/// Distributes outputs across inputs in order, splitting outputs when needed
	/// to match input amounts exactly. Dust fragments are allowed.
	fn allocate_outputs_to_inputs(
		inputs: impl IntoIterator<Item = Vtxo>,
		outputs: Vec<ArkoorDestination>,
	) -> Result<Vec<(Vtxo, Vec<ArkoorDestination>)>, ArkoorConstructionError> {
		let total_output = outputs.iter().map(|r| r.total_amount).sum::<Amount>();
		if outputs.is_empty() || total_output == Amount::ZERO {
			return Err(ArkoorConstructionError::NoOutputs);
		}

		let mut allocations: Vec<(Vtxo, Vec<ArkoorDestination>)> = Vec::new();

		let mut output_iter = outputs.into_iter();
		let mut current_output = output_iter.next();
		let mut current_output_remaining = current_output.as_ref()
			.map(|o| o.total_amount).unwrap_or_default();

		let mut total_input = Amount::ZERO;
		'inputs:
		for input in inputs {
			total_input += input.amount();

			let mut input_remaining = input.amount();
			let mut input_allocation: Vec<ArkoorDestination> = Vec::new();

			'outputs:
			while let Some(ref output) = current_output {
				let _: Infallible = if input_remaining == current_output_remaining {
					// perfect match: finish allocation and advance output
					input_allocation.push(ArkoorDestination {
						total_amount: current_output_remaining,
						policy: output.policy.clone(),
					});

					current_output = output_iter.next();
					current_output_remaining = current_output.as_ref()
						.map(|o| o.total_amount).unwrap_or_default();
					allocations.push((input, input_allocation));
					continue 'inputs;
				} else if input_remaining > current_output_remaining {
					// input exceeds output: consume output, continue
					input_allocation.push(ArkoorDestination {
						total_amount: current_output_remaining,
						policy: output.policy.clone(),
					});

					input_remaining -= current_output_remaining;

					current_output = output_iter.next();
					current_output_remaining = current_output.as_ref()
						.map(|o| o.total_amount).unwrap_or_default();
					continue 'outputs;
				} else {
					// input is less than output: finish allocation and keep remaining output
					input_allocation.push(ArkoorDestination {
						total_amount: input_remaining,
						policy: output.policy.clone(),
					});

					current_output_remaining -= input_remaining;

					allocations.push((input, input_allocation));
					continue 'inputs;
				};
			}
		}

		if total_input != total_output {
			return Err(ArkoorConstructionError::Unbalanced {
				input: total_input,
				output: total_output,
			});
		}

		Ok(allocations)
	}

	/// Create builder with checkpoints for multiple outputs
	pub fn new_with_checkpoints(
		inputs: impl IntoIterator<Item = Vtxo>,
		outputs: Vec<ArkoorDestination>,
	) -> Result<Self, ArkoorConstructionError> {
		Self::new(inputs, outputs, true)
	}

	/// Create builder without checkpoints for multiple outputs
	pub fn new_without_checkpoints(
		inputs: impl IntoIterator<Item = Vtxo>,
		outputs: Vec<ArkoorDestination>,
	) -> Result<Self, ArkoorConstructionError> {
		Self::new(inputs, outputs, false)
	}

	/// Convenience constructor for single output with automatic change
	///
	/// Calculates change amount and creates appropriate output
	/// (backward-compatible with old API)
	pub fn new_single_output_with_checkpoints(
		inputs: impl IntoIterator<Item = Vtxo>,
		output: ArkoorDestination,
		change_policy: VtxoPolicy,
	) -> Result<Self, ArkoorConstructionError> {
		// Calculate total input amount
		let inputs: Vec<_> = inputs.into_iter().collect();
		let total_input: Amount = inputs.iter().map(|v| v.amount()).sum();

		let change_amount = total_input.checked_sub(output.total_amount)
			.ok_or(ArkoorConstructionError::Unbalanced {
				input: total_input,
				output: output.total_amount,
			})?;

		let outputs = if change_amount == Amount::ZERO {
			vec![output]
		} else {
			vec![
				output,
				ArkoorDestination {
					total_amount: change_amount,
					policy: change_policy,
				},
			]
		};

		Self::new_with_checkpoints(inputs, outputs)
	}

	/// Convenience constructor for single output that claims all inputs
	pub fn new_claim_all_with_checkpoints(
		inputs: impl IntoIterator<Item = Vtxo>,
		output_policy: VtxoPolicy,
	) -> Result<Self, ArkoorConstructionError> {
		// Calculate total input amount
		let inputs: Vec<_> = inputs.into_iter().collect();
		let total_input: Amount = inputs.iter().map(|v| v.amount()).sum();

		let output = ArkoorDestination {
			total_amount: total_input,
			policy: output_policy,
		};

		Self::new_with_checkpoints(inputs, vec![output])
	}

	/// Convenience constructor for single output that claims all inputs
	pub fn new_claim_all_without_checkpoints(
		inputs: impl IntoIterator<Item = Vtxo>,
		output_policy: VtxoPolicy,
	) -> Result<Self, ArkoorConstructionError> {
		// Calculate total input amount
		let inputs: Vec<_> = inputs.into_iter().collect();
		let total_input: Amount = inputs.iter().map(|v| v.amount()).sum();

		let output = ArkoorDestination {
			total_amount: total_input,
			policy: output_policy,
		};

		Self::new_without_checkpoints(inputs, vec![output])
	}

	fn new(
		inputs: impl IntoIterator<Item = Vtxo>,
		outputs: Vec<ArkoorDestination>,
		use_checkpoint: bool,
	) -> Result<Self, ArkoorConstructionError> {
		// Allocate outputs to inputs
		let allocations = Self::allocate_outputs_to_inputs(inputs, outputs)?;

		// Build one ArkoorBuilder per inputpackage
		let mut builders = Vec::with_capacity(allocations.len());
		for (input, allocated_outputs) in allocations {
			let builder = ArkoorBuilder::new(
				input,
				allocated_outputs,
				vec![], // no isolated outputs
				use_checkpoint,
			)?;
			builders.push(builder);
		}

		Ok(Self { builders })
	}

	pub fn generate_user_nonces(
		self,
		user_keypairs: &[Keypair],
	) -> Result<ArkoorPackageBuilder<state::UserGeneratedNonces>, ArkoorSigningError> {
		if user_keypairs.len() != self.builders.len() {
			return Err(ArkoorSigningError::InvalidNbKeypairs {
				expected: self.builders.len(),
				got: user_keypairs.len(),
			})
		}

		let mut builder = Vec::with_capacity(self.builders.len());
		for (idx, package) in self.builders.into_iter().enumerate() {
			builder.push(package.generate_user_nonces(user_keypairs[idx]));
		}
		Ok(ArkoorPackageBuilder { builders: builder })
	}
}

impl ArkoorPackageBuilder<state::UserGeneratedNonces> {
	pub fn user_cosign(
		self,
		user_keypairs: &[Keypair],
		server_cosign_response: ArkoorPackageCosignResponse,
	) -> Result<ArkoorPackageBuilder<state::UserSigned>, ArkoorSigningError> {
		if server_cosign_response.responses.len() != self.builders.len() {
			return Err(ArkoorSigningError::InvalidNbPackages {
				expected: self.builders.len(),
				got: server_cosign_response.responses.len()
			})
		}

		if user_keypairs.len() != self.builders.len() {
			return Err(ArkoorSigningError::InvalidNbKeypairs {
				expected: self.builders.len(),
				got: user_keypairs.len(),
			})
		}

		let mut packages = Vec::with_capacity(self.builders.len());

		for (idx, pkg) in self.builders.into_iter().enumerate() {
			packages.push(pkg.user_cosign(
				&user_keypairs[idx],
				&server_cosign_response.responses[idx],
			)?,);
		}
		Ok(ArkoorPackageBuilder { builders: packages })
	}

	pub fn cosign_request(&self) -> ArkoorPackageCosignRequest<Vtxo> {
		let requests = self.builders.iter()
			.map(|package| package.cosign_request())
			.collect::<Vec<_>>();

		ArkoorPackageCosignRequest { requests }
	}
}

impl ArkoorPackageBuilder<state::UserSigned> {
	pub fn build_signed_vtxos(self) -> Vec<Vtxo> {
		self.builders.into_iter()
			.map(|b| b.build_signed_vtxos())
			.flatten()
			.collect::<Vec<_>>()
	}
}

impl ArkoorPackageBuilder<state::ServerCanCosign> {
	pub fn from_cosign_request(
		cosign_request: ArkoorPackageCosignRequest<Vtxo>,
	) -> Result<Self, ArkoorSigningError> {
		let request_iter = cosign_request.requests.into_iter();
		let mut packages = Vec::with_capacity(request_iter.size_hint().0);
		for request in request_iter {
			packages.push(ArkoorBuilder::from_cosign_request(request)?);
		}

		Ok(Self { builders: packages })
	}

	pub fn server_cosign(
		self,
		server_keypair: &Keypair,
	) -> Result<ArkoorPackageBuilder<state::ServerSigned>, ArkoorSigningError> {
		let mut packages = Vec::with_capacity(self.builders.len());
		for package in self.builders.into_iter() {
			packages.push(package.server_cosign(&server_keypair)?);
		}
		Ok(ArkoorPackageBuilder { builders: packages })
	}
}

impl ArkoorPackageBuilder<state::ServerSigned> {
	pub fn cosign_response(&self) -> ArkoorPackageCosignResponse {
		let responses = self.builders.iter()
			.map(|package| package.cosign_response())
			.collect::<Vec<_>>();

		ArkoorPackageCosignResponse { responses }
	}
}

impl<S: state::BuilderState> ArkoorPackageBuilder<S> {
	/// Access the input VTXO IDs
	pub fn input_ids<'a>(&'a self) -> impl Iterator<Item = VtxoId> + Clone + 'a {
		self.builders.iter().map(|b| b.input().id())
	}

	pub fn build_unsigned_vtxos<'a>(&'a self) -> impl Iterator<Item = Vtxo> + 'a {
		self.builders.iter()
			.map(|b| b.build_unsigned_vtxos())
			.flatten()
	}

	/// Builds the unsigned internal VTXOs
	///
	/// Returns the checkpoint outputs (if checkpoinst are used) and the
	/// dust isolation output (if dust isolation is used).
	pub fn build_unsigned_internal_vtxos<'a>(&'a self) -> impl Iterator<Item = Vtxo> + 'a {
		self.builders.iter()
			.map(|b| b.build_unsigned_internal_vtxos())
			.flatten()
	}

	/// Each [VtxoId] in the list is spent by [Txid]
	/// in an out-of-round transaction
	pub fn spend_info<'a>(&'a self) -> impl Iterator<Item = (VtxoId, Txid)> + 'a {
		self.builders.iter()
			.map(|b| b.spend_info())
			.flatten()
	}
}

#[cfg(test)]
mod test {
	use std::collections::HashMap;
	use std::str::FromStr;

	use bitcoin::{Transaction, Txid};
	use bitcoin::secp256k1::Keypair;
	use super::*;
	use crate::test::dummy::DummyTestVtxoSpec;
	use crate::PublicKey;

	fn server_keypair() -> Keypair {
		Keypair::from_str("f7a2a5d150afb575e98fff9caeebf6fbebbaeacfdfa7433307b208b39f1155f2").expect("Invalid key")
	}

	fn alice_keypair() -> Keypair {
		Keypair::from_str("9b4382c8985f12e4bd8d1b51e63615bf0187843630829f4c5e9c45ef2cf994a4").expect("Invalid key")
	}

	fn bob_keypair() -> Keypair {
		Keypair::from_str("c86435ba7e30d7afd7c5df9f3263ce2eb86b3ff9866a16ccd22a0260496ddf0f").expect("Invalid key")
	}


	fn alice_public_key() -> PublicKey {
		alice_keypair().public_key()
	}

	fn bob_public_key() -> PublicKey {
		bob_keypair().public_key()
	}

	fn dummy_vtxo_for_amount(amt: Amount) -> (Transaction, Vtxo) {
		DummyTestVtxoSpec {
			amount: amt,
			expiry_height: 1000,
			exit_delta: 128,
			user_keypair: alice_keypair(),
			server_keypair: server_keypair()
		}.build()
	}

	fn verify_package_builder(
		builder: ArkoorPackageBuilder<state::Initial>,
		keypairs: &[Keypair],
		funding_tx_map: HashMap<Txid, Transaction>,
	) {
		let user_builder = builder.generate_user_nonces(keypairs).expect("Valid nb of keypairs");
		let cosign_requests = user_builder.cosign_request();

		let cosign_responses = ArkoorPackageBuilder::from_cosign_request(cosign_requests)
			.expect("Invalid cosign requests")
			.server_cosign(&server_keypair())
			.expect("Wrong server key")
			.cosign_response();


		let vtxos = user_builder.user_cosign(keypairs, cosign_responses)
			.expect("Invalid cosign responses")
			.build_signed_vtxos();

		for vtxo in vtxos {
			let funding_txid = vtxo.chain_anchor().txid;
			let funding_tx = funding_tx_map.get(&funding_txid).expect("Funding tx not found");
			vtxo.validate(&funding_tx).expect("Invalid vtxo");

			let mut prev_tx = funding_tx.clone();
			for tx in vtxo.transactions().map(|item| item.tx) {
				crate::test::verify_tx(
					&[prev_tx.output[vtxo.chain_anchor().vout as usize].clone()],
					0,
					&tx).expect("Invalid transaction");
				prev_tx = tx;
			}
		}
	}

	#[test]
	fn send_full_vtxo() {
		// Alice sends 100_000 sat to Bob
		// She owns a single vtxo and fully spends it
		let (funding_tx, alice_vtxo) = dummy_vtxo_for_amount(Amount::from_sat(100_000));

		let package_builder = ArkoorPackageBuilder::new_single_output_with_checkpoints(
			[alice_vtxo],
			ArkoorDestination {
				total_amount: Amount::from_sat(100_000),
				policy: VtxoPolicy::new_pubkey(bob_public_key()),
			},
			VtxoPolicy::new_pubkey(alice_public_key())
		).expect("Valid package");

		let funding_map = HashMap::from([(funding_tx.compute_txid(), funding_tx)]);
		verify_package_builder(package_builder, &[alice_keypair()], funding_map);
	}

	#[test]
	fn arkoor_subdust_change() {
		// Alice tries to send 900 sats to Bob
		// She only has a vtxo worth a 1000 sats
		// She will create two outputs: 900 for Bob, 100 subdust change for Alice
		let (_funding_tx, alice_vtxo) = dummy_vtxo_for_amount(Amount::from_sat(1000));
		let package_builder = ArkoorPackageBuilder::new_single_output_with_checkpoints(
			[alice_vtxo],
			ArkoorDestination {
				total_amount: Amount::from_sat(900),
				policy: VtxoPolicy::new_pubkey(bob_public_key()),
			},
			VtxoPolicy::new_pubkey(alice_public_key())
		).expect("Valid package");

		// We should generate two vtxos: 900 for Bob, 100 subdust change for Alice
		let vtxos: Vec<Vtxo> = package_builder.build_unsigned_vtxos().collect();
		assert_eq!(vtxos.len(), 2);
		assert_eq!(vtxos[0].amount(), Amount::from_sat(900));
		assert_eq!(vtxos[0].policy().user_pubkey(), bob_public_key());
		assert_eq!(vtxos[1].amount(), Amount::from_sat(100));
		assert_eq!(vtxos[1].policy().user_pubkey(), alice_public_key());
	}

	#[test]
	fn can_send_multiple_inputs() {
		// Alice has a vtxo of 10_000, 5_000 and 2_000 sats
		// Seh can make a payment of 17_000 sats to Bob and spend all her money
		let (funding_tx_1, alice_vtxo_1) = dummy_vtxo_for_amount(Amount::from_sat(10_000));
		let (funding_tx_2, alice_vtxo_2) = dummy_vtxo_for_amount(Amount::from_sat(5_000));
		let (funding_tx_3, alice_vtxo_3) = dummy_vtxo_for_amount(Amount::from_sat(2_000));

		let package = ArkoorPackageBuilder::new_single_output_with_checkpoints(
			[alice_vtxo_1, alice_vtxo_2, alice_vtxo_3],
			ArkoorDestination {
				total_amount: Amount::from_sat(17_000),
				policy: VtxoPolicy::new_pubkey(bob_public_key()),
			},
			VtxoPolicy::new_pubkey(alice_public_key())
		).expect("Valid package");

		let vtxos: Vec<Vtxo> = package.build_unsigned_vtxos().collect();
		assert_eq!(vtxos.len(), 3);
		assert_eq!(vtxos[0].amount(), Amount::from_sat(10_000));
		assert_eq!(vtxos[1].amount(), Amount::from_sat(5_000));
		assert_eq!(vtxos[2].amount(), Amount::from_sat(2_000));
		assert_eq!(
			vtxos.iter().map(|v| v.policy().user_pubkey()).collect::<Vec<_>>(),
			vec![bob_public_key(); 3],
		);

		let funding_map = HashMap::from([
			(funding_tx_1.compute_txid(), funding_tx_1),
			(funding_tx_2.compute_txid(), funding_tx_2),
			(funding_tx_3.compute_txid(), funding_tx_3),
		]);
		verify_package_builder(
			package, &[alice_keypair(), alice_keypair(), alice_keypair()], funding_map,
		);
	}

	#[test]
	fn can_send_multiple_inputs_with_change() {
		// Alice has a vtxo of 10_000, 5_000 and 2_000 sats
		// She can make a payment of 16_000 sats to Bob
		// She will also get a vtxo with 1_000 sats as change
		let (funding_tx_1, alice_vtxo_1) = dummy_vtxo_for_amount(Amount::from_sat(10_000));
		let (funding_tx_2, alice_vtxo_2) = dummy_vtxo_for_amount(Amount::from_sat(5_000));
		let (funding_tx_3, alice_vtxo_3) = dummy_vtxo_for_amount(Amount::from_sat(2_000));

		let package = ArkoorPackageBuilder::new_single_output_with_checkpoints(
			[alice_vtxo_1, alice_vtxo_2, alice_vtxo_3],
			ArkoorDestination {
				total_amount: Amount::from_sat(16_000),
				policy: VtxoPolicy::new_pubkey(bob_public_key()),
			},
			VtxoPolicy::new_pubkey(alice_public_key())
		).expect("Valid package");

		let vtxos: Vec<Vtxo> = package.build_unsigned_vtxos().collect();
		assert_eq!(vtxos.len(), 4);
		assert_eq!(vtxos[0].amount(), Amount::from_sat(10_000));
		assert_eq!(vtxos[1].amount(), Amount::from_sat(5_000));
		assert_eq!(vtxos[2].amount(), Amount::from_sat(1_000));
		assert_eq!(vtxos[3].amount(), Amount::from_sat(1_000),
			"Alice should receive a 1000 sats as change",
		);

		assert_eq!(vtxos[0].policy().user_pubkey(), bob_public_key());
		assert_eq!(vtxos[1].policy().user_pubkey(), bob_public_key());
		assert_eq!(vtxos[2].policy().user_pubkey(), bob_public_key());
		assert_eq!(vtxos[3].policy().user_pubkey(), alice_public_key());

		let funding_map = HashMap::from([
			(funding_tx_1.compute_txid(), funding_tx_1),
			(funding_tx_2.compute_txid(), funding_tx_2),
			(funding_tx_3.compute_txid(), funding_tx_3),
		]);
		verify_package_builder(
			package, &[alice_keypair(), alice_keypair(), alice_keypair()], funding_map,
		);
	}

	#[test]
	fn can_send_multiple_vtxos_with_subdust_change() {
		// Alice has a vtxo of 5_000 sat and one of 1_000 sat
		// Alice will send 5_700 sats to Bob
		// The 300 sat change is subdust but will be created as separate output
		let (_funding_tx_1, alice_vtxo_1) = dummy_vtxo_for_amount(Amount::from_sat(5_000));
		let (_funding_tx_2, alice_vtxo_2) = dummy_vtxo_for_amount(Amount::from_sat(1_000));

		let package = ArkoorPackageBuilder::new_single_output_with_checkpoints(
			[alice_vtxo_1, alice_vtxo_2],
			ArkoorDestination {
				total_amount: Amount::from_sat(5_700),
				policy: VtxoPolicy::new_pubkey(bob_public_key()),
			},
			VtxoPolicy::new_pubkey(alice_public_key())
		).expect("Valid package");

		let vtxos: Vec<Vtxo> = package.build_unsigned_vtxos().collect();
		assert_eq!(vtxos.len(), 3);
		assert_eq!(vtxos[0].amount(), Amount::from_sat(5_000));
		assert_eq!(vtxos[0].policy().user_pubkey(), bob_public_key());
		assert_eq!(vtxos[1].amount(), Amount::from_sat(700));
		assert_eq!(vtxos[1].policy().user_pubkey(), bob_public_key());
		assert_eq!(vtxos[2].amount(), Amount::from_sat(300));
		assert_eq!(vtxos[2].policy().user_pubkey(), alice_public_key());
	}

	#[test]
	fn not_enough_money() {
		// Alice tries to send 1000 sats to Bob
		// She only has a vtxo worth a 900 sats
		// She will not be able to send the payment
		let (_funding_tx, alice_vtxo) = dummy_vtxo_for_amount(Amount::from_sat(900));
		let result = ArkoorPackageBuilder::new_single_output_with_checkpoints(
			[alice_vtxo],
			ArkoorDestination {
				total_amount: Amount::from_sat(1000),
				policy: VtxoPolicy::new_pubkey(bob_public_key()),
			},
			VtxoPolicy::new_pubkey(alice_public_key())
		);

		match result {
			Ok(_) => panic!("Package should be invalid"),
			Err(ArkoorConstructionError::Unbalanced { input, output }) => {
				assert_eq!(input, Amount::from_sat(900));
				assert_eq!(output, Amount::from_sat(1000));
			}
			Err(e) => panic!("Unexpected error: {:?}", e),
		}
	}

	#[test]
	fn not_enough_money_with_multiple_inputs() {
		// Alice has a vtxo of 10_000, 5_000 and 2_000 sats
		// She tries to send 20_000 sats to Bob
		// She will not be able to send the payment
		let (_funding_tx, alice_vtxo_1) = dummy_vtxo_for_amount(Amount::from_sat(10_000));
		let (_funding_tx, alice_vtxo_2) = dummy_vtxo_for_amount(Amount::from_sat(5_000));
		let (_funding_tx, alice_vtxo_3) = dummy_vtxo_for_amount(Amount::from_sat(2_000));

		let package = ArkoorPackageBuilder::new_single_output_with_checkpoints(
			[alice_vtxo_1, alice_vtxo_2, alice_vtxo_3],
			ArkoorDestination {
				total_amount: Amount::from_sat(20_000),
				policy: VtxoPolicy::new_pubkey(bob_public_key()),
			},
			VtxoPolicy::new_pubkey(alice_public_key())
		);

		match package {
			Ok(_) => panic!("Package should be invalid"),
			Err(ArkoorConstructionError::Unbalanced { input, output }) => {
				assert_eq!(input, Amount::from_sat(17_000));
				assert_eq!(output, Amount::from_sat(20_000));
			}
			Err(e) => panic!("Unexpected error: {:?}", e)
		}
	}

	#[test]
	fn can_use_all_provided_inputs_with_change() {
		// Alice has 4 vtxos of a thousand sats each
		// She will make a payment of 2000 sats to Bob
		// She includes all vtxos as input to the arkoor builder
		// The builder will use all inputs and create 2000 sats of change
		let (_funding_tx, alice_vtxo_1) = dummy_vtxo_for_amount(Amount::from_sat(1000));
		let (_funding_tx, alice_vtxo_2) = dummy_vtxo_for_amount(Amount::from_sat(1000));
		let (_funding_tx, alice_vtxo_3) = dummy_vtxo_for_amount(Amount::from_sat(1000));
		let (_funding_tx, alice_vtxo_4) = dummy_vtxo_for_amount(Amount::from_sat(1000));

		let package = ArkoorPackageBuilder::new_single_output_with_checkpoints(
			[alice_vtxo_1, alice_vtxo_2, alice_vtxo_3, alice_vtxo_4],
			ArkoorDestination {
				total_amount: Amount::from_sat(2000),
				policy: VtxoPolicy::new_pubkey(bob_public_key()),
			},
			VtxoPolicy::new_pubkey(alice_public_key())
		).expect("Package should be valid");

		// Verify outputs: should have 2000 for Bob and 2000 change for Alice
		let vtxos = package.build_unsigned_vtxos().collect::<Vec<_>>();
		let total_output = vtxos.iter().map(|v| v.amount()).sum::<Amount>();
		assert_eq!(total_output, Amount::from_sat(4000));
	}

	#[test]
	fn single_input_multiple_outputs() {
		// [10_000] -> [4_000, 3_000, 3_000]
		let (funding_tx, alice_vtxo) = dummy_vtxo_for_amount(Amount::from_sat(10_000));

		let outputs = vec![
			ArkoorDestination {
				total_amount: Amount::from_sat(4_000),
				policy: VtxoPolicy::new_pubkey(bob_public_key())
			},
			ArkoorDestination {
				total_amount: Amount::from_sat(3_000),
				policy: VtxoPolicy::new_pubkey(bob_public_key())
			},
			ArkoorDestination {
				total_amount: Amount::from_sat(3_000),
				policy: VtxoPolicy::new_pubkey(bob_public_key())
			},
		];

		let package = ArkoorPackageBuilder::new_with_checkpoints(
			[alice_vtxo.clone()],
			outputs,
		).expect("Valid package");

		let vtxos: Vec<Vtxo> = package.build_unsigned_vtxos().collect();
		assert_eq!(vtxos.len(), 3);
		assert_eq!(vtxos[0].amount(), Amount::from_sat(4_000));
		assert_eq!(vtxos[1].amount(), Amount::from_sat(3_000));
		assert_eq!(vtxos[2].amount(), Amount::from_sat(3_000));

		// Manually test one vtxo to verify the approach
		let user_keypair = alice_keypair();
		let user_builder = package.generate_user_nonces(&[user_keypair])
			.expect("Valid nb of keypairs");
		let cosign_requests = user_builder.cosign_request();

		let cosign_responses = ArkoorPackageBuilder::from_cosign_request(cosign_requests)
			.expect("Invalid cosign requests")
			.server_cosign(&server_keypair())
			.expect("Wrong server key")
			.cosign_response();

		let signed_vtxos = user_builder.user_cosign(&[user_keypair], cosign_responses)
			.expect("Invalid cosign responses")
			.build_signed_vtxos();

		assert_eq!(signed_vtxos.len(), 3, "Should create 3 signed vtxos");

		// Just validate the first vtxo against funding tx
		signed_vtxos[0].validate(&funding_tx).expect("First vtxo should be valid");
	}

	#[test]
	fn output_split_across_inputs() {
		// [600, 500] -> [800, 300]
		// Expect: input[0]->600, input[1]->[200, 300]
		let (_funding_tx_1, alice_vtxo_1) = dummy_vtxo_for_amount(Amount::from_sat(600));
		let (_funding_tx_2, alice_vtxo_2) = dummy_vtxo_for_amount(Amount::from_sat(500));

		let outputs = vec![
			ArkoorDestination {
				total_amount: Amount::from_sat(800),
				policy: VtxoPolicy::new_pubkey(bob_public_key())
			},
			ArkoorDestination {
				total_amount: Amount::from_sat(300),
				policy: VtxoPolicy::new_pubkey(bob_public_key())
			},
		];

		let package = ArkoorPackageBuilder::new_with_checkpoints(
			[alice_vtxo_1, alice_vtxo_2],
			outputs,
		).expect("Valid package");

		let vtxos: Vec<Vtxo> = package.build_unsigned_vtxos().collect();
		assert_eq!(vtxos.len(), 3);
		assert_eq!(vtxos[0].amount(), Amount::from_sat(600));
		assert_eq!(vtxos[0].policy().user_pubkey(), bob_public_key());
		assert_eq!(vtxos[1].amount(), Amount::from_sat(200));
		assert_eq!(vtxos[1].policy().user_pubkey(), bob_public_key());
		assert_eq!(vtxos[2].amount(), Amount::from_sat(300));
		assert_eq!(vtxos[2].policy().user_pubkey(), bob_public_key());
	}

	#[test]
	fn dust_splits_allowed() {
		// [500, 500] -> [750, 250]
		// Results in 250 sat fragments (< 330)
		let (_funding_tx_1, alice_vtxo_1) = dummy_vtxo_for_amount(Amount::from_sat(500));
		let (_funding_tx_2, alice_vtxo_2) = dummy_vtxo_for_amount(Amount::from_sat(500));

		let outputs = vec![
			ArkoorDestination {
				total_amount: Amount::from_sat(750),
				policy: VtxoPolicy::new_pubkey(bob_public_key())
			},
			ArkoorDestination {
				total_amount: Amount::from_sat(250),
				policy: VtxoPolicy::new_pubkey(bob_public_key())
			},
		];

		let package = ArkoorPackageBuilder::new_with_checkpoints(
			[alice_vtxo_1, alice_vtxo_2],
			outputs,
		).expect("Valid package");

		let vtxos: Vec<Vtxo> = package.build_unsigned_vtxos().collect();
		assert_eq!(vtxos.len(), 3);
		assert_eq!(vtxos[0].amount(), Amount::from_sat(500));
		assert_eq!(vtxos[1].amount(), Amount::from_sat(250)); // sub-dust!
		assert_eq!(vtxos[2].amount(), Amount::from_sat(250));
	}

	#[test]
	fn unbalanced_amounts_rejected() {
		// [1000] -> [600, 600] = 1200 > 1000
		let (_funding_tx, alice_vtxo) = dummy_vtxo_for_amount(Amount::from_sat(1000));

		let outputs = vec![
			ArkoorDestination {
				total_amount: Amount::from_sat(600),
				policy: VtxoPolicy::new_pubkey(bob_public_key())
			},
			ArkoorDestination {
				total_amount: Amount::from_sat(600),
				policy: VtxoPolicy::new_pubkey(bob_public_key())
			},
		];

		let result = ArkoorPackageBuilder::new_with_checkpoints(
			[alice_vtxo],
			outputs,
		);

		match result {
			Err(ArkoorConstructionError::Unbalanced { input, output }) => {
				assert_eq!(input, Amount::from_sat(1000));
				assert_eq!(output, Amount::from_sat(1200));
			}
			_ => panic!("Expected Unbalanced error"),
		}
	}

	#[test]
	fn empty_outputs_rejected() {
		let (_funding_tx, alice_vtxo) = dummy_vtxo_for_amount(Amount::from_sat(1000));

		let result = ArkoorPackageBuilder::new_with_checkpoints(
			[alice_vtxo],
			vec![],
		);

		match result {
			Err(ArkoorConstructionError::NoOutputs) => {}
			Err(e) => panic!("Expected NoOutputs error, got: {:?}", e),
			Ok(_) => panic!("Expected NoOutputs error, got Ok"),
		}
	}

	#[test]
	fn multiple_inputs_multiple_outputs_exact_balance() {
		// [1000, 2000, 1500] -> [2500, 2000]
		let (_funding_tx_1, alice_vtxo_1) = dummy_vtxo_for_amount(Amount::from_sat(1000));
		let (_funding_tx_2, alice_vtxo_2) = dummy_vtxo_for_amount(Amount::from_sat(2000));
		let (_funding_tx_3, alice_vtxo_3) = dummy_vtxo_for_amount(Amount::from_sat(1500));

		let outputs = vec![
			ArkoorDestination {
				total_amount: Amount::from_sat(2500),
				policy: VtxoPolicy::new_pubkey(bob_public_key())
			},
			ArkoorDestination {
				total_amount: Amount::from_sat(2000),
				policy: VtxoPolicy::new_pubkey(bob_public_key())
			},
		];

		let package = ArkoorPackageBuilder::new_with_checkpoints(
			[alice_vtxo_1, alice_vtxo_2, alice_vtxo_3],
			outputs,
		).expect("Valid package");

		let vtxos: Vec<Vtxo> = package.build_unsigned_vtxos().collect();
		assert_eq!(vtxos.len(), 4);
		// input[0] 1000 -> output[0]
		// input[1] 2000 -> output[0] 1500, output[1] 500
		// input[2] 1500 -> output[1] 1500
		assert_eq!(vtxos[0].amount(), Amount::from_sat(1000));
		assert_eq!(vtxos[1].amount(), Amount::from_sat(1500));
		assert_eq!(vtxos[2].amount(), Amount::from_sat(500));
		assert_eq!(vtxos[3].amount(), Amount::from_sat(1500));
	}

	#[test]
	fn single_output_across_many_inputs() {
		// [100, 100, 100, 100] -> [400]
		// All inputs consumed fully to create single output
		let (_funding_tx_1, alice_vtxo_1) = dummy_vtxo_for_amount(Amount::from_sat(100));
		let (_funding_tx_2, alice_vtxo_2) = dummy_vtxo_for_amount(Amount::from_sat(100));
		let (_funding_tx_3, alice_vtxo_3) = dummy_vtxo_for_amount(Amount::from_sat(100));
		let (_funding_tx_4, alice_vtxo_4) = dummy_vtxo_for_amount(Amount::from_sat(100));

		let outputs = vec![
			ArkoorDestination {
				total_amount: Amount::from_sat(400),
				policy: VtxoPolicy::new_pubkey(bob_public_key())
			},
		];

		let package = ArkoorPackageBuilder::new_with_checkpoints(
			[alice_vtxo_1, alice_vtxo_2, alice_vtxo_3, alice_vtxo_4],
			outputs,
		).expect("Valid package");

		let vtxos: Vec<Vtxo> = package.build_unsigned_vtxos().collect();
		assert_eq!(vtxos.len(), 4);
		assert_eq!(vtxos[0].amount(), Amount::from_sat(100));
		assert_eq!(vtxos[1].amount(), Amount::from_sat(100));
		assert_eq!(vtxos[2].amount(), Amount::from_sat(100));
		assert_eq!(vtxos[3].amount(), Amount::from_sat(100));
		let total: Amount = vtxos.iter().map(|v| v.amount()).sum();
		assert_eq!(total, Amount::from_sat(400));
	}

	#[test]
	fn many_outputs_from_single_input() {
		// [1000] -> [100, 200, 150, 250, 300]
		let (_funding_tx, alice_vtxo) = dummy_vtxo_for_amount(Amount::from_sat(1000));

		let outputs = vec![
			ArkoorDestination {
				total_amount: Amount::from_sat(100),
				policy: VtxoPolicy::new_pubkey(bob_public_key())
			},
			ArkoorDestination {
				total_amount: Amount::from_sat(200),
				policy: VtxoPolicy::new_pubkey(bob_public_key())
			},
			ArkoorDestination {
				total_amount: Amount::from_sat(150),
				policy: VtxoPolicy::new_pubkey(bob_public_key())
			},
			ArkoorDestination {
				total_amount: Amount::from_sat(250),
				policy: VtxoPolicy::new_pubkey(bob_public_key())
			},
			ArkoorDestination {
				total_amount: Amount::from_sat(300),
				policy: VtxoPolicy::new_pubkey(bob_public_key())
			},
		];

		let package = ArkoorPackageBuilder::new_with_checkpoints(
			[alice_vtxo],
			outputs,
		).expect("Valid package");

		let vtxos: Vec<Vtxo> = package.build_unsigned_vtxos().collect();
		assert_eq!(vtxos.len(), 5);
		assert_eq!(vtxos[0].amount(), Amount::from_sat(100));
		assert_eq!(vtxos[1].amount(), Amount::from_sat(200));
		assert_eq!(vtxos[2].amount(), Amount::from_sat(150));
		assert_eq!(vtxos[3].amount(), Amount::from_sat(250));
		assert_eq!(vtxos[4].amount(), Amount::from_sat(300));
	}

	#[test]
	fn first_input_exactly_matches_first_output() {
		// [1000, 500] -> [1000, 500]
		// Perfect alignment - each input goes to one output
		let (_funding_tx_1, alice_vtxo_1) = dummy_vtxo_for_amount(Amount::from_sat(1000));
		let (_funding_tx_2, alice_vtxo_2) = dummy_vtxo_for_amount(Amount::from_sat(500));

		let outputs = vec![
			ArkoorDestination {
				total_amount: Amount::from_sat(1000),
				policy: VtxoPolicy::new_pubkey(bob_public_key())
			},
			ArkoorDestination {
				total_amount: Amount::from_sat(500),
				policy: VtxoPolicy::new_pubkey(bob_public_key())
			},
		];

		let package = ArkoorPackageBuilder::new_with_checkpoints(
			[alice_vtxo_1, alice_vtxo_2],
			outputs,
		).expect("Valid package");

		let vtxos: Vec<Vtxo> = package.build_unsigned_vtxos().collect();
		assert_eq!(vtxos.len(), 2);
		assert_eq!(vtxos[0].amount(), Amount::from_sat(1000));
		assert_eq!(vtxos[1].amount(), Amount::from_sat(500));
	}

	#[test]
	fn empty_inputs_rejected() {
		// [] -> [1000] should fail
		let outputs = vec![
			ArkoorDestination {
				total_amount: Amount::from_sat(1000),
				policy: VtxoPolicy::new_pubkey(bob_public_key())
			},
		];

		let result = ArkoorPackageBuilder::new_with_checkpoints(
			Vec::<Vtxo>::new(),
			outputs,
		);

		match result {
			Ok(_) => panic!("Should reject empty inputs"),
			Err(ArkoorConstructionError::Unbalanced { input, output }) => {
				assert_eq!(input, Amount::ZERO);
				assert_eq!(output, Amount::from_sat(1000));
			}
			Err(e) => panic!("Unexpected error: {:?}", e),
		}
	}

	#[test]
	fn alternating_split_pattern() {
		// [300, 700, 500] -> [500, 400, 600]
		// Complex pattern: input[0] split across output[0-1],
		// input[1] covers rest of output[1] and part of output[2],
		// input[2] covers rest of output[2]
		let (_funding_tx_1, alice_vtxo_1) = dummy_vtxo_for_amount(Amount::from_sat(300));
		let (_funding_tx_2, alice_vtxo_2) = dummy_vtxo_for_amount(Amount::from_sat(700));
		let (_funding_tx_3, alice_vtxo_3) = dummy_vtxo_for_amount(Amount::from_sat(500));

		let outputs = vec![
			ArkoorDestination {
				total_amount: Amount::from_sat(500),
				policy: VtxoPolicy::new_pubkey(bob_public_key())
			},
			ArkoorDestination {
				total_amount: Amount::from_sat(400),
				policy: VtxoPolicy::new_pubkey(bob_public_key())
			},
			ArkoorDestination {
				total_amount: Amount::from_sat(600),
				policy: VtxoPolicy::new_pubkey(bob_public_key())
			},
		];

		let package = ArkoorPackageBuilder::new_with_checkpoints(
			[alice_vtxo_1, alice_vtxo_2, alice_vtxo_3],
			outputs,
		).expect("Valid package");

		let vtxos: Vec<Vtxo> = package.build_unsigned_vtxos().collect();
		assert_eq!(vtxos.len(), 5);
		// input[0] 300 -> output[0] 300
		assert_eq!(vtxos[0].amount(), Amount::from_sat(300));
		// input[1] 700 -> output[0] 200, output[1] 400, output[2] 100
		assert_eq!(vtxos[1].amount(), Amount::from_sat(200));
		assert_eq!(vtxos[2].amount(), Amount::from_sat(400));
		assert_eq!(vtxos[3].amount(), Amount::from_sat(100));
		// input[2] 500 -> output[2] 500
		assert_eq!(vtxos[4].amount(), Amount::from_sat(500));
		let total: Amount = vtxos.iter().map(|v| v.amount()).sum();
		assert_eq!(total, Amount::from_sat(1500));
	}
}

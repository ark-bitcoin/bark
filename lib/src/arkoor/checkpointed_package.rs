use bitcoin::Txid;
use bitcoin::secp256k1::Keypair;
use bitcoin_ext::P2TR_DUST;


use crate::arkoor::checkpoint::{CheckpointedArkoorBuilder, ArkoorConstructionError, state, CosignResponse, ArkoorSigningError, CosignRequest};
use crate::{Vtxo, VtxoId, VtxoRequest, VtxoPolicy, PublicKey, Amount};

pub struct CheckpointedPackageBuilder<S: state::BuilderState> {
	builders: Vec<CheckpointedArkoorBuilder<S>>,
}

#[derive(Debug, Clone)]
pub struct PackageCosignRequest<V> {
	pub requests: Vec<CosignRequest<V>>
}

impl<V> PackageCosignRequest<V> {
	pub fn convert_vtxo<F, O>(self, f: F) -> PackageCosignRequest<O>
		where F: Fn(V) -> O
	{
		PackageCosignRequest {
			requests: self.requests.into_iter().map(|r| {
				CosignRequest {
					user_pub_nonces: r.user_pub_nonces,
					input: f(r.input),
					outputs: r.outputs,
					dust_outputs: r.dust_outputs,
				}

			}).collect::<Vec<_>>()
		}
	}

	pub fn inputs(&self) -> impl Iterator<Item=&V> {
		self.requests.iter()
			.map(|r| Some(&r.input))
			.flatten()
	}
}


#[derive(Debug, Clone)]
pub struct PackageCosignResponse {
	pub responses: Vec<CosignResponse>
}

impl CheckpointedPackageBuilder<state::Initial> {

	pub fn new(
		inputs: impl IntoIterator<Item = Vtxo>,
		output: VtxoRequest,
		change_pubkey: PublicKey,
	) -> Result<Self, ArkoorConstructionError> {
		// Some of the algorithms read a bit awkward.
		// The key problem is that we can only iterate over the inputs once.
		let input_iter = inputs.into_iter();

		// Constructs a package for each input vtxo
		let mut packages = Vec::with_capacity(input_iter.size_hint().0);
		let mut to_be_paid = output.amount;
		for input in input_iter {
			let input_amount = input.amount();
			if to_be_paid >= input_amount {
				let package = CheckpointedArkoorBuilder::new(
					input,
					vec![VtxoRequest { amount: input_amount, policy: output.policy.clone() }],
					vec![], // no dust outputs
				)?;

				packages.push(package);
				to_be_paid = to_be_paid - input_amount;
			} else if to_be_paid >  Amount::ZERO {
				// If change_amount is less than P2TR we don't do change
				// We will send the left-overs as a tip
				let change_amount = input.amount() - to_be_paid;
				let requests = if change_amount < P2TR_DUST {
					vec![VtxoRequest { amount: input.amount(), policy: output.policy.clone() }]
				} else {
					vec![
						VtxoRequest { amount: to_be_paid, policy: output.policy.clone() },
						VtxoRequest { amount: change_amount, policy: VtxoPolicy::new_pubkey(change_pubkey) }
					]
				};

				let package = CheckpointedArkoorBuilder::new(
					input,
					requests,
					vec![], // no dust outputs
				)?;

				to_be_paid = Amount::ZERO;
				packages.push(package);
			} else {
				// In this case we aren't using all the inputs.
				return Err(ArkoorConstructionError::TooManyInputs)
			}
		}

		if to_be_paid != Amount::ZERO {
			return Err(ArkoorConstructionError::Unbalanced {
				input: output.amount - to_be_paid,
				output: output.amount,
			})
		}

		Ok(Self { builders: packages })
	}

	pub fn generate_user_nonces(self, user_keypairs: &[Keypair]) -> Result<CheckpointedPackageBuilder<state::UserGeneratedNonces>, ArkoorSigningError> {
		if user_keypairs.len() != self.builders.len() {
			return Err(ArkoorSigningError::InvalidNbKeypairs { expected: self.builders.len(), got: user_keypairs.len() })
		}

		let mut builder = Vec::with_capacity(self.builders.len());
		for (idx, package) in self.builders.into_iter().enumerate() {
			builder.push(package.generate_user_nonces(user_keypairs[idx]));
		}
		Ok(CheckpointedPackageBuilder { builders: builder })
	}
}

impl CheckpointedPackageBuilder<state::UserGeneratedNonces> {
	pub fn user_cosign(self, user_keypair: &[Keypair], server_cosign_response: PackageCosignResponse) -> Result<CheckpointedPackageBuilder<state::UserSigned>, ArkoorSigningError> {
		if server_cosign_response.responses.len() != self.builders.len() {
			return Err(ArkoorSigningError::InvalidNbPackages {
				expected: self.builders.len(),
				got: server_cosign_response.responses.len()
			})
		}

		if user_keypair.len() != self.builders.len() {
			return Err(ArkoorSigningError::InvalidNbKeypairs { expected: self.builders.len(), got: user_keypair.len()})
		}

		let mut packages = Vec::with_capacity(self.builders.len());

		for (idx, pkg) in self.builders.into_iter().enumerate() {
			packages.push(pkg.user_cosign(&user_keypair[idx], &server_cosign_response.responses[idx])?);
		}
		Ok(CheckpointedPackageBuilder { builders: packages })
	}

	pub fn cosign_requests(&self) -> PackageCosignRequest<Vtxo> {
		let requests = self.builders.iter()
			.map(|package| package.cosign_request())
			.collect::<Vec<_>>();

		PackageCosignRequest { requests }
	}
}

impl CheckpointedPackageBuilder<state::UserSigned> {
	pub fn build_signed_vtxos(self) -> Vec<Vtxo> {
		self.builders.into_iter()
			.map(|package| package.build_signed_vtxos())
			.flatten()
			.collect::<Vec<_>>()
	}
}

impl CheckpointedPackageBuilder<state::ServerCanCosign> {
	pub fn from_cosign_requests(cosign_requests: PackageCosignRequest<Vtxo>) -> Result<Self, ArkoorSigningError> {
		let request_iter = cosign_requests.requests.into_iter();
		let mut packages = Vec::with_capacity(request_iter.size_hint().0);
		for request in request_iter {
			packages.push(CheckpointedArkoorBuilder::from_cosign_request(request)?);
		}

		Ok(Self { builders: packages })
	}

	pub fn server_cosign(self, server_keypair: Keypair) -> Result<CheckpointedPackageBuilder<state::ServerSigned>, ArkoorSigningError> {
		let mut packages = Vec::with_capacity(self.builders.len());
		for package in self.builders.into_iter() {
			packages.push(package.server_cosign(server_keypair)?);
		}
		Ok(CheckpointedPackageBuilder { builders: packages })
	}
}

impl CheckpointedPackageBuilder<state::ServerSigned> {
	pub fn cosign_response(&self) -> PackageCosignResponse {
		let responses = self.builders.iter()
			.map(|package| package.cosign_response())
			.collect::<Vec<_>>();

		PackageCosignResponse { responses }
	}
}

impl<S: state::BuilderState> CheckpointedPackageBuilder<S> {

	pub fn build_unsigned_vtxos<'a>(&'a self) -> impl Iterator<Item = Vtxo> + 'a {
		self.builders.iter()
			.map(|b| b.build_unsigned_vtxos())
			.flatten()
	}

	pub fn build_unsigned_checkpoint_vtxos<'a>(&'a self) -> impl Iterator<Item = Vtxo> + 'a {
		self.builders.iter()
			.map(|b| b.build_unsigned_checkpoint_vtxos())
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

	fn dummy_vtxo_for_amount(amount: Amount) -> (Transaction, Vtxo) {
		DummyTestVtxoSpec {
			amount: amount,
			expiry_height: 1000,
			exit_delta: 128,
			user_keypair: alice_keypair(),
			server_keypair: server_keypair()
		}.build()
	}

	fn verify_package_builder(builder: CheckpointedPackageBuilder<state::Initial>, keypairs: &[Keypair], funding_tx_map: HashMap<Txid, Transaction>) {
		let user_builder = builder.generate_user_nonces(keypairs).expect("Valid nb of keypairs");
		let cosign_requests = user_builder.cosign_requests();

		let cosign_responses = CheckpointedPackageBuilder::from_cosign_requests(cosign_requests)
			.expect("Invalid cosign requests")
			.server_cosign(server_keypair())
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

		let package_builder = CheckpointedPackageBuilder::new(
			[alice_vtxo],
			VtxoRequest { amount: Amount::from_sat(100_000), policy: VtxoPolicy::new_pubkey(bob_public_key()) },
			alice_public_key()
		).expect("Valid package");

		let funding_map = HashMap::from([(funding_tx.compute_txid(), funding_tx)]);
		verify_package_builder(package_builder, &[alice_keypair()], funding_map);
	}

	#[test]
	fn arkoor_no_dust_change() {
		// Alice tries to send 900 sats to Bob
		// She only has a vtxo worth a 1000 sats
		// She will send the subdust remainder to Bob as well
		let (funding_tx, alice_vtxo) = dummy_vtxo_for_amount(Amount::from_sat(1000));
		let package_builder = CheckpointedPackageBuilder::new(
			[alice_vtxo],
			VtxoRequest { amount: Amount::from_sat(900), policy: VtxoPolicy::new_pubkey(bob_public_key()) },
			alice_public_key()
		).expect("Valid package");

		// We should generate one vtxo for an amount of 1000 sat to bob
		let vtxos: Vec<Vtxo> = package_builder.build_unsigned_vtxos().collect();
		assert_eq!(vtxos.len(), 1);
		assert_eq!(vtxos[0].amount(), Amount::from_sat(1000));
		assert_eq!(vtxos[0].policy().user_pubkey(), bob_public_key());


		// Verify if it produces valid vtxos
		let funding_map = HashMap::from([(funding_tx.compute_txid(), funding_tx)]);
		verify_package_builder(package_builder, &[alice_keypair()], funding_map);
	}

	#[test]
	fn can_send_multiple_inputs() {
		// Alice has a vtxo of 10_000, 5_000 and 2_000 sats
		// Seh can make a payment of 17_000 sats to Bob and spend all her money
		let (funding_tx_1, alice_vtxo_1) = dummy_vtxo_for_amount(Amount::from_sat(10_000));
		let (funding_tx_2, alice_vtxo_2) = dummy_vtxo_for_amount(Amount::from_sat(5_000));
		let (funding_tx_3, alice_vtxo_3) = dummy_vtxo_for_amount(Amount::from_sat(2_000));

		let package = CheckpointedPackageBuilder::new(
			[alice_vtxo_1, alice_vtxo_2, alice_vtxo_3],
			VtxoRequest { amount: Amount::from_sat(17_000), policy: VtxoPolicy::new_pubkey(bob_public_key()) },
			alice_public_key()
		).expect("Valid package");

		let vtxos: Vec<Vtxo> = package.build_unsigned_vtxos().collect();
		assert_eq!(vtxos.len(), 3);
		assert_eq!(vtxos[0].amount(), Amount::from_sat(10_000));
		assert_eq!(vtxos[1].amount(), Amount::from_sat(5_000));
		assert_eq!(vtxos[2].amount(), Amount::from_sat(2_000));
		assert_eq!(vtxos.iter().map(|v| v.policy().user_pubkey()).collect::<Vec<_>>(), vec![bob_public_key(); 3]);

		let funding_map = HashMap::from([
			(funding_tx_1.compute_txid(), funding_tx_1),
			(funding_tx_2.compute_txid(), funding_tx_2),
			(funding_tx_3.compute_txid(), funding_tx_3),
		]);
		verify_package_builder(package, &[alice_keypair(), alice_keypair(), alice_keypair()], funding_map);

	}

	#[test]
	fn can_send_multiple_inputs_with_change() {
		// Alice has a vtxo of 10_000, 5_000 and 2_000 sats
		// She can make a payment of 16_000 sats to Bob
		// She will also get a vtxo with 1_000 sats as change
		let (funding_tx_1, alice_vtxo_1) = dummy_vtxo_for_amount(Amount::from_sat(10_000));
		let (funding_tx_2, alice_vtxo_2) = dummy_vtxo_for_amount(Amount::from_sat(5_000));
		let (funding_tx_3, alice_vtxo_3) = dummy_vtxo_for_amount(Amount::from_sat(2_000));

		let package = CheckpointedPackageBuilder::new(
			[alice_vtxo_1, alice_vtxo_2, alice_vtxo_3],
			VtxoRequest { amount: Amount::from_sat(16_000), policy: VtxoPolicy::new_pubkey(bob_public_key()) },
			alice_public_key()
		).expect("Valid package");

		let vtxos: Vec<Vtxo> = package.build_unsigned_vtxos().collect();
		assert_eq!(vtxos.len(), 4);
		assert_eq!(vtxos[0].amount(), Amount::from_sat(10_000));
		assert_eq!(vtxos[1].amount(), Amount::from_sat(5_000));
		assert_eq!(vtxos[2].amount(), Amount::from_sat(1_000));
		assert_eq!(vtxos[3].amount(), Amount::from_sat(1_000), "Alice should receive a 1000 sats as change");

		assert_eq!(vtxos[0].policy().user_pubkey(), bob_public_key());
		assert_eq!(vtxos[1].policy().user_pubkey(), bob_public_key());
		assert_eq!(vtxos[2].policy().user_pubkey(), bob_public_key());
		assert_eq!(vtxos[3].policy().user_pubkey(), alice_public_key());

		let funding_map = HashMap::from([
			(funding_tx_1.compute_txid(), funding_tx_1),
			(funding_tx_2.compute_txid(), funding_tx_2),
			(funding_tx_3.compute_txid(), funding_tx_3),
		]);
		verify_package_builder(package, &[alice_keypair(), alice_keypair(), alice_keypair()], funding_map);
	}

	#[test]
	fn can_send_multiple_vtxos_and_dust_change_will_be_tipped() {
		// Alice has a vtxo of 5_000 sat and one of 1_000 sat
		// Alice will send 5_700 sats to Bob
		// Because the 300 sat change is subdust it will be tipped to Bob
		let (funding_tx_1, alice_vtxo_1) = dummy_vtxo_for_amount(Amount::from_sat(5_000));
		let (funding_tx_2, alice_vtxo_2) = dummy_vtxo_for_amount(Amount::from_sat(1_000));

		let package = CheckpointedPackageBuilder::new(
			[alice_vtxo_1, alice_vtxo_2],
			VtxoRequest { amount: Amount::from_sat(5_700), policy: VtxoPolicy::new_pubkey(bob_public_key()) },
			alice_public_key()
		).expect("Valid package");

		let vtxos: Vec<Vtxo> = package.build_unsigned_vtxos().collect();
		assert_eq!(vtxos.len(), 2);
		assert_eq!(vtxos[0].amount(), Amount::from_sat(5_000));
		assert_eq!(vtxos[1].amount(), Amount::from_sat(1_000));

		assert_eq!(vtxos[0].policy().user_pubkey(), bob_public_key());
		assert_eq!(vtxos[1].policy().user_pubkey(), bob_public_key());

		let funding_map = HashMap::from([
			(funding_tx_1.compute_txid(), funding_tx_1),
			(funding_tx_2.compute_txid(), funding_tx_2),
		]);
		verify_package_builder(package, &[alice_keypair(), alice_keypair()], funding_map);
	}

	#[test]
	fn not_enough_money() {
		// Alice tries to send 1000 sats to Bob
		// She only has a vtxo worth a 900 sats
		// She will not be able to send the payment
		let (_funding_tx, alice_vtxo) = dummy_vtxo_for_amount(Amount::from_sat(900));
		let result = CheckpointedPackageBuilder::new(
			[alice_vtxo],
			VtxoRequest { amount: Amount::from_sat(1000), policy: VtxoPolicy::new_pubkey(bob_public_key()) },
			alice_public_key()
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

		let package = CheckpointedPackageBuilder::new(
			[alice_vtxo_1, alice_vtxo_2, alice_vtxo_3],
			VtxoRequest { amount: Amount::from_sat(20_000), policy: VtxoPolicy::new_pubkey(bob_public_key()) },
			alice_public_key()
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
	fn cannot_send_dust() {
		// Alice has a vtxo worth a 1000 sats
		// Alice tries to send 100 sats to Bob
		// Sending subdust amounts is not allowed
		let (_funding_tx, alice_vtxo) = dummy_vtxo_for_amount(Amount::from_sat(1000));
		let result = CheckpointedPackageBuilder::new(
			[alice_vtxo],
			VtxoRequest {
				amount: Amount::from_sat(100),
				policy: VtxoPolicy::new_pubkey(bob_public_key())
			},
			alice_public_key()
		);

		match result {
			Ok(_) => panic!("Should not allow sending dust amounts"),
			Err(ArkoorConstructionError::Dust) => { /* ok */ }
			Err(e) => panic!("Unexpected error: {:?}", e)
		}
	}

	#[test]
	fn cannot_overprovision_vtxos() {
		// Alice has 4 vtxos of a thousand sats each
		// She will try to make a payment of 2000 sats to Bob
		// She will include all of these vtxos as input to the arkoor builder
		// The arkoor builder will refuse to make the payment because
		// alice has overprovisioned her vtxos.
		let (_funding_tx, alice_vtxo_1) = dummy_vtxo_for_amount(Amount::from_sat(1000));
		let (_funding_tx, alice_vtxo_2) = dummy_vtxo_for_amount(Amount::from_sat(1000));
		let (_funding_tx, alice_vtxo_3) = dummy_vtxo_for_amount(Amount::from_sat(1000));
		let (_funding_tx, alice_vtxo_4) = dummy_vtxo_for_amount(Amount::from_sat(1000));

		let package = CheckpointedPackageBuilder::new(
			[alice_vtxo_1, alice_vtxo_2, alice_vtxo_3, alice_vtxo_4],
			VtxoRequest { amount: Amount::from_sat(2000), policy: VtxoPolicy::new_pubkey(bob_public_key()) },
			alice_public_key()
		);

		match package {
			Ok(_) => panic!("Package should be invalid"),
			Err(ArkoorConstructionError::TooManyInputs) => { /* ok */ }
			Err(e) => panic!("Unexpected error: {:?}", e)
		}
	}
}

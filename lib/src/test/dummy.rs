use std::str::FromStr;

use bitcoin::{Amount, OutPoint, Txid, TxIn, TxOut, Transaction, Witness, ScriptBuf, Sequence};
use bitcoin::absolute::LockTime;
use bitcoin::hashes::Hash;
use bitcoin::transaction::Version;
use bitcoin::secp256k1::Keypair;

use bitcoin_ext::{BlockHeight, BlockDelta};

use crate::Vtxo;
use crate::board::BoardBuilder;

lazy_static! {
	pub static ref DUMMY_USER_KEY: Keypair = Keypair::from_str(
		"76f78cc00278817fe65fd81cb962782d2625834d08b66edbf2cd60f6c520db63",
	).unwrap();

	pub static ref DUMMY_SERVER_KEY: Keypair = Keypair::from_str(
		"f2a9eaeba1cdb8411dfda3c9ca391e4ad29938c4f0b9c0709376fc4a1cbf0e5d",
	).unwrap();
}

/// Just a utility to write unit tests
/// It can quickly create a vtxo that matches
/// some desired parameters
pub struct DummyTestVtxoSpec {
	pub amount: Amount,
	pub expiry_height: BlockHeight,
	pub exit_delta: BlockDelta,
	pub user_keypair: Keypair,
	pub server_keypair: Keypair,
}

impl Default for DummyTestVtxoSpec {
	fn default() -> Self {
		Self {
			amount: Amount::ONE_BTC,
			expiry_height: 10_000,
			exit_delta: 144,
			user_keypair: *DUMMY_USER_KEY,
			server_keypair: *DUMMY_SERVER_KEY,
		}
	}
}

impl DummyTestVtxoSpec {
	pub fn build(&self) -> (Transaction, Vtxo) {
		// The board-builder that is used by the user
		let user_builder = BoardBuilder::new(
			self.user_keypair.public_key(),
			self.expiry_height,
			self.server_keypair.public_key(),
			self.exit_delta,
		);

		let funding_tx = Transaction {
			version: Version(3),
			lock_time: LockTime::ZERO,
			input: vec![TxIn {
				previous_output: OutPoint::null(),
				script_sig: ScriptBuf::new(),
				sequence: Sequence::ZERO,
				witness: Witness::new(),
			}],
			output: vec![
				TxOut {
					value: self.amount,
					script_pubkey: user_builder.funding_script_pubkey(),
				}
			],
		};

		let funding_outpoint = OutPoint::new(funding_tx.compute_txid(), 0);

		let user_builder = user_builder
			.set_funding_details(self.amount, funding_outpoint)
			.generate_user_nonces();

		let user_pub_nonce = user_builder.user_pub_nonce();

		// The server builder
		let server_builder = BoardBuilder::new_for_cosign(
			self.user_keypair.public_key(),
			self.expiry_height,
			self.server_keypair.public_key(),
			self.exit_delta,
			self.amount,
			funding_outpoint,
			*user_pub_nonce,
		);

		let server_cosign_response = server_builder.server_cosign(&self.server_keypair);

		let vtxo = user_builder.build_vtxo(&server_cosign_response, &self.user_keypair).unwrap();
		(funding_tx, vtxo)
	}
}

pub fn random_utxo() -> OutPoint {
	OutPoint::new(Txid::from_byte_array(rand::random()), rand::random())
}

#[test]
fn create_dummy_output() {
	let board = DummyTestVtxoSpec {
		amount: Amount::from_sat(1000),
		expiry_height: 100000,
		exit_delta: 1000,
		user_keypair: Keypair::new(&crate::SECP, &mut bitcoin::secp256k1::rand::thread_rng()),
		server_keypair: Keypair::new(&crate::SECP, &mut bitcoin::secp256k1::rand::thread_rng()),
	};

	board.build();
}

#[test]
fn default_dummy_vtxo() {
	DummyTestVtxoSpec::default().build();
}


use std::borrow::Cow;
use std::str::FromStr;

use anyhow::Context;
use bitcoin::{OutPoint, Transaction};
use bitcoin::consensus::deserialize;
use bitcoin::secp256k1::SecretKey;
use tokio_postgres::Row;

use ark::{musig, VtxoId};
use ark::rounds::RoundId;

use crate::secret::Secret;


/// The relevant state kept for a forfeited vtxo.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForfeitState {
	/// The round at which the vtxo was forfeited. This is where the connector
	/// of the forfeit tx will come from.
	pub round_id: RoundId,
	#[serde(with = "crate::database::model::serde::pub_nonces")]
	pub user_nonces: Vec<musig::PublicNonce>,
	#[serde(with = "crate::database::model::serde::part_sigs")]
	pub user_part_sigs: Vec<musig::PartialSignature>,
	#[serde(with = "crate::database::model::serde::pub_nonces")]
	pub pub_nonces: Vec<musig::PublicNonce>,
	pub sec_nonces: Vec<Secret<musig::DangerousSecretNonce>>,
}

#[derive(Debug)]
pub struct ForfeitRoundState {
	pub round_id: RoundId,
	pub nb_input_vtxos: u32,
	pub nb_connectors_used: u32,
	pub connector_key: SecretKey,
}

impl TryFrom<Row> for ForfeitRoundState {
	type Error = anyhow::Error;

	fn try_from(row: Row) -> Result<Self, Self::Error> {
		Ok(ForfeitRoundState {
			round_id: RoundId::from_str(&row.get::<_, &str>("funding_txid"))
				.context("bad funding_txid stored in forfeit state")?,
			nb_input_vtxos: row.get("nb_input_vtxos"),
			nb_connectors_used: row.get("nb_connectors_used"),
			connector_key: SecretKey::from_slice(&row.get::<_, &[u8]>("connector_key"))
				.context("bad connector key stored in forfeit state")?,
		})
	}
}

#[derive(Debug)]
pub struct ForfeitClaimState<'a> {
	pub vtxo: VtxoId,
	pub connector_tx: Option<Cow<'a, Transaction>>,
	pub connector_cpfp: Option<Cow<'a, Transaction>>,
	pub connector: OutPoint,
	pub forfeit_tx: Cow<'a, Transaction>,
	pub forfeit_cpfp: Option<Cow<'a, Transaction>>,
}

impl TryFrom<Row> for ForfeitClaimState<'static> {
	type Error = anyhow::Error;

	fn try_from(row: Row) -> Result<Self, Self::Error> {
		Ok(ForfeitClaimState {
			vtxo: VtxoId::from_str(row.get::<_, &str>("vtxo_id"))?,
			connector_tx: row.get::<_, Option<&[u8]>>("connector_tx")
				.map(deserialize).transpose()
				.context("invalid connector_tx")?
				.map(Cow::Owned),
			connector_cpfp: row.get::<_, Option<&[u8]>>("connector_cpfp")
				.map(deserialize).transpose()
				.context("invalid connector_cpfp")?
				.map(Cow::Owned),
			connector: deserialize(row.get::<_, &[u8]>("connector"))
				.context("invalid connector point")?,
			forfeit_tx: Cow::Owned(deserialize(row.get::<_, &[u8]>("forfeit_tx"))
				.context("invalid forfeit_tx")?),
			forfeit_cpfp: row.get::<_, Option<&[u8]>>("forfeit_cpfp")
				.map(deserialize).transpose()
				.context("invalid forfeit_cpfp")?
				.map(Cow::Owned),
		})
	}
}

#[cfg(test)]
mod test {
	use super::*;
	use bitcoin::hex::{DisplayHex, FromHex};
	use bitcoin::key::Keypair;
	use bitcoin::secp256k1::rand;

	use ark::musig;

	use crate::SECP;

	#[test]
	fn forfeit_state_encoding() {
		// first test random roundtrip
		let key = Keypair::new(&*SECP, &mut rand::thread_rng());
		let (secn, pubn) = musig::nonce_pair(&key);
		let part = musig::PartialSignature::from_byte_array(
			&FromHex::from_hex("fe2b5cf922855b8318ba6224da3b0adabc0d9de4254b47d9687846861aa0f843").unwrap(),
		).unwrap();

		let ffs = ForfeitState {
			round_id: RoundId::from_slice(&[0u8; 32][..]).unwrap(),
			user_nonces: vec![pubn, pubn],
			user_part_sigs: vec![part, part],
			pub_nonces: vec![pubn, pubn],
			sec_nonces: vec![Secret::new(musig::DangerousSecretNonce::new(secn))],
		};
		let encoded = rmp_serde::to_vec_named(&ffs).unwrap();
		let decoded = rmp_serde::from_slice(&encoded[..]).unwrap();
		assert_eq!(ffs, decoded);

		// then test stability
		let bytes = Vec::<u8>::from_hex("85a8726f756e645f6964c4200000000000000000000000000000000000000000000000000000000000000000ab757365725f6e6f6e63657392c4420267390f9da47a07b025839c8efcb1a7bde7cf811f83aa2492924a7144054779ee03c3386f8699df043c23d3da71f7f72b9b70157f97b34546de54efc5c0f8af4507c4420267390f9da47a07b025839c8efcb1a7bde7cf811f83aa2492924a7144054779ee03c3386f8699df043c23d3da71f7f72b9b70157f97b34546de54efc5c0f8af4507ae757365725f706172745f7369677392c420fe2b5cf922855b8318ba6224da3b0adabc0d9de4254b47d9687846861aa0f843c420fe2b5cf922855b8318ba6224da3b0adabc0d9de4254b47d9687846861aa0f843aa7075625f6e6f6e63657392c4420267390f9da47a07b025839c8efcb1a7bde7cf811f83aa2492924a7144054779ee03c3386f8699df043c23d3da71f7f72b9b70157f97b34546de54efc5c0f8af4507c4420267390f9da47a07b025839c8efcb1a7bde7cf811f83aa2492924a7144054779ee03c3386f8699df043c23d3da71f7f72b9b70157f97b34546de54efc5c0f8af4507aa7365635f6e6f6e63657391dc0084220eccdcccf10f4f42ccefcc89cc85cccc407bcc9e74ccefcce8454c695fcc86cce6cc86ccd9ccd779cc83ccbdcc97ccfeccd14a3bcce57268ccb073ccd8ccb3cc9810ccfc2e0735ccb6ccd6ccf832044e78ccb004cceecc9505434f10cc875eccfb453d7c30ccefcc8cccb740066025cc8eccdd0fccd90709cce30d017dcccfcccf12ccfdccf37fcce220ccdfcce7ccc1537563ccb3357339ccac09ccacccf31cccb8cc9c09cc8cccab144bcc826078ccfd11cc940d48ccd01dcc95ccd82c56cca9ccda").unwrap();
		let stable = rmp_serde::from_slice::<ForfeitState>(&bytes).unwrap();
		let encoded = rmp_serde::to_vec_named(&stable).unwrap();
		assert_eq!(bytes.as_hex().to_string(), encoded.as_hex().to_string());

	}
}

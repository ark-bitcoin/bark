
use std::str::FromStr;

use bitcoin::{Transaction, Txid};
use bitcoin::consensus::deserialize;
use chrono::{DateTime, Local};
use tokio_postgres::Row;

use ark::{ProtocolEncoding, Vtxo, VtxoId};

use crate::database::forfeits::ForfeitState;


#[derive(Debug)]
pub struct VtxoState {
	pub id: i64,
	/// The id of the VTXO
	pub vtxo_id: VtxoId,

	/// The raw vtxo encoded.
	pub vtxo: Vtxo,
	// NB keep this type explicit as u32 instead of BlockHeight to ensure encoding is stable
	pub expiry: u32,

	/// If this vtxo was spent in an OOR tx, the txid of the OOR tx.
	pub oor_spent_txid: Option<Txid>,
	/// The round id this vtxo was forfeited in, plus the forfeit tx signatures
	/// of the user, if the vtxo was forfeited.
	pub forfeit_state: Option<ForfeitState>,
	/// The round id this vtxo was forfeited in.
	pub forfeit_round_id: Option<i64>,
	/// If this is a board vtxo, the time at which it was swept.
	pub board_swept_at: Option<DateTime<Local>>,
	pub created_at: DateTime<Local>,
	pub updated_at: DateTime<Local>,
}

impl VtxoState {
	pub fn is_spendable(&self) -> bool {
		self.oor_spent_txid.is_none() && self.forfeit_state.is_none()
	}
}

impl TryFrom<Row> for VtxoState {
	type Error = anyhow::Error;

	fn try_from(row: Row) -> Result<Self, Self::Error> {
		let vtxo_id = VtxoId::from_str(row.get::<_, &str>("vtxo_id"))?;
		let vtxo = Vtxo::deserialize(row.get("vtxo"))?;
		debug_assert_eq!(vtxo_id, vtxo.id());

		Ok(Self {
			id: row.get("id"),
			vtxo_id,
			vtxo,
			expiry: u32::try_from(row.get::<_, i32>("expiry"))?,
			oor_spent_txid: row
				.get::<_, Option<&str>>("oor_spent_txid")
				.map(|txid| Txid::from_str(txid))
				.transpose()?,
			forfeit_state: row
				.get::<_, Option<&[u8]>>("forfeit_state")
				.map(|bytes| rmp_serde::from_slice(bytes))
				.transpose()?,
			forfeit_round_id: row.get("forfeit_round_id"),
			board_swept_at: row.get("board_swept_at"),
			created_at: row.get("created_at"),
			updated_at: row.get("updated_at"),
		})
	}
}

#[derive(Debug, Clone)]
pub struct Sweep {
	pub txid: Txid,
	pub tx: Transaction
}

impl TryFrom<Row> for Sweep {
	type Error = anyhow::Error;

	fn try_from(value: Row) -> Result<Self, Self::Error> {
		let txid = Txid::from_str(&value.get::<_, String>("txid"))?;
		let tx = deserialize::<Transaction>(value.get("tx"))?;
		debug_assert_eq!(tx.compute_txid(), txid);

		Ok(Self { txid, tx })
	}
}

pub(crate) mod serde {
	use std::fmt;
	use serde::{Deserializer, Serializer};
	use crate::serde_util::Bytes;

	pub mod pub_nonces {
		use super::*;
		use serde::ser::SerializeSeq;
		use ark::musig::PublicNonce;

		pub fn serialize<S: Serializer>(nonces: &Vec<PublicNonce>, s: S) -> Result<S::Ok, S::Error> {
			let mut seq = s.serialize_seq(Some(nonces.len()))?;
			for nonce in nonces {
				seq.serialize_element(&Bytes(nonce.serialize()[..].into()))?;
			}
			seq.end()
		}

		pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<PublicNonce>, D::Error> {
			struct Visitor;

			impl<'de> serde::de::Visitor<'de> for Visitor {
				type Value = Vec<PublicNonce>;

				fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
					f.write_str("a list of public musig nonces")
				}

				fn visit_seq<A>(self, mut s: A) -> Result<Self::Value, A::Error>
					where A: serde::de::SeqAccess<'de>,
				{
					let mut ret = Vec::with_capacity(s.size_hint().unwrap_or(0));
					while let Some(e) = s.next_element::<Bytes>()? {
						ret.push(PublicNonce::from_byte_array(
							&TryFrom::try_from(e.0.as_ref()).map_err(serde::de::Error::custom)?
						).map_err(serde::de::Error::custom)?);
					}
					Ok(ret)
				}
			}
			d.deserialize_seq(Visitor)
		}
	}

	pub mod part_sigs {
		use super::*;
		use serde::ser::SerializeSeq;
		use ark::musig::PartialSignature;

		pub fn serialize<S: Serializer>(nonces: &Vec<PartialSignature>, s: S) -> Result<S::Ok, S::Error> {
			let mut seq = s.serialize_seq(Some(nonces.len()))?;
			for nonce in nonces {
				seq.serialize_element(&Bytes(nonce.serialize()[..].into()))?;
			}
			seq.end()
		}

		pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<PartialSignature>, D::Error> {
			struct Visitor;

			impl<'de> serde::de::Visitor<'de> for Visitor {
				type Value = Vec<PartialSignature>;

				fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
					f.write_str("a list of partial musig signatures")
				}

				fn visit_seq<A>(self, mut s: A) -> Result<Self::Value, A::Error>
					where A: serde::de::SeqAccess<'de>,
				{
					let mut ret = Vec::with_capacity(s.size_hint().unwrap_or(0));
					while let Some(e) = s.next_element::<Bytes>()? {
						ret.push(PartialSignature::from_byte_array(
							&TryFrom::try_from(e.0.as_ref()).map_err(serde::de::Error::custom)?
						).map_err(serde::de::Error::custom)?);
					}
					Ok(ret)
				}
			}
			d.deserialize_seq(Visitor)
		}
	}
}

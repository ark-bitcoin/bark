
use std::str::FromStr;

use bitcoin::Transaction;
use bitcoin::consensus::deserialize;
use bitcoin::secp256k1::SecretKey;
use bitcoin_ext::BlockHeight;
use chrono::{DateTime, Local};
use tokio_postgres::Row;

use ark::ProtocolEncoding;
use ark::rounds::{RoundId, RoundSeq};
use ark::tree::signed::SignedVtxoTreeSpec;


#[derive(Debug, Clone)]
pub struct StoredRound {
	pub id: i64,
	pub seq: RoundSeq,
	pub funding_txid: RoundId,
	pub funding_tx: Transaction,
	pub signed_tree: SignedVtxoTreeSpec,
	pub nb_input_vtxos: usize,
	pub connector_key: SecretKey,
	pub expiry_height: BlockHeight,
	pub swept_at: Option<DateTime<Local>>,
	pub created_at: DateTime<Local>,
}

impl TryFrom<Row> for StoredRound {
	type Error = anyhow::Error;

	fn try_from(row: Row) -> Result<Self, Self::Error> {
		let funding_txid = RoundId::from_str(&row.get::<_, &str>("funding_txid"))?;
		let funding_tx = deserialize::<Transaction>(row.get("funding_tx"))?;
		debug_assert_eq!(funding_tx.compute_txid(), funding_txid.as_round_txid());

		Ok(Self {
			id: row.get("id"),
			funding_txid,
			funding_tx,
			seq: RoundSeq::new(row.get::<_, i64>("seq") as u64),
			signed_tree: SignedVtxoTreeSpec::deserialize(row.get("signed_tree"))?,
			nb_input_vtxos: usize::try_from(row.get::<_, i32>("nb_input_vtxos"))?,
			connector_key: SecretKey::from_slice(row.get("connector_key"))?,
			expiry_height: row.get::<_, i32>("expiry") as BlockHeight,
			swept_at: row.get("swept_at"),
			created_at: row.get("created_at"),
		})
	}
}

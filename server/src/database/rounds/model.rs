
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
	pub id: RoundId,
	pub tx: Transaction,
	pub seq: RoundSeq,
	pub signed_tree: SignedVtxoTreeSpec,
	pub nb_input_vtxos: usize,
	pub connector_key: SecretKey,
	pub expiry_height: BlockHeight,
	pub created_at: DateTime<Local>,
}

impl TryFrom<Row> for StoredRound {
	type Error = anyhow::Error;

	fn try_from(row: Row) -> Result<Self, Self::Error> {
		let id = RoundId::from_str(&row.get::<_, &str>("id"))?;
		let tx = deserialize::<Transaction>(row.get("tx"))?;
		debug_assert_eq!(tx.compute_txid(), id.as_round_txid());

		Ok(Self {
			id, tx,
			seq: RoundSeq::new(row.get::<_, i64>("seq") as u64),
			signed_tree: SignedVtxoTreeSpec::deserialize(row.get("signed_tree"))?,
			nb_input_vtxos: usize::try_from(row.get::<_, i32>("nb_input_vtxos"))?,
			connector_key: SecretKey::from_slice(row.get("connector_key"))?,
			expiry_height: row.get::<_, i32>("expiry") as BlockHeight,
			created_at: row.get("created_at"),
		})
	}
}

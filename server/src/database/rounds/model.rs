
use std::str::FromStr;

use bitcoin::Transaction;
use bitcoin::consensus::deserialize;
use bitcoin::secp256k1::SecretKey;
use bitcoin_ext::BlockHeight;
use tokio_postgres::Row;

use ark::ProtocolEncoding;
use ark::rounds::RoundId;
use ark::tree::signed::SignedVtxoTreeSpec;


#[derive(Debug, Clone)]
pub struct StoredRound {
	pub id: RoundId,
	pub tx: Transaction,
	pub signed_tree: SignedVtxoTreeSpec,
	pub nb_input_vtxos: usize,
	pub connector_key: SecretKey,
	pub expiry_height: BlockHeight,
}

impl TryFrom<Row> for StoredRound {
	type Error = anyhow::Error;

	fn try_from(value: Row) -> Result<Self, Self::Error> {
		let id = RoundId::from_str(&value.get::<_, &str>("id"))?;
		let tx = deserialize::<Transaction>(value.get("tx"))?;
		debug_assert_eq!(tx.compute_txid(), id.as_round_txid());

		Ok(Self {
			id, tx,
			signed_tree: SignedVtxoTreeSpec::deserialize(value.get("signed_tree"))?,
			nb_input_vtxos: usize::try_from(value.get::<_, i32>("nb_input_vtxos"))?,
			connector_key: SecretKey::from_slice(value.get("connector_key"))?,
			expiry_height: value.get::<_, i32>("expiry") as BlockHeight,
		})
	}
}

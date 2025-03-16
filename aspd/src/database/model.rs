use std::str::FromStr;

use bitcoin::{Transaction, Txid};
use bitcoin::consensus::deserialize;
use bitcoin::secp256k1::SecretKey;
use tokio_postgres::Row;

use ark::{Vtxo, VtxoId};
use ark::musig::secpm::schnorr;
use ark::rounds::RoundId;
use ark::tree::signed::SignedVtxoTreeSpec;

#[derive(Debug, Clone)]
pub struct StoredRound {
	pub id: RoundId,
	pub tx: Transaction,
	pub signed_tree: SignedVtxoTreeSpec,
	pub nb_input_vtxos: u64,
	pub connector_key: SecretKey,
}

impl TryFrom<Row> for StoredRound {
	type Error = anyhow::Error;

	fn try_from(value: Row) -> Result<Self, Self::Error> {
		let id = RoundId::from_str(&value.get::<_, &str>("id"))?;
		let tx: Transaction = deserialize::<Transaction>(value.get("tx"))?;
		debug_assert_eq!(tx.compute_txid(), id.as_round_txid());

		Ok(Self {
			id, tx,
			signed_tree: SignedVtxoTreeSpec::decode(value.get("signed_tree"))?,
			nb_input_vtxos: u64::try_from(value.get::<_, i32>("nb_input_vtxos"))?,
			connector_key: SecretKey::from_slice(value.get("connector_key"))?,
		})
	}
}

#[derive(Debug, Clone)]
pub struct VtxoState {
	/// The id of the VTXO
	pub id: VtxoId,
	/// The raw vtxo encoded.
	pub vtxo: Vtxo,
	// NB keep this type explicit as u32 instead of BlockHeight to ensure encoding is stable
	pub expiry: u32,

	/// If this vtxo was spent in an OOR tx, the txid of the OOR tx.
	pub oor_spent: Option<Txid>,
	/// The forfeit tx signatures of the user if the vtxo was forfeited.
	pub forfeit_sigs: Option<Vec<schnorr::Signature>>,
}

impl VtxoState {
	pub fn is_spendable(&self) -> bool {
		self.oor_spent.is_none() && self.forfeit_sigs.is_none()
	}
}

impl TryFrom<Row> for VtxoState {
	type Error = anyhow::Error;

	fn try_from(value: Row) -> Result<Self, Self::Error> {
		let vtxo_id = VtxoId::from_str(value.get::<_, &str>("id"))?;
		let vtxo = Vtxo::decode(value.get("vtxo"))?;
		debug_assert_eq!(vtxo_id, vtxo.id());

		Ok(Self {
			id: vtxo_id,
			vtxo,
			expiry: u32::try_from(value.get::<_, i32>("expiry"))?,
			oor_spent: value
				.get::<_, Option<&[u8]>>("oor_spent")
				.map(|tx| deserialize(tx))
				.transpose()?,
			forfeit_sigs: value
				.get::<_, Option<Vec<&[u8]>>>("forfeit_sigs")
				.map(|sigs| sigs
					.into_iter()
					.map(|sig|  Ok(schnorr::Signature::from_byte_array(sig.try_into()?)))
					.collect::<anyhow::Result<Vec<_>>>()
				)
				.transpose()?
		})
	}
}

#[derive(Debug, Clone)]
pub struct PendingSweep {
	pub txid: Txid,
	pub tx: Transaction
}

impl TryFrom<Row> for PendingSweep {
	type Error = anyhow::Error;

	fn try_from(value: Row) -> Result<Self, Self::Error> {
		let txid = Txid::from_str(&value.get::<_, String>("txid"))?;
		let tx = deserialize::<Transaction>(value.get("tx"))?;
		debug_assert_eq!(tx.compute_txid(), txid);

		Ok(Self { txid, tx })
	}
}

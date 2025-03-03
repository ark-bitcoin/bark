use std::str::FromStr;

use bitcoin::{consensus::deserialize, secp256k1::PublicKey, Transaction, Txid};

use ark::{musig::secpm::schnorr, rounds::RoundId, tree::signed::SignedVtxoTreeSpec, Vtxo, VtxoId};
use tokio_postgres::Row;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct StoredRound {
	pub id: RoundId,
	pub tx: Transaction,
	pub signed_tree: SignedVtxoTreeSpec,
	pub nb_input_vtxos: u64,
}

impl TryFrom<Row> for StoredRound {
	type Error = anyhow::Error;

	fn try_from(value: Row) -> Result<Self, Self::Error> {
		let id = RoundId::from_str(&value.get::<_, String>("id"))?;
		let tx: Transaction = deserialize::<Transaction>(value.get("tx"))?;
		debug_assert_eq!(tx.compute_txid(), id.as_round_txid());

		Ok(Self {
			id, tx,
			signed_tree: SignedVtxoTreeSpec::decode(value.get("signed_tree"))?,
			nb_input_vtxos: u64::try_from(value.get::<_, i32>("nb_input_vtxos"))?
		})
	}
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct VtxoState {
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
		let vtxoid = value.get::<_, String>("id");
		let vtxo = Vtxo::decode(value.get("vtxo"))?;
		debug_assert_eq!(vtxoid, vtxo.id().to_string());

		Ok(Self {
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

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MailboxArkoor {
	pub id: VtxoId,
	pub pubkey: PublicKey,
	pub vtxo: Vtxo,
}

impl TryFrom<Row> for MailboxArkoor {
	type Error = anyhow::Error;

	fn try_from(value: Row) -> Result<Self, Self::Error> {
		let vtxoid = VtxoId::from_str(&value.get::<_, String>("id"))?;
		let vtxo = Vtxo::decode(value.get("vtxo"))?;
		debug_assert_eq!(vtxoid, vtxo.id());

		Ok(Self {
			id: vtxoid,
			vtxo,
			pubkey: PublicKey::from_slice(&value.get::<_, &[u8]>("pubkey"))?
		})
	}
}

#[derive(Debug, Clone, Deserialize, Serialize)]
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

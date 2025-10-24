use std::borrow::Borrow;
use std::fmt;
use std::str::FromStr;

use ark::musig::{DangerousSecretNonce, SecretNonce};
use ark::tree::signed::VtxoTreeSpec;
use bitcoin::consensus::encode::deserialize_hex;
use bitcoin::hex::FromHex;
use bitcoin::{Amount, Transaction};
use rusqlite::types::FromSql;
use rusqlite::{Row, RowIndex, Rows};

use ark::{ProtocolEncoding, Vtxo};
use ark::rounds::{RoundId, RoundSeq};

use crate::movement::{Movement, MovementKind, MovementRecipient};
use crate::round::{
	AttemptStartedState,
	VtxoForfeitedInRound,
	ForfeitSignedState,
	PaymentSubmittedState,
	PendingConfirmationState,
	RoundAbandonedState,
	RoundCancelledState,
	RoundConfirmedState,
	RoundParticipation,
	RoundState,
	RoundStateKind,
	VtxoTreeSignedState
};
use crate::vtxo_state::VtxoState;
use crate::WalletVtxo;

pub trait RowExt<'a>: Borrow<Row<'a>> {
	/// We need the value from a potentially optional column
	fn need<I, T>(&self, idx: I) -> anyhow::Result<T>
	where
		I: RowIndex + Clone + fmt::Display,
		T: FromSql,
	{
		match self.borrow().get::<I, Option<T>>(idx.clone())? {
			Some(v) => Ok(v),
			None => bail!("missing value for column '{}'", idx),
		}
	}
}

impl<'a> RowExt<'a> for Row<'a> {}

pub (crate) fn row_to_movement(row: &Row<'_>) -> anyhow::Result<Movement> {
	let fees: Amount = Amount::from_sat(row.get("fees_sat")?);

	let kind = MovementKind::from_str(&row.get::<_, String>("kind")?)?;
	let spends = serde_json::from_str::<Vec<String>>(&row.get::<_, String>("spends")?)?
		.iter()
		.map(|v| {
			let bytes = Vec::<u8>::from_hex(v).expect("corrupt db");
			Vtxo::deserialize(&bytes)
		})
		.collect::<Result<Vec<Vtxo>, _>>()?;

	let receives = serde_json::from_str::<Vec<String>>(&row.get::<_, String>("receives")?)?
		.iter()
		.map(|v| {
			let bytes = Vec::<u8>::from_hex(v).expect("corrupt db");
			Vtxo::deserialize(&bytes)
		})
		.collect::<Result<Vec<Vtxo>, _>>()?;


	let recipients = serde_json::from_str::<Vec<MovementRecipient>>(&row.get::<_, String>("recipients")?)?;

	Ok(Movement {
		id: row.get("id")?,
		kind: kind,
		fees: fees,
		spends: spends,
		receives: receives,
		recipients: recipients,
		created_at: row.get("created_at")?,
	})
}

fn row_to_participation(row: &Row<'_>) -> anyhow::Result<RoundParticipation> {
	let inputs = serde_json::from_str::<Vec<String>>(&row.need::<_, String>("inputs")?)?
		.iter()
		.map(|v| {
			let bytes = Vec::<u8>::from_hex(v).expect("corrupt db");
			Vtxo::deserialize(&bytes)
		})
		.collect::<Result<Vec<Vtxo>, _>>()?;

	let payment_requests = serde_json::from_slice(&row.need::<_, Vec<u8>>("payment_requests")?)?;
	let offboard_requests = serde_json::from_slice(&row.need::<_, Vec<u8>>("offboard_requests")?)?;

	Ok(RoundParticipation {
		inputs,
		outputs: payment_requests,
		offboards: offboard_requests,
	})
}

pub (crate) fn row_to_secret_nonces(row: &Row<'_>) -> anyhow::Result<Option<Vec<Vec<SecretNonce>>>> {
	let secret_nonces_raw = row.get::<_, Option<Vec<u8>>>("secret_nonces")?;

	if let Some(secret_nonces_raw) = secret_nonces_raw {
		let secret_nonces = serde_json::from_slice::<Vec<Vec<DangerousSecretNonce>>>(&secret_nonces_raw)?;
		let secret_nonces = secret_nonces.into_iter()
			.map(|sec_nonces| {
				let sec_nonces = sec_nonces.into_iter()
					.map(|dangerous_nonce| dangerous_nonce.to_sec_nonce())
					.collect::<Vec<_>>();
				sec_nonces
			})
			.collect::<Vec<_>>();
		Ok(Some(secret_nonces))
	} else {
		Ok(None)
	}
}

fn row_to_attempt_seq(row: &Row<'_>) -> anyhow::Result<Option<usize>> {
	let attempt_seq = row.get::<_, Option<i64>>("attempt_seq")?;
	Ok(attempt_seq.map(|v| v as usize))
}

fn row_to_round_txid(row: &Row<'_>) -> anyhow::Result<(Transaction, RoundId)> {
	let round_tx = deserialize_hex(&row.need::<_, String>("round_tx")?)?;
	let round_txid = RoundId::from_str(&row.need::<_, String>("round_txid")?)?;

	Ok((round_tx, round_txid))
}

fn row_to_vtxo_forfeited_in_round(row: &Row<'_>) -> anyhow::Result<Vec<VtxoForfeitedInRound>> {
	let forfeited_vtxos = serde_json::from_str::<Vec<VtxoForfeitedInRound>>(
		&row.need::<_, String>("vtxo_forfeited_in_round")?)?;
	Ok(forfeited_vtxos)
}

pub (crate) fn row_to_round_state(row: &Row<'_>) -> anyhow::Result<RoundState> {
	let round_attempt_id = row.need::<_, i64>("id")?;

	let round_seq = match row.get::<_, Option<i64>>("round_seq")? {
		Some(round_seq) => Some(RoundSeq::new(TryFrom::try_from(round_seq)?)),
		None => None,
	};

	let status = RoundStateKind::from_str(&row.need::<_, String>("status")?)?;

	match status {
		RoundStateKind::AttemptStarted => {
			Ok(RoundState::AttemptStarted(AttemptStartedState {
				round_attempt_id,
				round_seq: round_seq.expect("round_seq should be present during round"),
				attempt_seq: row_to_attempt_seq(row)?.expect("attempt_seq should be present during round"),
				participation: row_to_participation(row)?,
			}))
		},
		RoundStateKind::PaymentSubmitted => {
			let participation = row_to_participation(row)?;
			let cosign_keys = serde_json::from_slice(&row.need::<_, Vec<u8>>("cosign_keys")?)?;
			Ok(RoundState::PaymentSubmitted(PaymentSubmittedState {
				round_attempt_id,
				round_seq: round_seq.expect("round_seq should be present during round"),
				attempt_seq: row_to_attempt_seq(row)?.expect("attempt_seq should be present during round"),
				participation,
				cosign_keys,
			}))
		},
		RoundStateKind::VtxoTreeSigned => {
			let participation = row_to_participation(row)?;
			let (unsigned_round_tx, round_txid) = row_to_round_txid(row)?;
			let vtxo_tree = VtxoTreeSpec::deserialize(&row.need::<_, Vec<u8>>("vtxo_tree")?)?;
			Ok(RoundState::VtxoTreeSigned(VtxoTreeSignedState {
				round_attempt_id,
				round_seq: round_seq.expect("round_seq should be present during round"),
				attempt_seq: row_to_attempt_seq(row)?.expect("attempt_seq should be present during round"),
				participation,
				round_txid,
				unsigned_round_tx,
				vtxo_tree,
			}))
		},
		RoundStateKind::ForfeitSigned => {
			let forfeited_vtxos = row_to_vtxo_forfeited_in_round(row)?;

			let (unsigned_round_tx, round_txid) = row_to_round_txid(row)?;

			let vtxos = serde_json::from_slice::<Vec<Vec<u8>>>(&row.need::<_, Vec<u8>>("vtxos")?)?
				.iter().map(|v| Vtxo::deserialize(v))
				.collect::<Result<Vec<Vtxo>, _>>()?;

			Ok(RoundState::ForfeitSigned(ForfeitSignedState {
				round_attempt_id,
				round_seq: round_seq.expect("round_seq should be present during round"),
				attempt_seq: row_to_attempt_seq(row)?.expect("attempt_seq should be present during round"),
				participation: row_to_participation(row)?,
				vtxos,
				round_txid,
				unsigned_round_tx,
				forfeited_vtxos,
			}))
		},
		RoundStateKind::RoundCancelled => {
			let forfeited_vtxos = row_to_vtxo_forfeited_in_round(row)?;

			let (_, round_txid) = row_to_round_txid(row)?;
			Ok(RoundState::RoundCancelled(RoundCancelledState {
				round_attempt_id,
				round_seq,
				attempt_seq: row_to_attempt_seq(row)?,
				round_txid,
				forfeited_vtxos,
			}))
		},
		RoundStateKind::PendingConfirmation => {
			let forfeited_vtxos = row_to_vtxo_forfeited_in_round(row)?;
			let participation = row_to_participation(row)?;
			let vtxos = serde_json::from_slice::<Vec<Vec<u8>>>(&row.need::<_, Vec<u8>>("vtxos")?)?
				.iter().map(|v| Vtxo::deserialize(v))
				.collect::<Result<Vec<Vtxo>, _>>()?;

			let (round_tx, round_txid) = row_to_round_txid(row)?;

			Ok(RoundState::PendingConfirmation(PendingConfirmationState {
				round_attempt_id,
				round_seq,
				attempt_seq: row_to_attempt_seq(row)?,
				participation,
				round_txid,
				round_tx,
				vtxos,
				forfeited_vtxos,
			}))
		},
		RoundStateKind::RoundConfirmed => {
			let (round_tx, round_txid) = row_to_round_txid(row)?;
			Ok(RoundState::RoundConfirmed(RoundConfirmedState {
				round_attempt_id,
				round_seq,
				attempt_seq: row_to_attempt_seq(row)?,
				round_txid, round_tx,
			}))
		},
		RoundStateKind::RoundAbandonned => {
			Ok(RoundState::RoundAbandoned(RoundAbandonedState { round_attempt_id }))
		},
	}
}

pub (crate) fn row_to_wallet_vtxo(row: &Row<'_>) -> anyhow::Result<WalletVtxo> {
	let raw_vtxo = row.get::<_, Vec<u8>>("raw_vtxo")?;
	let vtxo = Vtxo::deserialize(&raw_vtxo)?;

	let state = serde_json::from_slice::<VtxoState>(&row.get::<_, Vec<u8>>("state")?)?;
	Ok(WalletVtxo { vtxo, state })
}

pub (crate) fn rows_to_wallet_vtxos(mut rows: Rows<'_>) -> anyhow::Result<Vec<WalletVtxo>> {
	let mut vtxos = Vec::new();
	while let Some(row) = rows.next()? {
		vtxos.push(row_to_wallet_vtxo(&row)?);
	}
	Ok(vtxos)
}
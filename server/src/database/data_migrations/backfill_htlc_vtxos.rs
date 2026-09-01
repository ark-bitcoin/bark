use anyhow::{bail, Context};
use futures::StreamExt;
use tokio_postgres::types::Type;

use ark::encode::ProtocolEncoding;
use ark::vtxo::policy::{ServerVtxoPolicy, VtxoPolicy, VtxoPolicyKind};

use crate::database::Db;

const INCOMING: &str = "incoming";
const OUTGOING: &str = "outgoing";
const FULFILLED: &str = "fulfilled";
const REVOKED: &str = "revoked";

/// Backfill the htlc_vtxo table from the existing vtxo rows.
///
/// We only consider an htlc revoked or fulfilled once an arkoor has
/// been signed. It is true resolution and not just the presence of
/// a preimage.
///
/// For HtlcSend we have only signed revocations. If an arkoor tx
/// is present we know the htlc has been revoked.
///
/// For HtlcRecv we have only signed when the user claims the htlc.
/// Each resolution is a fulfillment.
///
/// Remember that in arkoor the server signs first, and both spends
/// grant money to the user, so the resolution stands as soon as the
/// server has shared its sigs. We don't need to wait for the user
/// to provide their sigs as well.
pub async fn run(db: &Db) -> anyhow::Result<u64> {
	let reader = db.get_conn().await.context("reader connection")?;
	let writer = db.get_conn().await.context("writer connection")?;

	let htlc_kinds = [
		VtxoPolicyKind::ServerHtlcSend,
		VtxoPolicyKind::ServerHtlcSend_v0,
		VtxoPolicyKind::ServerHtlcRecv,
		VtxoPolicyKind::ServerHtlcRecv_v0,
	].iter().map(|k| k.to_string()).collect::<Vec<_>>();

	let select = reader.prepare_typed(
		"SELECT v.id, v.policy, \
			v.oor_spent_txid IS NOT NULL AS arkoor_spent \
		 FROM vtxo v \
		 WHERE v.policy_type = ANY($1)",
		&[Type::TEXT_ARRAY],
	).await.context("preparing select")?;

	let insert = writer.prepare_typed(
		"INSERT INTO htlc_vtxo (id, payment_hash, htlc_expiry, direction, resolution) \
		 VALUES ($1, $2, $3, $4::htlc_direction, $5::htlc_resolution) \
		 ON CONFLICT (id) DO NOTHING",
		&[Type::INT8, Type::TEXT, Type::INT4, Type::TEXT, Type::TEXT],
	).await.context("preparing insert")?;

	let rows = reader.query_raw(&select, &[&htlc_kinds]).await
		.context("selecting htlc vtxos")?;
	tokio::pin! { rows };

	let mut inserted: u64 = 0;

	while let Some(row) = rows.next().await {
		let row = row.context("reading vtxo row")?;
		let id: i64 = row.get("id");
		let policy_bytes: &[u8] = row.get("policy");
		let arkoor_spent: bool = row.get("arkoor_spent");

		let policy = ServerVtxoPolicy::deserialize(policy_bytes)
			.with_context(|| format!("failed to deserialize policy of vtxo id={}", id))?;
		let (payment_hash, htlc_expiry, direction) = match policy {
			ServerVtxoPolicy::User(VtxoPolicy::ServerHtlcSend(p)) =>
				(p.payment_hash, p.htlc_expiry, INCOMING),
			ServerVtxoPolicy::User(VtxoPolicy::ServerHtlcSend_v0(p)) =>
				(p.payment_hash, p.htlc_expiry, INCOMING),
			ServerVtxoPolicy::User(VtxoPolicy::ServerHtlcRecv(p)) =>
				(p.payment_hash, p.htlc_expiry, OUTGOING),
			ServerVtxoPolicy::User(VtxoPolicy::ServerHtlcRecv_v0(p)) =>
				(p.payment_hash, p.htlc_expiry, OUTGOING),
			other => bail!("vtxo id={} has unexpected policy {:?}", id, other.policy_type()),
		};

		let resolution = match direction {
			INCOMING if arkoor_spent => Some(REVOKED),
			OUTGOING if arkoor_spent => Some(FULFILLED),
			_ => None,
		};

		let htlc_expiry = i32::try_from(htlc_expiry)
			.with_context(|| format!("htlc_expiry out of range for vtxo id={}", id))?;

		inserted += writer.execute(
			&insert,
			&[&id, &payment_hash.to_string(), &htlc_expiry, &direction, &resolution],
		).await.with_context(|| format!("failed to insert htlc vtxo id={}", id))?;
	}

	eprintln!("backfill_htlc_vtxos: inserted {} rows", inserted);
	Ok(inserted)
}

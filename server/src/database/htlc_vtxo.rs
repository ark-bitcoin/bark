//! Storage for the htlc data of htlc vtxos.
//!
//! A row in `htlc_vtxo` means the htlc vtxo exists from the server's point
//! of view:
//!
//! - An htlc-send vtxo is granted by the client to the server. It only
//!   exists once the client has registered the signed transaction chain,
//!   because only then does the server hold a claim on the funds. Cosigning
//!   alone creates no row.
//! - An htlc-recv vtxo is granted by the server to the client. It exists as
//!   soon as the server hands out its signatures, because the client can
//!   take it onchain from that moment, without registering anything.

use std::fmt;
use std::str::FromStr;

use anyhow::Context;
use bitcoin::Amount;
use tokio_postgres::Row;
use tokio_postgres::types::Type;

use ark::VtxoId;
use ark::lightning::PaymentHash;
use ark::vtxo::Full;
use ark::vtxo::policy::ServerVtxoPolicy;
use bitcoin_ext::BlockHeight;

use super::model::VtxoState;
use super::Tx;

/// Direction of an htlc vtxo, from the server's point of view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HtlcDirection {
	/// An htlc-send vtxo: funds a payment towards the server.
	Incoming,
	/// An htlc-recv vtxo: pays out to the user.
	Outgoing,
}

impl HtlcDirection {
	pub fn as_str(&self) -> &'static str {
		match self {
			HtlcDirection::Incoming => "incoming",
			HtlcDirection::Outgoing => "outgoing",
		}
	}
}

impl fmt::Display for HtlcDirection {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str(self.as_str())
	}
}

impl FromStr for HtlcDirection {
	type Err = anyhow::Error;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		match s {
			"incoming" => Ok(HtlcDirection::Incoming),
			"outgoing" => Ok(HtlcDirection::Outgoing),
			other => bail!("invalid htlc_direction: {}", other),
		}
	}
}

/// Once it is clear who got/will get the bitcoin
/// an htlc is considered resolved.
///
/// An htlc is fullfilled if the party with the preimage-path got the money
/// An htlc is revoked if the party with the time-out path got the money.
///
/// Note, this is explicilty different from preimage released.
/// Eg: If an htlc is revoked and the preimage is released later.
///     We will still consider the htlc as revoked.
///
/// For an HTLC we consider an htlc resolved once an arkoor tx has been
/// signed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HtlcResolution {
	/// The htlc has been fullfilled.
	Fulfilled,
	/// The htlc hs been refunded
	Revoked,
}

impl HtlcResolution {
	pub fn as_str(&self) -> &'static str {
		match self {
			HtlcResolution::Fulfilled => "fulfilled",
			HtlcResolution::Revoked => "revoked",
		}
	}
}

impl fmt::Display for HtlcResolution {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str(self.as_str())
	}
}

impl FromStr for HtlcResolution {
	type Err = anyhow::Error;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		match s {
			"fulfilled" => Ok(HtlcResolution::Fulfilled),
			"revoked" => Ok(HtlcResolution::Revoked),
			other => bail!("invalid htlc_resolution: {}", other),
		}
	}
}

/// The htlc data of an htlc vtxo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Htlc {
	pub payment_hash: PaymentHash,
	pub htlc_expiry: BlockHeight,
	pub direction: HtlcDirection,
	pub resolution: Option<HtlcResolution>,
}

/// An htlc vtxo: the vtxo state joined with its htlc data.
#[derive(Debug)]
pub struct HtlcVtxo {
	pub htlc: Htlc,
	pub vtxo: VtxoState,
}

impl HtlcVtxo {
	pub fn amount(&self) -> Amount {
		self.vtxo.vtxo.amount()
	}

	/// The height at which the htlc expires.
	pub fn htlc_expiry(&self) -> BlockHeight {
		self.htlc.htlc_expiry
	}

	/// The height at which the vtxo itself expires.
	pub fn vtxo_expiry(&self) -> BlockHeight {
		self.vtxo.vtxo.expiry_height()
	}

	pub fn direction(&self) -> HtlcDirection {
		self.htlc.direction
	}
}

impl TryFrom<Row> for HtlcVtxo {
	type Error = anyhow::Error;

	fn try_from(row: Row) -> Result<Self, Self::Error> {
		let htlc = Htlc {
			payment_hash: PaymentHash::from_str(row.get::<_, &str>("payment_hash"))
				.context("invalid payment_hash in DB")?,
			htlc_expiry: u32::try_from(row.get::<_, i32>("htlc_expiry"))
				.context("htlc_expiry out of range for u32")?,
			direction: row.get::<_, &str>("direction").parse()?,
			resolution: row.get::<_, Option<&str>>("resolution")
				.map(|s| s.parse()).transpose()?,
		};
		let vtxo = VtxoState::<Full, ServerVtxoPolicy>::try_from(row)?
			.try_into_user_vtxo_state()
			.map_err(|v| anyhow!("htlc vtxo {} is not a user vtxo", v.vtxo_id))?;
		Ok(HtlcVtxo { htlc, vtxo })
	}
}

/// The columns of an [HtlcVtxo], selected from `vtxo v` joined with
/// `htlc_vtxo hv`.
const HTLC_VTXO_COLUMNS: &str = "
	v.id, v.vtxo_id, v.vtxo, v.expiry, v.oor_spent_txid, v.spent_in_round,
	v.offboarded_in, v.banned_until_height, v.confirmed_height,
	v.spend_state::TEXT AS spend_state, v.created_at, v.updated_at,
	hv.payment_hash, hv.htlc_expiry,
	hv.direction::TEXT AS direction, hv.resolution::TEXT AS resolution
";

/// Insert the htlc data of the given vtxos, with no resolution yet.
///
/// Idempotent: existing rows are left untouched, so retried registrations
/// and grants don't fail.
pub async fn create_htlc_vtxos(
	tx: &Tx<'_>,
	vtxos: &[(VtxoId, PaymentHash, BlockHeight)],
	direction: HtlcDirection,
) -> anyhow::Result<()> {
	if vtxos.is_empty() {
		return Ok(());
	}

	let mut vtxo_ids = Vec::with_capacity(vtxos.len());
	let mut payment_hashes = Vec::with_capacity(vtxos.len());
	let mut expiries = Vec::with_capacity(vtxos.len());
	for (vtxo_id, payment_hash, htlc_expiry) in vtxos {
		vtxo_ids.push(vtxo_id.to_string());
		payment_hashes.push(payment_hash.to_string());
		expiries.push(i32::try_from(*htlc_expiry)
			.with_context(|| format!("htlc_expiry of vtxo {} out of range for i32", vtxo_id))?);
	}

	let stmt = tx.prepare_typed("
		INSERT INTO htlc_vtxo (id, payment_hash, htlc_expiry, direction)
		SELECT v.id, u.payment_hash, u.htlc_expiry, $4::htlc_direction
		FROM UNNEST($1::text[], $2::text[], $3::int4[]) AS u(vtxo_id, payment_hash, htlc_expiry)
		JOIN vtxo v ON v.vtxo_id = u.vtxo_id
		ON CONFLICT (id) DO NOTHING
	", &[Type::TEXT_ARRAY, Type::TEXT_ARRAY, Type::INT4_ARRAY, Type::TEXT]).await?;

	let rows = tx.execute(&stmt, &[&vtxo_ids, &payment_hashes, &expiries, &direction.as_str()])
		.await.context("failed to create htlc vtxos")?;

	// Fewer inserted rows than vtxos can mean existing rows (fine) or
	// unknown vtxo ids (a caller bug), so only then check for missing ones.
	if rows < vtxos.len() as u64 {
		let missing = tx.query("
			SELECT u.vtxo_id
			FROM UNNEST($1::text[]) AS u(vtxo_id)
			LEFT JOIN vtxo v ON v.vtxo_id = u.vtxo_id
			WHERE v.vtxo_id IS NULL
		", &[&vtxo_ids]).await.context("failed to find missing vtxos")?;
		if !missing.is_empty() {
			let missing = missing.iter().map(|r| r.get::<_, &str>("vtxo_id"))
				.collect::<Vec<_>>();
			bail!("vtxos not found: {}", missing.join(", "));
		}
	}
	Ok(())
}

/// Fetch an htlc vtxo by its vtxo id.
pub async fn get_htlc_vtxo(
	tx: &Tx<'_>,
	vtxo_id: VtxoId,
) -> anyhow::Result<Option<HtlcVtxo>> {
	let stmt = tx.prepare_typed(&format!("
		SELECT {HTLC_VTXO_COLUMNS}
		FROM htlc_vtxo hv JOIN vtxo v ON v.id = hv.id
		WHERE v.vtxo_id = $1
	"), &[Type::TEXT]).await?;

	let row = tx.query_opt(&stmt, &[&vtxo_id.to_string()]).await
		.context("failed to get htlc vtxo")?;

	row.map(HtlcVtxo::try_from).transpose()
}

/// Fetch all htlc vtxos of a payment hash.
pub async fn get_htlc_vtxo_states_by_payment_hash(
	tx: &Tx<'_>,
	payment_hash: PaymentHash,
) -> anyhow::Result<Vec<HtlcVtxo>> {
	let stmt = tx.prepare_typed(&format!("
		SELECT {HTLC_VTXO_COLUMNS}
		FROM htlc_vtxo hv JOIN vtxo v ON v.id = hv.id
		WHERE hv.payment_hash = $1
		ORDER BY v.id
	"), &[Type::TEXT]).await?;

	let rows = tx.query(&stmt, &[&payment_hash.to_string()]).await
		.context("failed to get htlc vtxos by payment hash")?;

	rows.into_iter().map(HtlcVtxo::try_from).collect()
}

/// Set the resolution of the given htlc vtxos.
///
/// Vtxos without an htlc_vtxo row are skipped: an htlc vtxo that never
/// started to exist (e.g. an unregistered htlc-send) has nothing to resolve.
pub async fn set_htlc_vtxo_resolutions(
	tx: &Tx<'_>,
	vtxo_ids: &[VtxoId],
	resolution: HtlcResolution,
) -> anyhow::Result<()> {
	if vtxo_ids.is_empty() {
		return Ok(());
	}

	let ids = vtxo_ids.iter().map(|id| id.to_string()).collect::<Vec<_>>();
	let stmt = tx.prepare_typed("
		UPDATE htlc_vtxo SET resolution = $2::htlc_resolution
		FROM vtxo WHERE vtxo.id = htlc_vtxo.id AND vtxo.vtxo_id = ANY($1)
	", &[Type::TEXT_ARRAY, Type::TEXT]).await?;

	tx.execute(&stmt, &[&ids, &resolution.as_str()])
		.await.context("failed to set htlc vtxo resolutions")?;
	Ok(())
}

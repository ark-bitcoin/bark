
mod model;
pub use model::*;

use anyhow::Context;
use bitcoin::consensus::serialize;

use ark::rounds::RoundId;

use crate::database::Db;

impl Db {
	pub async fn store_forfeits_round_state(
		&self,
		round_id: RoundId,
		nb_connectors_used: u32,
	) -> anyhow::Result<()> {
		let conn = self.pool.get().await?;
		let stmt = conn.prepare(&format!("
			INSERT INTO forfeits_round_state (round_id, nb_connectors_used)
			VALUES ($1, $2)
			ON CONFLICT (round_id) DO UPDATE
			SET nb_connectors_used = EXCLUDED.nb_connectors_used;
		")).await?;
		let _ = conn.query(&stmt, &[&round_id.to_string(), &nb_connectors_used]).await?;
		Ok(())
	}

	pub async fn get_forfeits_round_states(&self) -> anyhow::Result<Vec<ForfeitRoundState>> {
		let conn = self.pool.get().await?;
		let stmt = conn.prepare(&format!("
			SELECT round.id, round.connector_key, round.nb_input_vtxos, state.nb_connectors_used
			FROM
				round
			INNER JOIN
				forfeits_round_state state
			ON
				round.id = state.round_id;
		")).await?;
		let rows = conn.query(&stmt, &[]).await?;

		Ok(rows.into_iter().map(TryFrom::try_from).collect::<Result<_, _>>()
				.context("corrupt db: invalid forfeit round state row")?)
	}

	pub async fn store_forfeits_claim_state(
		&self,
		claim_state: ForfeitClaimState<'_>,
	) -> anyhow::Result<()> {
		let conn = self.pool.get().await?;
		let stmt = conn.prepare(&format!("
			INSERT INTO forfeits_claim_state
				(vtxo_id, connector_tx, connector_cpfp, connector_point, forfeit_tx, forfeit_cpfp)
			VALUES ($1, $2, $3, $4, $5, $6)
			ON CONFLICT (vtxo) DO UPDATE
			SET forfeit_cpfp = EXCLUDED.forfeit_cpfp;
		")).await?;
		let _ = conn.query(&stmt, &[
			&claim_state.vtxo.to_string(),
			&claim_state.connector_tx.map(|tx| serialize(tx.as_ref())),
			&claim_state.connector_cpfp.map(|tx| serialize(tx.as_ref())),
			&serialize(&claim_state.connector),
			&serialize(claim_state.forfeit_tx.as_ref()),
			&claim_state.forfeit_cpfp.map(|tx| serialize(tx.as_ref())),
		]).await?;
		Ok(())
	}

	pub async fn get_forfeits_claim_states(&self) -> anyhow::Result<Vec<ForfeitClaimState>> {
		let conn = self.pool.get().await?;
		let stmt = conn.prepare(&format!("
			SELECT vtxo_id, connector_tx, connector_cpfp, connector_point, forfeit_tx, forfeit_cpfp
			FROM forfeits_claim_state
		")).await?;
		let rows = conn.query(&stmt, &[]).await?;

		Ok(rows.into_iter().map(TryFrom::try_from).collect::<Result<_, _>>()
				.context("corrupt db: invalid forfeit claim state row")?)
	}
}

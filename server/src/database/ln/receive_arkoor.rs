//! The arkoor that settles a lightning receive paid on the Ark address in
//! the route hints of its invoice.

use ark::VtxoId;

use crate::database::Tx;

use super::LightningHtlcSubscriptionStatus;

/// The VTXO ids of `inputs`, sorted, as the receive stores them.
fn sorted_ids(inputs: &[VtxoId]) -> Vec<String> {
	let mut ids = inputs.iter().map(ToString::to_string).collect::<Vec<_>>();
	ids.sort_unstable();
	ids
}

impl Tx<'_> {
	/// Settle the open receive `id` by a new arkoor that spends `inputs`,
	/// and record those inputs. An arkoor that the server co-signed before,
	/// through any call, has already paid where it pays, so it cannot settle
	/// a receive.
	pub(crate) async fn settle_lightning_receive_by_arkoor(
		&self,
		id: i64,
		inputs: &[VtxoId],
	) -> anyhow::Result<()> {
		let ids = sorted_ids(inputs);
		let spent = self.query_opt(
			"SELECT vtxo_id FROM vtxo WHERE vtxo_id = ANY($1) AND oor_spent_txid IS NOT NULL LIMIT 1",
			&[&ids],
		).await?;
		if spent.is_some() {
			return badarg!("arkoor was co-signed before and cannot settle the invoice");
		}
		let settled = self.execute("
			UPDATE lightning_htlc_subscription
			SET updated_at = NOW(), status = $2, arkoor_input_ids = $3
			WHERE id = $1 AND status = $4
		", &[
			&id, &LightningHtlcSubscriptionStatus::Settled, &ids, &LightningHtlcSubscriptionStatus::Created,
		]).await?;
		if settled != 1 {
			return badarg!("invoice is not payable");
		}
		Ok(())
	}

	/// Whether the arkoor that spends `inputs` settled the receive `id`.
	pub(crate) async fn lightning_receive_settled_by_arkoor(
		&self,
		id: i64,
		inputs: &[VtxoId],
	) -> anyhow::Result<bool> {
		let row = self.query_opt("
			SELECT id FROM lightning_htlc_subscription
			WHERE id = $1 AND status = $2 AND arkoor_input_ids = $3
		", &[&id, &LightningHtlcSubscriptionStatus::Settled, &sorted_ids(inputs)]).await?;
		Ok(row.is_some())
	}
}

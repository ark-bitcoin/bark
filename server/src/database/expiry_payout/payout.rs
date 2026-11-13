//! Expiry payout transactions: the locks that keep a watchman claim from
//! spending a decided tree.

use ark::ServerVtxo;

use crate::database::Tx;
use crate::error::ExpiryPayoutRefusal;

impl Tx<'_> {
	/// Lock the inputs of a watchman claim through its broadcast.
	pub async fn lock_watchman_claim_inputs(&self, vtxos: &[ServerVtxo]) -> anyhow::Result<()> {
		if !self.expiry_payouts() { return Ok(()); }
		let ids = vtxos.iter().map(|vtxo| vtxo.id()).collect::<Vec<_>>();
		self.lock_unallocated_watchman_inputs(&ids).await
	}

	/// Lock the inputs of a watchman claim through its broadcast, and refuse
	/// a claim of a tree that an expiry payout spends. The locks are taken
	/// in VTXO id order, as the decision takes them.
	pub async fn lock_unallocated_watchman_inputs(&self, ids: &[ark::VtxoId]) -> anyhow::Result<()> {
		if !self.expiry_payouts() { return Ok(()); }
		let ids = ids.iter().map(ToString::to_string).collect::<Vec<_>>();
		self.query("SELECT vtxo_id FROM vtxo WHERE vtxo_id=ANY($1) ORDER BY vtxo_id FOR UPDATE", &[&ids]).await?;
		// A root stays taken while its payout is pending or confirmed. An
		// operator decision stays taken until all its payouts conflicted. An
		// owner decision stays taken after a conflict too.
		if let Some(row) = self.query_opt("SELECT vtxo_id FROM ( \
			SELECT i.vtxo_id FROM expiry_payout_input i JOIN v_expiry_payout_state a ON a.id=i.expiry_payout_id \
				WHERE i.vtxo_id=ANY($1) AND a.status<>'conflicted' \
			UNION SELECT c.vtxo_id FROM expiry_payout_vtxo c JOIN v_expiry_payout_state a ON a.id=c.expiry_payout_id \
				WHERE c.vtxo_id=ANY($1) AND (a.status<>'conflicted' OR c.disposition='owner')) guarded \
			ORDER BY vtxo_id LIMIT 1", &[&ids]).await? {
			return Err(ExpiryPayoutRefusal::DecidedForPayout(row.get::<_, &str>("vtxo_id").parse()?).into());
		}
		Ok(())
	}
}

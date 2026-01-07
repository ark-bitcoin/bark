
use bitcoin::{TapSighash, Witness, taproot};
use bitcoin::key::Keypair;

use ark::vtxo::{TapScriptClause, VtxoClause};
use ark::vtxo::policy::signing::VtxoSigner;

use crate::{SECP, Wallet};

impl Wallet {
	pub (crate) async fn clause_keypair(&self, clause: &VtxoClause) -> Option<Keypair> {
		let clause_pubkey = clause.pubkey();
		self.pubkey_keypair(&clause_pubkey).await.ok()
			.flatten().map(|(_, keypair)| keypair)
	}
}

#[async_trait]
impl VtxoSigner for Wallet {
	async fn witness(
		&self,
		clause: &VtxoClause,
		control_block: &taproot::ControlBlock,
		sighash: TapSighash,
	) -> Option<Witness> {
		let signature = match self.clause_keypair(clause).await {
			Some(keypair) => {
				SECP.sign_schnorr_with_aux_rand(&sighash.into(), &keypair, &rand::random())
			},
			None => return None,
		};

		let witness = match clause {
			VtxoClause::DelayedSign(c) => c.witness(&signature, control_block),
			VtxoClause::DelayedTimelockSign(c) => c.witness(&signature, &control_block),
			VtxoClause::TimelockSign(c) => c.witness(&signature, &control_block),
			VtxoClause::HashDelaySign(c) => {
				let receive = self.db.fetch_lightning_receive_by_payment_hash(c.payment_hash)
					.await.ok().flatten();

				if let Some(receive) = receive {
					c.witness(&(signature, receive.payment_preimage), &control_block)
				} else {
					return None;
				}
			}
		};

		Some(witness)
	}
}
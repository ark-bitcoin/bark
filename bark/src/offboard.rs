
use std::ops::Mul;

use anyhow::Context;
use bitcoin::hashes::Hash;
use bitcoin::hex::DisplayHex;
use bitcoin::{Amount, SignedAmount, Transaction, Txid};
use log::info;

use ark::musig;
use ark::challenges::OffboardRequestChallenge;
use ark::offboard::{OffboardForfeitContext, OffboardRequest};
use ark::vtxo::VtxoRef;
use server_rpc::{protos, TryFromBytes};

use crate::{Wallet, WalletVtxo};
use crate::movement::update::MovementUpdate;
use crate::movement::{MovementDestination, MovementStatus};
use crate::server::ArkInfoExt;
use crate::subsystem::{OffboardMovement, Subsystem};


impl Wallet {
	async fn offboard(
		&self,
		vtxos: Vec<WalletVtxo>,
		destination: bitcoin::Address,
	) -> anyhow::Result<Txid> {
		let mut srv = self.require_server()?;
		let ark = srv.ark_info().await?;

		let destination_spk = destination.script_pubkey();
		let fee = ark.calculate_offboard_fee(&destination_spk)?;
		let vtxos_amount = vtxos.iter().map(|v| v.amount()).sum::<Amount>();
		let req_amount = vtxos_amount.checked_sub(fee)
			.context("fee is higher than selected VTXOs")?;

		let req = OffboardRequest {
			script_pubkey: destination_spk.clone(),
			amount: req_amount,
		};
		let challenge = OffboardRequestChallenge::new(&req, vtxos.iter().map(|v| v.id()));

		let vtxo_keys = {
			let mut keys = Vec::with_capacity(vtxos.len());
			for v in &vtxos {
				keys.push(self.get_vtxo_key(v).await?);
			}
			keys
		};
		let prep_resp = srv.client.prepare_offboard(protos::PrepareOffboardRequest {
			offboard: Some((&req).into()),
			input_vtxo_ids: vtxos.iter().map(|v| v.id().to_bytes().to_vec()).collect(),
			input_vtxo_ownership_proofs: vtxo_keys.iter()
				.map(|k| challenge.sign_with(k).serialize().to_vec())
				.collect(),
		}).await.context("prepare offboard request failed")?.into_inner();
		let unsigned_offboard_tx = bitcoin::consensus::deserialize::<Transaction>(
			&prep_resp.offboard_tx,
		).with_context(|| format!(
			"received invalid unsigned offboard tx from server: {}", prep_resp.offboard_tx.as_hex(),
		))?;
		let offboard_txid = unsigned_offboard_tx.compute_txid();
		info!("Received unsigned offboard tx {} from server", offboard_txid);
		let forfeit_cosign_nonces = prep_resp.forfeit_cosign_nonces.into_iter().map(|n| {
			Ok(musig::PublicNonce::from_bytes(&n)
				.context("received invalid public cosign nonce from server")?)
		}).collect::<anyhow::Result<Vec<_>>>()?;

		let ctx = OffboardForfeitContext::new(&vtxos, &unsigned_offboard_tx);
		ctx.validate_offboard_tx(&req).context("received invalid offboard tx from server")?;

		let sigs = ctx.user_sign_forfeits(&vtxo_keys, &forfeit_cosign_nonces);

		let finish_resp = srv.client.finish_offboard(protos::FinishOffboardRequest {
			offboard_txid: offboard_txid.as_byte_array().to_vec(),
			user_nonces: sigs.public_nonces.iter().map(|n| n.serialize().to_vec()).collect(),
			partial_signatures: sigs.partial_signatures.iter()
				.map(|s| s.serialize().to_vec())
				.collect(),
		}).await.context("error sending offboard forfeit signatures to server")?.into_inner();

		let signed_offboard_tx = bitcoin::consensus::deserialize::<Transaction>(
			&finish_resp.signed_offboard_tx,
		).with_context(|| format!(
			"received invalid offboard tx from server: {}", finish_resp.signed_offboard_tx.as_hex(),
		))?;
		if signed_offboard_tx.compute_txid() != offboard_txid {
			bail!("Signed offboard tx received from server is different from \
				unsigned tx we forfeited for: unsigned={}, signed={}",
				prep_resp.offboard_tx.as_hex(), finish_resp.signed_offboard_tx.as_hex(),
			);
		}
		// we don't accept the tx if our mempool doesn't accept it, it might be a double spend
		self.chain.broadcast_tx(&signed_offboard_tx).await.with_context(|| format!(
			"error broadcasting offboard tx {} (tx={})",
			offboard_txid, finish_resp.signed_offboard_tx.as_hex(),
		))?;

		self.mark_vtxos_as_spent(&vtxos).await?;
		let effective_amt = SignedAmount::try_from(vtxos_amount)
			.expect("can't have this many vtxo sats")
			.mul(-1);
		self.movements.new_finished_movement(
			Subsystem::OFFBOARD,
			OffboardMovement::Offboard.to_string(),
			MovementStatus::Successful,
			MovementUpdate::new()
				.intended_balance(effective_amt)
				.effective_balance(effective_amt)
				.fee(fee)
				.consumed_vtxos(&vtxos)
				.sent_to([MovementDestination::bitcoin(destination, req_amount)])
				.metadata(OffboardMovement::metadata(&signed_offboard_tx)),
		).await?;

		Ok(offboard_txid)
	}

	/// Offboard all VTXOs to a given [bitcoin::Address].
	pub async fn offboard_all(&self, address: bitcoin::Address) -> anyhow::Result<Txid> {
		let input_vtxos = self.spendable_vtxos().await?;
		Ok(self.offboard(input_vtxos, address).await?)
	}

	/// Offboard the given VTXOs to a given [bitcoin::Address].
	pub async fn offboard_vtxos<V: VtxoRef>(
		&self,
		vtxos: impl IntoIterator<Item = V>,
		address: bitcoin::Address,
	) -> anyhow::Result<Txid> {
		let mut input_vtxos = vec![];
		for v in vtxos {
			let id = v.vtxo_id();
			let vtxo = match self.db.get_wallet_vtxo(id).await? {
				Some(vtxo) => vtxo,
				_ => bail!("cannot find requested vtxo: {}", id),
			};
			input_vtxos.push(vtxo);
		}

		Ok(self.offboard(input_vtxos, address).await?)
	}
}

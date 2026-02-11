
use anyhow::Context;
use bitcoin::{Amount, SignedAmount, Transaction, Txid};
use bitcoin::hashes::Hash;
use bitcoin::hex::DisplayHex;
use bitcoin::secp256k1::Keypair;
use log::info;

use ark::{musig, Vtxo, VtxoPolicy};
use ark::arkoor::ArkoorDestination;
use ark::challenges::OffboardRequestChallenge;
use ark::offboard::{OffboardForfeitContext, OffboardRequest};
use ark::vtxo::VtxoRef;
use bitcoin_ext::P2TR_DUST;
use server_rpc::{protos, ServerConnection, TryFromBytes};

use crate::movement::manager::OnDropStatus;
use crate::vtxo::VtxoState;
use crate::{Wallet, WalletVtxo};
use crate::movement::update::MovementUpdate;
use crate::movement::{MovementDestination, MovementStatus};
use crate::server::ArkInfoExt;
use crate::subsystem::{OffboardMovement, Subsystem};


impl Wallet {
	async fn offboard_inner(
		&self,
		srv: &mut ServerConnection,
		vtxos: &[impl AsRef<Vtxo>],
		vtxo_keys: &[Keypair],
		req: &OffboardRequest,
	) -> anyhow::Result<Transaction> {
		// Register VTXOs with server before offboarding
		self.register_vtxos_with_server(&vtxos).await?;

		let challenge = OffboardRequestChallenge::new(
			&req, vtxos.iter().map(|v| v.as_ref().id()),
		);
		let prep_resp = srv.client.prepare_offboard(protos::PrepareOffboardRequest {
			offboard: Some(req.into()),
			input_vtxo_ids: vtxos.iter()
				.map(|v| v.as_ref().id().to_bytes().to_vec())
				.collect(),
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

		Ok(signed_offboard_tx)
	}

	/// Send to an onchain address using your offchain balance
	pub async fn send_onchain(
		&self,
		destination: bitcoin::Address,
		amount: Amount,
	) -> anyhow::Result<Txid> {
		if amount < P2TR_DUST {
			bail!("it doesn't make sense to send dust");
		}

		let (mut srv, ark) = self.require_server().await?;

		let destination_spk = destination.script_pubkey();
		let fee = ark.calculate_offboard_fee(&destination_spk)?;
		let required_amount = amount + fee;

		info!("We can only offboard whole VTXOs, so we will make an arkoor tx first...");

		// this will be the key that holds the temporary vtxos we will offboard
		let offboard_pubkey = self.derive_store_next_keypair().await
			.context("failed to create new keypair")?.0;
		let change_pubkey = self.derive_store_next_keypair().await
			.context("failed to create new keypair")?.0;
		let offboard_dest = ArkoorDestination {
			total_amount: required_amount,
			policy: VtxoPolicy::new_pubkey(offboard_pubkey.public_key()),
		};
		let arkoor = self.create_checkpointed_arkoor(
			offboard_dest,
			change_pubkey.public_key(),
		).await.context("error trying to prepare offboard VTXOs with an arkoor tx")?;

		self.store_spendable_vtxos(&arkoor.change).await
			.context("error storing change VTXOs from preparatory arkoor")?;
		self.store_locked_vtxos(&arkoor.created, None).await
			.context("error storing new VTXOs (locked) from preparatory arkoor")?;
		self.mark_vtxos_as_spent(&arkoor.inputs).await
			.context("error marking used input VTXOs as spent")?;

		let mut movement = self.movements.new_guarded_movement_with_update(
			Subsystem::OFFBOARD,
			OffboardMovement::SendOnchain.to_string(),
			OnDropStatus::Failed,
			MovementUpdate::new()
				.intended_balance(-amount.to_signed()?)
				.effective_balance(-required_amount.to_signed()?)
				.fee(fee)
				.consumed_vtxos(&arkoor.inputs)
				.produced_vtxos(&arkoor.change)
				.sent_to([MovementDestination::bitcoin(destination.clone(), amount)])
		).await?;
		let state = VtxoState::Locked { movement_id: Some(movement.id()) };
		self.set_vtxo_states(&arkoor.created, &state, &[]).await
			.context("error setting movement id on locked VTXOs")?;

		// now perform the offboard
		let vtxos = arkoor.created;

		let req = OffboardRequest {
			script_pubkey: destination_spk.clone(),
			amount: amount,
		};
		let vtxo_keys = vec![offboard_pubkey; vtxos.len()];

		let signed_offboard_tx = self.offboard_inner(&mut srv, &vtxos, &vtxo_keys, &req).await
			.context("error performing offboard")?;

		movement.apply_update(MovementUpdate::new()
			.metadata(OffboardMovement::metadata(&signed_offboard_tx))
		).await.context("error updating movement")?;
		movement.success().await
			.context("error marking movement as succesful")?;

		self.mark_vtxos_as_spent(&vtxos).await
			.context("error marking arkoor VTXOs as spent")?;

		Ok(signed_offboard_tx.compute_txid())
	}

	async fn offboard(
		&self,
		vtxos: Vec<WalletVtxo>,
		destination: bitcoin::Address,
	) -> anyhow::Result<Txid> {
		let (mut srv, ark) = self.require_server().await?;

		let destination_spk = destination.script_pubkey();
		let fee = ark.calculate_offboard_fee(&destination_spk)?;
		let vtxos_amount = vtxos.iter().map(|v| v.amount()).sum::<Amount>();
		let req_amount = vtxos_amount.checked_sub(fee)
			.context("fee is higher than selected VTXOs")?;

		if req_amount < P2TR_DUST {
			bail!("it doesn't make sense to offboard dust");
		}

		let vtxo_keys = {
			let mut keys = Vec::with_capacity(vtxos.len());
			for v in &vtxos {
				keys.push(self.get_vtxo_key(v).await?);
			}
			keys
		};

		let req = OffboardRequest {
			script_pubkey: destination_spk.clone(),
			amount: req_amount,
		};

		let signed_offboard_tx = self.offboard_inner(&mut srv, &vtxos, &vtxo_keys, &req).await
			.context("error performing offboard")?;

		self.mark_vtxos_as_spent(&vtxos).await?;
		let effective_amt = -SignedAmount::try_from(vtxos_amount)
			.expect("can't have this many vtxo sats");
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

		Ok(signed_offboard_tx.compute_txid())
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

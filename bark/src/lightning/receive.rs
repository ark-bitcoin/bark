use std::str::FromStr;

use anyhow::Context;
use bitcoin::{Amount, SignedAmount};
use bitcoin::hex::DisplayHex;
use futures::StreamExt;
use lightning_invoice::Bolt11Invoice;
use log::{info, trace, warn};

use ark::arkoor::ArkoorPackageBuilder;
use ark::{ProtocolEncoding, Vtxo, VtxoPolicy, VtxoRequest, musig};
use ark::lightning::{LightningReceiveChallenge, PaymentHash, Preimage};
use bitcoin_ext::{AmountExt, BlockDelta, BlockHeight};
use server_rpc::protos;
use server_rpc::protos::prepare_lightning_receive_claim_request::LightningReceiveAntiDos;

use crate::subsystem::{BarkSubsystem, LightningMovement, LightningReceiveMovement};
use crate::{Wallet, error};
use crate::movement::{MovementDestination, MovementStatus};
use crate::movement::update::MovementUpdate;
use crate::persist::models::LightningReceive;

/// Leniency delta to allow claim when blocks were mined between htlc
/// receive and claim preparation
const LIGHTNING_PREPARE_CLAIM_DELTA: BlockDelta = 2;

impl Wallet {
	/// Create, store and return a [Bolt11Invoice] for offchain boarding
	pub async fn bolt11_invoice(&self, amount: Amount) -> anyhow::Result<Bolt11Invoice> {
		let mut srv = self.require_server()?;
		let config = self.config();

		// User needs to enfore the following delta:
		// - vtxo exit delta + htlc expiry delta (to give him time to exit the vtxo before htlc expires)
		// - vtxo exit margin (to give him time to exit the vtxo before htlc expires)
		// - htlc recv claim delta (to give him time to claim the htlc before it expires)
		let requested_min_cltv_delta = srv.info.vtxo_exit_delta +
			srv.info.htlc_expiry_delta +
			config.vtxo_exit_margin +
			config.htlc_recv_claim_delta +
			LIGHTNING_PREPARE_CLAIM_DELTA;

		if requested_min_cltv_delta > srv.info.max_user_invoice_cltv_delta {
			bail!("HTLC CLTV delta ({}) is greater than Server's max HTLC recv CLTV delta: {}",
				requested_min_cltv_delta,
				srv.info.max_user_invoice_cltv_delta,
			);
		}

		let preimage = Preimage::random();
		let payment_hash = preimage.compute_payment_hash();
		info!("Start bolt11 board with preimage / payment hash: {} / {}",
			preimage.as_hex(), payment_hash.as_hex());

		let req = protos::StartLightningReceiveRequest {
			payment_hash: payment_hash.to_vec(),
			amount_sat: amount.to_sat(),
			min_cltv_delta: requested_min_cltv_delta as u32,
		};

		let resp = srv.client.start_lightning_receive(req).await?.into_inner();
		info!("Ark Server is ready to receive LN payment to invoice: {}.", resp.bolt11);

		let invoice = Bolt11Invoice::from_str(&resp.bolt11)
			.context("invalid bolt11 invoice returned by Ark server")?;

		self.db.store_lightning_receive(
			payment_hash,
			preimage,
			&invoice,
			requested_min_cltv_delta,
		)?;

		Ok(invoice)
	}

	/// Fetches the status of a lightning receive for the given [PaymentHash].
	pub fn lightning_receive_status(
		&self,
		payment: impl Into<PaymentHash>,
	) -> anyhow::Result<Option<LightningReceive>> {
		Ok(self.db.fetch_lightning_receive_by_payment_hash(payment.into())?)
	}

	/// Claim incoming lightning payment with the given [PaymentHash].
	///
	/// This function reveals the preimage of the lightning payment in
	/// exchange of getting pubkey VTXOs from HTLC ones
	///
	/// # Arguments
	///
	/// * `payment_hash` - The [PaymentHash] of the lightning payment
	/// to wait for.
	/// * `vtxos` - The list of HTLC VTXOs that were previously granted
	/// by the Server, with the hash lock clause matching payment hash.
	///
	/// # Returns
	///
	/// Returns an `anyhow::Result<()>`, which is:
	/// * `Ok(())` if the process completes successfully.
	/// * `Err` if an error occurs at any stage of the operation.
	///
	/// # Remarks
	///
	/// * The list of HTLC VTXOs must have the hash lock clause matching the given
	///   [PaymentHash].
	async fn claim_lightning_receive(
		&self,
		receive: &LightningReceive,
	) -> anyhow::Result<()> {
		let movement_id = receive.movement_id
			.context("No movement created for lightning receive")?;
		let mut srv = self.require_server()?;

		// order inputs by vtxoid before we generate nonces
		let inputs = {
			let htlc_vtxos = receive.htlc_vtxos.as_ref()
				.context("no HTLC VTXOs set on record yet")?;
			let mut ret = htlc_vtxos.iter().map(|v| &v.vtxo).collect::<Vec<_>>();
			ret.sort_by_key(|v| v.id());
			ret
		};

		let (keypairs, sec_nonces, pub_nonces) = inputs.iter().map(|v| {
			let keypair = self.get_vtxo_key(v)?;
			let (sec_nonce, pub_nonce) = musig::nonce_pair(&keypair);
			Ok((keypair, sec_nonce, pub_nonce))
		}).collect::<anyhow::Result<(Vec<_>, Vec<_>, Vec<_>)>>()?;

		// Claiming arkoor against preimage
		let (claim_keypair, _) = self.derive_store_next_keypair()?;
		let receive_policy = VtxoPolicy::new_pubkey(claim_keypair.public_key());

		let pay_req = VtxoRequest {
			policy: receive_policy.clone(),
			amount: inputs.iter().map(|v| v.amount()).sum(),
		};
		trace!("ln arkoor builder params: inputs: {:?}; user_nonces: {:?}; req: {:?}",
			inputs.iter().map(|v| v.id()).collect::<Vec<_>>(), pub_nonces, pay_req,
		);
		let builder = ArkoorPackageBuilder::new(
			inputs.iter().copied(), &pub_nonces, pay_req, None,
		)?;

		info!("Claiming arkoor against payment preimage");
		self.db.set_preimage_revealed(receive.payment_hash)?;
		let resp = srv.client.claim_lightning_receive(protos::ClaimLightningReceiveRequest {
			payment_hash: receive.payment_hash.to_byte_array().to_vec(),
			payment_preimage: receive.payment_preimage.to_vec(),
			vtxo_policy: receive_policy.serialize(),
			user_pub_nonces: pub_nonces.iter().map(|n| n.serialize().to_vec()).collect(),
		}).await?.into_inner();
		let cosign_resp: Vec<_> = resp.try_into().context("invalid cosign response")?;

		ensure!(builder.verify_cosign_response(&cosign_resp),
			"invalid arkoor cosignature received from server",
		);

		let (outputs, change) = builder.build_vtxos(&cosign_resp, &keypairs, sec_nonces)?;
		if change.is_some() {
			bail!("shouldn't have change VTXO, this is a bug");
		}

		let mut effective_balance = Amount::ZERO;
		for vtxo in &outputs {
			// TODO: bailing here results in vtxos not being registered despite preimage being revealed
			// should we make `srv.client.claim_lightning_receive` idempotent, so that bark can at
			// least retry some times before giving up and exiting?
			trace!("Validating Lightning receive claim VTXO {}: {}",
				vtxo.id(), vtxo.serialize_hex(),
			);
			self.validate_vtxo(vtxo).await
				.context("invalid arkoor from lightning receive")?;
			effective_balance += vtxo.amount();
		}

		self.store_spendable_vtxos(&outputs)?;
		self.mark_vtxos_as_spent(inputs)?;
		info!("Got arkoors from lightning: {}",
			outputs.iter().map(|v| v.id().to_string()).collect::<Vec<_>>().join(", ")
		);

		self.movements.update_movement(
			movement_id,
			MovementUpdate::new()
				.effective_balance(effective_balance.to_signed()?)
				.produced_vtxos(&outputs)
		).await?;
		self.movements.finish_movement(
			movement_id, MovementStatus::Finished,
		).await?;

		self.db.remove_pending_lightning_receive(receive.payment_hash)?;

		Ok(())
	}

	async fn compute_lightning_receive_anti_dos(
		&self,
		payment_hash: PaymentHash,
		token: Option<&str>,
	) -> anyhow::Result<LightningReceiveAntiDos> {
		Ok(if let Some(token) = token {
			LightningReceiveAntiDos::Token(token.to_string())
		} else {
			let challenge = LightningReceiveChallenge::new(payment_hash);
			// We get an existing VTXO as an anti-dos measure.
			let vtxo = self.select_vtxos_to_cover(Amount::ONE_SAT, None, None)
				.and_then(|vtxos| vtxos.into_iter().next().ok_or_else(|| anyhow!("have no spendable vtxo to prove ownership of")))?;
			let vtxo_keypair = self.get_vtxo_key(&vtxo).expect("owned vtxo should be in database");
			LightningReceiveAntiDos::InputVtxo(protos::InputVtxo {
				vtxo_id: vtxo.id().to_bytes().to_vec(),
				ownership_proof: {
					let sig = challenge.sign_with(vtxo.id(), vtxo_keypair);
					sig.serialize().to_vec()
				}
			})
		})
	}

	/// Check for incoming lightning payment with the given [PaymentHash].
	///
	/// This function checks for an incoming lightning payment with the
	/// given [PaymentHash] and returns the HTLC VTXOs that are associated
	/// with it.
	///
	/// # Arguments
	///
	/// * `payment_hash` - The [PaymentHash] of the lightning payment
	/// to check for.
	/// * `wait` - Whether to wait for the payment to be received.
	/// * `token` - An optional lightning receive token used to authenticate a lightning
	/// receive when no spendable VTXOs are owned by this wallet.
	///
	/// # Returns
	///
	/// Returns an `anyhow::Result<Vec<WalletVtxo>>`, which is:
	/// * `Ok(wallet_vtxos)` if the process completes successfully, where `wallet_vtxos` is
	///   the list of HTLC VTXOs that are associated with the payment.
	/// * `Err` if an error occurs at any stage of the operation.
	///
	/// # Remarks
	///
	/// * The invoice must contain an explicit amount specified in milli-satoshis.
	/// * The HTLC expiry height is calculated by adding the servers' HTLC expiry delta to the
	///   current chain tip.
	/// * The payment hash must be from an invoice previously generated using
	///   [Wallet::bolt11_invoice].
	async fn check_lightning_receive(
		&self,
		payment_hash: PaymentHash,
		wait: bool,
		token: Option<&str>,
	) -> anyhow::Result<LightningReceive> {
		let mut srv = self.require_server()?;
		let current_height = self.chain.tip().await?;

		let mut receive = self.db.fetch_lightning_receive_by_payment_hash(payment_hash)?
			.context("no pending lightning receive found for payment hash, might already be claimed")?;

		// If we have already HTLC VTXOs stored, we can return them without asking the server
		if receive.htlc_vtxos.is_some() {
			return Ok(receive)
		}

		info!("Waiting for payment...");
		let sub = srv.client.check_lightning_receive(protos::CheckLightningReceiveRequest {
			hash: payment_hash.to_byte_array().to_vec(), wait,
		}).await?.into_inner();

		let status = protos::LightningReceiveStatus::try_from(sub.status)
			.with_context(|| format!("unknown payment status: {}", sub.status))?;
		match status {
			// this is the good case
			protos::LightningReceiveStatus::Accepted
				| protos::LightningReceiveStatus::HtlcsReady => {},
			protos::LightningReceiveStatus::Created => {
				return Ok(receive);
			},
			protos::LightningReceiveStatus::Settled => bail!("payment already settled"),
			protos::LightningReceiveStatus::Cancelled => bail!("payment was canceled"),
		}

		let lightning_receive_anti_dos = match self.compute_lightning_receive_anti_dos(
			payment_hash, token,
		).await {
			Ok(anti_dos) => Some(anti_dos),
			Err(e) => {
				warn!("Could not compute anti-dos: {e}. Trying without");
				None
			},
		};

		let htlc_recv_expiry = current_height + receive.htlc_recv_cltv_delta as BlockHeight;

		let (next_keypair, _) = self.derive_store_next_keypair()?;
		let req = protos::PrepareLightningReceiveClaimRequest {
			payment_hash: receive.payment_hash.to_vec(),
			user_pubkey: next_keypair.public_key().serialize().to_vec(),
			htlc_recv_expiry,
			lightning_receive_anti_dos,
		};
		let res = srv.client.prepare_lightning_receive_claim(req).await
			.context("error preparing lightning receive claim")?.into_inner();
		let vtxos = res.htlc_vtxos.into_iter()
			.map(|b| Vtxo::deserialize(&b))
			.collect::<Result<Vec<_>, _>>()
			.context("invalid htlc vtxos from server")?;

		// sanity check the vtxos
		for vtxo in &vtxos {
			trace!("Received HTLC VTXO {} from server: {}", vtxo.id(), vtxo.serialize_hex());
			self.validate_vtxo(vtxo).await
				.context("received invalid HTLC VTXO from server")?;

			if let VtxoPolicy::ServerHtlcRecv(p) = vtxo.policy() {
				if p.payment_hash != receive.payment_hash {
					bail!("invalid payment hash on HTLC VTXOs received from server: {}",
						p.payment_hash,
					);
				}
				if p.user_pubkey != next_keypair.public_key() {
					bail!("invalid pubkey on HTLC VTXOs received from server: {}", p.user_pubkey);
				}
				if p.htlc_expiry < htlc_recv_expiry {
					bail!("HTLC VTXO expiry height is less than requested: Requested {}, received {}", htlc_recv_expiry, p.htlc_expiry);
				}
			} else {
				bail!("invalid HTLC VTXO policy: {:?}", vtxo.policy());
			}
		}

		// check sum match invoice amount
		let invoice_amount = receive.invoice.amount_milli_satoshis().map(|a| Amount::from_msat_floor(a))
			.expect("ln receive invoice should have amount");
		let htlc_amount = vtxos.iter().map(|v| v.amount()).sum::<Amount>();
		ensure!(vtxos.iter().map(|v| v.amount()).sum::<Amount>() >= invoice_amount,
			"Server didn't return enough VTXOs to cover invoice amount"
		);

		let movement_id = if let Some(movement_id) = receive.movement_id {
			movement_id
		} else {
			self.movements.new_movement(
				self.subsystem_ids[&BarkSubsystem::LightningReceive],
				LightningReceiveMovement::Receive.to_string(),
			).await?
		};
		self.store_locked_vtxos(&vtxos, Some(movement_id))?;

		let vtxo_ids = vtxos.iter().map(|v| v.id()).collect::<Vec<_>>();
		self.db.update_lightning_receive(payment_hash, &vtxo_ids, movement_id)?;

		self.movements.update_movement(
			movement_id,
			MovementUpdate::new()
				.intended_balance(invoice_amount.to_signed()?)
				.effective_balance(htlc_amount.to_signed()?)
				.metadata(LightningMovement::htlc_metadata(&vtxos)?)
				.received_on(
					[MovementDestination::new(receive.invoice.to_string(), htlc_amount)],
				),
		).await?;

		let vtxos = vtxos
			.into_iter()
			.map(|v| self.db
				.get_wallet_vtxo(v.id())
				.and_then(|op| op.context("Failed to get wallet VTXO for lightning receive"))
			).collect::<Result<Vec<_>, _>>()?;

		receive.htlc_vtxos = Some(vtxos);
		receive.movement_id = Some(movement_id);

		Ok(receive)
	}

	/// Check and claim a Lightning receive
	///
	/// This function checks for an incoming lightning payment with the given [PaymentHash]
	/// and then claims the payment using returned HTLC VTXOs.
	///
	/// # Arguments
	///
	/// * `payment_hash` - The [PaymentHash] of the lightning payment
	/// to check for.
	/// * `wait` - Whether to wait for the payment to be received.
	/// * `token` - An optional lightning receive token used to authenticate a lightning
	/// receive when no spendable VTXOs are owned by this wallet.
	///
	/// # Returns
	///
	/// * `Ok(true)` if the process completes successfully
	/// * `Ok(false)` if the payment was unavailable for claiming
	/// * `Err` if an error occurs at any stage of the operation.
	///
	/// # Remarks
	///
	/// * The payment hash must be from an invoice previously generated using
	///   [Wallet::bolt11_invoice].
	pub async fn try_claim_lightning_receive(
		&self,
		payment_hash: PaymentHash,
		wait: bool,
		token: Option<&str>,
	) -> anyhow::Result<bool> {
		let srv = self.require_server()?;

		let receive = self.check_lightning_receive(payment_hash, wait, token).await?;
		let vtxos = match receive.htlc_vtxos {
			// payment still not available
			None => return Ok(false),
			Some(ref vtxos) => vtxos,
		};

		if let Err(e) = self.claim_lightning_receive(&receive).await {
			error!("Failed to claim pubkey vtxo from htlc vtxo: {}", e);
			let tip = self.chain.tip().await?;

			let first_vtxo = &vtxos.first().unwrap().vtxo;
			debug_assert!(vtxos.iter().all(|v| {
				v.vtxo.policy() == first_vtxo.policy() && v.vtxo.exit_delta() == first_vtxo.exit_delta()
			}), "all htlc vtxos for the same payment hash should have the same policy and exit delta");

			let vtxo_htlc_expiry = first_vtxo.policy().as_server_htlc_recv()
				.expect("only server htlc recv vtxos can be pending lightning recv").htlc_expiry;

			let safe_exit_margin = first_vtxo.exit_delta() +
				srv.info.htlc_expiry_delta +
				self.config.vtxo_exit_margin;

			if tip > vtxo_htlc_expiry.saturating_sub(safe_exit_margin as BlockHeight) {
				if receive.preimage_revealed_at.is_some() {
					warn!("HTLC-recv VTXOs are about to expire and preimage has been disclosed, \
						must exit",);
					self.exit.write().await.mark_vtxos_for_exit(
						&vtxos.iter().map(|v| v.vtxo.clone()).collect::<Vec<_>>(),
					).await?;
					if let Some(id) = receive.movement_id {
						self.movements.update_movement(
							id,
							MovementUpdate::new()
								.exited_vtxos(vtxos)
						).await?;
						self.movements.finish_movement(id, MovementStatus::Failed).await?;
					}
				} else {
					warn!("HTLC-recv VTXOs are about to expire, but preimage has not been disclosed yet, mark htlc as cancelled");
					self.mark_vtxos_as_spent(vtxos)?;
					if let Some(id) = receive.movement_id {
						self.movements.update_movement(
							id,
							MovementUpdate::new()
								.effective_balance(SignedAmount::ZERO)
						).await?;
						self.movements.finish_movement(id, MovementStatus::Cancelled).await?;
					}
				}
			}

			Err(e).context("failed to claim lightning receive")
		} else {
			Ok(true)
		}
	}

	/// Check and claim all opened Lightning receive
	///
	/// This function fetches all opened lightning receives and then
	/// concurrently tries to check and claim them
	///
	/// # Arguments
	///
	/// * `wait` - Whether to wait for each payment to be received.
	///
	/// # Returns
	///
	/// Returns an `anyhow::Result<()>`, which is:
	/// * `Ok(())` if the process completes successfully.
	/// * `Err` if an error occurs at any stage of the operation.
	pub async fn try_claim_all_lightning_receives(&self, wait: bool) -> anyhow::Result<()> {
		// Asynchronously attempts to claim all pending receive by converting the list into a stream
		tokio_stream::iter(self.pending_lightning_receives()?)
			.for_each_concurrent(3, |rcv| async move {
				if let Err(e) = self.try_claim_lightning_receive(rcv.invoice.into(), wait, None).await {
					error!("Error claiming lightning receive: {:#}", e);
				}
			}).await;

		Ok(())
	}
}
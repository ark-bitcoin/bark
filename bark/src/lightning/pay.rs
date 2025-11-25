use std::fmt;

use anyhow::Context;
use bitcoin::Amount;
use bitcoin::hex::DisplayHex;
use lightning::util::ser::Writeable;
use lightning_invoice::Bolt11Invoice;
use lnurllib::lightning_address::LightningAddress;
use log::{debug, error, info, trace, warn};
use server_rpc::protos;

use ark::arkoor::ArkoorPackageBuilder;
use ark::lightning::{Bolt12Invoice, Bolt12InvoiceExt, Invoice, Offer, Preimage};
use ark::{ProtocolEncoding, VtxoPolicy, VtxoRequest, musig};
use bitcoin_ext::P2TR_DUST;

use crate::Wallet;
use crate::lightning::lnaddr_invoice;
use crate::movement::{MovementDestination, MovementStatus};
use crate::movement::update::MovementUpdate;
use crate::persist::models::LightningSend;
use crate::subsystem::{BarkSubsystem, LightningMovement, LightningSendMovement};


impl Wallet {
	async fn process_lightning_revocation(&self, payment: &LightningSend) -> anyhow::Result<()> {
		let mut srv = self.require_server()?;
		let htlc_vtxos = payment.htlc_vtxos.clone().into_iter()
			.map(|v| v.vtxo).collect::<Vec<_>>();

		info!("Processing {} HTLC VTXOs for revocation", htlc_vtxos.len());

		let mut secs = Vec::with_capacity(htlc_vtxos.len());
		let mut pubs = Vec::with_capacity(htlc_vtxos.len());
		let mut keypairs = Vec::with_capacity(htlc_vtxos.len());
		for input in htlc_vtxos.iter() {
			let keypair = self.get_vtxo_key(&input)?;
			let (s, p) = musig::nonce_pair(&keypair);
			secs.push(s);
			pubs.push(p);
			keypairs.push(keypair);
		}

		let revocation = ArkoorPackageBuilder::new_htlc_revocation(&htlc_vtxos, &pubs)?;

		let req = protos::RevokeLightningPaymentRequest {
			htlc_vtxo_ids: revocation.arkoors.iter()
				.map(|i| i.input.id().to_bytes().to_vec())
				.collect(),
			user_nonces: revocation.arkoors.iter()
				.map(|i| i.user_nonce.serialize().to_vec())
				.collect(),
		};
		let cosign_resp: Vec<_> = srv.client.revoke_lightning_payment(req).await?
			.into_inner().try_into().context("invalid server cosign response")?;
		ensure!(revocation.verify_cosign_response(&cosign_resp),
			"invalid arkoor cosignature received from server",
		);

		let (vtxos, _) = revocation.build_vtxos(&cosign_resp, &keypairs, secs)?;
		let mut revoked = Amount::ZERO;
		for vtxo in &vtxos {
			info!("Got revocation VTXO: {}: {}", vtxo.id(), vtxo.amount());
			revoked += vtxo.amount();
		}

		let count = vtxos.len();
		self.movements.update_movement(
			payment.movement_id,
			MovementUpdate::new()
				.effective_balance(-payment.amount.to_signed()? + revoked.to_signed()?)
				.produced_vtxos(&vtxos)
		).await?;
		self.store_spendable_vtxos(&vtxos)?;
		self.mark_vtxos_as_spent(&htlc_vtxos)?;
		self.movements.finish_movement(payment.movement_id, MovementStatus::Failed).await?;

		self.db.remove_lightning_send(payment.invoice.payment_hash())?;

		info!("Revoked {} HTLC VTXOs", count);

		Ok(())
	}

	/// Processes the result of a lightning payment by checking the preimage sent by the server and
	/// completing the payment if successful.
	///
	/// Note:
	/// - That function cannot return an Error if the server provides a valid preimage, meaning
	/// that if some occur, it is useless to ask for revocation as server wouldn't accept it.
	/// In that case, it is better to keep the payment pending and try again later
	///
	/// # Returns
	///
	/// Returns `Ok(Some(Preimage))` if the payment is successfully completed and a preimage is
	/// received.
	/// Returns `Ok(None)` if preimage is missing, invalid or does not match the payment hash.
	/// Returns an `Err` if an error occurs during the payment completion.
	async fn process_lightning_send_server_preimage(
		&self,
		preimage: Option<Vec<u8>>,
		payment: &LightningSend,
	) -> anyhow::Result<Option<Preimage>> {
		let payment_hash = payment.invoice.payment_hash();
		let preimage_res = preimage
			.context("preimage is missing")
			.map(|p| Ok(Preimage::try_from(p)?))
			.flatten();

		match preimage_res {
			Ok(preimage) if preimage.compute_payment_hash() == payment_hash => {
				info!("Lightning payment succeeded! Preimage: {}. Payment hash: {}",
					preimage.as_hex(), payment.invoice.payment_hash().as_hex());

				// Complete the payment
				self.db.remove_lightning_send(payment.invoice.payment_hash())?;
				self.mark_vtxos_as_spent(&payment.htlc_vtxos)?;
				self.movements.finish_movement(payment.movement_id,
					MovementStatus::Finished).await?;

				Ok(Some(preimage))
			},
			_ => {
				error!("Server failed to provide a valid preimage. \
					Payment hash: {}. Preimage result: {:#?}", payment_hash, preimage_res
				);
				Ok(None)
			}
		}
	}

	/// Checks the status of a lightning payment associated with a set of VTXOs, processes the
	/// payment result and optionally takes appropriate actions based on the payment outcome.
	///
	/// # Arguments
	///
	/// * `htlc_vtxos` - Slice of [WalletVtxo] objects that represent HTLC outputs involved in the
	///                  payment.
	///
	/// # Returns
	///
	/// Returns `Ok(Some(Preimage))` if the payment is successfully completed and a preimage is
	/// received.
	/// Returns `Ok(None)` for payments still pending, failed payments or if necessary revocation
	/// or exit processing occurs.
	/// Returns an `Err` if an error occurs during the process.
	///
	/// # Behavior
	///
	/// - Validates that all HTLC VTXOs share the same invoice, amount and policy.
	/// - Sends a request to the lightning payment server to check the payment status.
	/// - Depending on the payment status:
	///   - **Failed**: Revokes the associated VTXOs.
	///   - **Pending**: Checks if the HTLC has expired based on the tip height. If expired,
	///     revokes the VTXOs.
	///   - **Complete**: Extracts the payment preimage, logs the payment, registers movement
	///     in the database and returns
	pub async fn check_lightning_payment(&self, payment: &LightningSend)
		-> anyhow::Result<Option<Preimage>>
	{
		let mut srv = self.require_server()?;
		let tip = self.chain.tip().await?;

		let payment_hash = payment.invoice.payment_hash();

		let policy = payment.htlc_vtxos.first().context("no vtxo provided")?.vtxo.policy();
		debug_assert!(payment.htlc_vtxos.iter().all(|v| v.vtxo.policy() == policy),
			"All lightning htlc should have the same policy",
		);
		let policy = policy.as_server_htlc_send().context("VTXO is not an HTLC send")?;
		if policy.payment_hash != payment_hash {
			bail!("Payment hash mismatch");
		}

		let req = protos::CheckLightningPaymentRequest {
			hash: policy.payment_hash.to_vec(),
			wait: false,
		};
		let res = srv.client.check_lightning_payment(req).await?.into_inner();

		let payment_status = protos::PaymentStatus::try_from(res.status)?;

		let should_revoke = match payment_status {
			protos::PaymentStatus::Failed => {
				info!("Payment failed ({}): revoking VTXO", res.progress_message);
				true
			},
			protos::PaymentStatus::Pending => {
				if tip > policy.htlc_expiry {
					trace!("Payment is still pending, but HTLC is expired (tip: {}, \
						expiry: {}): revoking VTXO", tip, policy.htlc_expiry);
					true
				} else {
					trace!("Payment is still pending and HTLC is not expired (tip: {}, \
						expiry: {}): doing nothing for now", tip, policy.htlc_expiry);
					false
				}
			},
			protos::PaymentStatus::Complete => {
				let preimage_opt = self.process_lightning_send_server_preimage(
					res.payment_preimage, &payment,
				).await?;

				if let Some(preimage) = preimage_opt {
					return Ok(Some(preimage));
				} else {
					if tip > policy.htlc_expiry {
						trace!("Completed payment has no valid preimage and HTLC is \
							expired (tip: {}, expiry: {}): revoking VTXO", tip, policy.htlc_expiry);
						true
					} else {
						trace!("Completed payment has no valid preimage, but HTLC is \
							not expired (tip: {}, expiry: {}): doing nothing for now", tip, policy.htlc_expiry);
						false
					}
				}
			},
		};

		if should_revoke {
			if let Err(e) = self.process_lightning_revocation(payment).await {
				warn!("Failed to revoke VTXO: {}", e);

				// if one of the htlc is about to expire, we exit all of them.
				// Maybe we want a different behavior here, but we have to decide whether
				// htlc vtxos revocation is a all or nothing process.
				let min_expiry = payment.htlc_vtxos.iter()
					.map(|v| v.vtxo.spec().expiry_height).min().unwrap();

				if tip > min_expiry.saturating_sub(self.config().vtxo_refresh_expiry_threshold) {
					warn!("Some VTXO is about to expire soon, marking to exit");
					let vtxos = payment.htlc_vtxos
						.iter()
						.map(|v| v.vtxo.clone())
						.collect::<Vec<_>>();
					self.exit.write().await.mark_vtxos_for_exit(&vtxos).await?;

					let exited = vtxos.iter().map(|v| v.amount()).sum::<Amount>();
					self.movements.update_movement(
						payment.movement_id,
						MovementUpdate::new()
							.effective_balance(-payment.amount.to_signed()? + exited.to_signed()?)
							.exited_vtxos(&vtxos)
					).await?;
					self.movements.finish_movement(
						payment.movement_id, MovementStatus::Failed,
					).await?;
					self.db.remove_lightning_send(payment_hash)?;
				}
			}
		}

		Ok(None)
	}

	/// Pays a Lightning [Invoice] using Ark VTXOs. This is also an out-of-round payment
	/// so the same [Wallet::send_arkoor_payment] rules apply.
	pub async fn pay_lightning_invoice<T>(
		&self,
		invoice: T,
		user_amount: Option<Amount>,
	) -> anyhow::Result<Preimage>
	where
		T: TryInto<Invoice>,
		T::Error: std::error::Error + fmt::Display + Send + Sync + 'static,
	{
		let mut srv = self.require_server()?;

		let properties = self.db.read_properties()?.context("Missing config")?;

		let invoice = invoice.try_into().context("failed to parse invoice")?;
		if invoice.network() != properties.network {
			bail!("Invoice is for wrong network: {}", invoice.network());
		}

		if self.db.check_recipient_exists(&invoice.to_string())? {
			bail!("Invoice has already been paid");
		}

		invoice.check_signature()?;

		let amount = invoice.get_final_amount(user_amount)?;
		if amount < P2TR_DUST {
			bail!("Sent amount must be at least {}", P2TR_DUST);
		}

		let (change_keypair, _) = self.derive_store_next_keypair()?;

		let inputs = self.select_vtxos_to_cover(amount, None)
			.context("Could not find enough suitable VTXOs to cover lightning payment")?;

		let mut secs = Vec::with_capacity(inputs.len());
		let mut pubs = Vec::with_capacity(inputs.len());
		let mut keypairs = Vec::with_capacity(inputs.len());
		let mut input_ids = Vec::with_capacity(inputs.len());
		for input in inputs.iter() {
			let keypair = self.get_vtxo_key(&input)?;
			let (s, p) = musig::nonce_pair(&keypair);
			secs.push(s);
			pubs.push(p);
			keypairs.push(keypair);
			input_ids.push(input.id());
		}

		let req = protos::StartLightningPaymentRequest {
			invoice: invoice.to_string(),
			user_amount_sat: user_amount.map(|a| a.to_sat()),
			input_vtxo_ids: input_ids.iter().map(|v| v.to_bytes().to_vec()).collect(),
			user_nonces: pubs.iter().map(|p| p.serialize().to_vec()).collect(),
			user_pubkey: change_keypair.public_key().serialize().to_vec(),
		};

		let resp = srv.client.start_lightning_payment(req).await
			.context("htlc request failed")?.into_inner();

		let cosign_resp = resp.sigs.into_iter().map(|i| i.try_into())
			.collect::<Result<Vec<_>, _>>()?;
		let policy = VtxoPolicy::deserialize(&resp.policy)?;

		let pay_req = match policy {
			VtxoPolicy::ServerHtlcSend(policy) => {
				ensure!(policy.user_pubkey == change_keypair.public_key(), "user pubkey mismatch");
				ensure!(policy.payment_hash == invoice.payment_hash(), "payment hash mismatch");
				// TODO: ensure expiry is not too high? add new bark config to check against?
				VtxoRequest { amount: amount, policy: policy.into() }
			},
			_ => bail!("invalid policy returned from server"),
		};

		let builder = ArkoorPackageBuilder::new(
			&inputs, &pubs, pay_req, Some(change_keypair.public_key()),
		)?;

		ensure!(builder.verify_cosign_response(&cosign_resp),
			"invalid arkoor cosignature received from server",
		);

		let (htlc_vtxos, change_vtxo) = builder.build_vtxos(&cosign_resp, &keypairs, secs)?;

		// Validate the new vtxos. They have the same chain anchor.
		let mut effective_balance = Amount::ZERO;
		for vtxo in &htlc_vtxos {
			self.validate_vtxo(vtxo).await?;
			effective_balance += vtxo.amount();
		}

		let movement_id = self.movements.new_movement(
			self.subsystem_ids[&BarkSubsystem::LightningSend],
			LightningSendMovement::Send.to_string(),
		).await?;
		self.movements.update_movement(
			movement_id,
			MovementUpdate::new()
				.intended_balance(-amount.to_signed()?)
				.effective_balance(-effective_balance.to_signed()?)
				.consumed_vtxos(&inputs)
				.sent_to([MovementDestination::new(invoice.to_string(), amount)])
		).await?;
		self.store_locked_vtxos(&htlc_vtxos, Some(movement_id))?;
		self.mark_vtxos_as_spent(&input_ids)?;

		// Validate the change vtxo. It has the same chain anchor as the last input.
		if let Some(ref change) = change_vtxo {
			let last_input = inputs.last().context("no inputs provided")?;
			let tx = self.chain.get_tx(&last_input.chain_anchor().txid).await?;
			let tx = tx.with_context(|| {
				format!("input vtxo chain anchor not found for lightning change vtxo: {}", last_input.chain_anchor().txid)
			})?;
			change.validate(&tx).context("invalid lightning change vtxo")?;
			self.store_spendable_vtxos([change])?;
		}

		self.movements.update_movement(
			movement_id,
			MovementUpdate::new()
				.produced_vtxo_if_some(change_vtxo)
				.metadata(LightningMovement::htlc_metadata(&htlc_vtxos)?)
		).await?;

		let payment = self.db.store_new_pending_lightning_send(
			&invoice, &amount, &htlc_vtxos.iter().map(|v| v.id()).collect::<Vec<_>>(), movement_id,
		)?;

		let req = protos::SignedLightningPaymentDetails {
			invoice: invoice.to_string(),
			htlc_vtxo_ids: htlc_vtxos.iter().map(|v| v.id().to_bytes().to_vec()).collect(),
			wait: true,
		};

		let res = srv.client.finish_lightning_payment(req).await?.into_inner();
		debug!("Progress update: {}", res.progress_message);

		let preimage_opt = self.process_lightning_send_server_preimage(
			res.payment_preimage, &payment,
		).await?;

		if let Some(preimage) = preimage_opt {
			return Ok(preimage);
		} else {
			self.process_lightning_revocation(&payment).await?;
			bail!("Payment failed, but got revocation vtxos: {}", res.progress_message);
		}
	}

	/// Same as [Wallet::pay_lightning_invoice] but instead it pays a [LightningAddress].
	pub async fn pay_lightning_address(
		&self,
		addr: &LightningAddress,
		amount: Amount,
		comment: Option<&str>,
	) -> anyhow::Result<(Bolt11Invoice, Preimage)> {
		let invoice = lnaddr_invoice(addr, amount, comment).await
			.context("lightning address error")?;
		info!("Attempting to pay invoice {}", invoice);
		let preimage = self.pay_lightning_invoice(invoice.clone(), None).await
			.context("bolt11 payment error")?;
		Ok((invoice, preimage))
	}

	/// Attempts to pay the given BOLT12 [Offer] using offchain funds.
	pub async fn pay_lightning_offer(
		&self,
		offer: Offer,
		amount: Option<Amount>,
	) -> anyhow::Result<(Bolt12Invoice, Preimage)> {
		let mut srv = self.require_server()?;

		let offer_bytes = {
			let mut bytes = Vec::new();
			offer.write(&mut bytes).unwrap();
			bytes
		};

		let req = protos::FetchBolt12InvoiceRequest {
			offer: offer_bytes,
			amount_sat: amount.map(|a| a.to_sat()),
		};

		let resp = srv.client.fetch_bolt12_invoice(req).await?.into_inner();

		let invoice = Bolt12Invoice::try_from(resp.invoice)
			.map_err(|_| anyhow::anyhow!("invalid invoice"))?;

		invoice.validate_issuance(offer)?;

		let preimage = self.pay_lightning_invoice(invoice.clone(), None).await
			.context("bolt11 payment error")?;
		Ok((invoice, preimage))
	}

}

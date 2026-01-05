use std::fmt;

use anyhow::Context;
use bitcoin::Amount;
use bitcoin::hex::DisplayHex;
use lightning::util::ser::Writeable;
use lnurllib::lightning_address::LightningAddress;
use log::{error, info, trace, warn};
use server_rpc::protos::{self, lightning_payment_status::PaymentStatus};

use ark::arkoor::ArkoorPackageBuilder;
use ark::lightning::{Bolt12Invoice, Bolt12InvoiceExt, Invoice, Offer, PaymentHash, Preimage};
use ark::{ProtocolEncoding, VtxoPolicy, VtxoRequest, musig};
use bitcoin_ext::P2TR_DUST;

use crate::Wallet;
use crate::lightning::lnaddr_invoice;
use crate::movement::{MovementDestination, MovementStatus, PaymentMethod};
use crate::movement::update::MovementUpdate;
use crate::persist::models::LightningSend;
use crate::subsystem::{BarkSubsystem, LightningMovement, LightningSendMovement};


impl Wallet {
	/// Performs the revocation of HTLC VTXOs associated with a failed Lightning payment.
	///
	/// Builds a revocation package, requests server cosign,
	/// then constructs new spendable VTXOs from server response.
	///
	/// Updates wallet database and movement logs to reflect the failed
	/// payment and new produced VTXOs; removes the pending send record.
	///
	/// # Arguments
	///
	/// * `payment` - A reference to the [`LightningSend`] representing the failed payment whose
	///     associated HTLC VTXOs should be revoked.
	///
	/// # Errors
	///
	/// Returns an error if revocation fails at any step.
	///
	/// # Returns
	///
	/// Returns `Ok(())` if revocation succeeds and the wallet state is properly updated.
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

		let req = protos::RevokeLightningPayHtlcRequest {
			htlc_vtxo_ids: revocation.arkoors.iter()
				.map(|i| i.input.id().to_bytes().to_vec())
				.collect(),
			user_nonces: revocation.arkoors.iter()
				.map(|i| i.user_nonce.serialize().to_vec())
				.collect(),
		};
		let cosign_resp: Vec<_> = srv.client.request_lightning_pay_htlc_revocation(req).await?
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
		self.movements.finish_movement_with_update(
			payment.movement_id,
			MovementStatus::Failed,
			MovementUpdate::new()
				.effective_balance(-payment.amount.to_signed()? + revoked.to_signed()?)
				.produced_vtxos(&vtxos)
		).await?;
		self.store_spendable_vtxos(&vtxos)?;
		self.mark_vtxos_as_spent(&htlc_vtxos)?;

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
				self.db.finish_lightning_send(payment_hash, Some(preimage))?;
				self.mark_vtxos_as_spent(&payment.htlc_vtxos)?;
				self.movements.finish_movement(
					payment.movement_id, MovementStatus::Successful,
				).await?;

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
	/// * `payment_hash` - The [PaymentHash] identifying the lightning payment.
	/// * `wait`         - If true, asks the server to wait for payment completion (may block longer).
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
	/// - Sends a request to the Ark server to check the payment status.
	/// - Depending on the payment status:
	///   - **Failed**: Revokes the associated VTXOs.
	///   - **Pending**: Checks if the HTLC has expired based on the tip height. If expired,
	///     revokes the VTXOs.
	///   - **Complete**: Extracts the payment preimage, logs the payment, registers movement
	///     in the database and returns the preimage.
	pub async fn check_lightning_payment(&self, payment_hash: PaymentHash, wait: bool)
		-> anyhow::Result<Option<Preimage>>
	{
		trace!("Checking lightning payment status for payment hash: {}", payment_hash);

		let mut srv = self.require_server()?;

		let payment = self.db.get_lightning_send(payment_hash)?
			.context("no lightning send found for payment hash")?;

		// If the payment already has a preimage, it was already completed successfully
		if let Some(preimage) = payment.preimage {
			trace!("Payment already completed with preimage: {}", preimage.as_hex());
			return Ok(Some(preimage));
		}

		let policy = payment.htlc_vtxos.first().context("no vtxo provided")?.vtxo.policy();
		debug_assert!(payment.htlc_vtxos.iter().all(|v| v.vtxo.policy() == policy),
			"All lightning htlc should have the same policy",
		);
		let policy = policy.as_server_htlc_send().context("VTXO is not an HTLC send")?;
		if policy.payment_hash != payment_hash {
			bail!("Payment hash mismatch");
		}

		let req = protos::CheckLightningPaymentRequest {
			hash: payment_hash.to_vec(),
			wait,
		};
		// NB: we don't early return on server error or bad response because we
		// don't want it to prevent us from revoking or exiting HTLCs if necessary.
		let response = srv.client.check_lightning_payment(req).await
			.map(|r| r.into_inner().payment_status);

		let tip = self.chain.tip().await?;
		let expired = tip > policy.htlc_expiry;

		let should_revoke = match response {
			Ok(Some(PaymentStatus::Success(status))) => {
				let preimage_opt = self.process_lightning_send_server_preimage(
					Some(status.preimage), &payment,
				).await?;

				if let Some(preimage) = preimage_opt {
					return Ok(Some(preimage));
				} else {
					trace!("Server said payment is complete, but has no valid preimage: {:?}", preimage_opt);
					expired
				}
			},
			Ok(Some(PaymentStatus::Failed(_))) => {
				info!("Payment failed, revoking VTXO");
				true
			},
			Ok(Some(PaymentStatus::Pending(_))) => {
				trace!("Payment is still pending");
				expired
			},
			// bad server response or request error
			Ok(None) | Err(_) => expired,
		};

		if should_revoke {
			info!("Revoking HTLC VTXOs for payment {} (tip: {}, expiry: {})",
				payment_hash, tip, policy.htlc_expiry);

			if let Err(e) = self.process_lightning_revocation(&payment).await {
				warn!("Failed to revoke VTXO: {}", e);

				// if one of the htlc is about to expire, we exit all of them.
				// Maybe we want a different behavior here, but we have to decide whether
				// htlc vtxos revocation is a all or nothing process.
				let min_expiry = payment.htlc_vtxos.iter()
					.map(|v| v.vtxo.spec().expiry_height).min().unwrap();

				if tip > min_expiry.saturating_sub(self.config().vtxo_refresh_expiry_threshold) {
					warn!("Some HTLC VTXOs for payment {} are about to expire soon, marking to exit", payment_hash);

					let vtxos = payment.htlc_vtxos
						.iter()
						.map(|v| v.vtxo.clone())
						.collect::<Vec<_>>();
					self.exit.write().await.start_exit_for_vtxos(&vtxos).await?;

					let exited = vtxos.iter().map(|v| v.amount()).sum::<Amount>();
					self.movements.finish_movement_with_update(
						payment.movement_id,
						MovementStatus::Failed,
						MovementUpdate::new()
							.effective_balance(-payment.amount.to_signed()? + exited.to_signed()?)
							.exited_vtxos(&vtxos)
					).await?;
					self.db.finish_lightning_send(payment.invoice.payment_hash(), None)?;
				}

				return Err(e)
			}
		}

		Ok(None)
	}

	/// Pays a Lightning [Invoice] using Ark VTXOs. This is also an out-of-round payment
	/// so the same [Wallet::send_arkoor_payment] rules apply.
	///
	/// # Returns
	///
	/// Returns the [Invoice] for which payment was initiated.
	pub async fn pay_lightning_invoice<T>(
		&self,
		invoice: T,
		user_amount: Option<Amount>,
	) -> anyhow::Result<LightningSend>
	where
		T: TryInto<Invoice>,
		T::Error: std::error::Error + fmt::Display + Send + Sync + 'static,
	{
		let invoice = invoice.try_into().context("failed to parse invoice")?;
		let amount = invoice.get_final_amount(user_amount)?;
		info!("Sending bolt11 payment of {} to invoice {}", amount, invoice);
		self.make_lightning_payment(&invoice, invoice.clone().into(), user_amount).await
	}

	/// Same as [Wallet::pay_lightning_invoice] but instead it pays a [LightningAddress].
	pub async fn pay_lightning_address(
		&self,
		addr: &LightningAddress,
		amount: Amount,
		comment: Option<impl AsRef<str>>,
	) -> anyhow::Result<LightningSend> {
		let comment = comment.as_ref();
		let invoice = lnaddr_invoice(addr, amount, comment).await
			.context("lightning address error")?;
		info!("Sending {} to lightning address {}", amount, addr);
		let ret = self.make_lightning_payment(&invoice.into(), addr.clone().into(), None).await
			.context("bolt11 payment error")?;
		info!("Paid invoice {}", ret.invoice);
		Ok(ret)
	}

	/// Attempts to pay the given BOLT12 [Offer] using offchain funds.
	pub async fn pay_lightning_offer(
		&self,
		offer: Offer,
		user_amount: Option<Amount>,
	) -> anyhow::Result<LightningSend> {
		let mut srv = self.require_server()?;

		let offer_bytes = {
			let mut bytes = Vec::new();
			offer.write(&mut bytes).unwrap();
			bytes
		};

		let req = protos::FetchBolt12InvoiceRequest {
			offer: offer_bytes,
			amount_sat: user_amount.map(|a| a.to_sat()),
		};

		if let Some(amt) = user_amount {
			info!("Sending bolt12 payment of {} (user amount) to offer {}", amt, offer);
		} else if let Some(amt) = offer.amount() {
			info!("Sending bolt12 payment of {:?} (invoice amount) to offer {}", amt, offer);
		} else {
			warn!("Paying offer without amount nor user amount provided: {}", offer);
		}

		let resp = srv.client.fetch_bolt12_invoice(req).await?.into_inner();
		let invoice = Bolt12Invoice::try_from(resp.invoice)
			.map_err(|e| anyhow!("invalid invoice: {:?}", e))?;

		invoice.validate_issuance(&offer)
			.context("invalid BOLT12 invoice received from offer")?;

		let ret = self.make_lightning_payment(&invoice.into(), offer.into(), None).await
			.context("bolt12 payment error")?;
		info!("Paid invoice: {:?}", ret.invoice);

		Ok(ret)
	}

	/// Makes a payment using the Lightning Network. This is a low-level primitive to allow for
	/// more fine-grained control over the payment process. The primary purpose of using this method
	/// is to support [PaymentMethod::Custom] for other payment use cases such as LNURL-Pay.
	///
	/// It's recommended to use the following higher-level functions where suitable:
	/// - BOLT11: [Wallet::pay_lightning_invoice]
	/// - BOLT12: [Wallet::pay_lightning_offer]
	/// - Lightning Address: [Wallet::pay_lightning_address]
	///
	/// # Parameters
	/// - `invoice`: A reference to the BOLT11/BOLT12 invoice to be paid.
	/// - `original_payment_method`: The payment method that the given invoice was originally
	///   derived from (e.g., BOLT11, an offer, lightning address). This will appear in the stored
	///   [Movement](crate::movement::Movement).
	/// - `user_amount`: An optional custom amount to override the amount specified in the invoice.
	///   If not provided, the invoice's amount is used.
	///
	/// # Returns
	/// Returns a `Preimage` representing the successful payment. If an error occurs during the
	/// process, an `anyhow::Error` is returned.
	///
	/// # Errors
	/// This function can return an error for the following reasons:
	/// - If the given payment method is not either an officially supported lightning payment method
	///   or [PaymentMethod::Custom].
	/// - The `invoice` belongs to a different network than the one configured in the server's
	///   properties.
	/// - The `invoice` has already been paid (the payment hash exists in the database).
	/// - The `invoice` contains an invalid or tampered signature.
	/// - The amount to be sent is smaller than the dust limit (`P2TR_DUST`).
	/// - The wallet doesn't have enough funds to cover the payment.
	/// - Validation, signing, server or network issues occur.
	///
	/// # Notes
	/// - A movement won't be recorded until we receive an intermediary HTLC VTXO.
	/// - This is effectively an arkoor payment with an additional HTLC conversion step, so the
	///   same [Wallet::send_arkoor_payment] rules apply.
	pub async fn make_lightning_payment(
		&self,
		invoice: &Invoice,
		original_payment_method: PaymentMethod,
		user_amount: Option<Amount>,
	) -> anyhow::Result<LightningSend> {
		if !original_payment_method.is_lightning() && !original_payment_method.is_custom() {
			bail!("Invalid original payment method for lightning payment");
		}
		let mut srv = self.require_server()?;

		let properties = self.db.read_properties()?.context("Missing config")?;
		if invoice.network() != properties.network {
			bail!("Invoice is for wrong network: {}", invoice.network());
		}

		if self.db.get_lightning_send(invoice.payment_hash())?.is_some() {
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

		let req = protos::LightningPayHtlcCosignRequest {
			invoice: invoice.to_string(),
			user_amount_sat: user_amount.map(|a| a.to_sat()),
			input_vtxo_ids: input_ids.iter().map(|v| v.to_bytes().to_vec()).collect(),
			user_nonces: pubs.iter().map(|p| p.serialize().to_vec()).collect(),
			user_pubkey: change_keypair.public_key().serialize().to_vec(),
		};

		let resp = srv.client.request_lightning_pay_htlc_cosign(req).await
			.context("htlc request failed")?.into_inner();

		let cosign_resp = resp.sigs.into_iter().map(|i| i.try_into())
			.collect::<Result<Vec<_>, _>>()?;
		let policy = VtxoPolicy::deserialize(&resp.policy)?;

		let pay_req = match &policy {
			VtxoPolicy::ServerHtlcSend(policy) => {
				ensure!(policy.user_pubkey == change_keypair.public_key(), "user pubkey mismatch");
				ensure!(policy.payment_hash == invoice.payment_hash(), "payment hash mismatch");
				// TODO: ensure expiry is not too high? add new bark config to check against?
				VtxoRequest { amount: amount, policy: policy.clone().into() }
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

		let movement_id = self.movements.new_movement_with_update(
			self.subsystem_ids[&BarkSubsystem::LightningSend],
			LightningSendMovement::Send.to_string(),
			MovementUpdate::new()
				.intended_balance(-amount.to_signed()?)
				.effective_balance(-effective_balance.to_signed()?)
				.consumed_vtxos(&inputs)
				.sent_to([MovementDestination::new(original_payment_method, amount)])
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
				.metadata(LightningMovement::metadata(invoice.payment_hash(), &htlc_vtxos)?)
		).await?;

		let lightning_send = self.db.store_new_pending_lightning_send(
			&invoice, &amount, &htlc_vtxos.iter().map(|v| v.id()).collect::<Vec<_>>(), movement_id,
		)?;

		let req = protos::InitiateLightningPaymentRequest {
			invoice: invoice.to_string(),
			htlc_vtxo_ids: htlc_vtxos.iter().map(|v| v.id().to_bytes().to_vec()).collect(),
			#[allow(deprecated)]
			wait: false,
		};

		srv.client.initiate_lightning_payment(req).await?;

		Ok(lightning_send)
	}
}

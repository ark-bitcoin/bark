
pub mod cln;


use std::cmp;
use std::collections::HashMap;

use anyhow::Context;
use bitcoin::Amount;
use bitcoin::hex::DisplayHex;
use bitcoin::secp256k1::PublicKey;
use log::{info, trace, error};

use ark::{musig, ProtocolEncoding, Vtxo, VtxoId, VtxoPolicy, VtxoRequest};
use ark::arkoor::{ArkoorCosignResponse, ArkoorPackageBuilder};
use ark::lightning::{Bolt12Invoice, Invoice, Offer, PaymentHash, Preimage};
use server_rpc::protos;
use bitcoin_ext::{AmountExt, BlockHeight, P2TR_DUST};
use bitcoin_ext::rpc::RpcApi;

use crate::database::ln::{
	LightningHtlcSubscription, LightningHtlcSubscriptionStatus, LightningPaymentStatus,
};
use crate::error::ContextExt;
use crate::Server;


impl Server {
	pub async fn start_lightning_payment(
		&self,
		invoice: Invoice,
		amount: Amount,
		user_pubkey: PublicKey,
		inputs: Vec<Vtxo>,
		user_nonces: Vec<musig::PublicNonce>,
	) -> anyhow::Result<protos::StartLightningPaymentResponse> {
		let invoice_payment_hash = invoice.payment_hash();
		if self.db.get_open_lightning_payment_attempt_by_payment_hash(&invoice_payment_hash).await?.is_some() {
			return badarg!("payment already in progress for this invoice");
		}

		self.check_vtxos_not_exited(&inputs).await?;

		self.validate_arkoor_inputs(&inputs)?;

		//TODO(stevenroose) check that vtxos are valid

		let expiry = {
			let tip = self.bitcoind.get_block_count()? as BlockHeight;
			let sub = self.db.get_htlc_subscription_by_payment_hash(invoice_payment_hash).await?;

			// If we have a subscription for that invoice, it means user is
			// performing intra-Ark lightning payment: we will be the single
			// hop so we can use its min final cltv expiry delta as expiry delta
			let expiry_delta = if let Some(sub) = sub {
				sub.invoice.min_final_cltv_expiry_delta()
			} else {
				self.config.htlc_send_expiry_delta as u64
			};

			tip + expiry_delta as BlockHeight
		};

		if let Some(vtxo) = inputs.iter().find(|v| v.expiry_height() < expiry) {
			return badarg!("VTXO expires before HTLC expiry height: {}", vtxo.id());
		}

		let policy = VtxoPolicy::new_server_htlc_send(user_pubkey, invoice_payment_hash, expiry);
		let pay_req = VtxoRequest { amount, policy: policy.clone() };

		let package = ArkoorPackageBuilder::new(&inputs, &user_nonces, pay_req, Some(user_pubkey))
			.badarg("error creating arkoor package")?;

		let cosign_resp = self.cosign_oor_package_with_builder(&package).await?;

		Ok(protos::StartLightningPaymentResponse {
			sigs: cosign_resp.into_iter().map(|i| i.into()).collect(),
			policy: policy.serialize().to_vec(),
		})
	}

	/// Try to finish the lightning payment that was previously started.
	pub async fn finish_lightning_payment(
		&self,
		invoice: Invoice,
		htlc_vtxo_ids: Vec<VtxoId>,
		wait: bool,
	) -> anyhow::Result<protos::LightningPaymentResult> {
		//TODO(stevenroose) validate vtxo generally (based on input)
		let invoice_payment_hash = invoice.payment_hash();

		let htlc_vtxos = self.db.get_vtxos_by_id(&htlc_vtxo_ids).await?;

		let mut vtxos = vec![];
		for htlc_vtxo in htlc_vtxos {
			if !htlc_vtxo.is_spendable() {
				return badarg!("input vtxo is already spent");
			}

			let vtxo = htlc_vtxo.vtxo.clone();

			//TODO(stevenroose) need to check that the input vtxos are actually marked
			// as spent for this specific payment
			if vtxo.server_pubkey() != self.server_pubkey {
				return badarg!("invalid server pubkey used");
			}

			let payment_hash = vtxo.server_htlc_out_payment_hash()
				.context("vtxo provided is not an outgoing htlc vtxo")?;
			if payment_hash != invoice_payment_hash {
				return badarg!("htlc payment hash doesn't match invoice");
			}

			//TODO(stevenroose) no fee is charged here now
			if vtxo.amount() < P2TR_DUST {
				return badarg!("htlc vtxo amount is below dust threshold");
			}

			vtxos.push(vtxo);
		}

		let mut htlc_vtxo_sum = Amount::ZERO;
		let mut min_expiry_height = BlockHeight::MAX;
		for htlc_vtxo in &vtxos {
			let htlc = htlc_vtxo.policy().as_server_htlc_send()
				.context("vtxo provided is not an outgoing htlc vtxo")?;
			if htlc.payment_hash != invoice_payment_hash {
				return badarg!("htlc payment hash doesn't match invoice");
			}
			min_expiry_height = cmp::min(min_expiry_height, htlc.htlc_expiry);
			htlc_vtxo_sum += htlc_vtxo.amount();
		}

		if let Some(amount) = invoice.amount_milli_satoshis() {
			if htlc_vtxo_sum < Amount::from_msat_ceil(amount) {
				return badarg!("htlc vtxo amount too low for invoice");
				// any remainder we just keep, can later become fee
			}
		}

		// Spawn a task that performs the payment
		let res = self.cln.pay_bolt11(&invoice, htlc_vtxo_sum, min_expiry_height, wait).await;

		Self::process_lightning_pay_response(invoice_payment_hash, res)
	}

	pub async fn check_lightning_payment(
		&self,
		payment_hash: PaymentHash,
		wait: bool,
	) -> anyhow::Result<protos::LightningPaymentResult> {
		let res = self.cln.check_bolt11(&payment_hash, wait).await;

		Self::process_lightning_pay_response(payment_hash, res)
	}

	fn process_lightning_pay_response(
		payment_hash: PaymentHash,
		res: anyhow::Result<Preimage>,
	) -> anyhow::Result<protos::LightningPaymentResult> {
		match res {
			Ok(preimage) => {
				Ok(protos::LightningPaymentResult {
					progress_message: "Payment completed".to_string(),
					status: protos::PaymentStatus::Complete.into(),
					payment_hash: payment_hash.to_vec(),
					payment_preimage: Some(preimage.to_vec())
				})
			},
			Err(e) => {
				let status = e.downcast_ref::<LightningPaymentStatus>();
				if let Some(LightningPaymentStatus::Failed) = status {
					Ok(protos::LightningPaymentResult {
						progress_message: format!("Payment failed: {}", e),
						status: protos::PaymentStatus::Failed.into(),
						payment_hash: payment_hash.to_vec(),
						payment_preimage: None
					})
				} else {
					Ok(protos::LightningPaymentResult {
						progress_message: format!("Error during payment: {:?}", e),
						status: protos::PaymentStatus::Failed.into(),
						payment_hash: payment_hash.to_vec(),
						payment_preimage: None
					})
				}
			},
		}
	}

	pub async fn fetch_bolt12_invoice(&self, offer: Offer, amount: Amount) -> anyhow::Result<Bolt12Invoice> {
		let invoice = self.cln.fetch_bolt12_invoice(offer, amount).await?;
		Ok(invoice)
	}

	pub async fn revoke_bolt11_payment(
		&self,
		htlc_vtxo_ids: Vec<VtxoId>,
		user_nonces: Vec<musig::PublicNonce>,
	) -> anyhow::Result<Vec<ArkoorCosignResponse>> {
		let tip = self.bitcoind.get_block_count()? as BlockHeight;
		let db = self.db.clone();

		let htlc_vtxos = self.db.get_vtxos_by_id(&htlc_vtxo_ids).await?;

		let first = htlc_vtxos.first().badarg("vtxo is empty")?.vtxo.spec();
		let first_policy = first.policy.as_server_htlc_send().context("vtxo is not outgoing htlc vtxo")?;

		let mut vtxos = vec![];
		for htlc_vtxo in htlc_vtxos {
			let spec = htlc_vtxo.vtxo.spec();
			let policy = spec.policy.as_server_htlc_send()
				.context("vtxo is not outgoing htcl vtxo")?;

			if policy != first_policy {
				return badarg!("all revoked htlc vtxos must have same policy");
			}

			vtxos.push(htlc_vtxo.vtxo);
		}

		let invoice = db.get_lightning_invoice_by_payment_hash(&first_policy.payment_hash).await?;

		// If payment not found but input vtxos are found, we can allow revoke
		if let Some(invoice) = invoice {
			match invoice.last_attempt_status {
				Some(status) if status == LightningPaymentStatus::Failed => {},
				Some(status) if status == LightningPaymentStatus::Succeeded => {
					if let Some(preimage) = invoice.preimage {
						return badarg!("This lightning payment has completed. preimage: {}",
							preimage.as_hex());
					} else {
						error!("This lightning payment has completed, but no preimage found. Accepting revocation");
					}
				},
				_ if tip > first_policy.htlc_expiry => {
					// Check one last time to see if it completed
					if let Ok(preimage) = self.cln.check_bolt11(&invoice.payment_hash, false).await {
						return badarg!("This lightning payment has completed. preimage: {}",
							preimage.as_hex());
					}
				},
				_ => return badarg!("This lightning payment is not eligible for revocation yet")
			}
		}

		let pay_req = VtxoRequest {
			amount: vtxos.iter().map(|v| v.amount()).sum(),
			policy: VtxoPolicy::new_pubkey(vtxos.first().unwrap().user_pubkey()),
		};
		let package = ArkoorPackageBuilder::new(&vtxos, &user_nonces, pay_req, None)?;
		self.cosign_oor_package_with_builder(&package).await
	}

	pub async fn start_lightning_receive(
		&self,
		payment_hash: PaymentHash,
		amount: Amount,
	) -> anyhow::Result<protos::StartLightningReceiveResponse> {
		info!("Starting bolt11 board with payment_hash: {}", payment_hash.as_hex());

		if amount < P2TR_DUST {
			return badarg!("Requested amount must be at least {}", P2TR_DUST);
		}

		if let Some(max) = self.config.max_vtxo_amount {
			if amount > max {
				return badarg!("Requested amount exceeds limit of {}", max);
			}
		}

		let subscriptions = self.db.get_htlc_subscriptions_by_payment_hash(payment_hash).await?;

		let subscriptions_by_status = subscriptions.iter()
			.fold::<HashMap<_, Vec<_>>, _>(HashMap::new(), |mut acc, sub| {
				acc.entry(sub.status).or_default().push(sub);
				acc
			});

		if subscriptions_by_status.contains_key(&LightningHtlcSubscriptionStatus::Settled) {
			bail!("invoice already settled");
		}

		if subscriptions_by_status.contains_key(&LightningHtlcSubscriptionStatus::Accepted) {
			bail!("invoice already accepted");
		}

		if let Some(created) = subscriptions_by_status.get(&LightningHtlcSubscriptionStatus::Created) {
			if let Some(subscription) = created.first() {
				trace!("Found existing created subscription, returning invoice: {}",
					subscription.invoice.to_string(),
				);
				return Ok(protos::StartLightningReceiveResponse {
					bolt11: subscription.invoice.to_string()
				})
			}
		}

		let invoice = self.cln.generate_invoice(payment_hash, amount).await?;
		trace!("Hold invoice created. payment_hash: {}, amount: {}, {}",
			payment_hash, amount, invoice.to_string(),
		);

		Ok(protos::StartLightningReceiveResponse {
			bolt11: invoice.to_string()
		})
	}

	pub async fn check_lightning_receive(
		&self,
		payment_hash: PaymentHash,
		wait: bool,
	) -> anyhow::Result<LightningHtlcSubscription> {
		let sub = loop {
			if let Some(htlc) = self.db.get_htlc_subscription_by_payment_hash(payment_hash).await? {
				if htlc.status == LightningHtlcSubscriptionStatus::Settled {
					bail!("invoice already settled");
				}

				if htlc.status == LightningHtlcSubscriptionStatus::Accepted {
					break htlc;
				}
			}

			if !wait {
				bail!("payment not yet initiated by sender");
			}

			tokio::time::sleep(self.config.invoice_check_interval).await;
		};

		Ok(sub)
	}

	pub async fn prepare_lightning_claim(
		&self,
		payment_hash: PaymentHash,
		user_pubkey: PublicKey,
	) -> anyhow::Result<(LightningHtlcSubscription, Vec<Vtxo>)> {
		let mut sub = self.db.get_htlc_subscription_by_payment_hash(payment_hash).await?
			.not_found([payment_hash], "no pending payment with this payment hash")?;
		// first check whether we're in the right state to do this
		match sub.status {
			LightningHtlcSubscriptionStatus::Accepted => {}, // we continue
			LightningHtlcSubscriptionStatus::HtlcsReady => {
				// we already did this, let's fetch the vtxos and return them
				let vtxos = self.db.get_vtxos_by_id(&sub.htlc_vtxos).await?.into_iter()
					.map(|v| v.vtxo)
					.collect();
				return Ok((sub, vtxos));
			},
			LightningHtlcSubscriptionStatus::Cancelled => {
				return badarg!("payment cancelled");
			},
			LightningHtlcSubscriptionStatus::Settled => {
				return badarg!("payment already settled");
			},
			LightningHtlcSubscriptionStatus::Created => {
				return badarg!("payment not yet initiated by sender");
			},
		}

		let vtxos = {
			let expiry = self.chain_tip().height + self.config.htlc_send_expiry_delta as BlockHeight;
			let request = VtxoRequest {
				amount: sub.amount(),
				policy: VtxoPolicy::new_server_htlc_recv(user_pubkey, payment_hash, expiry),
			};
			self.vtxopool.send_arkoor(self, request).await.context("vtxopool error")?
		};

		self.db.update_lightning_htlc_subscription_with_htlcs(
			sub.id,
			vtxos.iter().map(|v| v.id()),
		).await.context("failed to store htlcs for ln receive")?;

		sub.status = LightningHtlcSubscriptionStatus::HtlcsReady;
		sub.htlc_vtxos = vtxos.iter().map(|v| v.id()).collect();

		Ok((sub, vtxos))
	}

	pub async fn claim_lightning_receive(
		&self,
		payment_hash: PaymentHash,
		vtxo_policy: VtxoPolicy,
		user_nonces: Vec<musig::PublicNonce>,
		payment_preimage: Preimage,
	) -> anyhow::Result<Vec<ArkoorCosignResponse>> {
		if payment_hash != payment_preimage.compute_payment_hash() {
			return badarg!("preimage doesn't match payment hash");
		}

		let sub = self.db.get_htlc_subscription_by_payment_hash(payment_hash).await?
			.not_found([payment_hash], "no pending payment with this payment hash")?;

		if sub.status != LightningHtlcSubscriptionStatus::HtlcsReady {
			return badarg!("payment status in incorrect state: {}", sub.status);
		}
		if sub.htlc_vtxos.is_empty() {
			error!("htlc subscription in status htlcs-ready without htlcs: {}", payment_hash);
			bail!("internal error: no HTLC VTXOs found");
		}

		let htlc_vtxos = self.db.get_vtxos_by_id(&sub.htlc_vtxos).await?;

		let vtxo_req = VtxoRequest {
			amount: sub.amount(),
			policy: vtxo_policy,
		};
		let input = {
			let mut ret = htlc_vtxos.iter().map(|v| &v.vtxo).collect::<Vec<_>>();
			ret.sort_by_key(|v| v.id());
			ret
		};
		let package = ArkoorPackageBuilder::new(input, &user_nonces, vtxo_req, None)
			.badarg("incorrect VTXO request data")?;

		self.cln.settle_invoice(sub.id, payment_preimage).await?
			.context("could not settle invoice")?;

		Ok(self.cosign_oor_package_with_builder(&package).await?)
	}
}

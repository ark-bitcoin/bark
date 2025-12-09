
pub mod cln;


use std::cmp;
use std::collections::HashMap;

use anyhow::Context;
use ark::integration::TokenStatus;
use bitcoin::Amount;
use bitcoin::hex::DisplayHex;
use bitcoin::secp256k1::{schnorr, PublicKey};
use log::{info, trace, error};
use uuid::Uuid;

use ark::{musig, ProtocolEncoding, Vtxo, VtxoId, VtxoPolicy, VtxoRequest};
use ark::arkoor::{ArkoorCosignResponse, ArkoorPackageBuilder};
use ark::challenges::LightningReceiveChallenge;
use ark::lightning::{Bolt12Invoice, Invoice, Offer, PaymentHash, PaymentStatus, Preimage};
use server_rpc::protos::{self, InputVtxo, lightning_payment_status};
use server_rpc::protos::prepare_lightning_receive_claim_request::LightningReceiveAntiDos;
use server_rpc::TryFromBytes;
use bitcoin_ext::{AmountExt, BlockDelta, BlockHeight, P2TR_DUST};
use bitcoin_ext::rpc::RpcApi;

use crate::database::ln::{
	LightningHtlcSubscription, LightningHtlcSubscriptionStatus, LightningPaymentStatus,
};
use crate::error::ContextExt;
use crate::{Server, CAPTAIND_API_KEY};


impl Server {
	pub async fn request_lightning_pay_htlc_cosign(
		&self,
		invoice: Invoice,
		amount: Amount,
		user_pubkey: PublicKey,
		inputs: Vec<Vtxo>,
		user_nonces: Vec<musig::PublicNonce>,
	) -> anyhow::Result<protos::LightningPayHtlcCosignResponse> {
		let invoice_payment_hash = invoice.payment_hash();
		if self.db.get_open_lightning_payment_attempt_by_payment_hash(&invoice_payment_hash).await?.is_some() {
			return badarg!("payment already in progress for this invoice");
		}

		self.check_vtxos_not_exited(&inputs).await?;

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

		let policy = VtxoPolicy::new_server_htlc_send(user_pubkey, invoice_payment_hash, expiry);
		let pay_req = VtxoRequest { amount, policy: policy.clone() };

		let package = ArkoorPackageBuilder::new(&inputs, &user_nonces, pay_req, Some(user_pubkey))
			.badarg("error creating arkoor package")?;

		let cosign_resp = self.cosign_oor_package_with_builder(&package).await?;

		Ok(protos::LightningPayHtlcCosignResponse {
			sigs: cosign_resp.into_iter().map(|i| i.into()).collect(),
			policy: policy.serialize().to_vec(),
		})
	}

	/// Try to finish the lightning payment that was previously started.
	pub async fn initiate_lightning_payment(
		&self,
		invoice: Invoice,
		htlc_vtxo_ids: Vec<VtxoId>,
	) -> anyhow::Result<()> {
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

		if let Some(amount) = invoice.amount_msat() {
			if htlc_vtxo_sum < Amount::from_msat_ceil(amount) {
				return badarg!("htlc vtxo amount too low for invoice");
				// any remainder we just keep, can later become fee
			}
		}

		// Spawn a task that performs the payment
		self.cln.pay_invoice(
			&invoice,
			htlc_vtxo_sum,
			min_expiry_height
		).await?;

		Ok(())
	}

	pub async fn check_lightning_payment(
		&self,
		payment_hash: PaymentHash,
		wait: bool,
	) -> anyhow::Result<lightning_payment_status::PaymentStatus> {
		let payment_status = self.cln.get_payment_status(&payment_hash, wait).await?;

		Ok(Self::format_lightning_pay_response(payment_status))
	}

	fn format_lightning_pay_response(
		res: PaymentStatus,
	) -> lightning_payment_status::PaymentStatus {
		match res {
			PaymentStatus::Success(preimage) => {
				lightning_payment_status::PaymentStatus::Success(protos::PaymentSuccessStatus {
					preimage: preimage.to_vec(),
				})
			},
			PaymentStatus::Failed => {
				lightning_payment_status::PaymentStatus::Failed(protos::Empty {})
			},
			PaymentStatus::Pending => {
				lightning_payment_status::PaymentStatus::Pending(protos::Empty {})
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
					let res = self.cln.get_payment_status(&invoice.payment_hash, false).await;
					if let Ok(PaymentStatus::Success(preimage)) = res {
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
		min_cltv_delta: BlockDelta,
	) -> anyhow::Result<protos::StartLightningReceiveResponse> {
		info!("Starting bolt11 board with payment_hash: {}", payment_hash.as_hex());

		if min_cltv_delta > self.config.max_user_invoice_cltv_delta {
			bail!("Requested min HTLC CLTV delta is greater than max HTLC recv CLTV delta: requested: {}, max: {}",
				min_cltv_delta, self.config.max_user_invoice_cltv_delta,
			);
		}

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

		// NB: we had user's requested cltv delta with the delta configured
		// between last lightning htlc and htlc-recv vtxo one
		let ln_cltv_delta = min_cltv_delta + self.config.htlc_expiry_delta;

		let invoice = self.cln.generate_invoice(payment_hash, amount, ln_cltv_delta).await?;
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
			let subscription = self.db.get_htlc_subscription_by_payment_hash(payment_hash).await?
				.not_found([payment_hash], "invoice not found")?;

			match subscription.status {
				LightningHtlcSubscriptionStatus::Accepted |
				LightningHtlcSubscriptionStatus::HtlcsReady => {
					break subscription;
				},
				LightningHtlcSubscriptionStatus::Settled |
				LightningHtlcSubscriptionStatus::Canceled |
				LightningHtlcSubscriptionStatus::Created => {
					if !wait {
						break subscription;
					}
				},
			}

			tokio::time::sleep(self.config.invoice_check_interval).await;
		};

		Ok(sub)
	}

	pub async fn prepare_lightning_claim(
		&self,
		payment_hash: PaymentHash,
		user_pubkey: PublicKey,
		htlc_recv_expiry: BlockHeight,
		anti_dos: Option<protos::prepare_lightning_receive_claim_request::LightningReceiveAntiDos>,
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
			LightningHtlcSubscriptionStatus::Canceled => {
				return badarg!("payment canceled");
			},
			LightningHtlcSubscriptionStatus::Settled => {
				return badarg!("payment already settled");
			},
			LightningHtlcSubscriptionStatus::Created => {
				return badarg!("payment not yet initiated by sender");
			},
		}

		self.verify_ln_receive_anti_dos(anti_dos, payment_hash).await?;

		let vtxos = {
			// We compare requested htlc expiry height with the lowest LN HTLC expiry height
			// If the difference is lower than the configured delta, we refuse the request.
			let expiry = match sub.lowest_incoming_htlc_expiry {
				Some(lowest_incoming_htlc_expiry) => {
					let max_htlc_recv_expiry = lowest_incoming_htlc_expiry + self.config.htlc_expiry_delta as BlockHeight;
					if htlc_recv_expiry > max_htlc_recv_expiry {
						return badarg!("Requested HTLC recv expiry is too high. Requested {}. Max {}",
							htlc_recv_expiry,
							max_htlc_recv_expiry,
						);
					}

					htlc_recv_expiry
				},
				None => {
					error!("An accepted invoice has no lowest HTLC expiry. subscription id: {}", sub.id);
					bail!("Cannot prepare claim: invoice subscription has no lowest HTLC expiry set");
				},
			};

			let request = VtxoRequest {
				amount: sub.amount(),
				policy: VtxoPolicy::new_server_htlc_recv(
					user_pubkey, payment_hash, expiry, self.config.htlc_expiry_delta,
				),
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

	async fn verify_ln_receive_anti_dos(
		&self,
		anti_dos: Option<LightningReceiveAntiDos>,
		payment_hash: PaymentHash,
	) -> anyhow::Result<()> {
		if let Some(anti_dos) = anti_dos {
			// Always verify anti-DoS proof or token if provided
			match anti_dos {
				LightningReceiveAntiDos::InputVtxo(InputVtxo { vtxo_id, ownership_proof }) => {
					let challenge = LightningReceiveChallenge::new(payment_hash);
					let vtxo_id = VtxoId::from_bytes(vtxo_id)?;
					let ownership_proof = schnorr::Signature::from_bytes(ownership_proof)?;

					let vtxos = self.db.get_vtxos_by_id(&[vtxo_id]).await?;
					let vtxo = vtxos.first().badarg("vtxo for proof not found")?;
					if !vtxo.is_spendable() {
						return badarg!("vtxo for proof is not spendable");
					}

					challenge.verify_input_vtxo_sig(&vtxo.vtxo, &ownership_proof).context("vtxo ownership proof invalid")?;
				},
				LightningReceiveAntiDos::Token(token_string) => {
					let api_key = self.db.get_integration_api_key_by_api_key(Uuid::parse_str(CAPTAIND_API_KEY)
						.expect("hardcoded api key is valid")).await?
						.context("captaind integration api key not found")?;
					let token = self.db.get_integration_token(&token_string).await?.context("token not found")?;

					if token.is_expired() {
						return badarg!("token has expired");
					}

					if !matches!(token.status, TokenStatus::Unused) {
						return badarg!("token has already been used or is invalid");
					}

					let filters = token.filters.clone();
					let _ = self.db.update_integration_token(token, api_key.id, TokenStatus::Used, &filters).await?;
				},
			}
		} else if self.config.ln_receive_anti_dos_required {
			return badarg!("either a receive token or a challenge proof must be provided");
		}

		Ok(())
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

		self.cln.settle_invoice(sub.id, payment_preimage).await
			.context("could not settle invoice")?;

		Ok(self.cosign_oor_package_with_builder(&package).await?)
	}
}

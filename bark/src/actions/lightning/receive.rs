//! State machine for incoming lightning payments.
//!
//! Identity (`invoice`, `payment_hash`, `payment_preimage`) and the
//! parameters fixed at invoice creation (htlc claim cltv delta, anti-dos
//! token) live on the action as top-level fields; the mutable bit is
//! [`Progress`], representing the current phase of the state machine.

use std::str::FromStr;
use std::time::Duration;

use anyhow::Context;
use bitcoin::{Amount, SignedAmount};
use lightning_invoice::Bolt11Invoice;
use log::{debug, error, info, trace, warn};
use rand::seq::IteratorRandom;

use ark::arkoor::package::ArkoorPackageBuilder;
use ark::attestations::LightningReceiveAttestation;
use ark::fees::validate_and_subtract_fee;
use ark::lightning::{Bolt11InvoiceExt, PaymentHash, Preimage};
use ark::{ProtocolEncoding, Vtxo, VtxoId, VtxoPolicy};
use ark::vtxo::Full;
use bitcoin_ext::{BlockDelta, BlockHeight};
use server_rpc::protos;
use server_rpc::protos::prepare_lightning_receive_claim_request::LightningReceiveAntiDos;

use crate::{Config, Wallet};
use crate::actions::{
	Advance, AdvanceError, BASE_RETRY_BACKOFF, WalletAction, WalletActionId, park_with_backoff,
};
use crate::arkoor::{DeliveryOutcome, post_arkoor_to_mailboxes};
use crate::movement::update::MovementUpdate;
use crate::movement::{MovementDestination, MovementId, MovementStatus};
use crate::persist::models::SettledLightningReceive;
use crate::subsystem::{LightningMovement, LightningReceiveMovement, Subsystem};
use crate::vtxo::VtxoLockHolder;

const LN_RECV_NAMESPACE: &str = "ln_recv";

/// Leniency delta to allow claim when blocks were mined between htlc
/// receive and claim preparation.
const LIGHTNING_PREPARE_CLAIM_DELTA: BlockDelta = 2;

/// How long to sleep between polls while waiting for an inbound payment
const AWAITING_PAYMENT_POLL_INTERVAL: Duration = Duration::from_secs(4);

/// Grace past the bolt11 invoice expiry before an unpaid receive is
/// reaped, to avoid racing a payment that lands right at the boundary.
const INVOICE_EXPIRY_GRACE: Duration = Duration::from_secs(60);

pub(crate) fn ln_recv_action_id(payment_hash: PaymentHash) -> WalletActionId {
	format!("{LN_RECV_NAMESPACE}.{payment_hash}")
}

fn validate_bolt11_payment_hash(
	invoice: &Bolt11Invoice,
	expected_payment_hash: PaymentHash,
) -> anyhow::Result<()> {
	let invoice_payment_hash = PaymentHash::from(invoice);
	ensure!(
		invoice_payment_hash == expected_payment_hash,
		"Ark server returned invoice with payment hash {}, expected {}",
		invoice_payment_hash,
		expected_payment_hash,
	);

	Ok(())
}

/// An incoming lightning payment, persisted as a single checkpoint row
/// stored at invoice creation time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LightningReceive {
	// Set at invoice creation, immutable thereafter:
	pub invoice: Bolt11Invoice,
	pub payment_hash: PaymentHash,
	pub payment_preimage: Preimage,
	pub htlc_recv_cltv_delta: BlockDelta,
	pub anti_dos_token: Option<String>,
	#[serde(default)]
	pub claim_destination: Option<ark::Address>,
	/// Index of the wallet key backing the HTLC-recv vtxo and, for local
	/// receives, the claim output.
	pub key_index: u32,

	// Mutable state:
	pub progress: Progress,
}

impl LightningReceive {
	pub fn id(&self) -> WalletActionId {
		ln_recv_action_id(self.payment_hash)
	}
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl WalletAction for LightningReceive {
	fn id(&self) -> WalletActionId { LightningReceive::id(self) }

	async fn advance(self, wallet: &Wallet) -> Result<Advance<Self>, AdvanceError> {
		let mut preimage_revealed = false;
		let new_progress = match self.progress.clone() {
			Progress::AwaitingPayment => {
				match check_incoming_lightning_payment(wallet, &self).await? {
					IncomingStatus::Pending => {
						if invoice_expired(&self.invoice) {
							info!("Removing unpaid expired lightning receive {}", self.payment_hash);
							return Ok(Advance::Done);
						}
						return Ok(Advance::Park {
							state: self,
							wake_after: Some(AWAITING_PAYMENT_POLL_INTERVAL),
							error: None,
						});
					},
					IncomingStatus::Canceled => {
						let err = anyhow!("Lightning receive {} canceled server-side", self.payment_hash);
						return Ok(Advance::Failed(err.into()));
					},
					IncomingStatus::Ready => {
						match prepare_lightning_receive_htlcs(wallet, &self).await? {
							Grant::Accepted(htlcs) => Progress::HtlcsReady(htlcs),
							Grant::Rejected(err) => {
								error!("Rejecting the HTLC vtxos granted for lightning receive {}: {:#}",
									self.payment_hash, err);
								return Ok(Advance::Failed(err.into()));
							},
						}
					},
				}
			},
			Progress::HtlcsReady(htlcs) => {
				// Preimage not revealed yet: if the HTLCs are near expiry,
				// abandon rather than commit;
				if is_htlc_near_expiry(wallet, &htlcs).await? {
					abandon_lightning_receive(wallet, &self, &htlcs).await?;
					return Ok(Advance::Done);
				}

				match claim_lightning_receive_htlcs(wallet, &self, &htlcs, &mut preimage_revealed).await {
					Ok(None) => return Ok(Advance::Done),
					Ok(Some(delivery)) => Progress::Delivering(delivery),
					Err(e) => {
						if preimage_revealed {
							// Preimage is out but a post-reveal step failed. Park
							// past the point of no return (PreimageRevealed never
							// abandons) and retry the idempotent claim later.
							warn!("lightning receive {} failed after revealing preimage, \
								retrying claim: {:#}", self.payment_hash, e);
							return Ok(Advance::Park {
								state: LightningReceive {
									progress: Progress::PreimageRevealed(htlcs),
									..self
								},
								wake_after: Some(BASE_RETRY_BACKOFF),
								error: None,
							});
						} else {
							return Err(e);
						}
					},
				}
			},
			Progress::PreimageRevealed(htlcs) => {
				match claim_lightning_receive_htlcs(wallet, &self, &htlcs, &mut preimage_revealed).await? {
					None => return Ok(Advance::Done),
					Some(delivery) => Progress::Delivering(delivery),
				}
			},
			Progress::Delivering(delivery) => {
				deliver_lightning_receive(wallet, &self, &delivery).await?;
				return Ok(Advance::Done);
			},
		};

		Ok(Advance::Next(LightningReceive { progress: new_progress, ..self }))
	}

	async fn on_retry(self, wallet: &Wallet, retries: u32, _error: AdvanceError)
		-> anyhow::Result<Advance<Self>>
	{
		match self.progress.clone() {
			// No money committed; just back off. Expiry reaping happens in advance.
			Progress::AwaitingPayment => Ok(park_with_backoff(self, retries)),
			Progress::HtlcsReady(htlcs) => {
				if is_htlc_near_expiry(wallet, &htlcs).await? {
					abandon_lightning_receive(wallet, &self, &htlcs).await?;
					let err = anyhow!("HTLCs near expiry, abandoning");
					return Ok(Advance::Failed(err.into()));
				}
				Ok(park_with_backoff(self, retries))
			},
			Progress::PreimageRevealed(_) | Progress::Delivering(_) => {
				let budget = u32::from(wallet.config().lightning_receive_claim_retries);
				if retries >= budget {
					let err = anyhow!("lightning receive claim retry budget exhausted");
					return Ok(Advance::Park { state: self, wake_after: None, error: Some(err.into()) });
				}
				Ok(park_with_backoff(self, retries))
			},
		}
	}

	async fn on_rejection(self, wallet: &Wallet, error: AdvanceError) -> anyhow::Result<Advance<Self>> {
		match self.progress.clone() {
			// Nothing committed server-side: drop the row ourselves and
			// surface the original error to the caller.
			Progress::AwaitingPayment => {
				let id = self.id();
				error!("Could not start lightning receive {}: {:?}", id, error);
				if let Err(e) = wallet.stop_wallet_action(&id).await {
					warn!("could not cancel awaiting-payment lightning receive {}: {:#}", id, e);
				}
				Ok(Advance::Failed(error.into()))
			},
			// Preimage not revealed yet: abandon locally (the inbound HTLC
			// times out and the sender is refunded).
			Progress::HtlcsReady(htlcs) => {
				error!("Server rejected lightning receive claim before preimage disclosure, abandoning");
				abandon_lightning_receive(wallet, &self, &htlcs).await?;
				Ok(Advance::Failed(error.into()))
			},
			Progress::PreimageRevealed(_) | Progress::Delivering(_) => {
				Ok(Advance::Park { state: self, wake_after: None, error: Some(error) })
			},
		}
	}
}

/// The phases of an incoming lightning receive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Progress {
	/// Invoice created, waiting for an inbound HTLC. No money yet.
	AwaitingPayment,
	/// Server prepared HTLC-recv vtxos; we hold them locked and the
	/// movement is created. The preimage has NOT been revealed yet, so the
	/// receive is still cancellable.
	HtlcsReady(Htlcs),
	/// The preimage has been revealed via the claim RPC in
	/// exchange of pubkey VTXOs.
	/// Past the point of no return — the receive can no longer be
	/// cancelled. On failure we leave it pending rather than auto-exit;
	/// the caller falls back to an on-chain exit via
	/// `Wallet::attempt_lightning_receive_exit`.
	PreimageRevealed(Htlcs),
	/// The claim outputs are cosigned and held locked; they still need
	/// to be forwarded to the claim destination's mailbox. Only entered
	/// when the receive has a claim destination that isn't our own.
	Delivering(Delivery),
}

/// A handle for the HTLC-recv vtxos the server granted us
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Htlcs {
	/// The VTXO IDs of the HTLC-recv vtxos
	pub vtxo_ids: Vec<VtxoId>,
	/// The ID of the ongoing movement
	pub movement_id: MovementId,
}

/// The result of asking the server to grant HTLC-recv vtxos.
pub(crate) enum Grant {
	/// The server granted vtxos we're willing to claim against.
	Accepted(Htlcs),
	/// The granted vtxos don't match what we asked for, so we reject them
	/// instead of claiming against them.
	Rejected(anyhow::Error),
}

/// A handle for the cosigned claim outputs awaiting forwarding to the
/// claim destination
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Delivery {
	/// The VTXOs to be delivered to an external party.
	#[serde(with = "ark::encode::serde::vec")]
	pub vtxos: Vec<Vtxo<Full>>,
	/// The ID of the ongoing movement
	pub movement_id: MovementId,
}

/// Triage of a payment hash on the receive side, mirroring
/// [`LightningSendState`](crate::actions::lightning::pay::LightningSendState):
/// settled (permanent record), in-progress (live checkpoint), or unknown.
#[derive(Debug, Clone)]
pub enum LightningReceiveState {
	InProgress(LightningReceive),
	Settled(SettledLightningReceive),
}

/// Outcome of polling the server for an inbound payment while in
/// [`Progress::AwaitingPayment`].
pub(crate) enum IncomingStatus {
	/// No inbound HTLC yet; keep waiting.
	Pending,
	/// The server is holding HTLCs ready for us to prepare and claim.
	Ready,
	/// The server canceled the hold invoice; nothing to claim.
	Canceled,
}

/// Mint a bolt11 invoice and build a fresh [`LightningReceive`] in
/// [`Progress::AwaitingPayment`]. The executor persists the returned
/// state; the caller is responsible for checkpoint existence checks.
pub(crate) async fn start_lightning_receive(
	wallet: &Wallet,
	amount: Amount,
	description: Option<String>,
	token: Option<String>,
	claim_destination: Option<ark::Address>,
) -> anyhow::Result<LightningReceive> {
	if amount == Amount::ZERO {
		bail!("Cannot create invoice for 0 sats (this would create an explicit 0 sat invoice, not an any-amount invoice)");
	}

	if let Some(destination) = claim_destination.as_ref() {
		wallet.validate_arkoor_address(destination).await?;
	}

	let (mut srv, ark_info) = wallet.require_server().await?;
	let config = wallet.config();

	let fee = ark_info.fees.lightning_receive.calculate(amount).context("fee overflowed")?;
	validate_and_subtract_fee(amount, fee)?;

	// User needs to enforce the following delta:
	// - vtxo exit delta + htlc expiry delta (time to exit the vtxo before the htlc expires)
	// - vtxo exit margin (time to exit the vtxo before the htlc expires)
	// - htlc recv claim delta (time to claim the htlc before it expires)
	let requested_min_cltv_delta = ark_info.vtxo_exit_delta
		.checked_add(ark_info.htlc_expiry_delta)
		.and_then(|v| v.checked_add(config.vtxo_exit_margin))
		.and_then(|v| v.checked_add(config.htlc_recv_claim_delta))
		.and_then(|v| v.checked_add(LIGHTNING_PREPARE_CLAIM_DELTA))
		.context("HTLC CLTV delta components sum overflows")?;

	if requested_min_cltv_delta > ark_info.max_user_invoice_cltv_delta {
		bail!("HTLC CLTV delta ({}) is greater than Server's max HTLC recv CLTV delta: {}",
			requested_min_cltv_delta,
			ark_info.max_user_invoice_cltv_delta,
		);
	}

	let preimage = Preimage::random();
	let payment_hash = preimage.compute_payment_hash();
	info!("Start bolt11 receive with payment hash: {}", payment_hash);

	let mailbox_kp = wallet.inner.seed.to_mailbox_keypair();
	let mailbox_id = ark::mailbox::MailboxIdentifier::from_pubkey(mailbox_kp.public_key());

	let req = protos::StartLightningReceiveRequest {
		payment_hash: payment_hash.to_vec(),
		amount_sat: amount.to_sat(),
		min_cltv_delta: requested_min_cltv_delta as u32,
		mailbox_id: Some(mailbox_id.serialize()),
		description,
	};

	let resp = srv.client.start_lightning_receive(req).await?.into_inner();
	info!("Ark Server is ready to receive LN payment to invoice: {}.", resp.bolt11);

	let invoice = Bolt11Invoice::from_str(&resp.bolt11)
		.context("invalid bolt11 invoice returned by Ark server")?;
	validate_bolt11_payment_hash(&invoice, payment_hash)?;

	let (_, key_index) = wallet.derive_store_next_keypair().await?;

	Ok(LightningReceive {
		invoice,
		payment_hash,
		payment_preimage: preimage,
		htlc_recv_cltv_delta: requested_min_cltv_delta,
		anti_dos_token: token,
		claim_destination,
		key_index,
		progress: Progress::AwaitingPayment,
	})
}

/// Build the anti-dos proof for a claim: an explicit token if the caller
/// supplied one, otherwise an attestation over an owned vtxo.
pub(crate) async fn compute_lightning_receive_anti_dos(
	wallet: &Wallet,
	payment_hash: PaymentHash,
	token: Option<&str>,
) -> anyhow::Result<LightningReceiveAntiDos> {
	Ok(if let Some(token) = token {
		LightningReceiveAntiDos::Token(token.to_string())
	} else {
		let tip = wallet.inner.chain.tip().await?;
		// The proof vtxo isn't spent, so any unexpired one will do; pick at
		// random but keep a 2-block margin: better no proof than one that
		// expires while the claim is in flight.
		let vtxo = wallet.spendable_vtxos().await?.into_iter()
			.filter(|v| v.expiry_height() > tip + 2)
			.choose(&mut rand::rng())
			.context("have no spendable vtxo with sufficient expiry margin to prove ownership of")?;
		let vtxo_keypair = wallet.get_vtxo_key(&vtxo).await
			.expect("owned vtxo should be in database");
		let attestation = LightningReceiveAttestation::new(payment_hash, vtxo.id(), &vtxo_keypair);
		LightningReceiveAntiDos::InputVtxo(protos::InputVtxo {
			vtxo_id: vtxo.id().to_bytes().to_vec(),
			attestation: attestation.serialize(),
		})
	})
}

/// AwaitingPayment poll: ask the server whether an inbound payment has
/// arrived without waiting.
pub(crate) async fn check_incoming_lightning_payment(
	wallet: &Wallet,
	recv: &LightningReceive,
) -> Result<IncomingStatus, AdvanceError> {
	let (mut srv, _) = wallet.require_server().await?;
	let sub = srv.client.check_lightning_receive(protos::CheckLightningReceiveRequest {
		hash: recv.payment_hash.to_byte_array().to_vec(),
		wait: false,
	}).await.map_err(AdvanceError::Server)?.into_inner();

	let status = protos::LightningReceiveStatus::try_from(sub.status)
		.with_context(|| format!("unknown payment status: {}", sub.status))?;
	debug!("Received status {:?} for {}", status, recv.payment_hash);

	Ok(match status {
		protos::LightningReceiveStatus::Accepted |
		protos::LightningReceiveStatus::HtlcsReady => IncomingStatus::Ready,
		protos::LightningReceiveStatus::Created => IncomingStatus::Pending,
		protos::LightningReceiveStatus::Canceled => IncomingStatus::Canceled,
		protos::LightningReceiveStatus::Settled => {
			return Err(anyhow!("payment already settled").into());
		},
	})
}

/// The number of blocks we need, counted from now, to claim an HTLC-recv
/// vtxo unilaterally once the server refuses to cosign.
fn htlc_recv_exit_blocks_needed(
	exit_delta: BlockDelta,
	htlc_expiry_delta: BlockDelta,
	config: &Config,
) -> anyhow::Result<BlockDelta> {
	exit_delta
		.checked_add(htlc_expiry_delta)
		.and_then(|v| v.checked_add(config.vtxo_exit_margin))
		.and_then(|v| v.checked_add(config.htlc_recv_claim_delta))
		.context("HTLC recv exit delta components sum overflows")
}

/// AwaitingPayment -> HtlcsReady. Asks the server to grant HTLC-recv
/// vtxos for the inbound payment, validates them, creates the receive
/// movement and stores the vtxos locked.
pub(crate) async fn prepare_lightning_receive_htlcs(
	wallet: &Wallet,
	recv: &LightningReceive,
) -> Result<Grant, AdvanceError> {
	let (mut srv, ark_info) = wallet.require_server().await?;
	let config = wallet.config();
	let current_height = wallet.inner.chain.tip().await?;
	let payment_hash = recv.payment_hash;

	let lightning_receive_anti_dos = match compute_lightning_receive_anti_dos(
		wallet, payment_hash, recv.anti_dos_token.as_deref(),
	).await {
		Ok(anti_dos) => Some(anti_dos),
		Err(e) => {
			info!("Could not compute anti-dos: {e:#}. Trying without");
			None
		},
	};

	let htlc_recv_expiry = current_height + recv.htlc_recv_cltv_delta as BlockHeight;
	let keypair = wallet.peek_keypair(recv.key_index).await?;
	let req = protos::PrepareLightningReceiveClaimRequest {
		payment_hash: payment_hash.to_vec(),
		user_pubkey: keypair.public_key().serialize().to_vec(),
		htlc_recv_expiry,
		lightning_receive_anti_dos,
	};
	let res = srv.client.prepare_lightning_receive_claim(req).await
		.map_err(AdvanceError::Server)?.into_inner();
	let vtxos = res.htlc_vtxos.into_iter()
		.map(|b| Vtxo::deserialize(&b))
		.collect::<Result<Vec<_>, _>>()
		.context("invalid htlc vtxos from server")?;

	// Sanity-check the vtxos.
	let mut htlc_amount = Amount::ZERO;
	for vtxo in &vtxos {
		trace!("Received HTLC VTXO {} from server: {}", vtxo.id(), vtxo.serialize_hex());
		wallet.validate_vtxo(vtxo).await
			.context("received invalid HTLC VTXO from server")?;
		htlc_amount += vtxo.amount();

		if let VtxoPolicy::ServerHtlcRecv(p) = vtxo.policy() {
			if p.payment_hash != payment_hash {
				return Err(anyhow!("invalid payment hash on HTLC VTXOs received from server: {}",
					p.payment_hash).into());
			}
			if p.user_pubkey != keypair.public_key() {
				return Err(anyhow!("invalid pubkey on HTLC VTXOs received from server: {}",
					p.user_pubkey).into());
			}
			// NB: p.htlc_expiry isn't compared against the freshly computed
			// htlc_recv_expiry: the server hands back the first attempt's
			// grant, so any block mined since would fail on every retry. The
			// claim deadline check below covers the grant's headroom.

			// Ensure that the server didn't inflate the deltas for the client's
			// unilateral exit clauses. Don't retry on any failure here: the
			// server hands back these very same vtxos on every later request
			// for this payment hash.
			let claim_by = htlc_recv_exit_blocks_needed(
				vtxo.exit_delta(), p.htlc_expiry_delta, config,
			).and_then(|blocks_needed| {
				current_height.checked_add(BlockHeight::from(blocks_needed))
					.context("HTLC VTXO claim deadline overflows")
			});
			let claim_by = match claim_by {
				Ok(claim_by) => claim_by,
				Err(e) => return Ok(Grant::Rejected(e)),
			};
			if claim_by > p.htlc_expiry {
				return Ok(Grant::Rejected(anyhow!(
					"HTLC VTXO timelocks leave no time to claim it unilaterally: we need \
					until height {} (exit delta {}, htlc expiry delta {}), but the server \
					can claim it from height {}",
					claim_by, vtxo.exit_delta(), p.htlc_expiry_delta, p.htlc_expiry,
				)));
			}
		} else {
			return Err(anyhow!("invalid HTLC VTXO policy: {:?}", vtxo.policy()).into());
		}
	}

	// We can't entirely trust the server-reported payment amount, so if there is a
	// discrepancy, fall back to checking the invoice amount.
	let invoice_amount = recv.invoice.get_payment_amount(None)
		.context("ln receive invoice should have amount")?;
	let server_received_amount = res.receive.map(|r| Amount::from_sat(r.amount_sat));
	let fee = {
		let fee = server_received_amount
			.and_then(|a| ark_info.fees.lightning_receive.calculate(a));
		match (server_received_amount, fee) {
			(Some(amount), Some(fee)) if htlc_amount + fee == amount => fee,
			_ => ark_info.fees.lightning_receive.calculate(invoice_amount)
				.expect("we previously validated this"),
		}
	};
	let received = htlc_amount + fee;
	if received < invoice_amount {
		return Err(anyhow!("Server didn't return enough VTXOs to cover invoice amount").into());
	}

	let movement_id = wallet.inner.movements.get_or_create_movement_with_action(
		Subsystem::LIGHTNING_RECEIVE,
		LightningReceiveMovement::Receive.to_string(),
		&recv.id(),
		MovementUpdate::new()
			.intended_balance(invoice_amount.to_signed().context("invoice amount out of range")?)
			.effective_balance(htlc_amount.to_signed().context("htlc amount out of range")?)
			.fee(fee)
			.metadata(LightningMovement::metadata(
				payment_hash, &vtxos, Some(recv.payment_preimage),
			))
			.received_on([MovementDestination::new(recv.invoice.clone().into(), received)]),
	).await.context("failed to create lightning receive movement")?;
	wallet.store_locked_vtxos(
		&vtxos,
		Some(VtxoLockHolder::Action { id: recv.id() }),
	).await?;

	// Sort for a deterministic checkpoint (the server may return them in any order).
	let mut vtxo_ids = vtxos.iter().map(|v| v.id()).collect::<Vec<_>>();
	vtxo_ids.sort();

	Ok(Grant::Accepted(Htlcs {
		vtxo_ids,
		movement_id,
	}))
}

/// Claiming -> done, or -> Delivering when the receive has a claim
/// destination that isn't our own. Reveals the preimage to the server in
/// exchange for a cosigned claim. Local receives finalise the movement
/// and write the permanent settled record here; external destinations
/// hold the outputs locked and hand off to [`deliver_lightning_receive`].
///
/// The server's `claim_lightning_receive` is idempotent on payment hash,
/// so this is safe to re-drive after a crash: a fresh cosign is returned
/// for the new nonces.
async fn claim_lightning_receive_htlcs(
	wallet: &Wallet,
	recv: &LightningReceive,
	htlcs: &Htlcs,
	preimage_revealed: &mut bool,
) -> Result<Option<Delivery>, AdvanceError> {
	let (mut srv, _) = wallet.require_server().await?;

	// Order inputs by vtxoid before generating nonces, then hydrate to
	// full so the arkoor builder has the genesis chain.
	let mut input_ids = htlcs.vtxo_ids.clone();
	input_ids.sort();
	let inputs = wallet.inner.db.get_full_vtxos(&input_ids).await
		.context("failed to hydrate htlc input vtxos")?;

	let mut keypairs = Vec::with_capacity(inputs.len());
	for v in &inputs {
		keypairs.push(wallet.get_vtxo_key(v).await?);
	}

	let receive_policy = if let Some(destination) = recv.claim_destination.as_ref() {
		destination.policy().clone()
	} else {
		let claim_key = wallet.peek_keypair(recv.key_index).await?.public_key();
		VtxoPolicy::new_pubkey(claim_key)
	};
	trace!("ln claim arkoor params: inputs: {:?}; policy: {:?}", input_ids, receive_policy);
	let builder = ArkoorPackageBuilder::new_claim_all_with_checkpoints(
		inputs, receive_policy,
	).context("creating claim arkoor builder failed")?
		.generate_user_nonces(&keypairs)
		.context("arkoor nonce generation for claim failed")?;

	info!("Claiming arkoor against payment preimage for {}", recv.payment_hash);
	*preimage_revealed = true;
	let package_cosign_request = protos::ArkoorPackageCosignRequest::from(builder.cosign_request());
	let resp = srv.client.claim_lightning_receive(protos::ClaimLightningReceiveRequest {
		payment_hash: recv.payment_hash.to_byte_array().to_vec(),
		payment_preimage: recv.payment_preimage.to_vec(),
		cosign_request: Some(package_cosign_request),
	}).await.map_err(AdvanceError::Server)?.into_inner();
	let cosign_resp = resp.try_into().context("invalid cosign response")?;

	let mut outputs = builder.user_cosign(&keypairs, cosign_resp)
		.context("claim arkoor cosign failed with user response")?
		.build_signed_vtxos();

	// Register the claim outputs so they are spendable for any later flow.
	wallet.register_vtxo_transactions_with_server(&outputs).await?;

	let mut effective_balance = Amount::ZERO;
	for vtxo in &outputs {
		// NB: bailing here results in vtxos not being registered despite the
		// preimage being revealed. The server's claim_lightning_receive is
		// idempotent, so bark can retry and obtain fresh cosign signatures.
		trace!("Validating Lightning receive claim VTXO {}: {}", vtxo.id(), vtxo.serialize_hex());
		wallet.validate_vtxo(vtxo).await
			.context("invalid arkoor from lightning receive")?;
		effective_balance += vtxo.amount();
	}

	info!("Got arkoors from lightning: {}",
		outputs.iter().map(|v| v.id().to_string()).collect::<Vec<_>>().join(", "));

	// A destination owned by this wallet needs no mailbox delivery: the
	// outputs are already keyed to one of our pubkeys.
	let external_destination = match recv.claim_destination.as_ref() {
		Some(destination) => wallet.pubkey_keypair(&destination.policy().user_pubkey())
			.await?.is_none(),
		None => false,
	};

	if external_destination {
		wallet.mark_vtxos_as_spent(&htlcs.vtxo_ids).await?;
		outputs.sort_unstable();
		return Ok(Some(Delivery {
			vtxos: outputs,
			movement_id: htlcs.movement_id,
		}));
	}

	wallet.store_spendable_vtxos(&outputs).await?;
	wallet.mark_vtxos_as_spent(&htlcs.vtxo_ids).await?;

	wallet.inner.movements.finish_movement_with_update(
		htlcs.movement_id,
		MovementStatus::Successful,
		MovementUpdate::new()
			.effective_balance(effective_balance.to_signed().context("effective balance out of range")?)
			.produced_vtxos(&outputs),
	).await.context("failed to finish lightning receive movement")?;

	let amount = recv.invoice.get_payment_amount(None).unwrap_or(effective_balance);
	wallet.inner.db.record_settled_lightning_receive(
		recv.payment_hash, recv.payment_preimage, &recv.invoice, amount,
	).await?;

	Ok(None)
}

/// Delivering -> done. Forwards the locked claim outputs to the claim
/// destination's mailbox, then finalises the movement and writes the
/// permanent settled record. Re-driving after a crash at most posts the
/// same vtxos to the mailbox again.
async fn deliver_lightning_receive(
	wallet: &Wallet,
	recv: &LightningReceive,
	delivery: &Delivery,
) -> Result<(), AdvanceError> {
	let destination = recv.claim_destination.as_ref()
		.context("delivering receive has no claim destination")?;
	deliver_vtxos_to_address(wallet, destination, &delivery.vtxos).await
		.context("failed to deliver lightning receive claim output to destination mailbox")?;

	let delivered = delivery.vtxos.iter().map(|v| v.amount()).sum();
	wallet.inner.movements.finish_movement_with_update(
		delivery.movement_id,
		MovementStatus::Successful,
		MovementUpdate::new()
			.effective_balance(SignedAmount::ZERO)
			.sent_to([MovementDestination::ark(destination.clone(), delivered)]),
	).await.context("failed to finish lightning receive movement")?;

	let amount = recv.invoice.get_payment_amount(None).unwrap_or(delivered);
	wallet.inner.db.record_settled_lightning_receive(
		recv.payment_hash, recv.payment_preimage, &recv.invoice, amount,
	).await?;

	Ok(())
}

async fn deliver_vtxos_to_address(
	wallet: &Wallet,
	destination: &ark::Address,
	vtxos: &[Vtxo<ark::vtxo::Full>],
) -> anyhow::Result<()> {
	let (mut srv, _) = wallet.require_server().await?;

	match post_arkoor_to_mailboxes(&mut srv, destination.delivery(), vtxos).await {
		DeliveryOutcome::AnySucceeded => Ok(()),
		DeliveryOutcome::AllFailed { summary } => bail!(summary),
	}
}

/// HtlcsReady abandon: the preimage was never revealed, so we simply drop
/// the HTLC vtxos and finish the movement as canceled. The inbound HTLC
/// times out server-side and the sender is refunded.
pub(crate) async fn abandon_lightning_receive(
	wallet: &Wallet,
	recv: &LightningReceive,
	htlcs: &Htlcs,
) -> anyhow::Result<()> {
	warn!("Abandoning lightning receive {} before preimage disclosure", recv.payment_hash);
	wallet.mark_vtxos_as_spent(&htlcs.vtxo_ids).await?;
	wallet.inner.movements.finish_movement_with_update(
		htlcs.movement_id,
		MovementStatus::Canceled,
		MovementUpdate::new().effective_balance(SignedAmount::ZERO),
	).await?;
	Ok(())
}

/// Returns whether the HTLC-recv vtxos are near (or past) expiry. The
/// expiry height lives on the vtxo policy, so we read it from the stored
/// vtxos rather than the checkpoint.
pub(crate) async fn is_htlc_near_expiry(
	wallet: &Wallet,
	htlcs: &Htlcs,
) -> anyhow::Result<bool> {
	let id = *htlcs.vtxo_ids.first().context("no HTLC vtxos on receive")?;
	let vtxo = wallet.get_vtxo_by_id(id).await?;
	let expiry = match vtxo.vtxo.policy() {
		VtxoPolicy::ServerHtlcRecv(p) => p.htlc_expiry,
		other => bail!("HTLC receive vtxo has unexpected policy: {:?}", other),
	};
	let tip = wallet.inner.chain.tip().await?;
	Ok(tip > expiry.saturating_sub(
		wallet.config().vtxo_refresh_expiry_threshold as BlockHeight,
	))
}

/// Whether an unpaid invoice has passed its bolt11 expiry plus a grace
/// margin and can be reaped.
pub(crate) fn invoice_expired(invoice: &Bolt11Invoice) -> bool {
	let now_secs = chrono::Utc::now().timestamp();
	if now_secs < 0 {
		return false;
	}
	let cutoff = Duration::from_secs(now_secs as u64).saturating_sub(INVOICE_EXPIRY_GRACE);
	invoice.would_expire(cutoff)
}

#[cfg(test)]
mod tests {
	use super::*;

	const TEST_INVOICE_STR: &str = "lntbs100u1p5j0x82sp5d0rwfh7tgrrlwsegy9rx3tzpt36cqwjqza5x4wvcjxjzscfaf6jspp5d8q7354dg3p8h0kywhqq5dq984r8f5en98hf9ln85ug0w8fx6hhsdqqcqzpc9qyysgqyk54v7tpzprxll7e0jyvtxcpgwttzk84wqsfjsqvcdtq47zt2wssxsmtjhz8dka62mdnf9jafhu3l4cpyfnsx449v4wstrwzzql2w5qqs8uh7p";

	fn test_bolt11() -> Bolt11Invoice {
		Bolt11Invoice::from_str(TEST_INVOICE_STR).expect("valid test invoice")
	}

	#[test]
	fn validate_bolt11_payment_hash_accepts_matching_hash() {
		let invoice = test_bolt11();
		let payment_hash = PaymentHash::from(&invoice);

		validate_bolt11_payment_hash(&invoice, payment_hash).unwrap();
	}

	#[test]
	fn validate_bolt11_payment_hash_rejects_mismatched_hash() {
		let invoice = test_bolt11();
		let mismatched_payment_hash = PaymentHash::from_slice(&[0xabu8; 32]).unwrap();

		let err = validate_bolt11_payment_hash(&invoice, mismatched_payment_hash)
			.expect_err("mismatched payment hash should fail");

		assert!(
			err.to_string().contains("returned invoice with payment hash"),
			"{err:?}",
		);
	}

	/// The blocks we ask the server to put between the tip and `htlc_expiry`
	/// when creating the invoice, see [start_lightning_receive].
	fn requested_cltv_delta(
		exit_delta: BlockDelta,
		htlc_expiry_delta: BlockDelta,
		config: &Config,
	) -> BlockDelta {
		exit_delta + htlc_expiry_delta + config.vtxo_exit_margin
			+ config.htlc_recv_claim_delta + LIGHTNING_PREPARE_CLAIM_DELTA
	}

	#[test]
	fn htlc_recv_exit_blocks_needed_fits_the_requested_cltv_delta() {
		let config = Config::network_default(bitcoin::Network::Bitcoin);

		// A server granting the deltas it advertised leaves us
		// LIGHTNING_PREPARE_CLAIM_DELTA to spare.
		for (exit_delta, htlc_expiry_delta) in [(144, 6), (144, 40), (100, 0)] {
			let needed = htlc_recv_exit_blocks_needed(
				exit_delta, htlc_expiry_delta, &config,
			).unwrap();
			let requested = requested_cltv_delta(exit_delta, htlc_expiry_delta, &config);

			assert_eq!(requested - needed, LIGHTNING_PREPARE_CLAIM_DELTA);
		}
	}

	#[test]
	fn htlc_recv_exit_blocks_needed_exceeds_cltv_delta_when_server_inflates_a_delta() {
		let config = Config::network_default(bitcoin::Network::Bitcoin);
		let requested = requested_cltv_delta(144, 6, &config);

		// Inflating either delta past the leniency delta eats the whole window.
		let inflated_expiry_delta = htlc_recv_exit_blocks_needed(144, 9, &config).unwrap();
		assert!(inflated_expiry_delta > requested);

		let inflated_exit_delta = htlc_recv_exit_blocks_needed(147, 6, &config).unwrap();
		assert!(inflated_exit_delta > requested);
	}

	#[test]
	fn htlc_recv_exit_blocks_needed_rejects_overflowing_deltas() {
		let config = Config::network_default(bitcoin::Network::Bitcoin);

		htlc_recv_exit_blocks_needed(BlockDelta::MAX, BlockDelta::MAX, &config)
			.expect_err("summing the deltas should overflow");
	}
}

use std::fmt;
use std::time::Duration;

use anyhow::Context;
use bitcoin::Amount;
use lightning::util::ser::Writeable;
use lnurllib::lightning_address::LightningAddress;
use lnurllib::lnurl::LnUrl;
use log::{info, warn};
use server_rpc::protos;

use ark::lightning::{
	offer_request_amount, Bolt11Invoice, Bolt11InvoiceExt, Bolt12Invoice, Bolt12InvoiceExt, Invoice,
	Offer, PaymentHash, Preimage,
};

use crate::Wallet;
use crate::WalletVtxo;
use crate::actions::{AdvanceResultExt, DriveMode, GuardedCheckpoint, WalletAction};
use crate::actions::lightning::pay::{
	Htlcs, LightningSend, LightningSendState, settle_lightning_send_payment,
	start_lightning_send, ln_pay_action_id,
};
use crate::lightning::{lnaddr_invoice, lnurlp_invoice};
use crate::movement::PaymentMethod;

/// Options for a lightning send, see [`Wallet::pay_lightning_invoice_with`].
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct LightningSendOptions {
	/// Keep the call open until the payment settles or fails, instead of
	/// returning once it has been kicked off.
	pub wait: bool,
	/// How long the server keeps trying to pay, capped to the server's
	/// maximum. `None` leaves it to the server.
	pub retry_for: Option<Duration>,
}

impl LightningSendOptions {
	pub fn wait(mut self, wait: bool) -> Self {
		self.wait = wait;
		self
	}

	pub fn retry_for(mut self, retry_for: Option<Duration>) -> Self {
		self.retry_for = retry_for;
		self
	}
}

impl Wallet {
	/// Returns every in-progress lightning send checkpoint.
	pub async fn pending_lightning_sends(&self) -> anyhow::Result<Vec<LightningSend>> {
		let mut result = Vec::new();
		for cp in self.inner.db.get_all_wallet_action_checkpoints().await? {
			if let Some(ls) = cp.into_lightning_send() {
				result.push(ls);
			}
		}
		Ok(result)
	}

	/// Returns every failed lightning payment currently stuck because revocation has failed. When
	/// HTLC VTXOs approach their expiry, the user should consider starting an exit for each VTXO.
	/// This will only happen automatically if the [Wallet::allow_lightning_send_to_exit] is called.
	pub async fn stuck_failed_lightning_sends(&self) -> anyhow::Result<Vec<LightningSend>> {
		let mut result = Vec::new();
		for send in self.pending_lightning_sends().await? {
			if send.has_failed_revocation() {
				result.push(send);
			}
		}
		Ok(result)
	}

	/// Opts the lightning send identified by `hash` into auto-exiting its
	/// HTLCs once they approach expiry, after revocation has failed.
	///
	/// The flag is persisted on the action checkpoint; the next drive
	/// (e.g. via [`Self::sync_pending_lightning_send_vtxos`] or
	/// [`Self::check_lightning_payment`]) picks it up and exits when
	/// HTLCs are near expiry. See [`LightningSend::has_failed_revocation`].
	pub async fn allow_lightning_send_to_exit(&self, hash: PaymentHash) -> anyhow::Result<()> {
		let mut checkpoint = self.try_lock_action::<LightningSend>(&ln_pay_action_id(hash)).await?
			.context("Payment operation already in progress for this invoice")?;
		if checkpoint.get().is_none() {
			bail!("no in-progress lightning send for payment hash {hash}");
		}
		checkpoint.update(self, |send| send.allow_exit_of_htlcs = true).await
	}

	/// Returns the VTXOs currently held by any in-progress lightning send.
	pub async fn pending_lightning_send_vtxos(&self) -> anyhow::Result<Vec<WalletVtxo>> {
		let mut vtxos = Vec::new();
		for send in self.pending_lightning_sends().await? {
			for id in send.pending_balance_vtxo_ids() {
				vtxos.push(self.get_vtxo_by_id(id).await?);
			}
		}
		Ok(vtxos)
	}

	/// Drives every pending lightning send forward by one step (or to
	/// completion if it's ready). Each action runs to its next park
	/// independently; errors on one don't stop the others.
	pub async fn sync_pending_lightning_send_vtxos(&self) -> anyhow::Result<()> {
		let pending = self.pending_lightning_sends().await?;
		if pending.is_empty() {
			return Ok(());
		}
		info!("Syncing {} pending lightning sends", pending.len());
		for send in pending {
			let id = send.id();
			if let Err(e) = self.drive_action::<LightningSend>(&id, DriveMode::UntilParkOrDone).await {
				warn!("Failed to sync lightning send {}: {:#}", id, e);
			}
		}
		Ok(())
	}

	/// Fetches the current checkpoint for the given payment hash, if any.
	pub async fn lightning_send_checkpoint(&self, hash: PaymentHash)
		-> anyhow::Result<Option<LightningSend>>
	{
		Ok(self.inner.db.get_wallet_action_checkpoint(&ln_pay_action_id(hash)).await?
			.and_then(|cp| cp.into_lightning_send()))
	}

	/// Triage a payment hash: paid, in-progress, or unknown.
	pub async fn lightning_send_state(&self, hash: PaymentHash)
		-> anyhow::Result<LightningSendState>
	{
		if let Some(paid) = self.inner.db.get_paid_invoice(hash).await? {
			return Ok(LightningSendState::Paid(paid));
		}
		if let Some(cp) = self.lightning_send_checkpoint(hash).await? {
			return Ok(LightningSendState::InProgress(cp));
		}
		Ok(LightningSendState::Unknown)
	}

	/// Cheap "has this invoice ever been paid?" check.
	pub async fn is_invoice_paid(&self, hash: PaymentHash) -> anyhow::Result<bool> {
		Ok(self.inner.db.get_paid_invoice(hash).await?.is_some())
	}

	/// Drive a lightning send forward (e.g., to settle a pending one
	/// or revoke a failed one). `wait=true` keeps driving past parks
	/// until the action terminates. Returns the current state.
	pub async fn check_lightning_payment(&self, hash: PaymentHash, wait: bool)
		-> anyhow::Result<LightningSendState>
	{
		// Drive a checkpoint even if the invoice is recorded as paid: that is
		// a settlement that stopped half-way, and the drive finishes it.
		let mode = if wait { DriveMode::UntilDone } else { DriveMode::UntilParkOrDone };
		self.drive_action::<LightningSend>(&ln_pay_action_id(hash), mode).await?;
		self.lightning_send_state(hash).await
	}

	/// Settle a payment using a preimage we already have (e.g. from a
	/// mailbox notification), skipping the server poll.
	pub(crate) async fn settle_lightning_send_with_preimage(
		&self,
		checkpoint: GuardedCheckpoint<LightningSend>,
		htlcs: Htlcs,
		preimage: Preimage,
	) -> anyhow::Result<()> {
		let send = checkpoint.get().context("lightning send has no checkpoint")?;
		let payment_hash = send.invoice.payment_hash();
		if preimage.compute_payment_hash() != payment_hash {
			bail!("preimage mismatch for payment hash {}", payment_hash);
		}
		settle_lightning_send_payment(self, send, &htlcs, preimage).await.into_anyhow()?;
		// Clean up like the executor does when an action is done. The
		// paid_invoice record is the source of truth from here on.
		checkpoint.finish(self).await
	}

	/// Pays a Lightning [Invoice] using Ark VTXOs.
	///
	/// `wait=true` keeps the call open until the payment settles or
	/// fails; `wait=false` returns once the payment has been kicked off
	/// and lets the background sync drive it to completion. Returns the
	/// parsed [`Invoice`] in either case; callers wanting the preimage
	/// can look up the settled record via [`Self::lightning_send_state`].
	pub async fn pay_lightning_invoice<T>(
		&self,
		invoice: T,
		user_amount: Option<Amount>,
		wait: bool,
	) -> anyhow::Result<Invoice>
	where
		T: TryInto<Invoice>,
		T::Error: std::error::Error + fmt::Display + Send + Sync + 'static,
	{
		let opts = LightningSendOptions::default().wait(wait);
		self.pay_lightning_invoice_with(invoice, user_amount, opts).await
	}

	/// Same as [`Self::pay_lightning_invoice`], with [`LightningSendOptions`].
	pub async fn pay_lightning_invoice_with<T>(
		&self,
		invoice: T,
		user_amount: Option<Amount>,
		opts: LightningSendOptions,
	) -> anyhow::Result<Invoice>
	where
		T: TryInto<Invoice>,
		T::Error: std::error::Error + fmt::Display + Send + Sync + 'static,
	{
		let invoice = invoice.try_into().context("failed to parse invoice")?;
		let amount = invoice.get_payment_amount(user_amount)?;
		info!("Sending bolt11 payment of {} to invoice {}", amount, invoice);
		self.make_lightning_payment_with(&invoice, invoice.clone().into(), user_amount, opts).await?;
		Ok(invoice)
	}

	/// Same as [`Self::pay_lightning_invoice`] but resolves the invoice
	/// from a [`LightningAddress`] first.
	pub async fn pay_lightning_address(
		&self,
		addr: &LightningAddress,
		amount: Amount,
		comment: Option<impl AsRef<str>>,
		wait: bool,
	) -> anyhow::Result<Invoice> {
		let opts = LightningSendOptions::default().wait(wait);
		self.pay_lightning_address_with(addr, amount, comment, opts).await
	}

	/// Same as [`Self::pay_lightning_address`], with [`LightningSendOptions`].
	pub async fn pay_lightning_address_with(
		&self,
		addr: &LightningAddress,
		amount: Amount,
		comment: Option<impl AsRef<str>>,
		opts: LightningSendOptions,
	) -> anyhow::Result<Invoice> {
		let comment = comment.as_ref();
		let invoice: Invoice = lnaddr_invoice(addr, amount, comment).await
			.context("lightning address error")?.into();
		info!("Sending {} to lightning address {}", amount, addr);
		self.make_lightning_payment_with(&invoice, addr.clone().into(), None, opts).await?;
		info!("Paid invoice {}", invoice);
		Ok(invoice)
	}

	/// Same as [`Self::pay_lightning_address`] but resolves the invoice from a
	/// raw LNURL-pay link (`lnurl1…`) first.
	///
	/// Errors if the link decodes to a non-pay LNURL (auth, withdraw, channel).
	pub async fn pay_lnurl(
		&self,
		lnurl: &LnUrl,
		amount: Amount,
		comment: Option<impl AsRef<str>>,
		wait: bool,
	) -> anyhow::Result<Invoice> {
		let opts = LightningSendOptions::default().wait(wait);
		self.pay_lnurl_with(lnurl, amount, comment, opts).await
	}

	/// Same as [`Self::pay_lnurl`], with [`LightningSendOptions`].
	pub async fn pay_lnurl_with(
		&self,
		lnurl: &LnUrl,
		amount: Amount,
		comment: Option<impl AsRef<str>>,
		opts: LightningSendOptions,
	) -> anyhow::Result<Invoice> {
		let invoice: Invoice = lnurlp_invoice(&lnurl.url, amount, comment).await
			.context("lnurl-pay error")?.into();
		info!("Sending {} to lnurl {}", amount, lnurl);
		self.make_lightning_payment_with(&invoice, lnurl.clone().into(), None, opts).await?;
		info!("Paid invoice {}", invoice);
		Ok(invoice)
	}

	/// Attempts to pay the given BOLT12 [`Offer`] using offchain funds.
	pub async fn pay_lightning_offer(
		&self,
		offer: Offer,
		user_amount: Option<Amount>,
		wait: bool,
	) -> anyhow::Result<Invoice> {
		let opts = LightningSendOptions::default().wait(wait);
		self.pay_lightning_offer_with(offer, user_amount, opts).await
	}

	/// Same as [`Self::pay_lightning_offer`], with [`LightningSendOptions`].
	pub async fn pay_lightning_offer_with(
		&self,
		offer: Offer,
		user_amount: Option<Amount>,
		opts: LightningSendOptions,
	) -> anyhow::Result<Invoice> {
		let (mut srv, _) = self.require_server().await?;

		let offer_bytes = {
			let mut bytes = Vec::new();
			offer.write(&mut bytes).context("failed to serialize BOLT12 offer")?;
			bytes
		};

		let req = protos::FetchBolt12InvoiceRequest {
			offer: offer_bytes,
			amount_sat: user_amount.map(|a| a.to_sat()),
		};

		// Since the server is the one fetching the invoice, it is the one building the
		// invoice request. We need to ensure that the amount we authorize here,
		// before the fetch, and the amount in the invoice we get back match during
		// validation below.
		let amount = offer_request_amount(&offer, user_amount)
			.context("cannot determine the amount to pay for this offer")?;
		if user_amount.is_some() {
			info!("Sending bolt12 payment of {} (user amount) to offer {}", amount, offer);
		} else {
			info!("Sending bolt12 payment of {} (offer amount) to offer {}", amount, offer);
		}

		let resp = srv.client.fetch_bolt12_invoice(req).await?.into_inner();
		let invoice = Bolt12Invoice::try_from(resp.invoice)
			.map_err(|e| anyhow!("invalid invoice: {:?}", e))?;

		invoice.validate_issuance(&offer, amount)
			.context("invalid BOLT12 invoice received from offer")?;

		let invoice: Invoice = invoice.into();
		self.make_lightning_payment_with(&invoice, offer.into(), Some(amount), opts).await?;
		info!("Paid invoice: {}", invoice);
		Ok(invoice)
	}

	/// Low-level lightning payment primitive. Exposed for
	/// [`PaymentMethod::Custom`] use cases (e.g. LNURL-pay).
	pub async fn make_lightning_payment(
		&self,
		invoice: &Invoice,
		original_payment_method: PaymentMethod,
		user_amount: Option<Amount>,
		wait: bool,
	) -> anyhow::Result<()> {
		let opts = LightningSendOptions::default().wait(wait);
		self.make_lightning_payment_with(invoice, original_payment_method, user_amount, opts).await
	}

	/// The Ark address in the route hints of `invoice` that we can pay
	/// it on with an arkoor, see [crate::Config::lightning_ark_address_hints].
	async fn ark_address_to_pay(&self, invoice: &Bolt11Invoice) -> anyhow::Result<Option<ark::Address>> {
		if !self.config().lightning_ark_address_hints {
			return Ok(None);
		}
		let Some(address) = invoice.ark_address() else { return Ok(None) };

		let (_, ark_info) = self.require_server().await?;
		Ok(address.is_for_server(ark_info.server_pubkey).then_some(address))
	}

	/// Same as [`Self::make_lightning_payment`], with [`LightningSendOptions`].
	pub async fn make_lightning_payment_with(
		&self,
		invoice: &Invoice,
		original_payment_method: PaymentMethod,
		user_amount: Option<Amount>,
		opts: LightningSendOptions,
	) -> anyhow::Result<()> {
		if !original_payment_method.is_lightning() && !original_payment_method.is_custom() {
			bail!("Invalid original payment method for lightning payment");
		}

		let payment_hash = invoice.payment_hash();
		let mode = if opts.wait { DriveMode::UntilDone } else { DriveMode::UntilParkOrDone };

		if let Invoice::Bolt11(bolt11) = invoice {
			if let Some(address) = self.ark_address_to_pay(bolt11).await? {
				let amount = invoice.get_payment_amount(user_amount)?;
				info!("Paying invoice {} with an arkoor of {} to {}", payment_hash, amount, address);
				// Boxed so every lightning payment's future does not carry the
				// arkoor send's state machine inline.
				Box::pin(self.send_arkoor(&address, amount, Some(bolt11.clone()))).await?;
				return Ok(());
			}
		}

		// An invoice paid earlier gets this error even while a drive holds
		// the lock of its send.
		if self.is_invoice_paid(payment_hash).await? {
			bail!("Invoice has already been paid");
		}

		let mut checkpoint = self.try_lock_action::<LightningSend>(&ln_pay_action_id(payment_hash))
			.await?
			.context("Payment operation already in progress for this invoice")?;

		// Check again under the lock: every settlement holds it, so the
		// invoice cannot be paid between this check and the start of a new
		// send.
		if self.is_invoice_paid(payment_hash).await? {
			bail!("Invoice has already been paid");
		}

		// Resume an existing checkpoint, or build a fresh send. A resumed
		// send keeps the retry time it was started with.
		if checkpoint.get().is_none() {
			let start = start_lightning_send(
				self, invoice.clone(), user_amount, original_payment_method, opts.retry_for,
			).await?;
			checkpoint.create(self, start).await?;
		}

		self.drive_checkpoint(checkpoint, mode).await
	}
}

#[cfg(all(test, feature = "sqlite"))]
mod test {
	use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};
	use futures::{FutureExt, StreamExt};
	use lightning_invoice::{Currency, InvoiceBuilder, PaymentSecret};
	use server_rpc::protos::mailbox_server::{LightningSendFinishedMessage, MailboxMessage};
	use server_rpc::protos::mailbox_server::mailbox_message::Message as MailboxMessageKind;

	use ark::VtxoId;
	use ark::test_util::VTXO_VECTORS;
	use bitcoin_ext::BlockHeight;

	use crate::{NotificationStream, WalletNotification};
	use crate::actions::lightning::pay::Progress;
	use crate::movement::{MovementId, MovementStatus};
	use crate::movement::update::MovementUpdate;
	use crate::subsystem::{LightningSendMovement, Subsystem};
	use crate::vtxo::{VtxoLockHolder, VtxoState};

	use super::*;

	/// A send the server is paying: its HTLC is locked by the action and its
	/// movement is pending.
	struct PendingSend {
		send: LightningSend,
		htlcs: Htlcs,
		preimage: Preimage,
	}

	impl PendingSend {
		fn hash(&self) -> PaymentHash {
			self.send.invoice.payment_hash()
		}
	}

	fn invoice_for(preimage: Preimage) -> Invoice {
		let secp = Secp256k1::new();
		let key = SecretKey::from_slice(&[2; 32]).unwrap();
		let invoice = InvoiceBuilder::new(Currency::Regtest)
			.description("test".into())
			.payment_hash(preimage.compute_payment_hash().to_sha256_hash())
			.payment_secret(PaymentSecret([42; 32]))
			.duration_since_epoch(Duration::from_secs(1_700_000_000))
			.min_final_cltv_expiry_delta(144)
			.amount_milli_satoshis(1_000_000)
			.build_signed(|hash: &Message| secp.sign_ecdsa_recoverable(hash, &key))
			.unwrap();
		Invoice::Bolt11(invoice)
	}

	async fn pending_send(wallet: &Wallet) -> PendingSend {
		let preimage = Preimage::random();
		let invoice = invoice_for(preimage);
		let action_id = ln_pay_action_id(invoice.payment_hash());

		let htlc = &VTXO_VECTORS.arkoor_htlc_out_vtxo;
		let locked = VtxoState::Locked { holder: Some(VtxoLockHolder::Action { id: action_id.clone() }) };
		wallet.inner.db.store_vtxos(&[(htlc, &locked)]).await.unwrap();
		let movement_id = wallet.inner.movements.get_or_create_movement_with_action(
			Subsystem::LIGHTNING_SEND,
			LightningSendMovement::Send.to_string(),
			&action_id,
			MovementUpdate::new(),
		).await.unwrap();

		let htlcs = Htlcs {
			vtxo_ids: vec![htlc.id()],
			mailbox_id: wallet.mailbox_identifier(),
			movement_id,
		};
		let key = VTXO_VECTORS.server_key.public_key();
		let send = LightningSend {
			invoice,
			original_payment_method: PaymentMethod::Custom("test".into()),
			input_vtxo_ids: vec![],
			payment_amount: Amount::from_sat(1_000),
			fee: Amount::ZERO,
			change_pieces: None,
			htlc_key: key,
			htlc_expiry: BlockHeight::new(1_000),
			movement_id: None,
			revocation_key: key,
			retry_for: None,
			progress: Progress::PaymentInitiated(htlcs.clone()),
			allow_exit_of_htlcs: false,
		};
		wallet.inner.db.upsert_wallet_action_checkpoint(&send.id(), &send.clone().into()).await.unwrap();

		PendingSend { send, htlcs, preimage }
	}

	/// Hand the mailbox the notification that the server paid the invoice.
	async fn notify_paid(wallet: &Wallet, send: &PendingSend) {
		let message = MailboxMessage {
			checkpoint: 1,
			message: Some(MailboxMessageKind::LightningSendFinished(LightningSendFinishedMessage {
				payment_hash: send.hash().to_vec(),
				preimage: Some(send.preimage.to_vec()),
				failure: None,
			})),
		};
		assert!(wallet.process_mailbox_message(message).await.is_continue());
	}

	async fn checkpoint(wallet: &Wallet, send: &PendingSend) -> Option<LightningSend> {
		wallet.lightning_send_checkpoint(send.hash()).await.unwrap()
	}

	async fn vtxo_state(wallet: &Wallet, id: VtxoId) -> VtxoState {
		wallet.inner.db.get_wallet_vtxo(id).await.unwrap().unwrap().state
	}

	/// Finish the send, like a driver that revoked its HTLCs.
	async fn finish(wallet: &Wallet, send: &PendingSend) {
		let checkpoint = wallet.try_lock_action::<LightningSend>(&send.send.id()).await.unwrap().unwrap();
		checkpoint.finish(wallet).await.unwrap();
	}

	/// The sync loop reads every pending send before it takes the lock of
	/// each. A send that another driver finished in between must stay
	/// finished. Here a drive of the old copy could not reach the server, so
	/// it would retry the step and write the copy back.
	#[tokio::test]
	async fn finished_send_is_not_brought_back_by_an_old_copy() {
		let (wallet, _conn) = Wallet::offline_for_test().await;
		let send = pending_send(&wallet).await;

		let old_copy = checkpoint(&wallet, &send).await.unwrap();
		// Another driver revokes the HTLCs and finishes the action.
		finish(&wallet, &send).await;

		let drive = wallet.drive_action::<LightningSend>(&old_copy.id(), DriveMode::UntilParkOrDone).await;

		assert_eq!(checkpoint(&wallet, &send).await, None);
		drive.unwrap();
		assert!(wallet.pending_lightning_sends().await.unwrap().is_empty());
	}

	/// Same, with the mailbox settling the send between the read and the
	/// drive of the old copy.
	#[tokio::test]
	async fn send_settled_by_the_mailbox_is_not_brought_back_by_an_old_copy() {
		let (wallet, _conn) = Wallet::offline_for_test().await;
		let send = pending_send(&wallet).await;

		let old_copy = checkpoint(&wallet, &send).await.unwrap();
		notify_paid(&wallet, &send).await;
		assert_eq!(checkpoint(&wallet, &send).await, None);

		let drive = wallet.drive_action::<LightningSend>(&old_copy.id(), DriveMode::UntilParkOrDone).await;

		assert_eq!(checkpoint(&wallet, &send).await, None);
		drive.unwrap();
		assert!(wallet.pending_lightning_sends().await.unwrap().is_empty());
		let state = wallet.lightning_send_state(send.hash()).await.unwrap();
		assert!(matches!(state, LightningSendState::Paid(_)), "{:?}", state);
	}

	/// The notification that the server paid the invoice can arrive while a
	/// drive holds the lock of the send: its status poll still saw the
	/// payment pending, and it is about to park the send. The mailbox gets
	/// the notification once, so that single notification must settle the
	/// send after the drive parks.
	#[tokio::test]
	async fn notification_during_a_drive_settles_the_send_after_the_drive_parks() {
		let (wallet, _conn) = Wallet::offline_for_test().await;
		let send = pending_send(&wallet).await;

		let drive_guard = wallet.inner.lock_manager.try_lock(&send.send.id()).await.unwrap();
		let drive_parks = async {
			tokio::time::sleep(Duration::from_millis(100)).await;
			wallet.inner.db.upsert_wallet_action_checkpoint(&send.send.id(), &send.send.clone().into())
				.await.unwrap();
			drop(drive_guard);
		};
		futures::join!(notify_paid(&wallet, &send), drive_parks);

		assert!(wallet.is_invoice_paid(send.hash()).await.unwrap());
		assert_eq!(checkpoint(&wallet, &send).await, None);
		assert_eq!(vtxo_state(&wallet, send.htlcs.vtxo_ids[0]).await, VtxoState::Spent);
		let movement = wallet.inner.db.get_movement_by_id(send.htlcs.movement_id).await.unwrap();
		assert_eq!(movement.status, MovementStatus::Successful);
	}

	/// The writes of a settlement before its checkpoint is removed, in the
	/// order that [settle_lightning_send_payment] and the executor make them.
	const SETTLEMENT_WRITES: usize = 4;

	/// Make the first `writes` writes of a settlement, then stop, as a crash
	/// would.
	async fn settle_partially(wallet: &Wallet, send: &PendingSend, writes: usize) {
		if writes >= 1 {
			wallet.inner.db.record_paid_invoice(send.hash(), send.preimage).await.unwrap();
		}
		if writes >= 2 {
			wallet.mark_vtxos_as_spent(&send.htlcs.vtxo_ids).await.unwrap();
		}
		if writes >= 3 {
			wallet.inner.movements.finish_movement_with_update(
				send.htlcs.movement_id,
				MovementStatus::Successful,
				MovementUpdate::new().metadata([(
					"payment_preimage".into(),
					serde_json::to_value(send.preimage).unwrap(),
				)]),
			).await.unwrap();
		}
		if writes >= 4 {
			wallet.release_action_locks(&send.send.id()).await.unwrap();
		}
	}

	/// How often the notifications received so far finished the movement as
	/// successful.
	fn successful_finishes(notifications: &mut NotificationStream, id: MovementId) -> usize {
		let mut finishes = 0;
		while let Some(Some(notification)) = notifications.next().now_or_never() {
			if let WalletNotification::MovementUpdated { movement } = notification
				&& movement.id == id && movement.status == MovementStatus::Successful
			{
				finishes += 1;
			}
		}
		finishes
	}

	#[derive(Debug, Clone, Copy)]
	enum Driver {
		CheckPayment,
		Sync,
		Mailbox,
	}

	async fn drive(wallet: &Wallet, send: &PendingSend, driver: Driver) {
		match driver {
			Driver::CheckPayment => {
				let state = wallet.check_lightning_payment(send.hash(), false).await.unwrap();
				assert!(matches!(state, LightningSendState::Paid(_)), "{:?}", state);
			},
			Driver::Sync => wallet.sync_pending_lightning_send_vtxos().await.unwrap(),
			Driver::Mailbox => notify_paid(wallet, send).await,
		}
	}

	/// A crash can stop a settlement after any of its writes. Every driver
	/// must then finish it, without the server, and exactly once.
	#[tokio::test]
	async fn every_driver_finishes_an_interrupted_settlement_once() {
		for driver in [Driver::CheckPayment, Driver::Sync, Driver::Mailbox] {
			for writes in 1..=SETTLEMENT_WRITES {
				let case = format!("{:?} after {} write(s)", driver, writes);
				let (wallet, _conn) = Wallet::offline_for_test().await;
				let mut notifications = wallet.subscribe_notifications();
				let send = pending_send(&wallet).await;

				settle_partially(&wallet, &send, writes).await;
				let paid = wallet.inner.db.get_paid_invoice(send.hash()).await.unwrap().unwrap();

				drive(&wallet, &send, driver).await;
				// A finished send gives the next drive nothing to do.
				drive(&wallet, &send, driver).await;

				assert_eq!(checkpoint(&wallet, &send).await, None, "{}", case);
				assert!(wallet.pending_lightning_sends().await.unwrap().is_empty(), "{}", case);

				let movement = wallet.inner.db.get_movement_by_id(send.htlcs.movement_id).await.unwrap();
				assert_eq!(movement.status, MovementStatus::Successful, "{}", case);
				assert_eq!(successful_finishes(&mut notifications, movement.id), 1, "{}", case);

				let htlc = wallet.inner.db.get_wallet_vtxo(send.htlcs.vtxo_ids[0]).await.unwrap().unwrap();
				assert_eq!(htlc.state, VtxoState::Spent, "{}", case);

				let paid_after = wallet.inner.db.get_paid_invoice(send.hash()).await.unwrap().unwrap();
				assert_eq!(paid_after, paid, "{}", case);
			}
		}
	}

	/// A send that has no HTLCs yet, for an invoice the wallet already paid,
	/// is a second attempt to pay it. It must not reach the server, and the
	/// movement of the send that paid must stay as it is.
	#[tokio::test]
	async fn second_attempt_to_pay_a_paid_invoice_is_dropped() {
		let (wallet, _conn) = Wallet::offline_for_test().await;
		let send = pending_send(&wallet).await;
		settle_partially(&wallet, &send, SETTLEMENT_WRITES).await;
		finish(&wallet, &send).await;
		let movement = wallet.inner.db.get_movement_by_id(send.htlcs.movement_id).await.unwrap();

		let input = &VTXO_VECTORS.board_vtxo;
		let locked = VtxoState::Locked { holder: Some(VtxoLockHolder::Action { id: send.send.id() }) };
		wallet.inner.db.store_vtxos(&[(input, &locked)]).await.unwrap();
		let second = LightningSend {
			input_vtxo_ids: vec![input.id()],
			progress: Progress::InputsLocked { movement_id: send.htlcs.movement_id },
			..send.send.clone()
		};
		wallet.inner.db.upsert_wallet_action_checkpoint(&second.id(), &second.into()).await.unwrap();

		wallet.sync_pending_lightning_send_vtxos().await.unwrap();

		assert_eq!(checkpoint(&wallet, &send).await, None);
		let input = wallet.inner.db.get_wallet_vtxo(input.id()).await.unwrap().unwrap();
		assert_eq!(input.state, VtxoState::Spendable);
		let movement_after = wallet.inner.db.get_movement_by_id(send.htlcs.movement_id).await.unwrap();
		assert_eq!(movement_after, movement);
	}
}

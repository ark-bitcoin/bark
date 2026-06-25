use anyhow::Context;
use tokio::sync::broadcast;
use tracing::{trace, warn};
use ark::lightning::{PaymentHash, Preimage};

use crate::database;
use crate::database::ln::{LightningPaymentAttempt, LightningPaymentStatus};
use crate::ln::settler::HtlcSettler;

/// Borrows the DB, mailbox manager, and payment update broadcast channel
/// so that every payment-attempt status change is consistently followed by
/// a broadcast and (for final states) a mailbox notification.
pub(crate) struct PaymentAttemptHandler<'a> {
	db: &'a database::Db,
	mailbox_manager: &'a crate::mailbox_manager::MailboxManager,
	payment_update_tx: &'a broadcast::Sender<PaymentHash>,
}

impl<'a> PaymentAttemptHandler<'a> {
	pub fn new(
		db: &'a database::Db,
		mailbox_manager: &'a crate::mailbox_manager::MailboxManager,
		payment_update_tx: &'a broadcast::Sender<PaymentHash>,
	) -> Self {
		Self { db, mailbox_manager, payment_update_tx }
	}

	/// Update a lightning payment attempt's status, broadcast the update, and
	/// post a send-finished notification to the sender's mailbox.
	pub async fn fail_payment_attempt(
		&self, attempt: &LightningPaymentAttempt, error: Option<&str>,
	) -> anyhow::Result<()> {
		let new_status = LightningPaymentStatus::Failed;
		self.db.write(async |t|
			t.update_lightning_payment_attempt_status(attempt, new_status, error).await
		).await?;

		trace!("Lightning payment attempt ({}): status updated to {} for payment hash {}.",
			attempt.id, new_status, attempt.payment_hash,
		);

		self.payment_update_tx.send(attempt.payment_hash)
			.context("payment update channel broken")?;

		self.post_lightning_send_finished(attempt.payment_hash, None).await;
		Ok(())
	}

	/// Verify and update a lightning payment attempt, broadcast the update, and
	/// post a send-finished notification to the sender's mailbox if the status
	/// reached a final state.
	///
	/// Wraps [`database::Db::verify_and_update_payment_attempt`] with broadcast
	/// and mailbox notification.
	///
	/// The caller is responsible for verifying that the preimage matches the payment hash.
	pub async fn process_payment_attempt(
		&self,
		settler: &HtlcSettler,
		attempt: &LightningPaymentAttempt,
		status: LightningPaymentStatus,
		payment_error: Option<&str>,
		final_amount_msat: Option<u64>,
		preimage: Option<Preimage>,
	) -> anyhow::Result<()> {
		// Store the preimage in the settlement table so the
		// watchman can use it to claim HTLC VTXOs on-chain.
		if let Some(preimage) = preimage {
			debug_assert!(
				matches!(status, LightningPaymentStatus::Succeeded),
				"payment is succeeded if preimage is known, not {}", status,
			);
			debug_assert!(
				preimage.compute_payment_hash() == attempt.payment_hash,
				"preimage must match payment hash",
			);
			settler.settle(preimage).await?;
		}

		let updated = self.db.write(async |t| {
			// Mark the spendable HTLC-send vtxos as ln-spent as soon as the
			// preimage is known. Any linked vtxo that wasn't spendable is left
			// untouched and reported, but the settlement still proceeds.
			if preimage.is_some() {
				let not_spendable = t.mark_htlc_send_vtxos_ln_spent(attempt.payment_hash).await?;
				if !not_spendable.is_empty() {
					warn!(
						"Lightning payment attempt ({}): HTLC-send vtxos for payment hash {} \
						were not spendable and left untouched: {:?}",
						attempt.id, attempt.payment_hash, not_spendable,
					);
				}
			}

			t.verify_and_update_payment_attempt(
				attempt, status, payment_error, final_amount_msat
			).await
		}).await?;

		if updated {
			trace!("Lightning payment attempt ({}): status updated to {} for payment hash {}.",
				attempt.id, status, attempt.payment_hash,
			);

			self.payment_update_tx.send(attempt.payment_hash)
				.context("payment update channel broken")?;

			if status.is_final() {
				self.post_lightning_send_finished(attempt.payment_hash, preimage).await;
			}
		}

		Ok(())
	}

	/// Post a lightning send finished notification to the sender's mailbox.
	async fn post_lightning_send_finished(
		&self,
		payment_hash: PaymentHash,
		preimage: Option<Preimage>,
	) {
		let mailbox_id = match self.db.read(async |t|
			t.get_lightning_sender_mailbox_id(payment_hash).await
		).await {
			Ok(Some(id)) => id,
			Ok(None) => return,
			Err(e) => {
				warn!("Failed to look up mailbox_id for {}: {:#}", payment_hash, e);
				return;
			},
		};

		match self.db.write(async |t|
			t.store_lightning_send_finished(mailbox_id, payment_hash, preimage).await
		).await {
			Ok(Some(checkpoint)) => {
				self.mailbox_manager.notify(mailbox_id, checkpoint);
			},
			Ok(None) => {},
			Err(e) => {
				warn!("Failed to store send finished notification for {}: {:#}", payment_hash, e);
			},
		}
	}
}

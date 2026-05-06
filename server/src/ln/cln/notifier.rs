use anyhow::Context;
use tokio::sync::broadcast;
use tracing::{trace, warn};
use ark::lightning::{PaymentHash, Preimage};

use crate::database;
use crate::database::ln::{LightningPaymentAttempt, LightningPaymentStatus};

/// Borrows the DB, mailbox manager, and payment update broadcast channel
/// so that every payment-attempt status change is consistently followed by
/// a broadcast and (for final states) a mailbox notification.
pub(in crate::ln::cln) struct PaymentAttemptNotifier<'a> {
	db: &'a database::Db,
	mailbox_manager: &'a crate::mailbox_manager::MailboxManager,
	payment_update_tx: &'a broadcast::Sender<PaymentHash>,
}

impl<'a> PaymentAttemptNotifier<'a> {
	pub fn new(
		db: &'a database::Db,
		mailbox_manager: &'a crate::mailbox_manager::MailboxManager,
		payment_update_tx: &'a broadcast::Sender<PaymentHash>,
	) -> Self {
		Self { db, mailbox_manager, payment_update_tx }
	}

	/// Update a lightning payment attempt's status, broadcast the update, and
	/// post a send-finished notification to the sender's mailbox.
	pub async fn update_lightning_payment_attempt_status(
		&self,
		attempt: &LightningPaymentAttempt,
		new_status: LightningPaymentStatus,
		error: Option<&str>,
		preimage: Option<Preimage>,
	) -> anyhow::Result<()> {
		self.db.write(async |t|
			t.update_lightning_payment_attempt_status(attempt, new_status, error).await
		).await?;

		trace!("Lightning payment attempt ({}): status updated to {} for payment hash {}.",
			attempt.id, new_status, attempt.payment_hash,
		);

		self.payment_update_tx.send(attempt.payment_hash)
			.context("payment update channel broken")?;

		if new_status.is_final() {
			self.post_lightning_send_finished(attempt.payment_hash, preimage).await;
		}

		Ok(())
	}

	/// Verify and update a lightning payment attempt, broadcast the update, and
	/// post a send-finished notification to the sender's mailbox if the status
	/// reached a final state.
	///
	/// Wraps [`database::Db::verify_and_update_payment_attempt`] with broadcast
	/// and mailbox notification.
	pub async fn verify_and_update_payment_attempt(
		&self,
		attempt: &LightningPaymentAttempt,
		status: LightningPaymentStatus,
		payment_error: Option<&str>,
		final_amount_msat: Option<u64>,
		preimage: Option<Preimage>,
	) -> anyhow::Result<()> {
		let updated = self.db.write(async |t|
			t.verify_and_update_payment_attempt(attempt, status, payment_error, final_amount_msat).await
		).await?;

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

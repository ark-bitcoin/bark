
pub extern crate ark;

pub extern crate bip39;
pub extern crate lightning_invoice;
pub extern crate lnurl as lnurllib;

use std::collections::HashMap;
use std::ops::ControlFlow;

use anyhow::Context;
use ark::tree::signed::UnlockHash;
use bitcoin::hashes::Hash;
use bitcoin::Amount;
use bitcoin::hex::DisplayHex;
use bitcoin::secp256k1::Keypair;
use futures::{FutureExt, Stream, StreamExt};
use log::{debug, error, info, trace, warn};
use tokio_util::sync::CancellationToken;

use ark::{ProtocolEncoding, Vtxo, VtxoId};
use ark::lightning::{PaymentHash, Preimage};
use ark::mailbox::{MailboxAuthorization, MailboxIdentifier};
use ark::vtxo::Full;
use server_rpc::{protos, MAX_NB_MAILBOX_RECOVERY_IDS};
use server_rpc::protos::mailbox_server::MailboxMessage;

use crate::{Wallet, SUBSCRIBE_REQUEST_TIMEOUT};
use crate::actions::DriveMode;
use crate::actions::lightning::pay::Progress;
use crate::movement::{MovementDestination, MovementStatus};
use crate::movement::update::MovementUpdate;
use crate::subsystem::{ArkoorMovement, Subsystem};


/// The maximum number of times we will call the fetch mailbox endpoint in one go
///
/// We can't trust the server to honestly tell us to keep trying more forever.
/// A malicious server could send us empty messages or invalid messages and
/// lock up our resources forever. So we limit the number of times we will fetch.
/// If a user actually has more messages left, he will have to call sync again.
///
/// (Note that currently the server sends 100 messages per fetch, so this would
/// only happen for users with more than 1000 pending items.)
const MAX_MAILBOX_REQUEST_BURST: usize = 10;

/// Key for the lock that serializes the arkoor receive dedup within a wallet.
///
/// Several consumers of one wallet process the same mailbox messages: the
/// daemon's always-on stream ([`Wallet::subscribe_process_mailbox_messages`])
/// runs alongside the startup / periodic `sync()` (which calls
/// [`Wallet::sync_mailbox`]), and a REST deployment can fire concurrent
/// `/sync` and `/sync/mailbox` requests. The server hands each consumer the
/// same messages from its checkpoint, so without serialization the
/// peek-then-store dedup in arkoor processing races: every consumer that wins
/// the [`crate::persist::BarkPersister::get_wallet_vtxo`] check before the
/// others store records its own receive movement, double-counting the receive.
///
/// Holding this lock across that check-then-store (in
/// [`Wallet::process_received_arkoor_package`]) makes it atomic across
/// consumers. The VTXO row is `INSERT OR IGNORE`, so once one consumer has
/// stored the package the rest see the VTXO already present and skip the
/// movement.
const MAILBOX_PROCESSING_LOCK_KEY: &str = "mailbox.processing";

/// How long a consumer waits for the arkoor dedup lock before giving up.
///
/// The critical section is a couple of server round trips plus local DB
/// writes, normally well under a second. On timeout we error rather than
/// block, handled like any other arkoor processing error: this message's
/// checkpoint isn't advanced and processing halts (see
/// [`Wallet::process_mailbox_message`]) so a later message can't bury it. A
/// timeout only happens if a holder is stuck for the full duration; normally
/// waiters acquire the lock and dedup as usual.
const MAILBOX_PROCESSING_LOCK_TIMEOUT: std::time::Duration =
	std::time::Duration::from_secs(30);

impl Wallet {
	/// Get the keypair used for the server mailbox
	pub fn mailbox_keypair(&self) -> Keypair {
		self.inner.seed.to_mailbox_keypair()
	}

	/// Get the keypair used for the server recovery mailbox
	pub fn recovery_mailbox_keypair(&self) -> Keypair {
		self.inner.seed.to_recovery_mailbox_keypair()
	}

	/// Get this wallet's server mailbox ID
	pub fn mailbox_identifier(&self) -> MailboxIdentifier {
		let mailbox_kp = self.mailbox_keypair();
		MailboxIdentifier::from_pubkey(mailbox_kp.public_key())
	}

	/// Get this wallet's server recovery mailbox ID
	pub fn recovery_mailbox_identifier(&self) -> MailboxIdentifier {
		let mailbox_kp = self.recovery_mailbox_keypair();
		MailboxIdentifier::from_pubkey(mailbox_kp.public_key())
	}

	/// Create a mailbox authorization that is valid until the given expiry time
	///
	/// This authorization can be used by third parties to lookup your mailbox
	/// with the Ark server.
	pub fn mailbox_authorization(
		&self,
		authorization_expiry: chrono::DateTime<chrono::Local>,
	) -> MailboxAuthorization {
		MailboxAuthorization::new(&self.mailbox_keypair(), authorization_expiry)
	}

	/// Subscribe to mailbox message stream.
	///
	/// If `since` is `None`, the stream will start from the last checkpoint stored in the database.
	///
	/// Returns a stream of mailbox messages.
	pub async fn subscribe_mailbox_messages(
		&self,
		since_checkpoint: Option<u64>,
	) -> anyhow::Result<impl Stream<Item = anyhow::Result<MailboxMessage>> + Unpin> {
		let (mut srv, _) = self.require_server().await?;

		let checkpoint = if let Some(since) = since_checkpoint {
			since
		} else {
			self.get_mailbox_checkpoint().await?
		};

		// we just need a short authorization for the stream initialization
		let expiry = chrono::Local::now() + std::time::Duration::from_secs(10);
		let auth = self.mailbox_authorization(expiry);
		let mailbox_id = auth.mailbox();

		let mut req = tonic::IntoRequest::into_request(protos::mailbox_server::MailboxRequest {
			mailbox_id: mailbox_id.serialize(),
			authorization: Some(auth.serialize()),
			checkpoint: checkpoint,
		});
		req.set_timeout(SUBSCRIBE_REQUEST_TIMEOUT);

		let stream = srv.mailbox_client.subscribe_mailbox(req).await?.into_inner().map(|m| {
			let m = m.context("received error on mailbox message stream")?;
			Ok::<_, anyhow::Error>(m)
		});

		Ok(stream)
	}

	/// Similar to [Wallet::subscribe_mailbox_messages] but it will also process each mailbox
	/// message indefinitely. This method won't stop until the given `shutdown` `CancellationToken`
	/// is triggered.
	///
	/// If `since_checkpoint` is `None`, the stream will start from the last checkpoint stored in
	/// the database.
	///
	/// Returns only once the stream is closed.
	pub async fn subscribe_process_mailbox_messages(
		&self,
		since_checkpoint: Option<u64>,
		shutdown: CancellationToken,
	) -> anyhow::Result<()> {
		let mut reconnect_count = 0;
		const MAX_RECONNECT_ATTEMPTS: usize = 5;

		'outer: loop {
			let mut stream = self.subscribe_mailbox_messages(since_checkpoint).await?;
			trace!("Connected to mailbox stream with server");

			loop {
				futures::select! {
					message = stream.next().fuse() => {
						match message {
							Some(Ok(message)) => {
								reconnect_count = 0;
								if self.process_mailbox_message(message).await.is_break() {
									// A message failed without advancing its
									// checkpoint. Stop consuming this stream and
									// resubscribe from the unadvanced checkpoint
									// so it's redelivered before a later message
									// can bury it.
									trace!("Halting mailbox stream after unadvanced message; resubscribing");
									continue 'outer;
								}
							},
							// A tonic h2 stream reset is almost always a
							// proxy- or server-side idle timeout rather than
							// a real failure; resubscribe quietly.
							Some(Err(e)) if crate::utils::is_h2_stream_error(&e) => {
								reconnect_count = 0;
								trace!("Mailbox stream reset by server, reconnecting: {e:#}");
								continue 'outer;
							},
							Some(Err(e)) => {
								return Err(e).context("error on mailbox message stream");
							},
							None if reconnect_count >= MAX_RECONNECT_ATTEMPTS => {
								bail!("Mailbox stream dropped by server, giving up to retry later");
							},
							None => {
								reconnect_count += 1;
								warn!("Mailbox stream dropped by server, reconnecting");
								continue 'outer;
							},
						}
					},
					_ = shutdown.cancelled().fuse() => {
						info!("Shutdown signal received! Shutting mailbox messages process...");
						return Ok(());
					},
				}
			}
		}
	}

	/// Sync with the mailbox on the Ark server and look for out-of-round received VTXOs.
	pub async fn sync_mailbox(&self) -> anyhow::Result<()> {
		let (mut srv, _) = self.require_server().await?;

		// we should be able to do all our syncing in 10 minutes
		let expiry = chrono::Local::now() + std::time::Duration::from_secs(10 * 60);
		let auth = self.mailbox_authorization(expiry);
		let mailbox_id = auth.mailbox();

		for _ in 0..MAX_MAILBOX_REQUEST_BURST {
			let checkpoint = self.get_mailbox_checkpoint().await?;
			let mailbox_req = protos::mailbox_server::MailboxRequest {
				mailbox_id: mailbox_id.serialize(),
				authorization: Some(auth.serialize()),
				checkpoint,
			};

			let mailbox_resp = srv.mailbox_client.read_mailbox(mailbox_req).await
				.context("error fetching mailbox")?.into_inner();
			debug!("Ark server has {} mailbox messages for us", mailbox_resp.messages.len());

			for mailbox_msg in mailbox_resp.messages {
				if self.process_mailbox_message(mailbox_msg).await.is_break() {
					// A message failed without advancing its checkpoint. Stop
					// so we don't advance past it; the next sync retries from
					// the same checkpoint.
					return Ok(());
				}
			}

			if !mailbox_resp.have_more {
				break;
			}
		}

		Ok(())
	}

	/// Turn raw byte arrays into VTXOs, then validate them.
	///
	/// This function doesn't return a result on purpose,
	/// because we want to make sure we don't early return on
	/// the first error. This ensure we process all VTXOs, even
	/// if some are invalid, and print everything we received.
	async fn process_raw_vtxos(
		&self,
		raw_vtxos: Vec<Vec<u8>>,
	) -> Vec<Vtxo<Full>> {
		let mut invalid_vtxos = Vec::with_capacity(raw_vtxos.len());
		let mut valid_vtxos = Vec::with_capacity(raw_vtxos.len());

		for bytes in &raw_vtxos {
			let vtxo = match Vtxo::<Full>::deserialize(&bytes) {
				Ok(vtxo) => vtxo,
				Err(e) => {
					error!("Failed to deserialize arkoor VTXO: {}: {}", bytes.as_hex(), e);
					invalid_vtxos.push(bytes);
					continue;
				}
			};

			if let Err(e) = self.validate_vtxo(&vtxo).await {
				error!("Received invalid arkoor VTXO {} from server: {}", vtxo.id(), e);
				invalid_vtxos.push(bytes);
				continue;
			}

			valid_vtxos.push(vtxo);
		}

		// We log all invalid VTXOs to keep track
		if !invalid_vtxos.is_empty() {
			error!("Received {} invalid arkoor VTXOs out of {} from server", invalid_vtxos.len(), raw_vtxos.len());
		}

		valid_vtxos
	}

	/// Process a single mailbox message and report whether the caller should
	/// keep consuming the mailbox.
	///
	/// Returns [`ControlFlow::Break`] when an arkoor package failed to process
	/// and its checkpoint was therefore not advanced. Because checkpoints are
	/// monotonic, the caller must stop before a later message stores a higher
	/// checkpoint and buries the unprocessed one; the next sync/resubscribe
	/// re-fetches from the unadvanced checkpoint and retries.
	pub(crate) async fn process_mailbox_message(
		&self,
		mailbox_msg: MailboxMessage,
	) -> ControlFlow<()> {
		use protos::mailbox_server::mailbox_message::Message;

		// Each arm returns whether the checkpoint should advance. Only
		// arkoor returns false on processing error so the server
		// redelivers and we retry. Every other arm advances regardless,
		// either because the work is idempotent and re-done on every
		// wallet sync, or because the message is informational/ignored.
		let advance = match mailbox_msg.message {
			Some(Message::Arkoor(msg)) => {
				match self.process_received_arkoor_package(msg.vtxos).await {
					Ok(()) => true,
					Err(e) => {
						error!("Error processing received arkoor package: {:#}", e);
						false
					}
				}
			}
			Some(Message::RoundParticipationCompleted(m)) => {
				info!("Server informed that round participation is ready, unlock_hash:{:?}",
					UnlockHash::from_slice(&m.unlock_hash).ok(),
				);
				if let Err(e) = self.sync_pending_rounds().await {
					error!("Error syncing pending rounds: {:#}", e);
				}
				true
			},
			Some(Message::IncomingLightningPayment(msg)) => {
				if let Err(e) = self.handle_lightning_receive_notification(msg).await {
					error!("Error handling lightning receive notification: {:#}", e);
				}
				true
			},
			Some(Message::RecoveryVtxoIds(_)) => {
				trace!("Received recovery VTXO IDs, ignoring");
				true
			}
			Some(Message::LightningSendFinished(msg)) => {
				if let Err(e) = self.handle_lightning_send_finished(msg, mailbox_msg.checkpoint).await {
					error!("Error handling lightning send finished notification: {:#}", e);
				}
				true
			}
			None => {
				warn!("Received unknown mailbox message kind at checkpoint {}; bark may need to be upgraded",
					mailbox_msg.checkpoint);
				true
			}
		};

		if advance {
			if let Err(e) = self.store_mailbox_checkpoint(mailbox_msg.checkpoint).await {
				error!("Error storing mailbox checkpoint: {:#}", e);
			}
			ControlFlow::Continue(())
		} else {
			// An arkoor package didn't process and its checkpoint wasn't
			// advanced. Stop here so a later message can't store a higher
			// checkpoint and bury it.
			ControlFlow::Break(())
		}
	}

	async fn process_received_arkoor_package(
		&self,
		raw_vtxos: Vec<Vec<u8>>,
	) -> anyhow::Result<()> {
		let vtxos = self.process_raw_vtxos(raw_vtxos).await;

		// Serialize the receive dedup across all consumers of this wallet's
		// mailbox so two of them can't both record a movement for the same
		// package. See MAILBOX_PROCESSING_LOCK_KEY. On lock failure we
		// return like any other arkoor processing error, leaving this
		// message's checkpoint unadvanced.
		let _guard = self.inner.lock_manager.lock(
			MAILBOX_PROCESSING_LOCK_KEY, MAILBOX_PROCESSING_LOCK_TIMEOUT,
		).await.context("failed to acquire mailbox processing lock")?;

		let mut new_vtxos = Vec::with_capacity(vtxos.len());
		for vtxo in &vtxos {
			// Skip if already in wallet
			if self.inner.db.get_wallet_vtxo(vtxo.id()).await?.is_some() {
				debug!("Ignoring duplicate arkoor VTXO {}", vtxo.id());
				continue;
			}

			trace!("Received arkoor VTXO {} for {}", vtxo.id(), vtxo.amount());
			new_vtxos.push(vtxo);
		}

		if new_vtxos.is_empty() {
			return Ok(());
		}

		// Redundantly re-register the received vtxos with the server. An
		// up-to-date sender already does this after cosign, but older
		// senders may not, so we do it on receive too to make sure the
		// server has signed_tx rows for our spendable vtxos. Any failure
		// is logged and swallowed: the receive must still proceed so we
		// don't lose track of the vtxos locally, and later spends will
		// retry registration if still needed.
		if let Err(e) = self.register_vtxo_transactions_with_server(&new_vtxos).await {
			warn!("Failed to register received arkoor vtxo transactions with server: {:#}", e);
		}

		let balance = vtxos
			.iter()
			.map(|vtxo| vtxo.amount()).sum::<Amount>()
			.to_signed()?;
		self.store_spendable_vtxos(&vtxos).await?;

		// Build received_on destinations from received VTXOs, aggregated by address
		let mut received_by_address = HashMap::<ark::Address, Amount>::new();
		for vtxo in &vtxos {
			if let Ok(Some((index, _))) = self.pubkey_keypair(&vtxo.user_pubkey()).await {
				if let Ok(address) = self.peek_address(index).await {
					*received_by_address.entry(address).or_default() += vtxo.amount();
				}
			}
		}
		let received_on: Vec<_> = received_by_address
			.iter()
			.map(|(addr, amount)| MovementDestination::ark(addr.clone(), *amount))
			.collect();

		let movement_id = self.inner.movements.new_finished_movement(
			Subsystem::ARKOOR,
			ArkoorMovement::Receive.to_string(),
			MovementStatus::Successful,
			MovementUpdate::new()
				.produced_vtxos(&vtxos)
				.intended_and_effective_balance(balance)
				.received_on(received_on),
		).await?;

		info!("Received arkoor (movement {}) for {}", movement_id, balance);

		Ok(())
	}

	/// Handle a lightning receive notification from the mailbox.
	///
	/// This is a signal that the server has received a lightning payment for us
	/// and we should come online to claim it.
	async fn handle_lightning_receive_notification(
		&self,
		notif: protos::mailbox_server::IncomingLightningPaymentMessage,
	) -> anyhow::Result<()> {
		let payment_hash = PaymentHash::try_from(notif.payment_hash)
			.context("invalid payment hash in lightning receive notification")?;

		debug!("Lightning receive notification: payment_hash={}", payment_hash);

		match self.try_claim_lightning_receive(payment_hash, false).await {
			Ok(_) => info!("Lightning receive claimed via mailbox notification for {}", payment_hash),
			Err(e) => error!("Failed to claim lightning receive for {}: {:#}", payment_hash, e),
		}

		Ok(())
	}

	/// Handle a lightning send finished notification from the mailbox.
	///
	/// This notification indicates that the server has completed processing
	/// a lightning payment we initiated, either successfully or with failure.
	async fn handle_lightning_send_finished(
		&self,
		notif: protos::mailbox_server::LightningSendFinishedMessage,
		checkpoint: u64,
	) -> anyhow::Result<()> {
		let payment_hash = PaymentHash::try_from(notif.payment_hash)
			.context("invalid payment hash in lightning send finished notification")?;

		let known_preimage = notif.preimage
			.and_then(|bytes| Preimage::try_from(bytes).ok());

		if known_preimage.is_some() {
			debug!("Lightning send finished notification (success): payment_hash={}", payment_hash);
		} else {
			debug!("Lightning send finished notification (failed): payment_hash={}", payment_hash);
		}

		// Errors are logged but not propagated: we always advance the
		// mailbox checkpoint to avoid re-processing the same
		// notification on the next poll.
		match self.is_invoice_paid(payment_hash).await {
			Ok(true) => {
				debug!("Lightning send {} already settled; ignoring notification", payment_hash);
			},
			Ok(false) => {
				let lookup = self.lightning_send_checkpoint(payment_hash).await;
				match lookup {
					Ok(Some(send)) => {
						let result = match (&send.progress, known_preimage) {
							(Progress::PaymentInitiated(htlcs), Some(preimage)) => {
								let htlcs = htlcs.clone();
								self.settle_lightning_send_with_preimage(send, htlcs, preimage).await
							},
							(Progress::PaymentInitiated(_), None) => {
								self.drive_action(send, DriveMode::UntilParkOrDone).await
							},
							_ => {
								debug!("Lightning send finished notification for {} but checkpoint is not PaymentInitiated; ignoring", payment_hash);
								Ok(())
							},
						};
						match result {
							Ok(()) => info!("Processed lightning send finished for {}", payment_hash),
							Err(e) => error!("Failed to process lightning send finished for {}: {:#}", payment_hash, e),
						}
					},
					Ok(None) => {
						warn!("Lightning send finished notification for unknown payment hash {}", payment_hash);
					},
					Err(e) => {
						error!("Failed to look up lightning send checkpoint for {}: {:#}", payment_hash, e);
					},
				}
			},
			Err(e) => {
				error!("Failed to look up paid_invoice for {}: {:#}", payment_hash, e);
			},
		}

		self.store_mailbox_checkpoint(checkpoint).await?;
		Ok(())
	}

	/// Post vtxo IDs to the server's recovery mailbox
	pub async fn post_recovery_vtxo_ids(
		&self,
		vtxo_ids: impl IntoIterator<Item = VtxoId>,
	) -> anyhow::Result<()> {
		let vtxo_ids = vtxo_ids.into_iter().map(|id| id.to_bytes().to_vec()).collect::<Vec<_>>();
		if vtxo_ids.is_empty() {
			return Ok(());
		}
		let nb_vtxos = vtxo_ids.len();

		// Prove ownership of the recovery mailbox; short validity is enough as
		// it's consumed by this single request.
		let expiry = chrono::Local::now() + std::time::Duration::from_secs(60);
		let auth = MailboxAuthorization::new(&self.recovery_mailbox_keypair(), expiry);
		let mailbox_id = self.recovery_mailbox_identifier().serialize();

		let (mut srv, _) = self.require_server().await?;
		for chunk in vtxo_ids.chunks(MAX_NB_MAILBOX_RECOVERY_IDS) {
			let req = protos::mailbox_server::PostRecoveryVtxoIdsRequest {
				mailbox_id: mailbox_id.clone(),
				vtxo_ids: chunk.to_vec(),
				authorization: Some(auth.serialize()),
			};

			srv.mailbox_client.post_recovery_vtxo_ids(req).await
				.context("error posting recovery vtxo IDs to server")?;
		}

		debug!("Posted {} recovery vtxo IDs to server", nb_vtxos);
		Ok(())
	}

	/// Return the stored mailbox checkpoint — the tip position the wallet
	/// has consumed up to. After a successful [`Self::sync_mailbox`], this value
	/// reflects the server's latest advertised tip.
	pub async fn get_mailbox_checkpoint(&self) -> anyhow::Result<u64> {
		Ok(self.inner.db.get_mailbox_checkpoint().await?)
	}

	async fn store_mailbox_checkpoint(&self, checkpoint: u64) -> anyhow::Result<()> {
		Ok(self.inner.db.store_mailbox_checkpoint(checkpoint).await?)
	}
}

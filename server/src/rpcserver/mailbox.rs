use std::pin::Pin;
use bitcoin::hashes::Hash;
use futures::Stream;
use futures::StreamExt;
use tracing::{error, warn};
use ark::{ProtocolEncoding, Vtxo, VtxoId};
use ark::mailbox::{BlindedMailboxIdentifier, MailboxAuthorization, MailboxIdentifier, MailboxType};
use server_rpc::{self as rpc, protos, TryFromBytes};

use crate::database::{Checkpoint, MailboxEntry, MailboxPayload};
use crate::rpcserver::{StatusContext, ToStatus, ToStatusResult};
use crate::rpcserver::macros::badarg;

/// Bail with `invalid_argument` if the authorization is expired, logging the
/// timing details so we can attribute failures to clock skew.
fn check_auth_not_expired(auth: &MailboxAuthorization) -> Result<(), tonic::Status> {
	if auth.is_expired() {
		let now = chrono::Local::now();
		let expiry = auth.expiry();
		slog!(MailboxAuthorizationExpired,
			expiry,
			now,
			late_by_secs: (now - expiry).num_seconds(),
		);
		return crate::error::badarg!("mailbox authorization expired").to_status();
	}
	Ok(())
}

#[allow(deprecated)]
fn new_mailbox_msg(entry: MailboxEntry) -> protos::mailbox_server::MailboxMessage {
	match entry.payload {
		MailboxPayload::Arkoor { vtxos } => {
			protos::mailbox_server::MailboxMessage {
				message: Some(protos::mailbox_server::mailbox_message::Message::Arkoor(
					protos::mailbox_server::ArkoorMessage {
						vtxos: vtxos.into_iter().map(|v| v.serialize()).collect(),
					}
				)),
				checkpoint: entry.checkpoint.into(),
			}
		},
		MailboxPayload::RoundParticipationCompleted { unlock_hash } => {
			protos::mailbox_server::MailboxMessage {
				message: Some(protos::mailbox_server::mailbox_message::Message::RoundParticipationCompleted(
					protos::mailbox_server::RoundParticipationCompleted {
						unlock_hash: unlock_hash.as_byte_array().to_vec(),
						// compat for <= v0.1.1
						payment_hashes: vec![unlock_hash.as_byte_array().to_vec()],
					}
				)),
				checkpoint: entry.checkpoint.into(),
			}
		},
		MailboxPayload::LightningReceive { payment_hash, amount_msat } => {
			protos::mailbox_server::MailboxMessage {
				message: Some(protos::mailbox_server::mailbox_message::Message::IncomingLightningPayment(
					protos::mailbox_server::IncomingLightningPaymentMessage {
						payment_hash: payment_hash.to_vec(),
						amount_msat,
					}
				)),
				checkpoint: entry.checkpoint.into(),
			}
		},
		MailboxPayload::RecoveryVtxoIds { vtxo_ids } => {
			protos::mailbox_server::MailboxMessage {
				message: Some(protos::mailbox_server::mailbox_message::Message::RecoveryVtxoIds(
					protos::mailbox_server::RecoveryVtxoIdsMessage {
						vtxo_ids: vtxo_ids.into_iter().map(|v| v.to_bytes().to_vec()).collect(),
					}
				)),
				checkpoint: entry.checkpoint.into(),
			}
		},
		MailboxPayload::LightningSendFinished { payment_hash, preimage } => {
			protos::mailbox_server::MailboxMessage {
				message: Some(protos::mailbox_server::mailbox_message::Message::LightningSendFinished(
					protos::mailbox_server::LightningSendFinishedMessage {
						payment_hash: payment_hash.to_vec(),
						preimage: preimage.map(|p| p.to_vec()),
					}
				)),
				checkpoint: entry.checkpoint.into(),
			}
		},
	}
}

#[async_trait]
impl rpc::server::MailboxService for crate::Server {
	#[tracing::instrument(skip(self, req))]
	async fn post_arkoor_message(
		&self,
		req: tonic::Request<protos::mailbox_server::PostArkoorMessageRequest>,
	) -> Result<tonic::Response<protos::core::Empty>, tonic::Status> {
		let req = req.into_inner();

		let vtxos = req.vtxos.into_iter()
			.map(|v| Vtxo::from_bytes(v))
			.collect::<Result<Vec<_>, _>>()?;
		if vtxos.is_empty() {
			self::badarg!("no vtxos provided");
		}

		let blinded_mailbox_id = BlindedMailboxIdentifier::from_bytes(&req.blinded_id.as_slice())?;
		// should all have same pubkey
		let vtxo_pubkey = vtxos[0].user_pubkey();
		if !vtxos.iter().skip(1).all(|v| v.user_pubkey() == vtxo_pubkey) {
			self::badarg!("all vtxos should share vtxo pubkey when mailbox is provided");
		}

		let mailbox_id = self.unblind_mailbox_id(blinded_mailbox_id, vtxo_pubkey);

		let checkpoint = self.db.write(async |t| {
			t.store_vtxos_in_mailbox(
				MailboxType::ArkoorReceive,
				mailbox_id,
				vtxos.as_slice(),
			).await
		}).await.to_status()?;

		// `None` means every posted vtxo was already in the mailbox. A duplicate
		// post is a no-op, so there's no new checkpoint to notify subscribers of.
		if let Some(checkpoint) = checkpoint {
			self.mailbox_manager.notify(mailbox_id, checkpoint);
		}

		Ok(tonic::Response::new(protos::core::Empty{}))
	}

	#[tracing::instrument(skip(self, req), fields(
		checkpoint = req.get_ref().checkpoint
	))]
	async fn read_mailbox(
		&self,
		req: tonic::Request<protos::mailbox_server::MailboxRequest>,
	) -> Result<tonic::Response<protos::mailbox_server::MailboxMessages>, tonic::Status> {
		let req = req.into_inner();

		let mailbox_id = MailboxIdentifier::deserialize(req.mailbox_id.as_slice())
			.badarg("invalid mailbox id")?;
		let auth_bytes = req.authorization.badarg("mailbox authorization required")?;
		let auth = MailboxAuthorization::deserialize(auth_bytes.as_slice())
			.badarg("invalid mailbox authorization")?;
		if auth.mailbox() != mailbox_id {
			self::badarg!("authorization doesn't match mailbox id");
		}
		check_auth_not_expired(&auth)?;
		if !auth.verify() {
			self::badarg!("invalid mailbox authorization signature");
		}
		let limit = self.config.max_read_mailbox_items;
		let entries_by_checkpoint = self.db.read(async |t| {
			t.get_mailbox_messages(mailbox_id, req.checkpoint, limit).await
		}).await.to_status()?;

		let response = protos::mailbox_server::MailboxMessages {
			have_more: entries_by_checkpoint.len() >= limit,
			messages: entries_by_checkpoint.into_iter().map(new_mailbox_msg).collect(),
		};

		Ok(tonic::Response::new(response))
	}

	type SubscribeMailboxStream = Pin<Box<
		dyn Stream<Item = Result<protos::mailbox_server::MailboxMessage, tonic::Status>> + Send + 'static
	>>;

	#[tracing::instrument(skip(self, req), fields(
		checkpoint = req.get_ref().checkpoint
	))]
	async fn subscribe_mailbox(
		&self,
		req: tonic::Request<protos::mailbox_server::MailboxRequest>,
	) -> Result<tonic::Response<Self::SubscribeMailboxStream>, tonic::Status> {
		let req = req.into_inner();

		let mailbox_id = MailboxIdentifier::deserialize(req.mailbox_id.as_slice())
			.badarg("invalid mailbox id")?;
		let auth_bytes = req.authorization.badarg("mailbox authorization required")?;
		let auth = MailboxAuthorization::deserialize(auth_bytes.as_slice())
			.badarg("invalid mailbox authorization")?;
		if auth.mailbox() != mailbox_id {
			self::badarg!("authorization doesn't match mailbox id");
		}
		check_auth_not_expired(&auth)?;
		if !auth.verify() {
			self::badarg!("invalid mailbox authorization signature");
		}

		let db = self.db.clone();
		let starting_checkpoint = Checkpoint::from(req.checkpoint.max(0));
		let ret_limit = self.config.max_read_mailbox_items;

		// Start listening for updates on the tip of the mailbox
		// I mark the first value as changed
		// This ensures `mailbox_tip_rx` will return immediately and
		// start fetching historical records
		let mut mailbox_tip_rx = self.mailbox_manager.subscribe(mailbox_id, 0);
		mailbox_tip_rx.mark_changed();

		let stream = async_stream::try_stream! {
			let mut processed_cp = starting_checkpoint;

			loop {
				if mailbox_tip_rx.changed().await.is_err() {
					error!("Mailbox sender dropped for mailbox id {}", mailbox_id);
					Err(anyhow!("internal mailbox stream closed").to_status())?;
				}

				let new_cp = *mailbox_tip_rx.borrow_and_update();
				if new_cp <= processed_cp {
					continue;
				}

				'fetching:
				loop {
					match db.read(async |tx| { tx.get_mailbox_messages(mailbox_id, processed_cp, ret_limit).await }).await {
						Ok(entries) => {
							let done = entries.len() < ret_limit;
							for entry in entries {
								let cp = entry.checkpoint;
								let msg = new_mailbox_msg(entry.clone());
								yield msg;
								processed_cp = cp;
							}
							if done {
								break 'fetching;
							}
						}
						Err(err) => {
							warn!("Failed to read mailbox from DB: {err:#}");
							Err(err.to_status())?;
						}
					}
				}
			}
		};

		let mgr = self.rtmgr.clone();
		let stream = stream.take_until(async move { mgr.shutdown_signal().await });

		Ok(tonic::Response::new(Box::pin(stream)))
	}

	#[tracing::instrument(skip(self, req))]
	async fn post_recovery_vtxo_ids(
		&self,
		req: tonic::Request<protos::mailbox_server::PostRecoveryVtxoIdsRequest>,
	) -> Result<tonic::Response<protos::core::Empty>, tonic::Status> {
		let req = req.into_inner();

		let vtxo_ids = req.vtxo_ids.into_iter()
			.map(|v| VtxoId::from_bytes(v))
			.collect::<Result<Vec<_>, _>>()?;
		if vtxo_ids.is_empty() {
			self::badarg!("no vtxo ids provided");
		}

		let mailbox_id = MailboxIdentifier::deserialize(req.mailbox_id.as_slice())
			.badarg("invalid mailbox id")?;

		// Optional for backward compat; verified like the read path when present.
		// TODO: make mandatory after 0.3.1, once all clients send it.
		if let Some(auth_bytes) = req.authorization {
			let auth = MailboxAuthorization::deserialize(auth_bytes.as_slice())
				.badarg("invalid mailbox authorization")?;
			if auth.mailbox() != mailbox_id {
				self::badarg!("authorization doesn't match mailbox id");
			}
			check_auth_not_expired(&auth)?;
			if !auth.verify() {
				self::badarg!("invalid mailbox authorization signature");
			}
		}

		let checkpoint = self.db.write(async |t| {
			t.store_vtxo_ids_in_mailbox(
				MailboxType::RecoveryVtxoId,
				mailbox_id,
				vtxo_ids.as_slice(),
			).await
		}).await.to_status()?;

		if let Some(checkpoint) = checkpoint {
			self.mailbox_manager.notify(mailbox_id, checkpoint);
		}

		Ok(tonic::Response::new(protos::core::Empty{}))
	}

}

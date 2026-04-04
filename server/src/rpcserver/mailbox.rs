use std::pin::Pin;
use bitcoin::hashes::Hash;
use futures::Stream;
use tracing::{error, warn};
use ark::{ProtocolEncoding, Vtxo, VtxoId};
use ark::mailbox::{BlindedMailboxIdentifier, MailboxAuthorization, MailboxIdentifier, MailboxType};
use server_rpc::{self as rpc, protos, TryFromBytes};

use crate::database::{Checkpoint, MailboxEntry, MailboxPayload};
use crate::rpcserver::{StatusContext, ToStatus, ToStatusResult};
use crate::rpcserver::macros::badarg;

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
				mailbox_type: MailboxType::ArkoorReceive as i32,
			}
		},
		MailboxPayload::RoundParticipationCompleted { unlock_hashes } => {
			protos::mailbox_server::MailboxMessage {
				message: Some(protos::mailbox_server::mailbox_message::Message::RoundParticipationCompleted(
					protos::mailbox_server::RoundParticipationCompleted {
						payment_hashes: unlock_hashes.into_iter()
							.map(|h| h.as_byte_array().to_vec())
							.collect(),
					}
				)),
				checkpoint: entry.checkpoint.into(),
				mailbox_type: MailboxType::RoundParticipationCompleted as i32,
			}
		},
		MailboxPayload::LightningReceive { payment_hash } => {
			protos::mailbox_server::MailboxMessage {
				message: Some(protos::mailbox_server::mailbox_message::Message::IncomingLightningPayment(
					protos::mailbox_server::IncomingLightningPaymentMessage {
						payment_hash: payment_hash.to_vec(),
					}
				)),
				checkpoint: entry.checkpoint.into(),
				mailbox_type: 0, // deprecated, always default
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
				mailbox_type: MailboxType::RecoveryVtxoId as i32,
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

		let checkpoint = self.db.store_vtxos_in_mailbox(MailboxType::ArkoorReceive, mailbox_id, vtxos.as_slice()).await.to_status()?
			.badarg("nothing was stored")?;

		self.mailbox_manager.notify(mailbox_id, checkpoint);

		Ok(tonic::Response::new(protos::core::Empty{}))
	}

	#[tracing::instrument(skip(self, req))]
	async fn post_vtxos_mailbox(
		&self,
		req: tonic::Request<protos::mailbox_server::PostVtxosMailboxRequest>,
	) -> Result<tonic::Response<protos::core::Empty>, tonic::Status> {
		let req = req.into_inner();

		let vtxos = req.vtxos.into_iter()
			.map(|v| Vtxo::from_bytes(v))
			.collect::<Result<Vec<_>, _>>()?;
		if vtxos.is_empty() {
			self::badarg!("no vtxos provided");
		}

		let mailbox_type = MailboxType::try_from(req.mailbox_type as u32)
			.map_err(|_| tonic::Status::invalid_argument("invalid mailbox type"))?;
		let blinded_mailbox_id = BlindedMailboxIdentifier::from_bytes(&req.blinded_id.as_slice())?;
		// should all have same pubkey
		let vtxo_pubkey = vtxos[0].user_pubkey();
		if !vtxos.iter().skip(1).all(|v| v.user_pubkey() == vtxo_pubkey) {
			self::badarg!("all vtxos should share vtxo pubkey when mailbox is provided");
		}

		let mailbox_id = self.unblind_mailbox_id(blinded_mailbox_id, vtxo_pubkey);

		let checkpoint = self.db.store_vtxos_in_mailbox(mailbox_type, mailbox_id, vtxos.as_slice()).await.to_status()?
			.badarg("nothing was stored")?;

		self.mailbox_manager.notify(mailbox_id, checkpoint);

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

		let unblinded_id = MailboxIdentifier::from_slice(req.unblinded_id.as_slice())
			.badarg("invalid unblinded mailbox id")?;
		let auth_bytes = req.authorization.badarg("mailbox authorization required")?;
		let auth = MailboxAuthorization::deserialize(auth_bytes.as_slice())
			.badarg("invalid mailbox authorization")?;
		if auth.mailbox() != unblinded_id {
			self::badarg!("authorization doesn't match mailbox id");
		}
		if auth.is_expired() {
			self::badarg!("mailbox authorization expired");
		}
		if !auth.verify() {
			self::badarg!("invalid mailbox authorization signature");
		}
		let limit = self.config.max_read_mailbox_items;
		let entries_by_checkpoint = self.db.get_mailbox_messages(
			unblinded_id,
			req.checkpoint,
			limit,
		).await.to_status()?;

		let response = protos::mailbox_server::MailboxMessages {
			have_more: entries_by_checkpoint.len() >= limit,
			messages: entries_by_checkpoint.into_iter().map(|entry| {
				new_mailbox_msg(entry)
			}).collect(),
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

		let mailbox_id = MailboxIdentifier::from_slice(req.unblinded_id.as_slice())
			.badarg("invalid unblinded mailbox id")?;
		let auth_bytes = req.authorization.badarg("mailbox authorization required")?;
		let auth = MailboxAuthorization::deserialize(auth_bytes.as_slice())
			.badarg("invalid mailbox authorization")?;
		if auth.mailbox() != mailbox_id {
			self::badarg!("authorization doesn't match mailbox id");
		}
		if auth.is_expired() {
			self::badarg!("mailbox authorization expired");
		}
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
					match db.get_mailbox_messages(mailbox_id, processed_cp, ret_limit).await {
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

		let mailbox_id = MailboxIdentifier::from_slice(req.unblinded_id.as_slice())
			.badarg("invalid unblinded mailbox id")?;

		let checkpoint = self.db.store_vtxo_ids_in_mailbox(MailboxType::RecoveryVtxoId, mailbox_id, vtxo_ids.as_slice()).await.to_status()?
			.badarg("nothing was stored")?;

		self.mailbox_manager.notify(mailbox_id, checkpoint);

		Ok(tonic::Response::new(protos::core::Empty{}))
	}

}

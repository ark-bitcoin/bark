use std::pin::Pin;

use futures::Stream;
use tracing::{error, warn};
use ark::{ProtocolEncoding, Vtxo};
use ark::mailbox::{BlindedMailboxIdentifier, MailboxAuthorization, MailboxIdentifier};
use server_rpc::{self as rpc, protos, TryFromBytes};

use crate::database::Checkpoint;
use crate::rpcserver::{StatusContext, ToStatus, ToStatusResult};
use crate::rpcserver::macros::badarg;

fn new_mailbox_msg(checkpoint: Checkpoint, vtxos: Vec<Vtxo>) -> protos::mailbox_server::MailboxMessage {
	protos::mailbox_server::MailboxMessage {
		message: Some(protos::mailbox_server::mailbox_message::Message::Arkoor(
			protos::mailbox_server::ArkoorMessage {
				vtxos: vtxos.into_iter().map(|v| v.serialize()).collect(),
			}
		)),
		checkpoint,
	}
}

#[async_trait]
impl rpc::server::MailboxService for crate::Server {
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

		let blinded_mailbox_id = BlindedMailboxIdentifier::from_bytes(&req.blinded_id.as_slice())?;
		// should all have same pubkey
		let vtxo_pubkey = vtxos[0].user_pubkey();
		if !vtxos.iter().skip(1).all(|v| v.user_pubkey() == vtxo_pubkey) {
			self::badarg!("all vtxos should share vtxo pubkey when mailbox is provided");
		}

		let mailbox_id = self.unblind_mailbox_id(blinded_mailbox_id, vtxo_pubkey);

		let checkpoint = self.db.store_vtxos_in_mailbox(mailbox_id, vtxos.as_slice()).await.to_status()?
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
		let limit = self.config.read_mailbox_max_items;
		let vtxos_by_checkpoint = self.db.get_vtxos_mailbox(
			unblinded_id,
			req.checkpoint,
			limit,
		).await.to_status()?;

		let response = protos::mailbox_server::MailboxMessages {
			have_more: vtxos_by_checkpoint.len() >= limit,
			messages: vtxos_by_checkpoint.into_iter().map(|(checkpoint, vtxos)| {
				new_mailbox_msg(checkpoint, vtxos)
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
		let ret_limit = self.config.read_mailbox_max_items;

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
					match db.get_vtxos_mailbox(mailbox_id, processed_cp, ret_limit).await {
						Ok(entries) => {
							let done = entries.len() < ret_limit;
							for (cp, vtxos) in entries {
								let msg = new_mailbox_msg(cp, vtxos);
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
}

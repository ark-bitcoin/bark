use std::pin::Pin;

use bitcoin::hex::DisplayHex;
use futures::Stream;
use opentelemetry::KeyValue;
use tracing::{error, warn};
use ark::{ProtocolEncoding, Vtxo};
use ark::mailbox::{BlindedMailboxIdentifier, MailboxAuthorization, MailboxIdentifier};
use server_rpc::{self as rpc, protos, TryFromBytes};

use crate::database::Checkpoint;
use crate::rpcserver::{StatusContext, ToStatus, ToStatusResult};
use crate::rpcserver::macros;

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
	async fn post_vtxos_mailbox(
		&self,
		req: tonic::Request<protos::mailbox_server::PostVtxosMailboxRequest>,
	) -> Result<tonic::Response<protos::core::Empty>, tonic::Status> {
		let _ = crate::rpcserver::middleware::RpcMethodDetails::grpc_ark(
			crate::rpcserver::middleware::rpc_names::ark::POST_VTXOS_MAILBOX,
		);
		let req = req.into_inner();

		crate::rpcserver::add_tracing_attributes(vec![
			KeyValue::new("blinded_id", req.blinded_id.as_hex().to_string())
		]);

		let vtxos = req.vtxos.into_iter()
			.map(|v| Vtxo::from_bytes(v))
			.collect::<Result<Vec<_>, _>>()?;
		if vtxos.is_empty() {
			macros::badarg!("no vtxos provided");
		}

		let blinded_mailbox_id = BlindedMailboxIdentifier::from_bytes(&req.blinded_id.as_slice())?;
		// should all have same pubkey
		let vtxo_pubkey = vtxos[0].user_pubkey();
		if !vtxos.iter().skip(1).all(|v| v.user_pubkey() == vtxo_pubkey) {
			macros::badarg!("all vtxos should share vtxo pubkey when mailbox is provided");
		}

		let mailbox_id = self.unblind_mailbox_id(blinded_mailbox_id, vtxo_pubkey);

		let checkpoint = self.db.store_vtxos_in_mailbox(mailbox_id, vtxos.as_slice()).await.to_status()?
			.badarg("nothing was stored")?;

		self.mailbox_manager.notify(mailbox_id, checkpoint);

		Ok(tonic::Response::new(protos::core::Empty{}))
	}

	async fn read_mailbox(
		&self,
		req: tonic::Request<protos::mailbox_server::MailboxRequest>,
	) -> Result<tonic::Response<protos::mailbox_server::MailboxMessages>, tonic::Status> {
		let _ = crate::rpcserver::middleware::RpcMethodDetails::grpc_ark(
			crate::rpcserver::middleware::rpc_names::ark::READ_MAILBOX,
		);
		let req = req.into_inner();

		crate::rpcserver::add_tracing_attributes(vec![
			KeyValue::new("unblinded_id", req.unblinded_id.as_hex().to_string()),
			KeyValue::new("authorization", req.authorization.clone().unwrap_or(vec![]).as_hex().to_string()),
			KeyValue::new("checkpoint", req.checkpoint.to_string()),
		]);

		let unblinded_id = MailboxIdentifier::from_slice(req.unblinded_id.as_slice())
			.badarg("invalid unblinded mailbox id")?;
		if let Some(auth) = req.authorization {
			let auth = MailboxAuthorization::deserialize(auth.as_slice())
				.badarg("invalid mailbox authorization")?;
			if auth.mailbox() != unblinded_id {
				macros::badarg!("authorization doesn't match mailbox id");
			}
		}
		let vtxos_by_checkpoint = self.db.get_vtxos_mailbox(
			unblinded_id,
			req.checkpoint,
		).await.to_status()?;

		let response = protos::mailbox_server::MailboxMessages {
			messages: vtxos_by_checkpoint.into_iter().map(|(checkpoint, vtxos)| {
				new_mailbox_msg(checkpoint, vtxos)
			}).collect(),
		};

		Ok(tonic::Response::new(response))
	}

	type SubscribeMailboxStream = Pin<Box<
		dyn Stream<Item = Result<protos::mailbox_server::MailboxMessage, tonic::Status>> + Send + 'static
	>>;

	async fn subscribe_mailbox(
		&self,
		req: tonic::Request<protos::mailbox_server::MailboxRequest>,
	) -> Result<tonic::Response<Self::SubscribeMailboxStream>, tonic::Status> {
		let _ = crate::rpcserver::middleware::RpcMethodDetails::grpc_ark(
			crate::rpcserver::middleware::rpc_names::ark::SUBSCRIBE_MAILBOX,
		);
		let req = req.into_inner();

		crate::rpcserver::add_tracing_attributes(vec![
			KeyValue::new("unblinded_id", req.unblinded_id.as_hex().to_string()),
			KeyValue::new("authorization", req.authorization.clone().unwrap_or(vec![]).as_hex().to_string()),
			KeyValue::new("checkpoint", req.checkpoint.to_string()),
		]);

		let mailbox_id = MailboxIdentifier::from_slice(req.unblinded_id.as_slice())
			.badarg("invalid unblinded mailbox id")?;
		if let Some(auth) = req.authorization {
			let auth = MailboxAuthorization::deserialize(auth.as_slice())
				.badarg("invalid mailbox authorization")?;
			if auth.mailbox() != mailbox_id {
				macros::badarg!("authorization doesn't match mailbox id");
			}
		}

		let db = self.db.clone();
		let starting_checkpoint = Checkpoint::from(req.checkpoint.max(0));

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

				match db.get_vtxos_mailbox(mailbox_id, processed_cp).await {
					Ok(entries) => {
						for (cp, vtxos) in entries {
							let msg = new_mailbox_msg(cp, vtxos);
							yield msg;
							processed_cp = cp;
						}
					}
					Err(err) => {
						warn!("Failed to read mailbox from DB: {err:#}");
						Err(err.to_status())?;
					}
				}
			}
		};

		Ok(tonic::Response::new(Box::pin(stream)))
	}
}

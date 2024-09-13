use std::fmt;

use anyhow::Context;
use tonic::transport::Channel;
use tokio::sync::broadcast;

use ark::lightning::PaymentStatus;
use bitcoin::hashes::{ripemd160, sha256, Hash};

use crate::grpc;
use crate::grpc::node_client::NodeClient;

type GrpcClient = NodeClient<Channel>;

pub struct SubscribeSendpay {
	pub client: NodeClient<Channel>,
	pub update_index: u64,
	pub created_index: u64,
}

impl SubscribeSendpay {
	pub async fn run(self, tx: broadcast::Sender<SendpaySubscriptionItem>) -> anyhow::Result<()> {
		let (u_idx, u_grpc, u_rx) = (self.update_index, self.client.clone(), tx.clone());
		let (c_idx, c_grpc, c_rx) = (self.created_index, self.client.clone(), tx.clone());
		let jh1 =  tokio::spawn(async move { updated_loop(u_idx, u_grpc, u_rx).await });
		let jh2 = tokio::spawn(async move { created_loop(c_idx, c_grpc, c_rx).await });

		let _ = futures::future::try_join(jh1, jh2).await
			.context("The task that processes sendpay-updates stopped unexpectedly")?;
		Ok(())
	}
}

#[derive(Debug, Clone)]
pub struct  SendpaySubscriptionItem {
	pub kind: SendpaySubscriptionIndex,
	pub status: PaymentStatus,
	pub part_id: u64,
	pub group_id: u64,
	pub payment_hash: sha256::Hash,
	pub payment_preimage: Option<ripemd160::Hash>,
}

impl fmt::Display for SendpaySubscriptionItem {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		let payment_hash = hex::encode(&self.payment_hash);
		write!(f, "{:?} sendpay with status {:?}. Attempt {} part {} of payment {}",
			self.kind, self.status, self.group_id, self.part_id, payment_hash,
		)
	}
}

#[derive(Debug, Clone)]
pub enum SendpaySubscriptionIndex {
	Created,
	Updated,
	Deleted
}

impl fmt::Display for SendpaySubscriptionIndex {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		fmt::Debug::fmt(self, f)
	}
}

async fn updated_loop(
	mut updated_index: u64,
	mut client: NodeClient<Channel>,
	sender: broadcast::Sender<SendpaySubscriptionItem>,
) -> anyhow::Result<()> {
	loop {
		// Wait for new updates
		let request = grpc::WaitRequest {
			subsystem: grpc::wait_request::WaitSubsystem::Sendpays as i32,
			indexname: grpc::wait_request::WaitIndexname::Updated as i32,
			nextvalue: updated_index,
		};

		match client.wait(request).await {
			Ok(_) => {
				// We know that an update exist
				// We retreive all the updates and process them
				updated_index = process_updated(&mut client, updated_index, &sender).await? + 1;
			}
			Err(e) => {
				trace!("Error in wait sendpay updated: {:?}", e)
			}
		}
	}
}

async fn created_loop(
	mut created_index: u64,
	mut client: NodeClient<Channel>,
	sender: broadcast::Sender<SendpaySubscriptionItem>,
) -> anyhow::Result<()> {
	loop {
		// Wait for new updates
		let request = grpc::WaitRequest {
			subsystem: grpc::wait_request::WaitSubsystem::Sendpays as i32,
			indexname: grpc::wait_request::WaitIndexname::Created as i32,
			nextvalue: created_index,
		};

		match client.wait(request).await {
			Ok(_) => {
				// We know that at least one item was created
				// We query them all and update them
				created_index = process_created(&mut client, created_index, &sender).await? + 1;
			}
			Err(e) => {
				trace!("Error in wait sendpay updated: {:?}", e)
			}
		}
	}
}

async fn process_updated(
	client: &mut GrpcClient,
	start_index: u64,
	tx: &broadcast::Sender<SendpaySubscriptionItem>
)-> anyhow::Result<u64> {
	let listsendpaysrequest = grpc::ListsendpaysRequest {
		bolt11: None,
		payment_hash: None,
		status: None,
		index: Some(grpc::listsendpays_request::ListsendpaysIndex::Updated as i32),
		start: Some(start_index),
		limit: None
	};

	let mut max_index = start_index;

	let updates = client.list_send_pays(listsendpaysrequest).await?.into_inner();
	for update in updates.payments {
		let updated_index = update.updated_index();

		let item = SendpaySubscriptionItem {
			kind: SendpaySubscriptionIndex::Updated,
			status: update.status().into(),
			part_id: update.partid(),
			group_id: update.groupid,
			payment_hash: sha256::Hash::from_slice(&update.payment_hash)?,
			payment_preimage: update.payment_preimage
				.map(|x| ripemd160::Hash::from_slice(&x))
				.transpose()?
		};

		if max_index < updated_index {
			max_index = updated_index;
		}

		trace!("Updated idx={} {:?}", updated_index, item);
		tx.send(item)?;
	}

	Ok(max_index)
}

async fn process_created(
	client: &mut GrpcClient,
	start_index: u64,
	tx: &broadcast::Sender<SendpaySubscriptionItem>
)-> anyhow::Result<u64> {
	let listsendpaysrequest = grpc::ListsendpaysRequest {
		bolt11: None,
		payment_hash: None,
		status: None,
		index: Some(grpc::listsendpays_request::ListsendpaysIndex::Created as i32),
		start: Some(start_index),
		limit: None
	};

	let mut max_index = start_index;

	let updates = client.list_send_pays(listsendpaysrequest).await?.into_inner();
	for update in updates.payments {
		let updated_index = update.updated_index();

		let item = SendpaySubscriptionItem {
			kind: SendpaySubscriptionIndex::Created,
			status: update.status().into(),
			part_id: update.partid(),
			group_id: update.groupid,
			payment_hash: sha256::Hash::from_slice(&update.payment_hash)?,
			payment_preimage: update.payment_preimage
				.map(|x| ripemd160::Hash::from_slice(&x))
				.transpose()?
		};

		if max_index < updated_index {
			max_index = updated_index;
		}

		trace!("Created {:?}", item);
		tx.send(item)?;
	}

	Ok(max_index)
}

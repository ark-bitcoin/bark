
use std::{fmt, fs};
use std::time::{Duration, UNIX_EPOCH, SystemTime};
use std::convert::TryInto;

use anyhow::Context;
use bitcoin::Amount;
use bitcoin::hashes::hex::DisplayHex;
use bitcoin::hashes::{sha256, Hash};
use lightning_invoice::Bolt11Invoice;
use tokio::time::MissedTickBehavior;
use tokio::sync::broadcast;
use tokio_stream::StreamExt;
use tokio_stream::wrappers::{IntervalStream, BroadcastStream};
use tonic::transport::{Channel, ClientTlsConfig, Certificate, Identity};
use log::{trace, debug, info, warn};

use ark::lightning::{SignedBolt11Payment, PaymentStatus};
use cln_rpc::ClnGrpcClient;
use cln_rpc::listsendpays_request::ListsendpaysIndex;
use cln_rpc::node_client::NodeClient;

use crate::config::Lightningd;
use crate::system::RuntimeManager;

type GrpcClient = NodeClient<Channel>;

impl Lightningd {
	pub async fn grpc_client(&self) ->  anyhow::Result<NodeClient<tonic::transport::Channel>> {
		// Client doesn't support grpc over http
		// We need to use https using m-TLS authentication
		let ca_pem = fs::read_to_string(&self.server_cert_path)?;
		let id_pem = fs::read_to_string(&self.client_cert_path)?;
		let id_key = fs::read_to_string(&self.client_key_path)?;

		let channel = Channel::builder(self.uri.clone().into())
			.tls_config(ClientTlsConfig::new()
				.ca_certificate(Certificate::from_pem(ca_pem))
				.identity(Identity::from_pem(&id_pem, &id_key))
				)?
			.connect()
			.await?;

		let client = NodeClient::new(channel);
		Ok(client)
	}

	/// Verifies if the configuration is valid
	pub async fn check_connection(&self) -> anyhow::Result<()> {
		let mut grpc_client = self.grpc_client().await?;
		let _ = grpc_client.getinfo(cln_rpc::GetinfoRequest{}).await?.into_inner();
		Ok(())
	}
}

pub async fn run_process_sendpay_updates(
	rtmgr: RuntimeManager,
	cln_config: &Lightningd,
	tx: broadcast::Sender<SendpaySubscriptionItem>,
) -> anyhow::Result<()> {
	// Get the grpc-client
	let mut client = cln_config.grpc_client().await.context("Failed to connect to lightningd over grpc")?;

	// TODO: I now request the latest start-index from cln
	// However, it is nicer to store the start-indcies somewhere in the database
	// This would allow us to replay all send-pays if aspd crashes and cln keeps running
	let updated_index = client.wait(cln_rpc::WaitRequest {
		subsystem: cln_rpc::wait_request::WaitSubsystem::Sendpays as i32,
		indexname: cln_rpc::wait_request::WaitIndexname::Updated as i32,
		nextvalue: 0
	}).await?.into_inner().updated() + 1;

	let created_index = client.wait(cln_rpc::WaitRequest {
		subsystem: cln_rpc::wait_request::WaitSubsystem::Sendpays as i32,
		indexname: cln_rpc::wait_request::WaitIndexname::Created as i32,
		nextvalue: 0
	}).await?.into_inner().created() + 1;

	info!("Start listening for sendpays for created_index={}, updated_index={}",
		created_index, updated_index,
	);

	let subscribe_send_pay = SubscribeSendpay {
		rtmgr,
		client: client.clone(),
		created_index,
		update_index: updated_index,
	};

	subscribe_send_pay.run(tx).await.context("sendpay processor shut ")?;

	Ok(())
}


/// Calls the pay-command over gRPC.
/// If the payment completes successfully it will return the pre-image
/// Otherwise, an error will be returned
async fn call_pay_bolt11(
	grpc_client: &mut ClnGrpcClient,
	invoice: &Bolt11Invoice,
	amount: Option<Amount>,
) -> anyhow::Result<Vec<u8>> {
	if invoice.amount_milli_satoshis().is_some() && amount.is_some() {
		bail!("The invoice has an amount encoced. Drop the user-amount");
	}
	if invoice.amount_milli_satoshis().is_none() && amount.is_none() {
		bail!("Amount not encoded in invoice nor provided by user. Try providing a user-amount")
	}

	// Call the pay command
	let pay_response = grpc_client.pay(cln_rpc::PayRequest {
		bolt11: invoice.to_string(),
		label: None,
		maxfee: None,
		maxfeepercent: None,
		retry_for: None,
		maxdelay: None,
		amount_msat: {
			if invoice.amount_milli_satoshis().is_none() {
				Some(amount.unwrap().into())
			} else {
				None
			}
		},
		description: None,
		exemptfee: None,
		riskfactor: None,
		exclude: vec![],
		localinvreqid: None,
		partial_msat: None,
	}).await?.into_inner();


	let status_name = pay_response.status().as_str_name();
	let payment_preimage = pay_response.payment_preimage;
	if payment_preimage.len() > 0 {
		Ok(payment_preimage)
	} else {
		bail!("Pay returned with status {}", status_name)
	}
}


/// Pays a bolt-11 invoice and returns the pre-image
///
/// This method is also more clever than calling the grpc-method.
/// We might be able to recover from a short connection-break or time-outs
/// from Core Lightning.
pub async fn pay_bolt11(
	mut cln_client: ClnGrpcClient,
	payment: SignedBolt11Payment,
	sendpay_rx: broadcast::Receiver<SendpaySubscriptionItem>,
) -> anyhow::Result<Vec<u8>> {
	// TODO: Store the payment state somewhere and handle stuck payments properly
	// If your funds get stuck paying a lightning-invoice might take a very long-time.
	let invoice = payment.payment.invoice;
	if invoice.check_signature().is_err() {
		bail!("Invalid signature in Bolt-11 invoice");
	}

	// Set variables related to payment
	let payment_hash = invoice.payment_hash();
	let amount = if invoice.amount_milli_satoshis().is_none() {
		Some(payment.payment.payment_amount)
	} else {
		None
	};
	let payment_start_time = SystemTime::now();


	// Call pay over GRPC
	// If it returns a pre-image we know the call succeeded
	// This method might fail even if the payment will succeed
	// (grpc-connection problems or time-outs).
	// We keep the error-around but will verify if the payment actually failed.
	info!("Forwarding bolt11 invoice of {:?}: {}", amount, invoice);
	let pay_bolt11_err = match call_pay_bolt11(&mut cln_client, &invoice, amount).await {
		Ok(preimage) => {
			debug!("Done, preimage: {} for invoice {}", preimage.as_hex(), invoice);
			return Ok(preimage);
		},
		Err(err) => {
			warn!("Pay returned with erro: {:?}", err);
			err
		}
	};
	debug!("Forward rpc returned without success, polling lightningd for status updates...");

	// I am not sure if we need this
	// IF there is no entry in `listpays` we assume one of the prechecks failed
	// This avoids a possible race-condition where the listpays didn't appear yet
	// TODO: investigate
	tokio::time::sleep(Duration::from_millis(100)).await;

	// TODO: Something bad happened if we trigger the `?`.
	// We should handle it better?
	// This probably means cln went unavailable
	// We don't know the payment status and just give up
	let listpays_response = cln_client.list_pays(cln_rpc::ListpaysRequest {
		bolt11: Some(invoice.to_string()),
		payment_hash: None,
		status: None,
		start: None,
		index: None,
		limit: None,
	}).await.context("internal error occured: Payment status is unknown")?.into_inner();

	if listpays_response.pays.len() == 0 {
		// Pay faield but didn't attempt to make a payment.
		// This means one of the pre-flight checks failed.
		// We return the error message to the user
		warn!("Failed to execute payment: {}", pay_bolt11_err);
		return Err(pay_bolt11_err)
	}


	// We will now start polling `sendpay` to see if the payment succeeded.
	//
	// We will create a stream that indicates when we should poll `sendpay`.
	// The stream doesn't contain any data. All items are `()`. But whenever
	// a new item appears we will poll `sendpay`.

	// The heart-beat ensures we triggers every 10 seconds
	let mut interval = tokio::time::interval(std::time::Duration::from_secs(10));
	interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
	let heartbeat_stream = IntervalStream::new(interval).map(|_| ());

	// whenever we receive an update that is relevant to the current payment
	// we will poll again. We just ignnore errors in this stream.
	// We only provide the updates at a best-effort basis. The heart-beat
	// will ensure we never starve the loop.
	let sendpay_stream = BroadcastStream::new(sendpay_rx.resubscribe())
		.filter_map(Result::ok)
		.filter(|item| item.payment_hash == *payment_hash)
		.map(|_| ());

	// Do the polling
	let mut stream = sendpay_stream.merge(heartbeat_stream);
	while let Some(_) = stream.next().await {
		let (status, preimage) = invoice_pay_status(&mut cln_client, &invoice, payment_start_time).await?;
		trace!("Bolt11 status {} for invoice {}", status, invoice);
		match status {
			PaymentStatus::Complete => {
				let preimage = preimage.expect("preimage on succeed");
				debug!("Done, preimage: {} for invoice {}", preimage.as_hex(), invoice);
				return Ok(preimage);
			},
			PaymentStatus::Failed => bail!("Payment failed"),
			PaymentStatus::Pending => {},
		}
	};

	panic!("Error making payment. We should never get here as the stream above should never close");
}

async fn invoice_pay_status(
	cln_client: &mut ClnGrpcClient,
	bolt11_invoice: &Bolt11Invoice,
	since: SystemTime,
) -> anyhow::Result<(PaymentStatus, Option<Vec<u8>>)> {
	let listpays_response = cln_client.list_pays(cln_rpc::ListpaysRequest {
		bolt11: Some(bolt11_invoice.to_string()),
		payment_hash: None,
		status: None,
		limit: None,
		index: None,
		start: None,
	}).await.context("Internal error occured: Payment status is unknown")?.into_inner();

	for pay in listpays_response.pays.iter() {
		if pay.created_at > since.duration_since(UNIX_EPOCH).unwrap().as_secs() {
			let ret = match pay.status().into() {
				PaymentStatus::Complete => (PaymentStatus::Complete, Some(pay.preimage().to_vec())),
				PaymentStatus::Pending => (PaymentStatus::Pending, None),
				PaymentStatus::Failed => (PaymentStatus::Failed, None),
			};
			return Ok(ret);
		}
	}

	return Ok((PaymentStatus::Failed, None))
}

pub struct SubscribeSendpay {
	rtmgr: RuntimeManager,
	pub client: NodeClient<Channel>,
	pub update_index: u64,
	pub created_index: u64,
}

impl SubscribeSendpay {
	pub async fn run(self, tx: broadcast::Sender<SendpaySubscriptionItem>) -> anyhow::Result<()> {
		let (u_idx, u_grpc, u_rx) = (self.update_index, self.client.clone(), tx.clone());
		let rtmgr = self.rtmgr.clone();
		let jh1 = tokio::spawn(async move {
			let _worker = rtmgr.spawn_critical("SubscribeSendpayUpdated");
			tokio::select! {
				res = updated_loop(u_idx, u_grpc, u_rx) => res,
				_ = rtmgr.shutdown_signal() => Ok(()),
			}
		});

		let (c_idx, c_grpc, c_rx) = (self.created_index, self.client.clone(), tx.clone());
		let rtmgr = self.rtmgr.clone();
		let jh2 = tokio::spawn(async move {
			let _worker = rtmgr.spawn_critical("SubscribeSendpayCreated");
			tokio::select! {
				res = created_loop(c_idx, c_grpc, c_rx) => res,
				_ = rtmgr.shutdown_signal() => Ok(()),
			}
		});

		let (created_output, updated_output) = futures::future::try_join(jh1, jh2).await
			.context("The task that processes sendpay-updates stopped unexpectedly")?;

		created_output.context("created")?;
		updated_output.context("updated")?;

		Ok(())
	}
}

#[derive(Debug, Clone)]
pub struct  SendpaySubscriptionItem {
	pub kind: ListsendpaysIndex,
	pub status: PaymentStatus,
	pub part_id: u64,
	pub group_id: u64,
	pub payment_hash: sha256::Hash,
	pub payment_preimage: Option<[u8; 32]>,
}

impl fmt::Display for SendpaySubscriptionItem {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{:?} sendpay with status {:?}. Attempt {} part {} of payment {}",
			self.kind, self.status, self.group_id, self.part_id,
			self.payment_hash.to_byte_array().as_hex(),
		)
	}
}

async fn updated_loop(
	mut updated_index: u64,
	mut client: NodeClient<Channel>,
	sender: broadcast::Sender<SendpaySubscriptionItem>,
) -> anyhow::Result<()> {
	loop {
		// Wait for sendpay updates
		let request = cln_rpc::WaitRequest {
			subsystem: cln_rpc::wait_request::WaitSubsystem::Sendpays as i32,
			indexname: cln_rpc::wait_request::WaitIndexname::Updated as i32,
			nextvalue: updated_index,
		};

		match client.wait(request).await {
			Ok(_) => {
				// We know that an update exist
				// We retreive all the updates and process them
				updated_index = process_sendpay(
					&mut client,
					ListsendpaysIndex::Updated,
					updated_index,
					&sender
				).await? + 1;
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
		// Wait for new sendpay creation
		let request = cln_rpc::WaitRequest {
			subsystem: cln_rpc::wait_request::WaitSubsystem::Sendpays as i32,
			indexname: cln_rpc::wait_request::WaitIndexname::Created as i32,
			nextvalue: created_index,
		};

		match client.wait(request).await {
			Ok(_) => {
				// We know that at least one item was created
				// We query them all and update them
				created_index = process_sendpay(
					&mut client,
					ListsendpaysIndex::Created,
					created_index,
					&sender
				).await? + 1;
			}
			Err(e) => trace!("Error in wait sendpay updated: {:?}", e)
		}
	}
}

async fn process_sendpay(
	client: &mut GrpcClient,
	kind: ListsendpaysIndex,
	start_index: u64,
	tx: &broadcast::Sender<SendpaySubscriptionItem>
)-> anyhow::Result<u64> {
	let listsendpaysrequest = cln_rpc::ListsendpaysRequest {
		bolt11: None,
		payment_hash: None,
		status: None,
		index: Some(kind as i32),
		start: Some(start_index),
		limit: None
	};

	let mut max_index = start_index;

	let updates = client.list_send_pays(listsendpaysrequest).await?.into_inner();
	for update in updates.payments {
		let updated_index = update.updated_index();

		let item = SendpaySubscriptionItem {
			kind: kind,
			status: update.status().into(),
			part_id: update.partid(),
			group_id: update.groupid,
			payment_hash: sha256::Hash::from_slice(&update.payment_hash)?,
			payment_preimage: update.payment_preimage.map(|p| p[..].try_into()).transpose()?,
		};

		if max_index < updated_index {
			max_index = updated_index;
		}

		match kind {
			ListsendpaysIndex::Created => trace!("Created {:?}", item),
			ListsendpaysIndex::Updated =>
				trace!("Updated idx={} {:?}", updated_index, item),
		}

		tx.send(item)?;
	}

	Ok(max_index)
}

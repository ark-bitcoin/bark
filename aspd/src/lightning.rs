use std::fs;
use std::time::{Duration, UNIX_EPOCH, SystemTime};

use anyhow::Context;
use bitcoin::Amount;
use lightning_invoice::Bolt11Invoice;
use tonic::transport::{Channel, ClientTlsConfig, Certificate, Identity};
use tokio::time::MissedTickBehavior;
use tokio_stream::StreamExt;
use tokio_stream::wrappers::{IntervalStream, BroadcastStream};
use tokio::sync::broadcast;

use ark::lightning::{SignedBolt11Payment, PaymentStatus};
use bark_cln::ClnGrpcClient;
use bark_cln::grpc;
use bark_cln::grpc::node_client::NodeClient;
use bark_cln::subscribe_sendpay::{SubscribeSendpay, SendpaySubscriptionItem};

use crate::ClnConfig;

impl ClnConfig {

	pub async fn grpc_client(&self) ->  anyhow::Result<NodeClient<tonic::transport::Channel>> {
		// Client doesn't support grpc over http
		// We need to use https using m-TLS authentication
		let ca_pem = fs::read_to_string(&self.grpc_server_cert_path)?;
		let id_pem = fs::read_to_string(&self.grpc_client_cert_path)?;
		let id_key = fs::read_to_string(&self.grpc_client_key_path)?;

		let channel = Channel::builder(self.grpc_uri.clone().into())
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
		let _ = grpc_client.getinfo(grpc::GetinfoRequest{}).await?.into_inner();
		Ok(())
	}
}

pub async fn run_process_sendpay_updates(
	cln_config: &ClnConfig,
	tx: broadcast::Sender<SendpaySubscriptionItem>,
) -> anyhow::Result<()> {
	// Get the grpc-client
	let mut client = cln_config.grpc_client().await.context("Failed to connect to lightningd over grpc")?;

	// TODO: I now request the latest start-index from cln
	// However, it is nicer to store the start-indcies somewhere in the database
	// This would allow us to replay all send-pays if aspd crashes and cln keeps running
	let updated_index = client.wait(grpc::WaitRequest {
		subsystem: grpc::wait_request::WaitSubsystem::Sendpays as i32,
		indexname: grpc::wait_request::WaitIndexname::Updated as i32,
		nextvalue: 0
	}).await?.into_inner().updated() + 1;
	let created_index = client.wait(grpc::WaitRequest {
		subsystem: grpc::wait_request::WaitSubsystem::Sendpays as i32,
		indexname: grpc::wait_request::WaitIndexname::Created as i32,
		nextvalue: 0
	}).await?.into_inner().created() + 1;

	info!("Start listening for sendpays for created_index={}, updated_index={}",
		created_index, updated_index,
	);

	let subscribe_send_pay = SubscribeSendpay {
		client: client.clone(),
		created_index: created_index,
		update_index: updated_index,
	};

	subscribe_send_pay.run(tx).await.context("sendpay processor shut ")?;
	Ok(())
}


/// Calls the pay-command over gRPC.
/// If the payment completes successfully it will return the pre-image
/// Otherwise, an error will be returned
pub async fn call_pay_bolt11(
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
	let pay_response = grpc_client.pay(grpc::PayRequest {
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
	let pay_bolt11_err = match call_pay_bolt11(&mut cln_client, &invoice, amount).await {
		Ok(preimage) => return Ok(preimage),
		Err(err) => {
			warn!("Pay returned with erro: {:?}", err);
			err
		}
	};

	// I am not sure if we need this
	// IF there is no entry in `listpays` we assume one of the prechecks failed
	// This avoids a possible race-condition where the listpays didn't appear yet
	// TODO: investigate
	tokio::time::sleep(Duration::from_millis(100)).await;

	// Todo: Something bad happened if we trigger the `?`.
	// We should handle it better?
	// This probably means cln went unavailable
	// We don't know the payment status and just give up
	let listpays_response = cln_client.list_pays(grpc::ListpaysRequest {
		bolt11: Some(invoice.to_string()),
		payment_hash: None,
		status: None,
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
	// The stream doesn't contain any data. All items are `()`. But whenver
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
		match status {
			PaymentStatus::Complete => return Ok(preimage.expect("preimage on succeed")),
			PaymentStatus::Failed => bail!("Payment failed"),
			PaymentStatus::Pending => {},
		}
	};

	panic!("Error making payment. We should never get here as the stream above should never close");
}

pub async fn invoice_pay_status(
	cln_client: &mut ClnGrpcClient,
	bolt11_invoice: &Bolt11Invoice,
	since: SystemTime,
) -> anyhow::Result<(PaymentStatus, Option<Vec<u8>>)> {
	let listpays_response = cln_client.list_pays(grpc::ListpaysRequest {
		bolt11: Some(bolt11_invoice.to_string()),
		payment_hash: None,
		status: None,
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

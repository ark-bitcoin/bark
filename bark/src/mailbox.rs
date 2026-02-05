
pub extern crate ark;

pub extern crate bip39;
pub extern crate lightning_invoice;
pub extern crate lnurl as lnurllib;

use std::collections::HashMap;

use anyhow::Context;
use bitcoin::Amount;
use bitcoin::hex::DisplayHex;
use bitcoin::secp256k1::Keypair;
use log::{debug, error, info};

use ark::{ProtocolEncoding, Vtxo};
use ark::mailbox::MailboxIdentifier;
use protos::mailbox_server::mailbox_message;
use server_rpc::protos;
use server_rpc::protos::mailbox_server::ArkoorMessage;
use crate::movement::{MovementDestination, MovementStatus};
use crate::movement::update::MovementUpdate;
use crate::Wallet;
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

impl Wallet {
	/// Fetch the mailbox keypair.
	pub fn mailbox_keypair(&self) -> anyhow::Result<Keypair> {
		Ok(self.seed.to_mailbox_keypair())
	}

	/// Sync with the mailbox on the Ark server and look for out-of-round received VTXOs.
	pub async fn sync_mailbox(&self) -> anyhow::Result<()> {
		let mut srv = self.require_server()?;

		let mailbox_id = MailboxIdentifier::from_pubkey(self.mailbox_keypair()?.public_key());

		for _ in 0..MAX_MAILBOX_REQUEST_BURST {
			let checkpoint = self.get_mailbox_checkpoint().await?;
			let mailbox_req = protos::mailbox_server::MailboxRequest {
				unblinded_id: mailbox_id.to_vec(),
				// TODO (mailbox): Add support for mailbox authorization
				authorization: None,
				checkpoint,
			};

			let mailbox_resp = srv.mailbox_client.read_mailbox(mailbox_req).await
				.context("error fetching mailbox")?.into_inner();
			debug!("Ark server has {} mailbox messages for us", mailbox_resp.messages.len());

			for mailbox_msg in mailbox_resp.messages {
				match mailbox_msg.message {
					Some(mailbox_message::Message::Arkoor(ArkoorMessage { vtxos })) => {
						let result = self
							.process_received_arkoor_package(vtxos, Some(mailbox_msg.checkpoint)).await;
						if let Err(e) = result {
							error!("Error processing received arkoor package: {:#}", e);
						}
					},
					None => debug!("Unknown mailbox message: {:?}", mailbox_msg),
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
	) -> Vec<Vtxo> {
		let mut invalid_vtxos = Vec::with_capacity(raw_vtxos.len());
		let mut valid_vtxos = Vec::with_capacity(raw_vtxos.len());

		for bytes in &raw_vtxos {
			let vtxo = match Vtxo::deserialize(&bytes) {
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

			info!("Received valid arkoor VTXO {}", vtxo.serialize_hex());
			valid_vtxos.push(vtxo);
		}

		// We log all invalid VTXOs to keep track
		if !invalid_vtxos.is_empty() {
			error!("Received {} invalid arkoor VTXOs out of {} from server", invalid_vtxos.len(), raw_vtxos.len());
		}

		// We log all valid VTXOs to keep track
		if !valid_vtxos.is_empty() {
			for vtxo in &valid_vtxos {
				info!("Valid arkoor VTXO: {}", vtxo.serialize_hex());
			}
			info!("Received {} valid arkoor VTXOs out of {} from server", valid_vtxos.len(), raw_vtxos.len());
		}

		valid_vtxos
	}

	async fn process_received_arkoor_package(
		&self,
		raw_vtxos: Vec<Vec<u8>>,
		checkpoint: Option<u64>,
	) -> anyhow::Result<()> {
		let vtxos = self.process_raw_vtxos(raw_vtxos).await;

		let mut new_vtxos = Vec::with_capacity(vtxos.len());
		for vtxo in &vtxos {
			// Skip if already in wallet
			if self.db.get_wallet_vtxo(vtxo.id()).await?.is_some() {
				info!("Ignoring duplicate arkoor VTXO {}", vtxo.id());
				continue;
			}

			new_vtxos.push(vtxo);
		}

		if new_vtxos.is_empty() {
			return Ok(());
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
				if let Ok(address) = self.peak_address(index).await {
					*received_by_address.entry(address).or_default() += vtxo.amount();
				}
			}
		}
		let received_on: Vec<_> = received_by_address
			.into_iter()
			.map(|(addr, amount)| MovementDestination::ark(addr, amount))
			.collect();

		self.movements.new_finished_movement(
			Subsystem::ARKOOR,
			ArkoorMovement::Receive.to_string(),
			MovementStatus::Successful,
			MovementUpdate::new()
				.produced_vtxos(&vtxos)
				.intended_and_effective_balance(balance)
				.received_on(received_on),
		).await?;

		if let Some(checkpoint) = checkpoint {
			self.store_mailbox_checkpoint(checkpoint).await?;
		}

		Ok(())
	}

	async fn get_mailbox_checkpoint(&self) -> anyhow::Result<u64> {
		Ok(self.db.get_mailbox_checkpoint().await?)
	}

	async fn store_mailbox_checkpoint(&self, checkpoint: u64) -> anyhow::Result<()> {
		Ok(self.db.store_mailbox_checkpoint(checkpoint).await?)
	}
}

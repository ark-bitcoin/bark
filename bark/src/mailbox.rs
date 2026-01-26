
pub extern crate ark;

pub extern crate bip39;
pub extern crate lightning_invoice;
pub extern crate lnurl as lnurllib;


use anyhow::Context;
use bitcoin::Amount;
use bitcoin::hex::DisplayHex;
use bitcoin::secp256k1::{Keypair, PublicKey};
use log::{debug, error, info};

use ark::{ProtocolEncoding, Vtxo};
use ark::mailbox::MailboxIdentifier;
use protos::mailbox_server::mailbox_message;
use server_rpc::{self as rpc, protos};
use server_rpc::protos::mailbox_server::ArkoorMessage;
use crate::movement::MovementStatus;
use crate::movement::update::MovementUpdate;
use crate::Wallet;
use crate::subsystem::{ArkoorMovement, Subsystem};

impl Wallet {
	/// Fetch the mailbox keypair.
	pub fn mailbox_keypair(&self) -> anyhow::Result<Keypair> {
		Ok(self.seed.to_mailbox_keypair())
	}

	pub async fn sync_oors(&self) -> anyhow::Result<()> {
		let last_pk_index = self.db.get_last_vtxo_key_index().await?.unwrap_or_default();
		let pubkeys = (0..=last_pk_index).map(|idx| {
			self.seed.derive_vtxo_keypair(idx).public_key()
		}).collect::<Vec<_>>();

		self.sync_arkoor_for_pubkeys(&pubkeys).await?;

		self.sync_mailbox().await?;

		Ok(())
	}

	/// Sync with the Ark server and look for out-of-round received VTXOs by public key.
	async fn sync_arkoor_for_pubkeys(
		&self,
		public_keys: &[PublicKey],
	) -> anyhow::Result<()> {
		let mut srv = self.require_server()?;

		for pubkeys in public_keys.chunks(rpc::MAX_NB_MAILBOX_PUBKEYS) {
			// Then sync OOR vtxos.
			debug!("Emptying OOR mailbox at Ark server...");
			let req = protos::ArkoorVtxosRequest {
				pubkeys: pubkeys.iter().map(|pk| pk.serialize().to_vec()).collect(),
			};

			#[allow(deprecated)]
			let packages = srv.client.empty_arkoor_mailbox(req).await
				.context("error fetching oors")?.into_inner().packages;
			debug!("Ark server has {} arkoor packages for us", packages.len());

			for package in packages {
				let result = self
					.process_received_arkoor_package(package.vtxos, None).await;
				if let Err(e) = result {
					error!("Error processing received arkoor package: {:#}", e);
				}
			}
		}

		Ok(())
	}

	/// Sync with the mailbox on the Ark server and look for out-of-round received VTXOs.
	async fn sync_mailbox(&self) -> anyhow::Result<()> {
		let mut srv = self.require_server()?;

		let mailbox_id = MailboxIdentifier::from_pubkey(self.mailbox_keypair()?.public_key());
		let checkpoint = self.get_mailbox_checkpoint().await?;
		let mailbox_req = protos::mailbox_server::MailboxRequest {
			unblinded_id: mailbox_id.to_vec(),
			// TODO (mailbox): Add support for mailbox authorization
			authorization: None,
			checkpoint,
		};
		let mailbox_msgs = srv.mailbox_client.read_mailbox(mailbox_req).await
			.context("error fetching mailbox")?.into_inner().messages;
		debug!("Ark server has {} mailbox messages for us", mailbox_msgs.len());

		for mailbox_msg in mailbox_msgs {
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
		self.movements.new_finished_movement(
			Subsystem::ARKOOR,
			ArkoorMovement::Receive.to_string(),
			MovementStatus::Successful,
			MovementUpdate::new()
				.produced_vtxos(&vtxos)
				.intended_and_effective_balance(balance),
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

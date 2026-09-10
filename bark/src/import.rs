//! Manual VTXO import.
//!
//! An import re-adds a VTXO the wallet has no record of but can prove it owns,
//! after a lost database or a restore from an older backup.
//!
//! The wallet owns a VTXO when it can derive the VTXO's user pubkey from its
//! seed. That keypair also authorizes the query that asks the server whether
//! the VTXO is spent. A spent VTXO is stored as spent rather than refused,
//! since it is part of the wallet's history.

use anyhow::{anyhow, Context};
use bitcoin::secp256k1::Keypair;
use log::{info, warn};

use ark::{Vtxo, VtxoId};
use ark::vtxo::Full;
use server_rpc::protos::VtxoSpendState;

use crate::Wallet;
use crate::vtxo::{VtxoState, VtxoValidationError};

/// Why a VTXO could not be imported.
#[derive(Debug, thiserror::Error)]
pub enum ImportVtxoError {
	#[error("vtxo {id} failed to validate: {source}")]
	Invalid {
		id: VtxoId,
		source: VtxoValidationError,
	},

	#[error("unable to derive the key for vtxo {id} from this seed with a {gap_limit} gap limit")]
	KeyNotFound {
		id: VtxoId,
		gap_limit: u32,
	},

	#[error("vtxo {id} is neither spendable nor spent, so it cannot be imported: the server \
		reports it as {state:?}")]
	InFlight {
		id: VtxoId,
		state: VtxoSpendState,
	},

	#[error("unexpected error: {0:#}")]
	Transient(#[from] anyhow::Error),
}

/// Arguments for [`Wallet::import_vtxos`].
#[derive(Debug, Clone, Default)]
pub struct ImportVtxoArgs {
	/// Gap limit for the key scan that decides whether we own the VTXOs,
	/// overriding [`crate::Config::vtxo_key_gap_limit`].
	///
	/// Default: none
	pub gap_limit: Option<u32>,

	/// Import as spendable without asking the server for each VTXO's state. Skipping it can leave
	/// the wallet with spent VTXOs incorrectly marked as spendable.
	///
	/// Default: false
	pub skip_status_check: bool,

	/// Keep the VTXOs that import successfully even when another one in the
	/// batch fails. The returned ids are the ones that were kept.
	///
	/// Default: false, so a single failure discards the whole batch.
	pub allow_partial: bool,
}

impl Wallet {
	/// Manually import VTXOs into the wallet.
	///
	/// Returns the ids now held, whether this call stored them or found them
	/// already there, so a failed batch can be retried. Each VTXO is stored in the
	/// state the server reports. One VTXO that cannot be imported discards the
	/// whole batch, unless [`ImportVtxoArgs::allow_partial`] is set: the VTXOs
	/// that did import are then kept, and the failure is logged.
	pub async fn import_vtxos(
		&self,
		vtxos: &[Vtxo<Full>],
		args: ImportVtxoArgs,
	) -> Result<Vec<VtxoId>, ImportVtxoError> {
		let mut ids = Vec::<VtxoId>::with_capacity(vtxos.len());
		let mut pending = Vec::<&Vtxo<Full>>::with_capacity(vtxos.len());
		for vtxo in vtxos {
			let vtxo_id = vtxo.id();
			if self.inner.db.get_wallet_vtxo(vtxo_id).await?.is_some() {
				info!("VTXO {} already exists in wallet, skipping import", vtxo_id);
				ids.push(vtxo_id);
			} else if !pending.iter().any(|v| v.id() == vtxo_id) {
				if let Err(e) = self.validate_vtxo(vtxo).await {
					let e = ImportVtxoError::Invalid { id: vtxo_id, source: e };
					if !args.allow_partial {
						return Err(e);
					}
					warn!("Not importing vtxo {vtxo_id}: {e}");
				} else {
					pending.push(vtxo);
				}
			}
		}
		if pending.is_empty() {
			return Ok(ids);
		}

		let gap_limit = args.gap_limit.unwrap_or(self.inner.config.vtxo_key_gap_limit);
		// Collected before the await: a closure over `&&Vtxo` held across it is not
		// general enough over lifetimes for the axum handler's Send bound.
		let user_pubkeys = pending.iter().map(|v| v.user_pubkey()).collect::<Vec<_>>();
		let keypairs = self.find_vtxo_keypairs(user_pubkeys, gap_limit).await
			.context("error scanning the vtxo key space")?;

		let mut to_store = Vec::with_capacity(pending.len());
		for vtxo in &pending {
			let id = vtxo.id();
			let state = match keypairs.get(&vtxo.user_pubkey()) {
				None => Err(ImportVtxoError::KeyNotFound { id, gap_limit }),
				Some(keypair) => self.import_vtxo_state(vtxo, keypair, &args).await,
			};
			match state {
				Ok(state) => to_store.push((*vtxo, state)),
				Err(e) => {
					if !args.allow_partial {
						return Err(e);
					}
					warn!("Not importing vtxo {id}: {e}");
				},
			}
		}
		if to_store.is_empty() {
			return Ok(ids);
		}

		let rows = to_store.iter().map(|(v, s)| (*v, s)).collect::<Vec<_>>();
		self.inner.db.store_vtxos(&rows).await
			.context("failed to store imported VTXOs")?;

		for (vtxo, state) in &to_store {
			info!("Successfully imported VTXO {} as {}", vtxo.id(), state.kind());
			ids.push(vtxo.id());
		}

		Ok(ids)
	}

	/// The state to store `vtxo` in, which the server decides unless the caller
	/// opted out of the query.
	///
	/// `keypair` must be `vtxo`'s user keypair: it signs the attestation the
	/// query needs.
	async fn import_vtxo_state(
		&self,
		vtxo: &Vtxo<Full>,
		keypair: &Keypair,
		args: &ImportVtxoArgs,
	) -> Result<VtxoState, ImportVtxoError> {
		if args.skip_status_check {
			return Ok(VtxoState::Spendable);
		}

		let id = vtxo.id();
		Ok(match self.fetch_vtxo_spend_state(id, keypair).await? {
			VtxoSpendState::Spendable => VtxoState::Spendable,
			VtxoSpendState::Spent => VtxoState::Spent,
			state @ (
				VtxoSpendState::Unclaimed
				| VtxoSpendState::Unregistered
				| VtxoSpendState::HtlcRecvUnclaimed
			) => return Err(ImportVtxoError::InFlight { id, state }),
			VtxoSpendState::Unspecified => return Err(ImportVtxoError::Transient(
				anyhow!("server returned an unspecified spend state for vtxo {id}"),
			)),
		})
	}

	/// Manually import a single VTXO into the wallet.
	///
	/// See [`Wallet::import_vtxos`], which this defers to.
	pub async fn import_vtxo(
		&self,
		vtxo: &Vtxo<Full>,
		args: ImportVtxoArgs,
	) -> Result<(), ImportVtxoError> {
		self.import_vtxos(std::slice::from_ref(vtxo), args).await?;
		Ok(())
	}
}

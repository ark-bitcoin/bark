//! Arkoor receive wallet action.
//!
//! The received VTXOs are immutable and live on [`ArkoorReceive`]; the mutable
//! bit is the [`Progress`] enum. The VTXOs are stored locked by the action and
//! only become spendable once the server registers them.

use std::collections::HashMap;

use anyhow::Context;
use bitcoin::Amount;
use bitcoin::hashes::{sha256, Hash, HashEngine};
use log::{error, info, warn};
use server_rpc::StatusExt;

use ark::{Vtxo, VtxoId};
use ark::vtxo::Full;
use ark::vtxo::policy::VtxoPolicyKind;
use ark::vtxo::policy::signing::VtxoSigner;

use crate::Wallet;
use crate::actions::{
	Advance, AdvanceError, IntoAdvanceResult, WalletAction, WalletActionCheckpoint, WalletActionId,
};
use crate::movement::{MovementDestination, MovementStatus};
use crate::movement::update::MovementUpdate;
use crate::subsystem::{ArkoorMovement, Subsystem};
use crate::vtxo::{VtxoLockHolder, VtxoValidationError};

const ARKOOR_RECV_NAMESPACE: &str = "arkoor_recv";

/// A received arkoor package, persisted as a single checkpoint row from the
/// moment the wallet reads it from its mailbox.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArkoorReceive {
	// Immutable state:
	pub id: WalletActionId,
	/// The received VTXOs, sorted by id.
	#[serde(with = "ark::encode::serde::vec")]
	pub vtxos: Vec<Vtxo<Full>>,

	// Mutable state:
	pub progress: Progress,
}

impl ArkoorReceive {
	/// A receive of the given VTXOs, which must not be empty. Its id is a hash
	/// of the sorted VTXO ids, so a package always maps to the same action and
	/// two packages share an action only if they hold the same VTXOs.
	pub(crate) fn new(mut vtxos: Vec<Vtxo<Full>>) -> anyhow::Result<Self> {
		if vtxos.is_empty() {
			bail!("an arkoor receive needs at least one VTXO");
		}
		vtxos.sort_unstable_by_key(|v| v.id());
		let mut engine = sha256::Hash::engine();
		for vtxo in &vtxos {
			engine.input(&vtxo.id().to_bytes());
		}
		let hash = sha256::Hash::from_engine(engine);
		Ok(ArkoorReceive {
			id: format!("{ARKOOR_RECV_NAMESPACE}.{hash}"),
			vtxos,
			progress: Progress::Received,
		})
	}

	pub fn id(&self) -> WalletActionId {
		self.id.clone()
	}

	pub fn vtxo_ids(&self) -> impl Iterator<Item = VtxoId> + '_ {
		self.vtxos.iter().map(|v| v.id())
	}

	/// The VTXOs not refused before being stored.
	fn valid_vtxos<'a>(
		&'a self,
		resolution: &'a Resolution,
	) -> impl Iterator<Item = &'a Vtxo<Full>> + 'a {
		self.vtxos.iter().filter(|v| !resolution.invalid.contains(&v.id()))
	}
}

/// The phases of an arkoor receive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Progress {
	/// The package was read from the mailbox. Its VTXOs are neither validated
	/// nor stored yet.
	Received,
	/// The VTXOs not refused are stored locked by the action. Each drive asks
	/// the server to register the stored VTXOs that are neither registered nor
	/// lost yet, and a drive that leaves some of them unresolved records a
	/// pending receive movement.
	Registering(Resolution),
	/// Every VTXO is refused, registered or lost. The registered ones still
	/// need to become spendable and the lost ones spent.
	Settling(Resolution),
}

/// The VTXOs of the receive that are not to be registered any more.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Resolution {
	/// The VTXOs refused before being stored, sorted. See
	/// [`validate_arkoor_receive`].
	pub invalid: Vec<VtxoId>,
	/// The VTXOs the server registered, sorted.
	pub registered: Vec<VtxoId>,
	/// The VTXOs whose chain lost a double spend on-chain, sorted.
	pub lost: Vec<VtxoId>,
}

impl Resolution {
	fn is_resolved(&self, id: VtxoId) -> bool {
		self.invalid.contains(&id) || self.registered.contains(&id) || self.lost.contains(&id)
	}
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl WalletAction for ArkoorReceive {
	fn id(&self) -> WalletActionId { ArkoorReceive::id(self) }

	fn from_checkpoint(checkpoint: WalletActionCheckpoint) -> Option<Self> {
		checkpoint.into_arkoor_receive()
	}

	async fn advance(self, wallet: &Wallet) -> Result<Advance<Self>, AdvanceError> {
		let progress = match &self.progress {
			Progress::Received => {
				let resolution = Resolution {
					invalid: validate_arkoor_receive(wallet, &self).await?,
					..Resolution::default()
				};
				if self.vtxo_ids().all(|id| resolution.is_resolved(id)) {
					warn!("Arkoor receive {} has no valid VTXO, dropping it", self.id);
					return Ok(Advance::Done);
				}
				start_arkoor_receive(wallet, &self, &resolution).await?;
				Progress::Registering(resolution)
			},
			Progress::Registering(resolution) => {
				let resolution = match register_arkoor_receive(wallet, &self, resolution.clone()).await {
					Ok(resolution) => resolution,
					Err(e) => {
						record_pending_arkoor_receive(wallet, &self, resolution).await?;
						return Err(e);
					},
				};
				if self.vtxo_ids().all(|id| resolution.is_resolved(id)) {
					Progress::Settling(resolution)
				} else {
					record_pending_arkoor_receive(wallet, &self, &resolution).await?;
					return Ok(Advance::Park {
						state: ArkoorReceive { progress: Progress::Registering(resolution), ..self },
						wake_after: None,
						error: None,
					});
				}
			},
			Progress::Settling(resolution) => {
				settle_arkoor_receive(wallet, &self, resolution).await?;
				return Ok(Advance::Done);
			},
		};

		Ok(Advance::Next(ArkoorReceive { progress, ..self }))
	}

	/// None: the VTXOs are not the wallet's until the server registers them,
	/// and once it does they are spendable.
	fn pending_balance_vtxo_ids(&self) -> Vec<VtxoId> {
		Vec::new()
	}

	/// Parks the action. Finishing it would make every VTXO it holds locked
	/// spendable, registered or not.
	async fn on_abort(self, _wallet: &Wallet, error: anyhow::Error) -> Advance<Self> {
		Advance::Park { state: self, wake_after: None, error: Some(error) }
	}
}

/// Received -> Registering. Refuses the VTXOs that are not a payment to this
/// wallet, logging why. A chain source error is retried.
///
/// Returns the refused VTXOs, sorted.
async fn validate_arkoor_receive(
	wallet: &Wallet,
	recv: &ArkoorReceive,
) -> Result<Vec<VtxoId>, AdvanceError> {
	let (_, ark_info) = wallet.require_server().await.retry()?;
	let tip = wallet.inner.chain.tip().await
		.context("cannot vet received arkoor VTXOs, no chain tip").retry()?;

	let mut invalid = Vec::new();
	for vtxo in &recv.vtxos {
		match wallet.validate_vtxo(vtxo).await {
			Ok(()) => {},
			Err(VtxoValidationError::Chain(e)) => {
				return Err(e.context(format!("failed to validate received arkoor VTXO {}", vtxo.id())))
					.retry();
			},
			Err(e) => {
				error!("Received invalid arkoor VTXO {} from server: {}", vtxo.id(), e);
				invalid.push(vtxo.id());
				continue;
			},
		}
		if let Err(e) = check_arkoor_receive_policy(vtxo, ark_info.server_pubkey) {
			error!("Refusing received arkoor VTXO {}: {}", vtxo.id(), e);
			invalid.push(vtxo.id());
			continue;
		}
		if wallet.find_signable_clause(vtxo).await.is_none() {
			error!("Refusing received arkoor VTXO {}: not owned by this wallet", vtxo.id());
			invalid.push(vtxo.id());
			continue;
		}
		if vtxo.expiry_height() <= tip {
			warn!("Received arkoor VTXO {} that expired at height {} (tip {}); \
				keeping it, it needs a refresh", vtxo.id(), vtxo.expiry_height(), tip,
			);
		}
	}

	if !invalid.is_empty() {
		error!("Received {} invalid arkoor VTXOs out of {} from server",
			invalid.len(), recv.vtxos.len(),
		);
	}
	invalid.sort_unstable();
	Ok(invalid)
}

/// Whether a structurally-valid arkoor vtxo is safe to store as a spendable
/// received payment.
///
/// [`Wallet::validate_vtxo`] only proves the vtxo's genesis chain was cosigned
/// by the server pubkey embedded in the vtxo. A received payment additionally
/// has to be a final, self-custodial coin, so we require that:
///
/// - the policy is [`VtxoPolicyKind::Pubkey`]: an in-flight HTLC (or any other
///   server contract) is not a payment, and the server refuses to let us spend
///   it as an arkoor/round/offboard input;
/// - the vtxo commits to *our* server's pubkey, not a foreign server's.
///
/// Expiry is not a reason to refuse. The sender paid with a vtxo that was
/// valid when the server cosigned it; if we only sync after it expired, the
/// payment is still ours and the coin needs a refresh, not a rejection.
///
/// Ownership (that the wallet holds a signable key) is checked by the caller,
/// which has async database access.
fn check_arkoor_receive_policy(
	vtxo: &Vtxo<Full>,
	server_pubkey: bitcoin::secp256k1::PublicKey,
) -> anyhow::Result<()> {
	let kind = vtxo.policy().policy_type();
	if kind != VtxoPolicyKind::Pubkey {
		bail!("not a final payment VTXO (policy: {})", kind);
	}
	if vtxo.server_pubkey() != server_pubkey {
		bail!("VTXO commits to a foreign server pubkey {}", vtxo.server_pubkey());
	}
	Ok(())
}

/// Stores the VTXOs not refused, locked by the action.
async fn start_arkoor_receive(
	wallet: &Wallet,
	recv: &ArkoorReceive,
	resolution: &Resolution,
) -> Result<(), AdvanceError> {
	let valid = recv.valid_vtxos(resolution).cloned().collect::<Vec<_>>();
	wallet.store_locked_vtxos(
		&valid,
		Some(VtxoLockHolder::Action { id: recv.id() }),
	).await.retry()
}

/// The receive movement of the VTXOs of `recv` not refused, crediting
/// `credited` of them.
async fn arkoor_receive_movement_update(
	wallet: &Wallet,
	recv: &ArkoorReceive,
	resolution: &Resolution,
	credited: &[Vtxo<Full>],
) -> Result<MovementUpdate, AdvanceError> {
	let valid = recv.valid_vtxos(resolution).cloned().collect::<Vec<_>>();
	let intended = valid.iter().map(|v| v.amount()).sum::<Amount>();
	let effective = credited.iter().map(|v| v.amount()).sum::<Amount>();
	Ok(MovementUpdate::new()
		.intended_balance(intended.to_signed().context("receive amount out of range").abort()?)
		.effective_balance(effective.to_signed().context("receive amount out of range").abort()?)
		.replace_received_on(received_on_destinations(wallet, &valid).await)
		.produced_vtxos(credited))
}

/// Records the receive as a pending movement crediting nothing, unless the
/// action already has its movement.
async fn record_pending_arkoor_receive(
	wallet: &Wallet,
	recv: &ArkoorReceive,
	resolution: &Resolution,
) -> Result<(), AdvanceError> {
	wallet.inner.movements.get_or_create_movement_with_action(
		Subsystem::ARKOOR,
		ArkoorMovement::Receive.to_string(),
		&recv.id(),
		arkoor_receive_movement_update(wallet, recv, resolution, &[]).await?,
	).await.context("failed to create arkoor receive movement").retry()?;
	Ok(())
}

/// Asks the server to register the VTXOs not resolved yet. The VTXOs the server
/// refuses stay unresolved, unless a confirmed transaction double spends their
/// chain: then they are lost.
async fn register_arkoor_receive(
	wallet: &Wallet,
	recv: &ArkoorReceive,
	mut resolution: Resolution,
) -> Result<Resolution, AdvanceError> {
	let pending = recv.vtxos.iter()
		.filter(|v| !resolution.is_resolved(v.id()))
		.collect::<Vec<_>>();

	// Registers them all at once first, and one by one when the server refuses the batch.
	let refused = match wallet.register_vtxo_transactions_with_server(&pending).await {
		Ok(()) => {
			resolution.registered.extend(pending.iter().map(|v| v.id()));
			Vec::new()
		},
		Err(e) if is_registration_refusal(&e) => {
			let mut refused = Vec::new();
			for vtxo in pending {
				match wallet.register_vtxo_transactions_with_server([vtxo]).await {
					Ok(()) => resolution.registered.push(vtxo.id()),
					Err(e) if is_registration_refusal(&e) => refused.push((vtxo, e)),
					Err(e) => return Err(e.context("failed to register received arkoor VTXO")).retry(),
				}
			}
			refused
		},
		Err(e) => return Err(e.context("failed to register received arkoor VTXOs")).retry(),
	};

	for (vtxo, error) in refused {
		if chain_double_spent(wallet, vtxo).await.retry()? {
			warn!("Received arkoor VTXO {} lost a double spend on-chain, it will not be credited",
				vtxo.id(),
			);
			resolution.lost.push(vtxo.id());
		} else {
			warn!("Server refused to register received arkoor VTXO {}, \
				keeping it locked and retrying later: {:#}", vtxo.id(), error,
			);
		}
	}

	resolution.registered.sort_unstable();
	resolution.lost.sort_unstable();
	Ok(resolution)
}

/// Settling -> done. Makes the registered VTXOs spendable, marks the lost ones
/// spent and finishes the movement, creating it if no drive recorded it as
/// pending.
async fn settle_arkoor_receive(
	wallet: &Wallet,
	recv: &ArkoorReceive,
	resolution: &Resolution,
) -> Result<(), AdvanceError> {
	// Spend the lost VTXOs first: finishing the action makes any VTXO it still
	// holds spendable.
	wallet.mark_vtxos_as_spent(&resolution.lost).await.retry()?;
	wallet.unlock_vtxos(
		&resolution.registered,
		Some(VtxoLockHolder::Action { id: recv.id() }),
	).await.retry()?;

	let credited = recv.vtxos.iter()
		.filter(|v| resolution.registered.contains(&v.id()))
		.cloned()
		.collect::<Vec<_>>();
	let status = if credited.is_empty() {
		MovementStatus::Failed
	} else {
		MovementStatus::Successful
	};
	let movement_id = wallet.inner.movements.finish_movement_with_action(
		Subsystem::ARKOOR,
		ArkoorMovement::Receive.to_string(),
		&recv.id(),
		status,
		arkoor_receive_movement_update(wallet, recv, resolution, &credited).await?,
	).await.context("failed to finish arkoor receive movement").retry()?;

	if credited.is_empty() {
		warn!("Arkoor receive {} (movement {}) failed, none of its VTXOs were credited",
			recv.id(), movement_id,
		);
	} else {
		let balance = credited.iter().map(|v| v.amount()).sum::<Amount>();
		info!("Received arkoor (movement {}) for {}", movement_id, balance);
	}
	Ok(())
}

/// Whether the server answered a registration request by refusing it, rather than failing to
/// process it.
fn is_registration_refusal(err: &anyhow::Error) -> bool {
	err.downcast_ref::<tonic::Status>().is_some_and(|s| s.is_rejection())
}

/// Whether a confirmed transaction double spends the chain of `vtxo`, so that the VTXO can
/// never confirm.
///
/// Follows the chain from its anchor while its transactions are confirmed. The first
/// unconfirmed one lost a double spend exactly when one of its inputs is spent by a confirmed
/// transaction.
async fn chain_double_spent(wallet: &Wallet, vtxo: &Vtxo<Full>) -> anyhow::Result<bool> {
	let chain = &wallet.inner.chain;
	let anchor = vtxo.chain_anchor().txid;
	if chain.tx_status(anchor).await?.confirmed_height().is_none() {
		return Ok(false);
	}
	for item in vtxo.transactions() {
		let txid = item.tx.compute_txid();
		if chain.tx_status(txid).await?.confirmed_height().is_some() {
			continue;
		}
		for input in &item.tx.input {
			if chain.outpoint_spent_confirmed(input.previous_output).await? {
				return Ok(true);
			}
		}
		return Ok(false);
	}
	Ok(false)
}

/// The addresses the given VTXOs were received on, with the amount received on each.
async fn received_on_destinations(
	wallet: &Wallet,
	vtxos: &[Vtxo<Full>],
) -> Vec<MovementDestination> {
	let mut received_by_address = HashMap::<ark::Address, Amount>::new();
	for vtxo in vtxos {
		if let Ok(Some((index, _))) = wallet.pubkey_keypair(&vtxo.user_pubkey()).await {
			if let Ok(address) = wallet.peek_address(index).await {
				*received_by_address.entry(address).or_default() += vtxo.amount();
			}
		}
	}
	received_by_address
		.into_iter()
		.map(|(addr, amount)| MovementDestination::ark(addr, amount))
		.collect()
}

#[cfg(test)]
mod test {
	use super::*;

	use ark::SECP;
	use ark::test_util::VTXO_VECTORS;
	use bitcoin::secp256k1::Keypair;

	/// The arkoor receive path must only store final, self-custodial coins for
	/// our own server. This pins the two ways a received vtxo can be unsafe.
	#[test]
	fn arkoor_receive_policy_gate() {
		let vectors = &*VTXO_VECTORS;
		let server_pubkey = vectors.server_key.public_key();

		// A final Pubkey payment vtxo committing to our server is acceptable.
		let good = &vectors.board_vtxo;
		check_arkoor_receive_policy(good, server_pubkey)
			.expect("a Pubkey vtxo must be accepted");

		// An HTLC-send vtxo is an in-flight contract, not a payment.
		let htlc = &vectors.arkoor_htlc_out_vtxo;
		check_arkoor_receive_policy(htlc, server_pubkey)
			.expect_err("an HTLC-send vtxo must be refused as a payment");

		// A vtxo committing to some other server's key is not ours to trust.
		let foreign_server = Keypair::from_seckey_slice(&SECP, &[0x11; 32])
			.unwrap().public_key();
		check_arkoor_receive_policy(good, foreign_server)
			.expect_err("a vtxo for a foreign server must be refused");
	}

	#[test]
	fn arkoor_receive_id_covers_every_vtxo() {
		let vectors = &*VTXO_VECTORS;
		let a = vectors.board_vtxo.clone();
		let b = vectors.arkoor2_vtxo.clone();
		let c = vectors.round1_vtxo.clone();
		let id = |vtxos: Vec<Vtxo<Full>>| ArkoorReceive::new(vtxos).unwrap().id();

		assert_eq!(id(vec![a.clone(), b.clone()]), id(vec![b.clone(), a.clone()]));
		assert_ne!(id(vec![a.clone(), b.clone()]), id(vec![a.clone(), c.clone()]));
		assert_ne!(id(vec![a.clone(), b.clone()]), id(vec![a.clone()]));
		assert_ne!(id(vec![a.clone(), b.clone()]), id(vec![a, b, c]));
		ArkoorReceive::new(Vec::new()).expect_err("an empty receive must be refused");
	}
}

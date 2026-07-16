//!
//! A test to ensure that it is possible to implement the [BarkPersister] trait.
//!
//! This test is purely about the type names being available in the public API,
//! so all that matters is that the code can compile. It doesn't have to run.
//!


#[cfg(feature = "onchain-bdk")]
use bdk_wallet::ChangeSet;
use bitcoin::consensus::deserialize;
use bitcoin::{Amount, BlockHash, Network, SignedAmount, Transaction, Txid};
use bitcoin::bip32::Fingerprint;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::PublicKey;
use chrono::{DateTime, Local};
use lightning_invoice::Bolt11Invoice;

use ark::{ProtocolEncoding, Vtxo, VtxoId};
use ark::vtxo::Full;
use ark::lightning::{PaymentHash, Preimage};
use bitcoin_ext::BlockRef;

use bark::{WalletProperties, WalletVtxo};
use bark::actions::{WalletActionCheckpoint, WalletActionId};
use bark::exit::{ExitState, ExitStateKind, ExitClaimableState, ExitTxOrigin};
use bark::movement::{
	Movement, MovementDestination, MovementId, MovementStatus, MovementSubsystem,
	MovementTimestamp, PaymentMethod,
};
use bark::movement::update::MovementUpdate;
use bark::persist::BarkPersister;
use bark::persist::models::{
	PaidInvoice, StoredExit, StoredRoundState, Unlocked,
	RoundStateId, SerdeRoundState, PendingOffboard,
};
use bark::round::RoundState;
use bark::vtxo::{VtxoState, VtxoStateKind};


struct Dummy;

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl BarkPersister for Dummy {
	async fn init_wallet(&self, _properties: &WalletProperties) -> anyhow::Result<()> {
		Ok(())
	}

	#[cfg(feature = "onchain-bdk")]
	async fn initialize_bdk_wallet(&self) -> anyhow::Result<ChangeSet> {
		Ok(ChangeSet::default())
	}

	#[cfg(feature = "onchain-bdk")]
	async fn store_bdk_wallet_changeset(&self, _changeset: &ChangeSet) -> anyhow::Result<()> {
		Ok(())
	}

	async fn read_properties(&self) -> anyhow::Result<Option<WalletProperties>> {
		Ok(Some(WalletProperties {
			network: Network::Bitcoin,
			fingerprint: Fingerprint::default(),
			server_pubkey: None,
			server_mailbox_pubkey: None,
		}))
	}

	async fn set_server_pubkey(&self, _server_pubkey: PublicKey) -> anyhow::Result<()> {
		Ok(())
	}

	async fn set_server_mailbox_pubkey(&self, _server_mailbox_pubkey: PublicKey) -> anyhow::Result<()> {
		Ok(())
	}

	async fn get_wallet_vtxo(&self, _id: VtxoId) -> anyhow::Result<Option<WalletVtxo>> {
		Ok(Some(WalletVtxo {
			vtxo: Vtxo::deserialize(&[])?,
			state: VtxoState::Spendable,
			exit_depth: 0,
			exit_tx_weight: bitcoin::Weight::ZERO,
		}))
	}

	async fn get_all_vtxos(&self) -> anyhow::Result<Vec<WalletVtxo>> {
		Ok(Vec::<WalletVtxo>::from([WalletVtxo {
			vtxo: Vtxo::deserialize(&[])?,
			state: VtxoState::Spendable,
			exit_depth: 0,
			exit_tx_weight: bitcoin::Weight::ZERO,
		}]))
	}

	async fn get_vtxos_by_state(&self, _state: &[VtxoStateKind]) -> anyhow::Result<Vec<WalletVtxo>> {
		Ok(Vec::<WalletVtxo>::from([WalletVtxo {
			vtxo: Vtxo::deserialize(&[])?,
			state: VtxoState::Locked {
				holder: Some(bark::vtxo::VtxoLockHolder::Movement { id: MovementId::new(0) }),
			},
			exit_depth: 0,
			exit_tx_weight: bitcoin::Weight::ZERO,
		}]))
	}

	async fn get_full_vtxo(&self, _id: VtxoId) -> anyhow::Result<Option<Vtxo<Full>>> {
		Ok(Some(Vtxo::deserialize(&[])?))
	}

	async fn get_full_vtxos(&self, _ids: &[VtxoId]) -> anyhow::Result<Vec<Vtxo<Full>>> {
		Ok(Vec::new())
	}

	async fn remove_vtxo(&self, _id: VtxoId) -> anyhow::Result<Option<Vtxo<Full>>> {
		Ok(Some(Vtxo::deserialize(&[])?))
	}

	async fn has_spent_vtxo(&self, _id: VtxoId) -> anyhow::Result<bool> {
		Ok(true)
	}

	async fn store_vtxo_key(&self, _index: u32, _public_key: PublicKey) -> anyhow::Result<()> {
		Ok(())
	}

	async fn get_last_vtxo_key_index(&self) -> anyhow::Result<Option<u32>> {
		Ok(Some(0))
	}

	async fn get_public_key_idx(&self, _public_key: &PublicKey) -> anyhow::Result<Option<u32>> {
		Ok(Some(0))
	}

	async fn store_mailbox_checkpoint(&self, _checkpoint: u64) -> anyhow::Result<()> {
		Ok(())
	}

	async fn get_mailbox_checkpoint(&self) -> anyhow::Result<u64> {
		Ok(0u64)
	}

	async fn upsert_wallet_action_checkpoint(
		&self,
		_id: &WalletActionId,
		_checkpoint: &WalletActionCheckpoint,
	) -> anyhow::Result<()> {
		Ok(())
	}

	async fn get_wallet_action_checkpoint(
		&self,
		_id: &WalletActionId,
	) -> anyhow::Result<Option<WalletActionCheckpoint>> {
		Ok(None)
	}

	async fn get_all_wallet_action_checkpoints(
		&self,
	) -> anyhow::Result<Vec<WalletActionCheckpoint>> {
		Ok(vec![])
	}

	async fn remove_wallet_action_checkpoint(
		&self,
		_id: &WalletActionId,
	) -> anyhow::Result<()> {
		Ok(())
	}

	async fn record_paid_invoice(
		&self,
		_payment_hash: PaymentHash,
		_preimage: Preimage,
	) -> anyhow::Result<()> {
		Ok(())
	}

	async fn get_paid_invoice(
		&self,
		_payment_hash: PaymentHash,
	) -> anyhow::Result<Option<PaidInvoice>> {
		Ok(None)
	}

	async fn record_settled_lightning_receive(
		&self,
		_payment_hash: PaymentHash,
		_preimage: Preimage,
		_invoice: &Bolt11Invoice,
		_amount: bitcoin::Amount,
	) -> anyhow::Result<()> {
		Ok(())
	}

	async fn get_settled_lightning_receive(
		&self,
		_payment_hash: PaymentHash,
	) -> anyhow::Result<Option<bark::persist::models::SettledLightningReceive>> {
		Ok(None)
	}

	async fn store_exit_vtxo_entry(&self, _exit: &StoredExit) -> anyhow::Result<()> {
		Ok(())
	}

	async fn remove_exit_vtxo_entry(&self, _id: &VtxoId) -> anyhow::Result<()> {
		Ok(())
	}

	async fn get_exit_vtxo_entries(&self) -> anyhow::Result<Vec<StoredExit>> {
		Ok(Vec::<StoredExit>::from([
			StoredExit {
				vtxo_id: VtxoId::from_slice(&[])?,
				state: ExitState::Claimable(ExitClaimableState {
					tip_height: 0,
					claimable_since: BlockRef {
						height: 0,
						hash: BlockHash::all_zeros(),
					},
					last_scanned_block: None,
				}),
				history: Vec::<ExitState>::new(),
				movement_id: None,
			}
		]))
	}

	async fn get_exit_vtxo_entries_with_states(
		&self,
		states: &[ExitStateKind],
	) -> anyhow::Result<Vec<StoredExit>> {
		let entries = self.get_exit_vtxo_entries().await?;
		Ok(entries.into_iter().filter(|e| states.contains(&e.state.kind())).collect())
	}

	async fn get_exit_vtxo_entry(&self, id: &VtxoId) -> anyhow::Result<Option<StoredExit>> {
		let entries = self.get_exit_vtxo_entries().await?;
		Ok(entries.into_iter().find(|e| e.vtxo_id == *id))
	}

	async fn store_exit_child_tx(
		&self,
		_exit_txid: Txid,
		_child_tx: &Transaction,
		_origin: ExitTxOrigin,
	) -> anyhow::Result<()> {
		Ok(())
	}

	async fn get_exit_child_tx(
		&self,
		_exit_txid: Txid,
	) -> anyhow::Result<Option<(Transaction, ExitTxOrigin)>> {
		Ok(Some((
			deserialize::<Transaction>(&[])?,
			ExitTxOrigin::Wallet {
			confirmed_in: Some(BlockRef {
				height: 0,
				hash: BlockHash::all_zeros(),
			}),
		})))
	}

	async fn update_vtxo_state_checked(
		&self,
		_vtxo_id: VtxoId,
		_new_state: VtxoState,
		_allowed_old_states: &[VtxoStateKind],
	) -> anyhow::Result<WalletVtxo> {
		Ok(Vec::<WalletVtxo>::from([WalletVtxo {
			vtxo: Vtxo::deserialize(&[])?,
			state: VtxoState::Spent,
			exit_depth: 0,
			exit_tx_weight: bitcoin::Weight::ZERO,
		}]).pop().unwrap())
	}

	async fn update_vtxo_states_checked(
		&self,
		_vtxo_ids: &[VtxoId],
		_new_state: VtxoState,
		_allowed_old_states: &[VtxoStateKind],
	) -> anyhow::Result<()> {
		Ok(())
	}

	async fn store_pending_offboard(
		&self,
		_pending: &PendingOffboard,
	) -> anyhow::Result<()> {
		Ok(())
	}

	async fn get_pending_offboards(&self) -> anyhow::Result<Vec<PendingOffboard>> {
		Ok(vec![])
	}

	async fn remove_pending_offboard(&self, _movement_id: MovementId) -> anyhow::Result<()> {
		Ok(())
	}

	async fn store_round_state(&self, _round_state: &RoundState) -> anyhow::Result<RoundStateId> {
		Ok(RoundStateId(5))
	}

	async fn update_round_state(&self, _round_state: &StoredRoundState) -> anyhow::Result<()> {
		Ok(())
	}

	async fn remove_round_state(&self, _round_state: &StoredRoundState) -> anyhow::Result<()> {
		Ok(())
	}

	async fn get_round_state_by_id(&self, _id: RoundStateId) -> anyhow::Result<Option<StoredRoundState<Unlocked>>> {
		let state = rmp_serde::from_slice::<SerdeRoundState>(&[]).unwrap().into();
		Ok(Some(StoredRoundState::new(RoundStateId(5), state)))
	}

	async fn get_pending_round_state_ids(&self) -> anyhow::Result<Vec<RoundStateId>> {
		Ok(vec![RoundStateId(5)])
	}

	async fn create_new_movement(
		&self,
		_status: MovementStatus,
		_subsystem: &MovementSubsystem,
		_time: DateTime<Local>,
		_action_id: Option<&str>,
	) -> anyhow::Result<MovementId> {
		Ok(MovementId::new(0))
	}

	async fn get_or_create_movement_for_action(
		&self,
		_subsystem: &MovementSubsystem,
		_time: DateTime<Local>,
		_action_id: &str,
		_update: MovementUpdate,
	) -> anyhow::Result<(MovementId, bool)> {
		Ok((MovementId::new(0), true))
	}

	async fn update_movement(&self, _movement: &Movement) -> anyhow::Result<()> {
		Ok(())
	}

	async fn get_movement_by_id(&self, _movement_id: MovementId) -> anyhow::Result<Movement> {
		Ok(dummy_movement(MovementStatus::Pending))
	}

	async fn get_all_movements(&self) -> anyhow::Result<Vec<Movement>> {
		Ok(vec![dummy_movement(MovementStatus::Failed)])
	}

	async fn get_movements_by_payment_method(
		&self,
		_payment_method: &PaymentMethod,
	) -> anyhow::Result<Vec<Movement>> {
		Ok(vec![])
	}

	async fn store_vtxos(
		&self,
		_vtxos: &[(&Vtxo<Full>, &VtxoState)],
	) -> anyhow::Result<()> {
		Ok(())
	}
}

fn dummy_movement(status: MovementStatus) -> Movement {
	Movement {
		status,
		id: MovementId::new(0),
		subsystem: MovementSubsystem {
			name: "".to_string(),
			kind: "".to_string(),
		},
		metadata: serde_json::Map::new(),
		intended_balance: SignedAmount::ZERO,
		effective_balance: SignedAmount::ZERO,
		offchain_fee: Amount::ZERO,
		sent_to: vec![MovementDestination {
			destination: PaymentMethod::Custom("".into()),
			amount: Amount::ZERO,
		}],
		received_on: vec![],
		input_vtxos: vec![],
		output_vtxos: vec![],
		exited_vtxos: vec![],
		time: MovementTimestamp {
			created_at: Local::now(),
			updated_at: Local::now(),
			completed_at: Some(Local::now()),
		},
	}
}

#[test]
fn compiles_if_all_types_are_exported() {
	// If this file compiles, we're good.
	let _dummy = Dummy {};
}

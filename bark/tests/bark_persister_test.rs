//!
//! A test to ensure that it is possible to implement the [BarkPersister] trait.
//!

use std::collections::HashMap;
use std::str::FromStr;

use bdk_wallet::ChangeSet;
use bitcoin::{Amount, BlockHash, Network, SignedAmount, Transaction, Txid};
use bitcoin::bip32::Fingerprint;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::PublicKey;
use chrono::{DateTime, Local};
use lightning_invoice::Bolt11Invoice;

use ark::{Vtxo, VtxoId};
use ark::lightning::{Invoice, PaymentHash, Preimage};
use bitcoin_ext::{BlockDelta, BlockRef};
use server_rpc::TryFromBytes;

use bark::{WalletProperties, WalletVtxo};
use bark::exit::models::{ExitState, ExitClaimableState, ExitTxOrigin};
use bark::movement::{
	Movement, MovementDestination, MovementId, MovementStatus, MovementSubsystem, MovementTimestamp,
};
use bark::persist::{BarkPersister, RoundStateId, StoredRoundState};
use bark::persist::models::{self, PendingLightningSend, LightningReceive, StoredExit};
use bark::round::{RoundState, UnconfirmedRound};
use bark::vtxo::state::{VtxoState, VtxoStateKind};


struct Dummy;

impl BarkPersister for Dummy {
	fn init_wallet(&self, _properties: &WalletProperties) -> anyhow::Result<()> {
		Ok(())
	}

	fn initialize_bdk_wallet(&self) -> anyhow::Result<ChangeSet> {
		Ok(ChangeSet::default())
	}

	fn store_bdk_wallet_changeset(&self, _changeset: &ChangeSet) -> anyhow::Result<()> {
		Ok(())
	}

	fn read_properties(&self) -> anyhow::Result<Option<WalletProperties>> {
		Ok(Some(WalletProperties {
			network: Network::Bitcoin,
			fingerprint: Fingerprint::default(),
		}))
	}

	fn check_recipient_exists(&self, _recipient: &str) -> anyhow::Result<bool> {
		Ok(true)
	}

	fn store_pending_board(
		&self,
		_vtxo: &Vtxo,
		_funding_tx: &Transaction,
		_movement_id: MovementId,
	) -> anyhow::Result<()> {
		Ok(())
	}

	fn remove_pending_board(&self, _vtxo_id: &VtxoId) -> anyhow::Result<()> {
		Ok(())
	}

	fn get_all_pending_board_ids(&self) -> anyhow::Result<Vec<VtxoId>> {
		Ok(vec![])
	}

	fn get_wallet_vtxo(&self, _id: VtxoId) -> anyhow::Result<Option<WalletVtxo>> {
		Ok(Some(WalletVtxo {
			vtxo: Vtxo::from_bytes([])?,
			state: VtxoState::Spendable,
		}))
	}

	fn get_all_vtxos(&self) -> anyhow::Result<Vec<WalletVtxo>> {
		Ok(Vec::<WalletVtxo>::from([WalletVtxo {
			vtxo: Vtxo::from_bytes([])?,
			state: VtxoState::Spendable,
		}]))
	}

	fn get_vtxos_by_state(&self, _state: &[VtxoStateKind]) -> anyhow::Result<Vec<WalletVtxo>> {
		Ok(Vec::<WalletVtxo>::from([WalletVtxo {
			vtxo: Vtxo::from_bytes([])?,
			state: VtxoState::Locked {
				movement_id: Some(MovementId::new(0)),
			},
		}]))
	}

	fn remove_vtxo(&self, _id: VtxoId) -> anyhow::Result<Option<Vtxo>> {
		Ok(Some(Vtxo::from_bytes([])?))
	}

	fn has_spent_vtxo(&self, _id: VtxoId) -> anyhow::Result<bool> {
		Ok(true)
	}

	fn store_vtxo_key(&self, _index: u32, _public_key: PublicKey) -> anyhow::Result<()> {
		Ok(())
	}

	fn get_last_vtxo_key_index(&self) -> anyhow::Result<Option<u32>> {
		Ok(Some(0))
	}

	fn get_public_key_idx(&self, _public_key: &PublicKey) -> anyhow::Result<Option<u32>> {
		Ok(Some(0))
	}

	fn store_new_pending_lightning_send(
		&self,
		invoice: &Invoice,
		amount: &Amount,
		_vtxos: &[VtxoId],
		movement_id: MovementId
	) -> anyhow::Result<PendingLightningSend> {
		Ok(PendingLightningSend {
			invoice: invoice.clone(),
			amount: *amount,
			htlc_vtxos: vec![],
			movement_id,
		})
	}

	fn get_all_pending_lightning_send(&self) -> anyhow::Result<Vec<PendingLightningSend>> {
		Ok(vec![])
	}

	fn remove_pending_lightning_send(&self, _payment_hash: PaymentHash) -> anyhow::Result<()> {
		Ok(())
	}

	fn store_lightning_receive(
		&self,
		_payment_hash: PaymentHash,
		_preimage: Preimage,
		_invoice: &Bolt11Invoice,
		_htlc_recv_cltv_delta: BlockDelta,
	) -> anyhow::Result<()> {
		Ok(())
	}

	fn get_all_pending_lightning_receives(&self) -> anyhow::Result<Vec<LightningReceive>> {
		Ok(Vec::<LightningReceive>::from([
			dummy_lightning_receive(),
		]))
	}

	fn set_preimage_revealed(&self, _payment_hash: PaymentHash) -> anyhow::Result<()> {
		Ok(())
	}

	fn update_lightning_receive(
		&self,
		_payment_hash: PaymentHash,
		_vtxo_ids: &[VtxoId],
		_movement_id: MovementId,
	) -> anyhow::Result<()> {
		Ok(())
	}

	fn fetch_lightning_receive_by_payment_hash(
		&self,
		_payment_hash: PaymentHash,
	) -> anyhow::Result<Option<LightningReceive>> {
		Ok(Some(dummy_lightning_receive()))
	}

	fn remove_pending_lightning_receive(&self, _payment_hash: PaymentHash) -> anyhow::Result<()> {
		Ok(())
	}

	fn store_exit_vtxo_entry(&self, _exit: &StoredExit) -> anyhow::Result<()> {
		Ok(())
	}

	fn remove_exit_vtxo_entry(&self, _id: &VtxoId) -> anyhow::Result<()> {
		Ok(())
	}

	fn get_exit_vtxo_entries(&self) -> anyhow::Result<Vec<StoredExit>> {
		Ok(Vec::<StoredExit>::from([
			StoredExit {
				vtxo_id: VtxoId::from_bytes([])?,
				state: ExitState::Claimable(ExitClaimableState {
					tip_height: 0,
					claimable_since: BlockRef {
						height: 0,
						hash: BlockHash::all_zeros(),
					},
					last_scanned_block: None,
				}),
				history: Vec::<ExitState>::new(),
			}
		]))
	}

	fn store_exit_child_tx(
		&self,
		_exit_txid: Txid,
		_child_tx: &Transaction,
		_origin: ExitTxOrigin,
	) -> anyhow::Result<()> {
		Ok(())
	}

	fn get_exit_child_tx(
		&self,
		_exit_txid: Txid,
	) -> anyhow::Result<Option<(Transaction, ExitTxOrigin)>> {
		Ok(Some((
			Transaction::from_bytes([])?,
			ExitTxOrigin::Wallet {
			confirmed_in: Some(BlockRef {
				height: 0,
				hash: BlockHash::all_zeros(),
			}),
		})))
	}

	fn update_vtxo_state_checked(
		&self,
		_vtxo_id: VtxoId,
		_new_state: VtxoState,
		_allowed_old_states: &[VtxoStateKind],
	) -> anyhow::Result<WalletVtxo> {
		Ok(Vec::<WalletVtxo>::from([WalletVtxo {
			vtxo: Vtxo::from_bytes([])?,
			state: VtxoState::Spent,
		}]).pop().unwrap())
	}

	fn store_round_state_lock_vtxos(&self, _round_state: &RoundState) -> anyhow::Result<RoundStateId> {
		Ok(RoundStateId(5))
	}

	fn update_round_state(&self, _round_state: &StoredRoundState) -> anyhow::Result<()> {
		Ok(())
	}

	fn remove_round_state(&self, _round_state: &StoredRoundState) -> anyhow::Result<()> {
		Ok(())
	}

	fn load_round_states(&self) -> anyhow::Result<Vec<StoredRoundState>> {
		Ok(vec![StoredRoundState {
			id: RoundStateId(5),
			state: rmp_serde::from_slice::<models::SerdeRoundState>(&[]).unwrap().into(),
		}])
	}

	fn store_recovered_round(&self, _round: &UnconfirmedRound) -> anyhow::Result<()> {
		Ok(())
	}
	fn remove_recovered_round(&self, _funding_txid: Txid) -> anyhow::Result<()> {

		Ok(())
	}

	fn load_recovered_rounds(&self) -> anyhow::Result<Vec<UnconfirmedRound>> {
		Ok(vec![rmp_serde::from_slice::<models::SerdeUnconfirmedRound>(&[]).unwrap().into()])
	}

	fn create_new_movement(
		&self,
		_status: MovementStatus,
		_subsystem: &MovementSubsystem,
		_time: DateTime<Local>,
	) -> anyhow::Result<MovementId> {
		Ok(MovementId::new(0))
	}

	fn update_movement(&self, _movement: &Movement) -> anyhow::Result<()> {
		Ok(())
	}

	fn get_movement_by_id(&self, _movement_id: MovementId) -> anyhow::Result<Movement> {
		Ok(dummy_movement(MovementStatus::Pending))
	}

	fn get_all_movements(&self) -> anyhow::Result<Vec<Movement>> {
		Ok(vec![dummy_movement(MovementStatus::Failed)])
	}

	fn get_pending_board_movement_id(&self, _vtxo_id: VtxoId) -> anyhow::Result<MovementId> {
		Ok(MovementId::new(0))
	}

	fn store_vtxos(
		&self,
		_vtxos: &[(&Vtxo, &VtxoState)],
	) -> anyhow::Result<()> {
		Ok(())
	}
}

fn dummy_lightning_receive() -> LightningReceive {
	LightningReceive {
		payment_hash: PaymentHash::from_bytes([]).unwrap(),
		payment_preimage: Preimage::from_bytes([]).unwrap(),
		invoice: Bolt11Invoice::from_str("bob").unwrap(),
		preimage_revealed_at:Some(0),
		htlc_vtxos: None,
		htlc_recv_cltv_delta: 0,
		movement_id: Some(MovementId::new(0)),
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
		metadata: HashMap::new(),
		intended_balance: SignedAmount::ZERO,
		effective_balance: SignedAmount::ZERO,
		offchain_fee: Amount::ZERO,
		sent_to: vec![MovementDestination {
			destination: "".to_string(),
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

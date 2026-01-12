//!
//! A test to ensure that it is possible to implement the [BarkPersister] trait.
//!
//! This test is purely about the type names being available in the public API,
//! so all that matters is that the code can compile. It doesn't have to run.
//!

use std::collections::HashMap;
use std::str::FromStr;

#[cfg(feature = "onchain_bdk")]
use bdk_wallet::ChangeSet;
use bitcoin::consensus::deserialize;
use bitcoin::{Amount, BlockHash, Network, SignedAmount, Transaction, Txid};
use bitcoin::bip32::Fingerprint;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::PublicKey;
use chrono::{DateTime, Local};
use lightning_invoice::Bolt11Invoice;

use ark::{ProtocolEncoding, Vtxo, VtxoId};
use ark::lightning::{Invoice, PaymentHash, Preimage};
use bitcoin_ext::{BlockDelta, BlockRef};

use bark::{WalletProperties, WalletVtxo};
use bark::exit::{ExitState, ExitClaimableState, ExitTxOrigin};
use bark::movement::{
	Movement, MovementDestination, MovementId, MovementStatus, MovementSubsystem,
	MovementTimestamp, PaymentMethod,
};
use bark::persist::{BarkPersister, RoundStateId, StoredRoundState};
use bark::persist::models::{self, LightningReceive, LightningSend, PendingBoard, StoredExit};
use bark::round::RoundState;
use bark::vtxo::{VtxoState, VtxoStateKind};


struct Dummy;

#[async_trait::async_trait]
impl BarkPersister for Dummy {
	async fn init_wallet(&self, _properties: &WalletProperties) -> anyhow::Result<()> {
		Ok(())
	}

	#[cfg(feature = "onchain_bdk")]
	async fn initialize_bdk_wallet(&self) -> anyhow::Result<ChangeSet> {
		Ok(ChangeSet::default())
	}

	#[cfg(feature = "onchain_bdk")]
	async fn store_bdk_wallet_changeset(&self, _changeset: &ChangeSet) -> anyhow::Result<()> {
		Ok(())
	}

	async fn read_properties(&self) -> anyhow::Result<Option<WalletProperties>> {
		Ok(Some(WalletProperties {
			network: Network::Bitcoin,
			fingerprint: Fingerprint::default(),
		}))
	}

	async fn check_recipient_exists(&self, _recipient: &PaymentMethod) -> anyhow::Result<bool> {
		Ok(true)
	}

	async fn store_pending_board(
		&self,
		_vtxo: &Vtxo,
		_funding_tx: &Transaction,
		_movement_id: MovementId,
	) -> anyhow::Result<()> {
		Ok(())
	}

	async fn remove_pending_board(&self, _vtxo_id: &VtxoId) -> anyhow::Result<()> {
		Ok(())
	}

	async fn get_all_pending_board_ids(&self) -> anyhow::Result<Vec<VtxoId>> {
		Ok(vec![])
	}

	async fn get_pending_board_by_vtxo_id(&self, _vtxo_id: VtxoId) -> anyhow::Result<Option<PendingBoard>> {
		Ok(None)
	}

	async fn get_wallet_vtxo(&self, _id: VtxoId) -> anyhow::Result<Option<WalletVtxo>> {
		Ok(Some(WalletVtxo {
			vtxo: Vtxo::deserialize(&[])?,
			state: VtxoState::Spendable,
		}))
	}

	async fn get_all_vtxos(&self) -> anyhow::Result<Vec<WalletVtxo>> {
		Ok(Vec::<WalletVtxo>::from([WalletVtxo {
			vtxo: Vtxo::deserialize(&[])?,
			state: VtxoState::Spendable,
		}]))
	}

	async fn get_vtxos_by_state(&self, _state: &[VtxoStateKind]) -> anyhow::Result<Vec<WalletVtxo>> {
		Ok(Vec::<WalletVtxo>::from([WalletVtxo {
			vtxo: Vtxo::deserialize(&[])?,
			state: VtxoState::Locked {
				movement_id: Some(MovementId::new(0)),
			},
		}]))
	}

	async fn remove_vtxo(&self, _id: VtxoId) -> anyhow::Result<Option<Vtxo>> {
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

	async fn store_new_pending_lightning_send(
		&self,
		invoice: &Invoice,
		amount: &Amount,
		_vtxos: &[VtxoId],
		movement_id: MovementId
	) -> anyhow::Result<LightningSend> {
		Ok(LightningSend {
			invoice: invoice.clone(),
			amount: *amount,
			htlc_vtxos: vec![],
			preimage: None,
			movement_id,
			finished_at: None,
		})
	}

	async fn get_all_pending_lightning_send(&self) -> anyhow::Result<Vec<LightningSend>> {
		Ok(vec![])
	}

	async fn finish_lightning_send(
		&self,
		_payment_hash: PaymentHash,
		_preimage: Option<Preimage>,
	) -> anyhow::Result<()> {
		Ok(())
	}

	async fn remove_lightning_send(&self, _payment_hash: PaymentHash) -> anyhow::Result<()> {
		Ok(())
	}

	async fn get_lightning_send(&self, _payment_hash: PaymentHash) -> anyhow::Result<Option<LightningSend>> {
		Ok(Some(dummy_lightning_send()))
	}

	async fn store_lightning_receive(
		&self,
		_payment_hash: PaymentHash,
		_preimage: Preimage,
		_invoice: &Bolt11Invoice,
		_htlc_recv_cltv_delta: BlockDelta,
	) -> anyhow::Result<()> {
		Ok(())
	}

	async fn get_all_pending_lightning_receives(&self) -> anyhow::Result<Vec<LightningReceive>> {
		Ok(Vec::<LightningReceive>::from([
			dummy_lightning_receive(),
		]))
	}

	async fn set_preimage_revealed(&self, _payment_hash: PaymentHash) -> anyhow::Result<()> {
		Ok(())
	}

	async fn update_lightning_receive(
		&self,
		_payment_hash: PaymentHash,
		_vtxo_ids: &[VtxoId],
		_movement_id: MovementId,
	) -> anyhow::Result<()> {
		Ok(())
	}

	async fn fetch_lightning_receive_by_payment_hash(
		&self,
		_payment_hash: PaymentHash,
	) -> anyhow::Result<Option<LightningReceive>> {
		Ok(Some(dummy_lightning_receive()))
	}

	async fn finish_pending_lightning_receive(&self, _payment_hash: PaymentHash) -> anyhow::Result<()> {
		Ok(())
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
			}
		]))
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
		}]).pop().unwrap())
	}

	async fn store_round_state_lock_vtxos(&self, _round_state: &RoundState) -> anyhow::Result<RoundStateId> {
		Ok(RoundStateId(5))
	}

	async fn update_round_state(&self, _round_state: &StoredRoundState) -> anyhow::Result<()> {
		Ok(())
	}

	async fn remove_round_state(&self, _round_state: &StoredRoundState) -> anyhow::Result<()> {
		Ok(())
	}

	async fn load_round_states(&self) -> anyhow::Result<Vec<StoredRoundState>> {
		Ok(vec![StoredRoundState {
			id: RoundStateId(5),
			state: rmp_serde::from_slice::<models::SerdeRoundState>(&[]).unwrap().into(),
		}])
	}

	async fn create_new_movement(
		&self,
		_status: MovementStatus,
		_subsystem: &MovementSubsystem,
		_time: DateTime<Local>,
	) -> anyhow::Result<MovementId> {
		Ok(MovementId::new(0))
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

	async fn store_vtxos(
		&self,
		_vtxos: &[(&Vtxo, &VtxoState)],
	) -> anyhow::Result<()> {
		Ok(())
	}
}

fn dummy_lightning_send() -> LightningSend {
	LightningSend {
		invoice: Invoice::Bolt11(Bolt11Invoice::from_str("bob").unwrap()),
		amount: Amount::ZERO,
		htlc_vtxos: vec![],
		movement_id: MovementId::new(0),
		preimage: None,
		finished_at: None,
	}
}

fn dummy_lightning_receive() -> LightningReceive {
	LightningReceive {
		payment_hash: PaymentHash::from_slice(&[]).unwrap(),
		payment_preimage: Preimage::from_slice(&[]).unwrap(),
		invoice: Bolt11Invoice::from_str("bob").unwrap(),
		preimage_revealed_at: None,
		htlc_vtxos: None,
		htlc_recv_cltv_delta: 0,
		movement_id: Some(MovementId::new(0)),
		finished_at: None,
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

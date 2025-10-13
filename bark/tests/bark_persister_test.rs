use std::str::FromStr;

use bdk_wallet::ChangeSet;
use bitcoin::{Amount, BlockHash, Network, ScriptBuf, Transaction, Txid};
use bitcoin::bip32::Fingerprint;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::PublicKey;
use lightning_invoice::Bolt11Invoice;

use ark::{OffboardRequest, Vtxo, VtxoId, VtxoPolicy};
use ark::lightning::{Invoice, PaymentHash, Preimage};
use ark::musig::SecretNonce;
use ark::musig::secpm::ffi::MUSIG_SECNONCE_SIZE;
use ark::rounds::{RoundId, RoundSeq};
use ark::vtxo::{PubkeyVtxoPolicy, ServerHtlcRecvVtxoPolicy, ServerHtlcSendVtxoPolicy};
use bark::{WalletProperties, WalletVtxo};
use bark::movement::{Movement, MovementArgs, MovementKind, MovementRecipient};
use bark::persist::BarkPersister;
use bark::persist::models::{LightningReceive, StoredExit, StoredVtxoRequest};
use bark::round::{
	AttemptStartedState, PendingConfirmationState, RoundConfirmedState, RoundParticipation,
	RoundState, VtxoForfeitedInRound,
};
use bark::vtxo_state::{VtxoState, VtxoStateKind};
use bark_json::exit::ExitState;
use bark_json::exit::states::{ExitClaimableState, ExitTxOrigin};
use bitcoin_ext::{BlockHeight, BlockRef};
use server_rpc::TryFromBytes;

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

	fn get_movements(&self) -> anyhow::Result<Vec<Movement>> {
		Ok(Vec::<Movement>::from([Movement {
			id: 0,
			kind: MovementKind::Board,
			fees: Amount::ZERO,
			spends: Vec::<Vtxo>::new(),
			receives: Vec::<Vtxo>::new(),
			recipients: Vec::<MovementRecipient>::from([MovementRecipient {
				recipient: "".to_string(),
				amount: Amount::ZERO,
			}]),
			created_at: "".to_string(),
		}]))
	}

	fn register_movement(&self, _movement: MovementArgs) -> anyhow::Result<()> {
		Ok(())
	}

	fn store_new_round_attempt(
		&self,
		_round_seq: RoundSeq,
		_attempt_seq: usize,
		_round_participation: RoundParticipation,
	) -> anyhow::Result<AttemptStartedState> {
		Ok(AttemptStartedState {
			round_attempt_id: 0,
			round_seq: RoundSeq::new(0),
			attempt_seq: 0,
			participation: dummy_round_participation()
		})
	}

	fn store_pending_confirmation_round(
		&self,
		_round_txid: RoundId,
		_round_tx: Transaction,
		_reqs: Vec<StoredVtxoRequest>,
		_vtxos: Vec<Vtxo>,
	) -> anyhow::Result<PendingConfirmationState> {
		Ok(PendingConfirmationState {
			round_attempt_id: 0,
			round_seq: Some(RoundSeq::new(0)),
			attempt_seq: Some(0),
			participation: dummy_round_participation(),
			round_tx: Transaction::from_bytes([])?,
			round_txid: RoundId::from_bytes([])?,
			vtxos: Vec::<Vtxo>::new(),
			forfeited_vtxos: Vec::<VtxoForfeitedInRound>::from([
				VtxoForfeitedInRound {
					round_attempt_id: 0,
					vtxo_id: VtxoId::from_bytes([])?,
					double_spend_txid: Some(Txid::all_zeros()),
				}
			]),
		})
	}

	fn store_round_state(
		&self,
		_round_state: RoundState,
		_prev_state: RoundState,
	) -> anyhow::Result<RoundState> {
		Ok(dummy_round_state())
	}

	fn store_secret_nonces(
		&self,
		_round_attempt_id: i64,
		_secret_nonces: Vec<Vec<SecretNonce>>,
	) -> anyhow::Result<()> {
		Ok(())
	}

	fn take_secret_nonces(
		&self,
		_round_attempt_id: i64,
	) -> anyhow::Result<Option<Vec<Vec<SecretNonce>>>> {
		Ok(Some(vec![Vec::<SecretNonce>::from([
			SecretNonce::dangerous_from_bytes([0u8; MUSIG_SECNONCE_SIZE])
		])]))
	}

	fn get_round_attempt_by_id(
		&self,
		_round_attempt_id: i64,
	) -> anyhow::Result<Option<RoundState>> {
		Ok(Some(dummy_round_state()))
	}

	fn get_round_attempt_by_round_txid(
		&self,
		_round_id: RoundId,
	) -> anyhow::Result<Option<RoundState>> {
		Ok(Some(dummy_round_state()))
	}

	fn list_pending_rounds(&self) -> anyhow::Result<Vec<RoundState>> {
		Ok(Vec::<RoundState>::from([dummy_round_state()]))
	}

	fn get_wallet_vtxo(&self, _id: VtxoId) -> anyhow::Result<Option<WalletVtxo>> {
		Ok(Some(WalletVtxo {
			vtxo: Vtxo::from_bytes([])?,
			state: VtxoState::Spendable,
		}))
	}

	fn get_vtxos_by_state(&self, _state: &[VtxoStateKind]) -> anyhow::Result<Vec<WalletVtxo>> {
		Ok(Vec::<WalletVtxo>::from([WalletVtxo {
			vtxo: Vtxo::from_bytes([])?,
			state: VtxoState::PendingLightningRecv {
				payment_hash: PaymentHash::from_bytes([])?,
			},
		}]))
	}

	fn get_in_round_vtxos(&self) -> anyhow::Result<Vec<WalletVtxo>> {
		Ok(Vec::<WalletVtxo>::from([WalletVtxo {
			vtxo: Vtxo::from_bytes([])?,
			state: VtxoState::PendingLightningSend {
				invoice: Invoice::Bolt11(Bolt11Invoice::from_str("bob")?),
				amount: Amount::ZERO,
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

	fn store_lightning_receive(
		&self,
		_payment_hash: PaymentHash,
		_preimage: Preimage,
		_invoice: &Bolt11Invoice,
	) -> anyhow::Result<()> {
		Ok(())
	}

	fn get_lightning_receives(&self) -> anyhow::Result<Vec<LightningReceive>> {
		Ok(Vec::<LightningReceive>::from([
			dummy_lightning_receive(),
		]))
	}

	fn get_pending_lightning_receives(&self) -> anyhow::Result<Vec<LightningReceive>> {
		Ok(Vec::<LightningReceive>::from([
			dummy_lightning_receive(),
		]))
	}

	fn set_preimage_revealed(&self, _payment_hash: PaymentHash) -> anyhow::Result<()> {
		Ok(())
	}

	fn fetch_lightning_receive_by_payment_hash(
		&self,
		_payment_hash: PaymentHash,
	) -> anyhow::Result<Option<LightningReceive>> {
		Ok(Some(dummy_lightning_receive()))
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
}

fn dummy_lightning_receive() -> LightningReceive {
	LightningReceive {
		payment_hash: PaymentHash::from_bytes([]).unwrap(),
		payment_preimage: Preimage::from_bytes([]).unwrap(),
		invoice: Bolt11Invoice::from_str("bob").unwrap(),
		preimage_revealed_at:Some(0),
	}
}

fn dummy_round_participation() -> RoundParticipation {
	RoundParticipation {
		inputs: Vec::<Vtxo>::new(),
		outputs: Vec::<StoredVtxoRequest>::from([
			StoredVtxoRequest {
				request_policy: VtxoPolicy::Pubkey(PubkeyVtxoPolicy {
					user_pubkey: PublicKey::from_bytes([]).unwrap(),
				}),
				amount: Amount::ZERO,
				state: VtxoState::Spendable,
			},
			StoredVtxoRequest {
				request_policy: VtxoPolicy::ServerHtlcSend(ServerHtlcSendVtxoPolicy {
					user_pubkey: PublicKey::from_bytes([]).unwrap(),
					payment_hash: PaymentHash::from_bytes([]).unwrap(),
					htlc_expiry: 0 as BlockHeight,
				}),
				amount: Amount::ZERO,
				state: VtxoState::Spendable,
			},
			StoredVtxoRequest {
				request_policy: VtxoPolicy::ServerHtlcRecv(ServerHtlcRecvVtxoPolicy {
					user_pubkey: PublicKey::from_bytes([]).unwrap(),
					payment_hash: PaymentHash::from_bytes([]).unwrap(),
					htlc_expiry: 0 as BlockHeight,
				}),
				amount: Amount::ZERO,
				state: VtxoState::Spendable,
			},
		]),
		offboards: Vec::<OffboardRequest>::from([
			OffboardRequest {
				script_pubkey: ScriptBuf::new_p2a(),
				amount: Amount::ZERO,
			},
		]),
	}
}

fn dummy_round_state() -> RoundState {
	RoundState::RoundConfirmed(RoundConfirmedState {
		round_attempt_id: 0,
		round_seq: Some(RoundSeq::new(0)),
		attempt_seq: Some(0),
		round_tx: Transaction::from_bytes([]).unwrap(),
		round_txid: RoundId::from_bytes([]).unwrap(),
	})
}

#[test]
fn compiles_if_all_types_are_exported() {
	// If this file compiles, we're good.
	let _dummy = Dummy {};
}
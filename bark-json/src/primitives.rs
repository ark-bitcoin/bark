
use std::ops::Deref;
use std::sync::Arc;

use bark::actions::WalletActionId;
use bitcoin::{Amount, OutPoint, SignedAmount, Transaction, Txid};
use bitcoin::secp256k1::PublicKey;
#[cfg(feature = "utoipa")]
use utoipa::ToSchema;

use ark::{Vtxo, VtxoId};
use ark::vtxo::{Full, VtxoPolicyKind};
use bark::movement::MovementId;
use bark::vtxo::VtxoState;
use bitcoin_ext::{BlockDelta, BlockHeight};

/// Reference to a block in the blockchain.
///
/// Contains the block height and hash. Serializes as an object with `height` and `hash` fields.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct BlockRef {
	pub height: BlockHeight,
	#[cfg_attr(feature = "utoipa", schema(value_type = String))]
	pub hash: bitcoin::BlockHash,
}

impl From<bitcoin_ext::BlockRef> for BlockRef {
	fn from(v: bitcoin_ext::BlockRef) -> Self {
		BlockRef {
			height: v.height,
			hash: v.hash,
		}
	}
}

impl From<BlockRef> for bitcoin_ext::BlockRef {
	fn from(v: BlockRef) -> Self {
		bitcoin_ext::BlockRef {
			height: v.height,
			hash: v.hash,
		}
	}
}

/// Struct representing information about an Unspent Transaction Output (UTXO).
///
/// This structure provides details about a UTXO, which includes the outpoint (transaction ID and
/// index), the associated amount in satoshis, and the block height at which the transaction was
/// confirmed (if available).
///
/// # Serde Behavior
///
/// * The `amount` field is serialized and deserialized with a custom function from the `bitcoin`
///   crate that ensures the value is interpreted as satoshis with the name `amount_sat`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct UtxoInfo {
	/// Contains the reference to the specific transaction output via transaction ID and index.
	#[cfg_attr(feature = "utoipa", schema(value_type = String))]
	pub outpoint: OutPoint,
	/// The value of the UTXO in satoshis.
	#[serde(rename = "amount_sat", with = "bitcoin::amount::serde::as_sat")]
	#[cfg_attr(feature = "utoipa", schema(value_type = u64))]
	pub amount: Amount,
	/// An optional field that specifies the block height at which the transaction was confirmed. If
	/// the transaction is unconfirmed, this value will be `None`.
	pub confirmation_height: Option<u32>,
}

impl From<bark::UtxoInfo> for UtxoInfo {
	fn from(v: bark::UtxoInfo) -> Self {
		UtxoInfo {
			outpoint: v.outpoint,
			amount: v.amount,
			confirmation_height: v.confirmation_height,
		}
	}
}

impl From<bark::onchain::Utxo> for UtxoInfo {

	fn from(v: bark::onchain::Utxo) -> Self {
		match v {
			bark::onchain::Utxo::Local(o) => UtxoInfo {
				outpoint: o.outpoint,
				amount: o.amount,
				confirmation_height: o.confirmation_height,
			},
			bark::onchain::Utxo::Exit(e) => UtxoInfo {
				outpoint: e.vtxo.point(),
				amount: e.vtxo.amount(),
				confirmation_height: Some(e.height),
			},
		}
	}
}

/// Information about a single VTXO (Virtual Transaction Output).
///
/// A VTXO is a chain of off-chain, pre-signed transactions rooted in an
/// on-chain output. It represents spendable bitcoin on Ark.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct VtxoInfo {
	/// Unique identifier for this VTXO, formatted as `txid:vout`.
	#[cfg_attr(feature = "utoipa", schema(value_type = String))]
	pub id: VtxoId,
	/// The value of this VTXO in sats.
	#[serde(rename = "amount_sat", with = "bitcoin::amount::serde::as_sat")]
	#[cfg_attr(feature = "utoipa", schema(value_type = u64))]
	pub amount: Amount,
	/// The spending policy that governs this VTXO.
	#[cfg_attr(feature = "utoipa", schema(value_type = String))]
	pub policy_type: VtxoPolicyKind,
	/// The owner's public key. Only the holder of the corresponding
	/// private key can spend this VTXO.
	#[cfg_attr(feature = "utoipa", schema(value_type = String))]
	pub user_pubkey: PublicKey,
	/// The Ark server's public key used to co-sign transactions
	/// involving this VTXO.
	#[cfg_attr(feature = "utoipa", schema(value_type = String))]
	pub server_pubkey: PublicKey,
	/// The block height at which this VTXO expires. After expiry, the
	/// server can reclaim the sats. Refresh before expiry to receive
	/// new VTXOs, or exit to move them on-chain.
	pub expiry_height: BlockHeight,
	/// The relative timelock, in blocks, that must elapse before the
	/// final on-chain claim in an emergency exit.
	pub exit_delta: BlockDelta,
	/// The on-chain outpoint that roots this VTXO, formatted as
	/// `txid:vout`. Typically an output of a round transaction or a
	/// board transaction.
	#[cfg_attr(feature = "utoipa", schema(value_type = String))]
	pub chain_anchor: OutPoint,
	/// The number of off-chain transactions in this VTXO. Each must
	/// be broadcast and confirmed on-chain in sequence during an
	/// emergency exit.
	pub exit_depth: Option<u16>,
}

impl<'a> From<&'a Vtxo<Full>> for VtxoInfo {
	fn from(v: &'a Vtxo<Full>) -> VtxoInfo {
		VtxoInfo {
			id: v.id(),
			amount: v.amount(),
			policy_type: v.policy().policy_type(),
			user_pubkey: v.user_pubkey(),
			server_pubkey: v.server_pubkey(),
			expiry_height: v.expiry_height(),
			exit_delta: v.exit_delta(),
			chain_anchor: v.chain_anchor(),
			exit_depth: Some(v.exit_depth()),
		}
	}
}

impl From<Vtxo<Full>> for VtxoInfo {
	fn from(v: Vtxo<Full>) -> VtxoInfo {
		VtxoInfo::from(&v)
	}
}

/// A VTXO together with its current wallet state.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct WalletVtxoInfo {
	/// The VTXO details.
	#[serde(flatten)]
	pub vtxo: VtxoInfo,
	/// The current state of this VTXO in the wallet.
	pub state: VtxoStateInfo,
}

impl<'a> From<&'a bark::WalletVtxo> for WalletVtxoInfo {
	fn from(v: &'a bark::WalletVtxo) -> Self {
		WalletVtxoInfo {
			vtxo: VtxoInfo {
				id: v.id(),
				amount: v.amount(),
				policy_type: v.policy().policy_type(),
				user_pubkey: v.user_pubkey(),
				server_pubkey: v.server_pubkey(),
				expiry_height: v.expiry_height(),
				exit_delta: v.exit_delta(),
				chain_anchor: v.chain_anchor(),
				exit_depth: Some(v.exit_depth),
			},
			state: VtxoStateInfo::from(&v.state),
		}
	}
}

/// Hex-encoded serialized VTXO.
///
/// Serializes as a plain hex string. Can be passed to
/// `POST /wallet/import-vtxo` to re-import this VTXO.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct EncodedVtxo(pub String);

impl Deref for WalletVtxoInfo {
	type Target = VtxoInfo;

	fn deref(&self) -> &Self::Target {
		&self.vtxo
	}
}

/// The current state of a VTXO in the wallet.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum VtxoStateInfo {
	/// The VTXO can be spent immediately.
	Spendable,
	/// The VTXO has already been spent.
	Spent,
	/// The VTXO has been moved on-chain via a unilateral exit and is no longer
	/// usable in the protocol.
	Exited,
	/// The VTXO is locked by an in-progress movement (e.g. a pending
	/// round or Lightning payment).
	Locked {
		/// The movement that locked this VTXO, if any.
		#[serde(skip_serializing_if = "Option::is_none")]
		#[cfg_attr(feature = "utoipa", schema(value_type = u32))]
		movement_id: Option<MovementId>,
		/// The action that locked this VTXO, if any.
		#[serde(skip_serializing_if = "Option::is_none")]
		#[cfg_attr(feature = "utoipa", schema(value_type = String))]
		action_id: Option<WalletActionId>,
	},
}

impl<'a> From<&'a VtxoState> for VtxoStateInfo {
	fn from(state: &'a VtxoState) -> Self {
		match state {
			VtxoState::Spendable => VtxoStateInfo::Spendable,
			VtxoState::Spent => VtxoStateInfo::Spent,
			VtxoState::Exited => VtxoStateInfo::Exited,
			VtxoState::Locked { holder } => {
				match holder {
					Some(bark::vtxo::VtxoLockHolder::Movement { id }) => {
						VtxoStateInfo::Locked { movement_id: Some(*id), action_id: None }
					},
					Some(bark::vtxo::VtxoLockHolder::Action { id }) => {
						VtxoStateInfo::Locked { movement_id: None, action_id: Some(id.clone()) }
					},
					None => VtxoStateInfo::Locked { movement_id: None, action_id: None },
				}
			},
		}
	}
}

/// An information struct used to pair the ID of a transaction with the full transaction for ease
/// of use and readability for the user
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct TransactionInfo {
	#[cfg_attr(feature = "utoipa", schema(value_type = String))]
	pub txid: Txid,
	#[serde(with = "bitcoin::consensus::serde::With::<bitcoin::consensus::serde::Hex>")]
	#[cfg_attr(feature = "utoipa", schema(value_type = String))]
	pub tx: Transaction,
}

impl From<bark::exit::TransactionInfo> for TransactionInfo {
	fn from(v: bark::exit::TransactionInfo) -> Self {
		TransactionInfo { txid: v.txid, tx: v.tx }
	}
}

impl From<Transaction> for TransactionInfo {
	fn from(v: Transaction) -> Self {
		TransactionInfo { txid: v.compute_txid(), tx: v }
	}
}

impl From<Arc<Transaction>> for TransactionInfo {
	fn from(v: Arc<Transaction>) -> Self {
		TransactionInfo { txid: v.compute_txid(), tx: (*v).clone() }
	}
}

/// A richer wallet-transaction summary returned by the onchain transactions endpoint.
///
/// Includes the raw transaction plus its fee, the wallet's net balance change, and
/// confirmation status.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct WalletTxInfo {
	#[cfg_attr(feature = "utoipa", schema(value_type = String))]
	pub txid: Txid,
	#[serde(with = "bitcoin::consensus::serde::With::<bitcoin::consensus::serde::Hex>")]
	#[cfg_attr(feature = "utoipa", schema(value_type = String))]
	pub tx: Transaction,
	/// Total fee paid by the transaction, when known. `None` for txs whose foreign
	/// prevouts BDK has not indexed (e.g. inbound payments observed via the
	/// bitcoind-rpc sync path; esplora sync always populates prevouts).
	#[serde(rename = "onchain_fee_sat", default, with = "bitcoin::amount::serde::as_sat::opt", skip_serializing_if = "Option::is_none")]
	#[cfg_attr(feature = "utoipa", schema(value_type = Option<u64>))]
	pub onchain_fees: Option<Amount>,
	/// Net change to the wallet's balance: `received - sent` over wallet-owned outputs.
	/// Positive for inbound, negative for outbound, zero for self-spends with no net change.
	#[serde(rename = "balance_change_sat", with = "bitcoin::amount::serde::as_sat")]
	#[cfg_attr(feature = "utoipa", schema(value_type = i64))]
	pub balance_change: SignedAmount,
	/// `Some` when the transaction is mined; `None` while still in the mempool.
	pub confirmation: Option<BlockRef>,
	/// `true` when this tx spends a P2A fee anchor output — i.e. it is a CPFP
	/// child bumping its parent. In bark this typically means the wallet is
	/// fee-bumping an exit transaction.
	pub is_cpfp: bool,
}

impl From<bark::onchain::WalletTxInfo> for WalletTxInfo {
	fn from(v: bark::onchain::WalletTxInfo) -> Self {
		WalletTxInfo {
			txid: v.txid,
			tx: (*v.tx).clone(),
			onchain_fees: v.onchain_fees,
			balance_change: v.balance_change,
			confirmation: v.confirmation.map(Into::into),
			is_cpfp: v.is_cpfp,
		}
	}
}

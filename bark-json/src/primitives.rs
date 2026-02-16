
use std::ops::Deref;
use std::sync::Arc;

use bitcoin::{Amount, OutPoint, Transaction, Txid};
use bitcoin::secp256k1::PublicKey;
#[cfg(feature = "utoipa")]
use utoipa::ToSchema;

use ark::{Vtxo, VtxoId};
use ark::vtxo::VtxoPolicyKind;
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

/// Struct representing information about a VTXO.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct VtxoInfo {
	#[cfg_attr(feature = "utoipa", schema(value_type = String))]
	pub id: VtxoId,
	#[serde(rename = "amount_sat", with = "bitcoin::amount::serde::as_sat")]
	#[cfg_attr(feature = "utoipa", schema(value_type = u64))]
	pub amount: Amount,
	#[cfg_attr(feature = "utoipa", schema(value_type = String))]
	pub policy_type: VtxoPolicyKind,
	#[cfg_attr(feature = "utoipa", schema(value_type = String))]
	pub user_pubkey: PublicKey,
	#[cfg_attr(feature = "utoipa", schema(value_type = String))]
	pub server_pubkey: PublicKey,
	pub expiry_height: BlockHeight,
	pub exit_delta: BlockDelta,
	#[cfg_attr(feature = "utoipa", schema(value_type = String))]
	pub chain_anchor: OutPoint,
	pub exit_depth: u16,
}

impl<'a> From<&'a Vtxo> for VtxoInfo {
	fn from(v: &'a Vtxo) -> VtxoInfo {
		VtxoInfo {
			id: v.id(),
			amount: v.amount(),
			policy_type: v.policy().policy_type(),
			user_pubkey: v.user_pubkey(),
			server_pubkey: v.server_pubkey(),
			expiry_height: v.expiry_height(),
			exit_delta: v.exit_delta(),
			chain_anchor: v.chain_anchor(),
			exit_depth: v.exit_depth(),
		}
	}
}

impl From<Vtxo> for VtxoInfo {
	fn from(v: Vtxo) -> VtxoInfo {
		VtxoInfo::from(&v)
	}
}

/// Same as [VtxoInfo], but with the current VTXO state.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct WalletVtxoInfo {
	#[serde(flatten)]
	pub vtxo: VtxoInfo,
	pub state: VtxoStateInfo,
}

impl From<bark::WalletVtxo> for WalletVtxoInfo {
	fn from(v: bark::WalletVtxo) -> Self {
		WalletVtxoInfo {
			vtxo: v.vtxo.into(),
			state: v.state.into(),
		}
	}
}

impl Deref for WalletVtxoInfo {
	type Target = VtxoInfo;

	fn deref(&self) -> &Self::Target {
		&self.vtxo
	}
}

/// Describe the state of a [Vtxo] with additional context.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum VtxoStateInfo {
	Spendable,
	Spent,
	Locked {
		#[serde(skip_serializing_if = "Option::is_none")]
		#[cfg_attr(feature = "utoipa", schema(value_type = u32))]
		movement_id: Option<MovementId>,
	},
}

impl From<VtxoState> for VtxoStateInfo {
	fn from(state: VtxoState) -> Self {
		match state {
			VtxoState::Spendable => VtxoStateInfo::Spendable,
			VtxoState::Spent => VtxoStateInfo::Spent,
			VtxoState::Locked { movement_id } => VtxoStateInfo::Locked {
				movement_id,
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

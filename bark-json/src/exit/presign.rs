use bitcoin::{Transaction, Txid};

use ark::VtxoId;

#[cfg(feature = "utoipa")]
use utoipa::ToSchema;

use crate::exit::package::FeeInfo;
use crate::primitives::TransactionInfo;

/// How much of a [PresignedExit]'s remaining broadcast work could be funded and signed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub enum PresignedExitStatus {
	/// Every package has a signed child; the exit's broadcast completes once wave
	/// `exited_in_wave` confirms (absent when the chain is already confirmed and there is
	/// nothing to broadcast). `fee_info` totals the children's fees over the combined weight
	/// of this exit's packages.
	FullySigned {
		#[serde(default, skip_serializing_if = "Option::is_none")]
		exited_in_wave: Option<usize>,
		fee_info: FeeInfo,
	},
	/// Confirmed funds ran out mid-chain: wave `last_wave` holds this exit's last signed
	/// package and `unsigned` continues right after it.
	PartiallySigned { last_wave: usize },
	/// No package could be funded.
	Unsigned,
}

impl From<bark::exit::PresignedExitStatus> for PresignedExitStatus {
	fn from(v: bark::exit::PresignedExitStatus) -> Self {
		match v {
			bark::exit::PresignedExitStatus::FullySigned { exited_in_wave, fee_info } =>
				PresignedExitStatus::FullySigned { exited_in_wave, fee_info: fee_info.into() },
			bark::exit::PresignedExitStatus::PartiallySigned { last_wave } =>
				PresignedExitStatus::PartiallySigned { last_wave },
			bark::exit::PresignedExitStatus::Unsigned => PresignedExitStatus::Unsigned,
		}
	}
}

/// A signed CPFP child transaction and the fee it commits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct PresignedExitChildInfo {
	#[cfg_attr(feature = "utoipa", schema(value_type = String))]
	pub txid: Txid,
	#[serde(with = "bitcoin::consensus::serde::With::<bitcoin::consensus::serde::Hex>")]
	#[cfg_attr(feature = "utoipa", schema(value_type = String))]
	pub tx: Transaction,
	/// The exit transaction is zero-fee, so this is the fee of the whole package.
	pub fee_info: FeeInfo,
}

impl From<bark::exit::PresignedExitChildInfo> for PresignedExitChildInfo {
	fn from(v: bark::exit::PresignedExitChildInfo) -> Self {
		PresignedExitChildInfo {
			txid: v.txid,
			tx: v.tx,
			fee_info: v.fee_info.into(),
		}
	}
}

/// An `(exit, child)` transaction package, to be broadcast as one unit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct PresignedExitPackage {
	/// The VTXO whose exit this package advances.
	#[cfg_attr(feature = "utoipa", schema(value_type = String))]
	pub vtxo_id: VtxoId,
	/// The zero-fee exit transaction.
	pub exit: TransactionInfo,
	/// The signed CPFP child paying for `exit`.
	pub child: PresignedExitChildInfo,
}

impl From<bark::exit::PresignedExitPackage> for PresignedExitPackage {
	fn from(v: bark::exit::PresignedExitPackage) -> Self {
		PresignedExitPackage {
			vtxo_id: v.vtxo_id,
			exit: v.exit.into(),
			child: v.child.into(),
		}
	}
}

/// One step of the broadcast plan; see [PresignedExits] for the rules.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct PresignedWave {
	/// Packages funded independently of each other, broadcast together.
	pub packages: Vec<PresignedExitPackage>,
	/// Exit transactions already in the mempool; they confirm with this wave. Only the first
	/// wave has any.
	pub in_mempool: Vec<TransactionInfo>,
}

impl From<bark::exit::PresignedWave> for PresignedWave {
	fn from(v: bark::exit::PresignedWave) -> Self {
		PresignedWave {
			packages: v.packages.into_iter().map(Into::into).collect(),
			in_mempool: v.in_mempool.into_iter().map(Into::into).collect(),
		}
	}
}

/// The presigned broadcast work for one VTXO.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct PresignedExit {
	#[cfg_attr(feature = "utoipa", schema(value_type = String))]
	pub vtxo_id: VtxoId,
	pub status: PresignedExitStatus,
	/// The remaining tail of this exit's chain that could not be funded, in broadcast order;
	/// its first transaction spends this exit's last signed one. Empty when fully signed.
	pub unsigned: Vec<TransactionInfo>,
}

impl From<bark::exit::PresignedExit> for PresignedExit {
	fn from(v: bark::exit::PresignedExit) -> Self {
		PresignedExit {
			vtxo_id: v.vtxo_id,
			status: v.status.into(),
			unsigned: v.unsigned.into_iter().map(Into::into).collect(),
		}
	}
}

/// Presigned emergency-exit chains for a set of VTXOs: a wave-by-wave broadcast plan plus a
/// per-VTXO summary.
///
/// Execute the plan in wave order: broadcast all of a wave's packages together, then wait for
/// every one, and its `in_mempool` transactions, to confirm before the next wave — each
/// wave's children spend change confirmed by the previous wave.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct PresignedExits {
	/// One entry per requested VTXO, in request order.
	pub exits: Vec<PresignedExit>,
	/// The broadcast plan. Confirmed transactions are omitted, relayed ones are listed in
	/// `in_mempool`, and a package shared by several exits appears once, under the first exit
	/// that references it.
	pub waves: Vec<PresignedWave>,
}

impl From<bark::exit::PresignedExits> for PresignedExits {
	fn from(v: bark::exit::PresignedExits) -> Self {
		PresignedExits {
			exits: v.exits.into_iter().map(Into::into).collect(),
			waves: v.waves.into_iter().map(Into::into).collect(),
		}
	}
}

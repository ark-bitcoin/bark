use bitcoin::Amount;
#[cfg(feature = "utoipa")]
use utoipa::ToSchema;
use ark::fees::PpmFeeRate;

/// Complete fee schedule for all operations.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct FeeSchedule {
	pub board: BoardFees,
	pub offboard: OffboardFees,
	pub refresh: RefreshFees,
	pub lightning_receive: LightningReceiveFees,
	pub lightning_send: LightningSendFees,
}

impl From<ark::fees::FeeSchedule> for FeeSchedule {
	fn from(v: ark::fees::FeeSchedule) -> Self {
		Self {
			board: v.board.into(),
			offboard: v.offboard.into(),
			refresh: v.refresh.into(),
			lightning_receive: v.lightning_receive.into(),
			lightning_send: v.lightning_send.into(),
		}
	}
}

impl From<FeeSchedule> for ark::fees::FeeSchedule {
	fn from(v: FeeSchedule) -> Self {
		Self {
			board: v.board.into(),
			offboard: v.offboard.into(),
			refresh: v.refresh.into(),
			lightning_receive: v.lightning_receive.into(),
			lightning_send: v.lightning_send.into(),
		}
	}
}

/// Entry in a table to calculate the PPM (parts per million) fee rate of a transaction based on how
/// new a VTXO is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct PpmExpiryFeeEntry {
	/// A threshold for the number of blocks until a VTXO expires for the `ppm` amount to apply.
	/// As an example, if this value is set to 50 and a VTXO expires in 60 blocks, this
	/// [PpmExpiryFeeEntry] will be used to calculate the fee unless another entry exists with an
	/// `expiry_blocks_threshold` with a value between 51 and 60 (inclusive).
	pub expiry_blocks_threshold: u32,
	/// PPM (parts per million) fee rate to apply for this expiry period.
	#[cfg_attr(feature = "utoipa", schema(value_type = u64))]
	pub ppm: PpmFeeRate,
}

impl From<ark::fees::PpmExpiryFeeEntry> for PpmExpiryFeeEntry {
	fn from(v: ark::fees::PpmExpiryFeeEntry) -> Self {
		Self {
			expiry_blocks_threshold: v.expiry_blocks_threshold,
			ppm: v.ppm,
		}
	}
}

impl From<PpmExpiryFeeEntry> for ark::fees::PpmExpiryFeeEntry {
	fn from(v: PpmExpiryFeeEntry) -> Self {
		Self {
			expiry_blocks_threshold: v.expiry_blocks_threshold,
			ppm: v.ppm,
		}
	}
}

/// Fees for boarding the ark.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct BoardFees {
	/// Minimum fee to charge.
	#[serde(rename = "min_fee_sat", with = "bitcoin::amount::serde::as_sat")]
	#[cfg_attr(feature = "utoipa", schema(value_type = u64))]
	pub min_fee: Amount,
	/// A fee applied to every transaction regardless of value.
	#[serde(rename = "base_fee_sat", with = "bitcoin::amount::serde::as_sat")]
	#[cfg_attr(feature = "utoipa", schema(value_type = u64))]
	pub base_fee: Amount,
	/// PPM (parts per million) fee rate to apply based on the value of the transaction.
	#[cfg_attr(feature = "utoipa", schema(value_type = u64))]
	pub ppm: PpmFeeRate,
}

impl From<ark::fees::BoardFees> for BoardFees {
	fn from(v: ark::fees::BoardFees) -> Self {
		Self {
			min_fee: v.min_fee,
			base_fee: v.base_fee,
			ppm: v.ppm,
		}
	}
}

impl From<BoardFees> for ark::fees::BoardFees {
	fn from(v: BoardFees) -> Self {
		Self {
			min_fee: v.min_fee,
			base_fee: v.base_fee,
			ppm: v.ppm,
		}
	}
}

/// Fees for offboarding from the ark.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct OffboardFees {
	/// A fee applied to every transaction regardless of value.
	#[serde(rename = "base_fee_sat", with = "bitcoin::amount::serde::as_sat")]
	#[cfg_attr(feature = "utoipa", schema(value_type = u64))]
	pub base_fee: Amount,
	/// A table mapping how soon a VTXO will expire to a PPM (parts per million) fee rate.
	/// The table should be sorted by each `expiry_blocks_threshold` value in ascending order.
	pub ppm_expiry_table: Vec<PpmExpiryFeeEntry>,
}

impl From<ark::fees::OffboardFees> for OffboardFees {
	fn from(v: ark::fees::OffboardFees) -> Self {
		Self {
			base_fee: v.base_fee,
			ppm_expiry_table: v.ppm_expiry_table.into_iter().map(Into::into).collect(),
		}
	}
}

impl From<OffboardFees> for ark::fees::OffboardFees {
	fn from(v: OffboardFees) -> Self {
		Self {
			base_fee: v.base_fee,
			ppm_expiry_table: v.ppm_expiry_table.into_iter().map(Into::into).collect(),
		}
	}
}

/// Fees for refresh operations.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct RefreshFees {
	/// A fee applied to every transaction regardless of value.
	#[serde(rename = "base_fee_sat", with = "bitcoin::amount::serde::as_sat")]
	#[cfg_attr(feature = "utoipa", schema(value_type = u64))]
	pub base_fee: Amount,
	/// A table mapping how soon a VTXO will expire to a PPM (parts per million) fee rate.
	/// The table should be sorted by each `expiry_blocks_threshold` value in ascending order.
	pub ppm_expiry_table: Vec<PpmExpiryFeeEntry>,
}

impl From<ark::fees::RefreshFees> for RefreshFees {
	fn from(v: ark::fees::RefreshFees) -> Self {
		Self {
			base_fee: v.base_fee,
			ppm_expiry_table: v.ppm_expiry_table.into_iter().map(Into::into).collect(),
		}
	}
}

impl From<RefreshFees> for ark::fees::RefreshFees {
	fn from(v: RefreshFees) -> Self {
		Self {
			base_fee: v.base_fee,
			ppm_expiry_table: v.ppm_expiry_table.into_iter().map(Into::into).collect(),
		}
	}
}

/// Fees for lightning receive operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct LightningReceiveFees {
	/// A fee applied to every transaction regardless of value.
	#[serde(rename = "base_fee_sat", with = "bitcoin::amount::serde::as_sat")]
	#[cfg_attr(feature = "utoipa", schema(value_type = u64))]
	pub base_fee: Amount,
	/// PPM (parts per million) fee rate to apply based on the value of the transaction.
	#[cfg_attr(feature = "utoipa", schema(value_type = u64))]
	pub ppm: PpmFeeRate,
}

impl From<ark::fees::LightningReceiveFees> for LightningReceiveFees {
	fn from(v: ark::fees::LightningReceiveFees) -> Self {
		Self {
			base_fee: v.base_fee,
			ppm: v.ppm,
		}
	}
}

impl From<LightningReceiveFees> for ark::fees::LightningReceiveFees {
	fn from(v: LightningReceiveFees) -> Self {
		Self {
			base_fee: v.base_fee,
			ppm: v.ppm,
		}
	}
}

/// Fees for lightning send operations.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct LightningSendFees {
	/// Minimum fee to charge.
	#[serde(rename = "min_fee_sat", with = "bitcoin::amount::serde::as_sat")]
	#[cfg_attr(feature = "utoipa", schema(value_type = u64))]
	pub min_fee: Amount,
	/// A fee applied to every transaction regardless of value.
	#[serde(rename = "base_fee_sat", with = "bitcoin::amount::serde::as_sat")]
	#[cfg_attr(feature = "utoipa", schema(value_type = u64))]
	pub base_fee: Amount,
	/// A table mapping how soon a VTXO will expire to a PPM (parts per million) fee rate.
	/// The table should be sorted by each `expiry_blocks_threshold` value in ascending order.
	pub ppm_expiry_table: Vec<PpmExpiryFeeEntry>,
}

impl From<ark::fees::LightningSendFees> for LightningSendFees {
	fn from(v: ark::fees::LightningSendFees) -> Self {
		Self {
			min_fee: v.min_fee,
			base_fee: v.base_fee,
			ppm_expiry_table: v.ppm_expiry_table.into_iter().map(Into::into).collect(),
		}
	}
}

impl From<LightningSendFees> for ark::fees::LightningSendFees {
	fn from(v: LightningSendFees) -> Self {
		Self {
			min_fee: v.min_fee,
			base_fee: v.base_fee,
			ppm_expiry_table: v.ppm_expiry_table.into_iter().map(Into::into).collect(),
		}
	}
}

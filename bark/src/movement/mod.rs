

pub mod error;
pub mod manager;
pub mod update;
mod payment_method;

pub use self::payment_method::PaymentMethod;

use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;

use bitcoin::{Amount, SignedAmount};
use chrono::DateTime;
use lightning::offers::offer::Offer;
use lnurllib::lightning_address::LightningAddress;
use serde::{Deserialize, Serialize};

use ark::VtxoId;
use ark::lightning::Invoice;

const MOVEMENT_PENDING: &'static str = "pending";
const MOVEMENT_SUCCESSFUL: &'static str = "successful";
const MOVEMENT_FAILED: &'static str = "failed";
const MOVEMENT_CANCELED: &'static str = "canceled";

/// Describes an attempted movement of offchain funds within the [Wallet](crate::Wallet).
#[derive(Debug, Clone)]
pub struct Movement {
	/// The internal ID of the movement.
	pub id: MovementId,
	/// The status of the movement.
	pub status: MovementStatus,
	/// Contains information about the subsystem that created the movement as well as the purpose
	/// of the movement.
	pub subsystem: MovementSubsystem,
	/// Miscellaneous metadata for the movement. This is JSON containing arbitrary information as
	/// defined by the subsystem that created the movement.
	pub metadata: HashMap<String, serde_json::Value>,
	/// How much the movement was expected to increase or decrease the balance by. This is always an
	/// estimate and often discounts any applicable fees.
	pub intended_balance: SignedAmount,
	/// How much the wallet balance actually changed by. Positive numbers indicate an increase and
	/// negative numbers indicate a decrease. This is often inclusive of applicable fees, and it
	/// should be the most accurate number.
	pub effective_balance: SignedAmount,
	/// How much the movement cost the user in offchain fees. If there are applicable onchain fees
	/// they will not be included in this value but, depending on the subsystem, could be found in
	/// the metadata.
	pub offchain_fee: Amount,
	/// A list of external recipients that received funds from this movement.
	pub sent_to: Vec<MovementDestination>,
	/// Describes the means by which the wallet received funds in this movement. This could include
	/// BOLT11 invoices or other useful data.
	pub received_on: Vec<MovementDestination>,
	/// A list of [Vtxo](ark::Vtxo) IDs that were consumed by this movement and are either locked or
	/// unavailable.
	pub input_vtxos: Vec<VtxoId>,
	/// A list of IDs for new VTXOs that were produced as a result of this movement. Often change
	/// VTXOs will be found here for outbound actions unless this was an inbound action.
	pub output_vtxos: Vec<VtxoId>,
	/// A list of IDs for VTXOs that were marked for unilateral exit as a result of this movement.
	/// This could happen for many reasons, e.g. an unsuccessful lightning payment which can't be
	/// revoked but is about to expire. VTXOs listed here will result in a reduction of spendable
	/// balance due to the VTXOs being managed by the [crate::Exit] system.
	pub exited_vtxos: Vec<VtxoId>,
	/// Contains the times at which the movement was created, updated and completed.
	pub time: MovementTimestamp,
}

/// A unique identifier for a movement.
#[derive(Clone, Copy, Eq, Hash, PartialEq, Deserialize, Serialize)]
pub struct MovementId(pub u32);

impl MovementId {
	pub fn new(id: u32) -> Self {
		Self(id)
	}
}

impl fmt::Display for MovementId {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		fmt::Display::fmt(&self.0, f)
	}
}

impl fmt::Debug for MovementId {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		fmt::Display::fmt(&self, f)
	}
}

/// Represents the current status of a [Movement]. It's important to note that each status can
/// result in fund changes. As an example, a lightning payment could fail but this will still result
/// in a change of VTXOs. You can't assume that [MovementStatus::Failed] means that user funds
/// didn't change.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MovementStatus {
	/// The default status of a new [Movement]. Should be treated as in-progress.
	Pending,
	/// The [Movement] has completed with changes. Note; this does not necessarily mean the [Movement]
	/// completed successfully, e.g., VTXOs may be consumed and new ones produced.
	Successful,
	/// The [Movement] failed to complete due to an error. This should result in changes in user
	/// funds.
	Failed,
	/// A [Movement] was canceled, either by the protocol (e.g., lightning payments) or by the
	/// user.
	Canceled,
}

impl MovementStatus {
	/// Returns the canonical stable string for this status.
	///
	/// The returned value is intended for persistence and interoperability.
	/// Use [`MovementStatus::from_str`] to parse it back.
	pub fn as_str(&self) -> &'static str {
		match self {
			Self::Pending => MOVEMENT_PENDING,
			Self::Successful => MOVEMENT_SUCCESSFUL,
			Self::Failed => MOVEMENT_FAILED,
			Self::Canceled => MOVEMENT_CANCELED,
		}
	}
}

impl fmt::Display for MovementStatus {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str(self.as_str())
	}
}

impl fmt::Debug for MovementStatus {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		fmt::Display::fmt(&self, f)
	}
}

impl FromStr for MovementStatus {
	type Err = anyhow::Error;

	/// Formats the kind as its canonical string (same as [`MovementStatus::as_str`]).
	fn from_str(s: &str) -> Result<Self, Self::Err> {
		match s {
			MOVEMENT_PENDING => Ok(MovementStatus::Pending),
			MOVEMENT_SUCCESSFUL => Ok(MovementStatus::Successful),
			MOVEMENT_FAILED => Ok(MovementStatus::Failed),
			MOVEMENT_CANCELED => Ok(MovementStatus::Canceled),
			_ => bail!("Invalid MovementStatus: {}", s),
		}
	}
}

impl Serialize for MovementStatus {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: serde::Serializer,
	{
		serializer.serialize_str(self.as_str())
	}
}

impl<'de> Deserialize<'de> for MovementStatus {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: serde::Deserializer<'de>,
	{
		let s = String::deserialize(deserializer)?;
		MovementStatus::from_str(&s).map_err(serde::de::Error::custom)
	}
}

/// Describes a recipient of a movement. This could either be an external recipient in send actions
/// or it could be the bark wallet itself.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MovementDestination {
	/// An address, invoice or any other identifier to distinguish the recipient.
	pub destination: PaymentMethod,
	/// How many sats the recipient received.
	pub amount: Amount,
}

impl MovementDestination {
	pub fn new(payment_method: PaymentMethod, amount: Amount) -> Self {
		Self { destination: payment_method, amount }
	}

	pub fn ark(address: ark::Address, amount: Amount) -> Self {
		Self::new(address.into(), amount)
	}

	pub fn bitcoin(address: bitcoin::Address, amount: Amount) -> Self {
		Self::new(address.into(), amount)
	}

	pub fn invoice(invoice: Invoice, amount: Amount) -> Self {
		Self::new(invoice.into(), amount)
	}

	pub fn offer(offer: Offer, amount: Amount) -> Self {
		Self::new(offer.into(), amount)
	}

	pub fn lightning_address(address: LightningAddress, amount: Amount) -> Self {
		Self::new(address.into(), amount)
	}

	pub fn custom(destination: String, amount: Amount) -> Self {
		Self::new(PaymentMethod::Custom(destination), amount)
	}
}

/// Contains information about the subsystem that created the movement as well as the purpose
/// of the movement.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct MovementSubsystem {
	/// The name of the subsystem that created and manages the movement.
	pub name: String,
	/// The action responsible for registering the movement.
	pub kind: String,
}

/// Contains the times at which the movement was created, updated and completed.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MovementTimestamp {
	/// When the movement was first created.
	pub created_at: DateTime<chrono::Local>,
	/// When the movement was last updated.
	pub updated_at: DateTime<chrono::Local>,
	/// The action responsible for registering the movement.
	pub completed_at: Option<DateTime<chrono::Local>>,
}

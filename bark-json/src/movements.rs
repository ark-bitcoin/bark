use std::collections::HashMap;
use std::str::FromStr;

use anyhow::anyhow;
use bitcoin::{Amount, ScriptBuf, SignedAmount};
use chrono::DateTime;

use ark::VtxoId;
use ark::lightning::{Invoice, Offer};
use bark::lnurllib::lightning_address::LightningAddress;
use bark::movement::MovementId;


#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub enum MovementStatus {
	/// The default status of a new [Movement]. Should be treated as in-progress.
	Pending,
	/// The [Movement] has completed successfully.
	Successful,
	/// The [Movement] failed to complete due to an error. Note; this does not mean that VTXOs or
	/// user funds didn't change, old VTXOs may be consumed and new ones produced.
	Failed,
	/// A [Movement] was canceled, either by the protocol (e.g., lightning payments) or by the
	/// user.
	Canceled,
}

impl From<bark::movement::MovementStatus> for MovementStatus {
	fn from(v: bark::movement::MovementStatus) -> Self {
		match v {
			bark::movement::MovementStatus::Pending => Self::Pending,
			bark::movement::MovementStatus::Successful => Self::Successful,
			bark::movement::MovementStatus::Failed => Self::Failed,
			bark::movement::MovementStatus::Canceled => Self::Canceled,
		}
	}
}

/// Describes an attempted movement of offchain funds within the [bark::Wallet].
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct Movement {
	/// The internal ID of the movement.
	#[cfg_attr(feature = "utoipa", schema(value_type = u32))]
	pub id: MovementId,
	/// The status of the movement.
	pub status: MovementStatus,
	/// Contains information about the subsystem that created the movement as well as the purpose
	/// of the movement.
	pub subsystem: MovementSubsystem,
	/// Miscellaneous metadata for the movement. This is JSON containing arbitrary information as
	/// defined by the subsystem that created the movement.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub metadata: Option<HashMap<String, serde_json::Value>>,
	/// How much the movement was expected to increase or decrease the balance by. This is always an
	/// estimate and often discounts any applicable fees.
	#[serde(rename="intended_balance_sat", with="bitcoin::amount::serde::as_sat")]
	#[cfg_attr(feature = "utoipa", schema(value_type = i64))]
	pub intended_balance: SignedAmount,
	/// How much the wallet balance actually changed by. Positive numbers indicate an increase and
	/// negative numbers indicate a decrease. This is often inclusive of applicable fees, and it
	/// should be the most accurate number.
	#[serde(rename="effective_balance_sat", with="bitcoin::amount::serde::as_sat")]
	#[cfg_attr(feature = "utoipa", schema(value_type = i64))]
	pub effective_balance: SignedAmount,
	/// How much the movement cost the user in offchain fees. If there are applicable onchain fees
	/// they will not be included in this value but, depending on the subsystem, could be found in
	/// the metadata.
	#[serde(rename="offchain_fee_sat", with="bitcoin::amount::serde::as_sat")]
	#[cfg_attr(feature = "utoipa", schema(value_type = u64))]
	pub offchain_fee: Amount,
	/// A list of external recipients that received funds from this movement.
	pub sent_to: Vec<MovementDestination>,
	/// Describes the means by which the wallet received funds in this movement. This could include
	/// BOLT11 invoices or other useful data.
	pub received_on: Vec<MovementDestination>,
	/// A list of [Vtxo](ark::Vtxo) IDs that were consumed by this movement and
	/// are either locked or unavailable.
	#[cfg_attr(feature = "utoipa", schema(value_type = Vec<String>))]
	pub input_vtxos: Vec<VtxoId>,
	/// A list of IDs for new VTXOs that were produced as a result of this movement. Often change
	/// VTXOs will be found here for outbound actions unless this was an inbound action.
	#[cfg_attr(feature = "utoipa", schema(value_type = Vec<String>))]
	pub output_vtxos: Vec<VtxoId>,
	/// A list of IDs for VTXOs that were marked for unilateral exit as a result of this movement.
	/// This could happen for many reasons, e.g. an unsuccessful lightning payment which can't be
	/// revoked but is about to expire. VTXOs listed here will result in a reduction of spendable
	/// balance due to the VTXOs being managed by the [bark::exit::Exit] system.
	#[cfg_attr(feature = "utoipa", schema(value_type = Vec<String>))]
	pub exited_vtxos: Vec<VtxoId>,
	/// Contains the times at which the movement was created, updated and completed.
	pub time: MovementTimestamp,
}

impl From<bark::movement::Movement> for Movement {
	fn from(m: bark::movement::Movement) -> Self {
		Movement {
			id: m.id,
			status: m.status.into(),
			subsystem: MovementSubsystem::from(m.subsystem),
			metadata: if m.metadata.is_empty() { None } else { Some(m.metadata) },
			intended_balance: m.intended_balance,
			effective_balance: m.effective_balance,
			offchain_fee: m.offchain_fee,
			sent_to: m.sent_to.into_iter().map(MovementDestination::from).collect(),
			received_on: m.received_on.into_iter().map(MovementDestination::from).collect(),
			input_vtxos: m.input_vtxos,
			output_vtxos: m.output_vtxos,
			exited_vtxos: m.exited_vtxos,
			time: MovementTimestamp::from(m.time),
		}
	}
}

/// Describes a recipient of a movement. This could either be an external recipient in send actions
/// or it could be the bark wallet itself.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct MovementDestination {
	/// An address, invoice or any other identifier to distinguish the recipient.
	pub destination: PaymentMethod,
	/// How many sats the recipient received.
	#[serde(rename="amount_sat", with="bitcoin::amount::serde::as_sat")]
	#[cfg_attr(feature = "utoipa", schema(value_type = u64))]
	pub amount: Amount,
}

impl From<bark::movement::MovementDestination> for MovementDestination {
	fn from(d: bark::movement::MovementDestination) -> Self {
		MovementDestination {
			destination: PaymentMethod::from(d.destination),
			amount: d.amount,
		}
	}
}

/// Provides a typed mechanism for describing the recipient in a [MovementDestination].
/// This is a bark-json wrapper that serializes all payment methods as strings for utoipa
/// compatibility.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(tag = "type", content = "value", rename_all = "kebab-case")]
pub enum PaymentMethod {
	/// An [ark::Address] format for bark.
	Ark(String),
	/// An onchain [bitcoin::Address].
	Bitcoin(String),
	/// An onchain [bitcoin::ScriptBuf] output, typically used for non-address formats like
	/// OP_RETURN.
	OutputScript(String),
	/// Any supported form of lightning invoice, e.g., BOLT11 and BOLT12.
	Invoice(String),
	/// A reusable BOLT12 offer for making lightning payments.
	Offer(String),
	/// A variant using an email-like lightning address format.
	LightningAddress(String),
	/// An alternative payment method that isn't native to bark.
	Custom(String),
}

#[cfg(feature = "utoipa")]
impl utoipa::PartialSchema for PaymentMethod {
	fn schema() -> utoipa::openapi::RefOr<utoipa::openapi::schema::Schema> {
		use utoipa::openapi::schema;

		schema::ObjectBuilder::new()
			.title(Some("PaymentMethod"))
			.description(Some("A payment method with a type discriminator and string value"))
			.property(
				"type",
				schema::ObjectBuilder::new()
					.schema_type(schema::SchemaType::Type(schema::Type::String))
					.enum_values(Some([
						"ark",
						"bitcoin",
						"output-script",
						"invoice",
						"offer",
						"lightning-address",
						"custom",
					]))
					.description(Some("The type of payment method"))
			)
			.required("type")
			.property(
				"value",
				schema::ObjectBuilder::new()
					.schema_type(schema::SchemaType::Type(schema::Type::String))
					.description(Some("The payment method value (address, invoice, etc.)"))
			)
			.required("value")
			.into()
	}
}

#[cfg(feature = "utoipa")]
impl utoipa::ToSchema for PaymentMethod {
	fn name() -> std::borrow::Cow<'static, str> {
		std::borrow::Cow::Borrowed("PaymentMethod")
	}
}

impl From<bark::movement::PaymentMethod> for PaymentMethod {
	fn from(p: bark::movement::PaymentMethod) -> Self {
		match p {
			bark::movement::PaymentMethod::Ark(a) => Self::Ark(a.to_string()),
			bark::movement::PaymentMethod::Bitcoin(b) => Self::Bitcoin(b.assume_checked().to_string()),
			bark::movement::PaymentMethod::OutputScript(s) => Self::OutputScript(s.to_hex_string()),
			bark::movement::PaymentMethod::Invoice(i) => Self::Invoice(i.to_string()),
			bark::movement::PaymentMethod::Offer(o) => Self::Offer(o.to_string()),
			bark::movement::PaymentMethod::LightningAddress(l) => Self::LightningAddress(l.to_string()),
			bark::movement::PaymentMethod::Custom(c) => Self::Custom(c),
		}
	}
}

impl TryFrom<PaymentMethod> for bark::movement::PaymentMethod {
	type Error = anyhow::Error;

	fn try_from(p: PaymentMethod) -> Result<Self, Self::Error> {
		match p {
			PaymentMethod::Ark(a) => Ok(bark::movement::PaymentMethod::Ark(
				ark::Address::from_str(&a)?,
			)),
			PaymentMethod::Bitcoin(b) => Ok(bark::movement::PaymentMethod::Bitcoin(
				bitcoin::Address::from_str(&b)?,
			)),
			PaymentMethod::OutputScript(s) => Ok(bark::movement::PaymentMethod::OutputScript(
				ScriptBuf::from_hex(&s)?,
			)),
			PaymentMethod::Invoice(i) => Ok(bark::movement::PaymentMethod::Invoice(
				Invoice::from_str(&i)?,
			)),
			PaymentMethod::Offer(o) => Ok(bark::movement::PaymentMethod::Offer(
				Offer::from_str(&o).map_err(|e| anyhow!("Failed to parse offer: {:?}", e))?,
			)),
			PaymentMethod::LightningAddress(l) => Ok(bark::movement::PaymentMethod::LightningAddress(
				LightningAddress::from_str(&l)?,
			)),
			PaymentMethod::Custom(c) => Ok(bark::movement::PaymentMethod::Custom(c)),
		}
	}
}

/// Contains information about the subsystem that created the movement as well as the purpose
/// of the movement.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct MovementSubsystem {
	/// The name of the subsystem that created and manages the movement.
	pub name: String,
	/// The action responsible for registering the movement.
	pub kind: String,
}

impl From<bark::movement::MovementSubsystem> for MovementSubsystem {
	fn from(s: bark::movement::MovementSubsystem) -> Self {
		MovementSubsystem {
			name: s.name,
			kind: s.kind,
		}
	}
}

/// Contains the times at which the movement was created, updated and completed.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct MovementTimestamp {
	/// When the movement was first created.
	pub created_at: DateTime<chrono::Local>,
	/// When the movement was last updated.
	pub updated_at: DateTime<chrono::Local>,
	/// The action responsible for registering the movement.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub completed_at: Option<DateTime<chrono::Local>>,
}

impl From<bark::movement::MovementTimestamp> for MovementTimestamp {
	fn from(t: bark::movement::MovementTimestamp) -> Self {
		MovementTimestamp {
			created_at: t.created_at,
			updated_at: t.updated_at,
			completed_at: t.completed_at,
		}
	}
}

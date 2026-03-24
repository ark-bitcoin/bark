use std::str::FromStr;

use anyhow::Context;
use bitcoin::address::{NetworkChecked, NetworkUnchecked};
use bitcoin::hex::DisplayHex;
use lightning::offers::invoice::Bolt12Invoice;
use lightning::offers::offer::Offer;
use lightning_invoice::Bolt11Invoice;
use lnurllib::lightning_address::LightningAddress;
use serde::{Deserialize, Serialize};

use ark::lightning::Invoice;

const PAYMENT_METHOD_TAG: &str = "type";
const PAYMENT_METHOD_VALUE: &str = "value";
const PAYMENT_METHOD_ARK: &str = "ark";
const PAYMENT_METHOD_BITCOIN: &str = "bitcoin";
const PAYMENT_METHOD_OUTPUT_SCRIPT: &str = "output-script";
const PAYMENT_METHOD_INVOICE: &str = "invoice";
const PAYMENT_METHOD_OFFER: &str = "offer";
const PAYMENT_METHOD_LIGHTNING_ADDRESS: &str = "lightning-address";
const PAYMENT_METHOD_CUSTOM: &str = "custom";

/// Provides a typed mechanism for describing the recipient in a
/// [MovementDestination](crate::movement::MovementDestination).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PaymentMethod {
	/// An [ark::Address] for bark.
	Ark(ark::Address),
	/// An onchain [bitcoin::Address].
	Bitcoin(bitcoin::Address<NetworkUnchecked>),
	/// An onchain [bitcoin::ScriptBuf] output, typically used for non-address formats like
	/// OP_RETURN.
	OutputScript(bitcoin::ScriptBuf),
	/// Any supported form of lightning [Invoice], e.g., [Bolt11Invoice] and [Bolt12Invoice].
	Invoice(Invoice),
	/// A reusable BOLT12 [Offer] for lightning payments.
	Offer(Offer),
	/// An email-like format used to retrieve a [Bolt11Invoice].
	LightningAddress(LightningAddress),
	/// An alternative payment method that isn't native to bark.
	Custom(String),
}

impl PaymentMethod {
	pub fn is_ark(&self) -> bool {
		match self {
			PaymentMethod::Ark(_) => true,
			PaymentMethod::Bitcoin(_) => false,
			PaymentMethod::OutputScript(_) => false,
			PaymentMethod::Invoice(_) => false,
			PaymentMethod::Offer(_) => false,
			PaymentMethod::LightningAddress(_) => false,
			PaymentMethod::Custom(_) => false,
		}
	}

	pub fn is_bitcoin(&self) -> bool {
		match self {
			PaymentMethod::Ark(_) => false,
			PaymentMethod::Bitcoin(_) => true,
			PaymentMethod::OutputScript(_) => true,
			PaymentMethod::Invoice(_) => false,
			PaymentMethod::Offer(_) => false,
			PaymentMethod::LightningAddress(_) => false,
			PaymentMethod::Custom(_) => false,
		}
	}

	pub fn is_custom(&self) -> bool {
		match self {
			PaymentMethod::Ark(_) => false,
			PaymentMethod::Bitcoin(_) => false,
			PaymentMethod::OutputScript(_) => false,
			PaymentMethod::Invoice(_) => false,
			PaymentMethod::Offer(_) => false,
			PaymentMethod::LightningAddress(_) => false,
			PaymentMethod::Custom(_) => true,
		}
	}

	/// Returns whether the payment method is a lightning payment method, e.g., BOLT11.
	pub fn is_lightning(&self) -> bool {
		match self {
			PaymentMethod::Ark(_) => false,
			PaymentMethod::Bitcoin(_) => false,
			PaymentMethod::OutputScript(_) => false,
			PaymentMethod::Invoice(_) => true,
			PaymentMethod::Offer(_) => true,
			PaymentMethod::LightningAddress(_) => true,
			PaymentMethod::Custom(_) => false,
		}
	}

	/// Returns the type tag string for this payment method.
	pub fn type_str(&self) -> &'static str {
		match self {
			PaymentMethod::Ark(_) => PAYMENT_METHOD_ARK,
			PaymentMethod::Bitcoin(_) => PAYMENT_METHOD_BITCOIN,
			PaymentMethod::OutputScript(_) => PAYMENT_METHOD_OUTPUT_SCRIPT,
			PaymentMethod::Invoice(_) => PAYMENT_METHOD_INVOICE,
			PaymentMethod::Offer(_) => PAYMENT_METHOD_OFFER,
			PaymentMethod::LightningAddress(_) => PAYMENT_METHOD_LIGHTNING_ADDRESS,
			PaymentMethod::Custom(_) => PAYMENT_METHOD_CUSTOM,
		}
	}

	/// Returns the value as a plain string for this payment method.
	pub fn value_string(&self) -> String {
		match self {
			PaymentMethod::Ark(addr) => addr.to_string(),
			PaymentMethod::Bitcoin(addr) => addr.assume_checked_ref().to_string(),
			PaymentMethod::OutputScript(script) => script.as_bytes().to_lower_hex_string(),
			PaymentMethod::Invoice(invoice) => invoice.to_string(),
			PaymentMethod::Offer(offer) => offer.to_string(),
			PaymentMethod::LightningAddress(addr) => addr.to_string(),
			PaymentMethod::Custom(custom) => custom.clone(),
		}
	}

	/// Construct a PaymentMethod from a type tag and value string.
	pub fn from_type_value(type_str: &str, value: &str) -> anyhow::Result<Self> {
		match type_str {
			PAYMENT_METHOD_ARK => {
				let addr = ark::Address::from_str(value)
					.context("invalid ark address")?;
				Ok(PaymentMethod::Ark(addr))
			},
			PAYMENT_METHOD_BITCOIN => {
				let addr = bitcoin::Address::from_str(value)
					.context("invalid bitcoin address")?;
				Ok(PaymentMethod::Bitcoin(addr))
			},
			PAYMENT_METHOD_OUTPUT_SCRIPT => {
				let script = bitcoin::ScriptBuf::from_hex(value)
					.context("invalid output script hex")?;
				Ok(PaymentMethod::OutputScript(script))
			},
			PAYMENT_METHOD_INVOICE => {
				let invoice = Invoice::from_str(value)
					.context("invalid invoice")?;
				Ok(PaymentMethod::Invoice(invoice))
			},
			PAYMENT_METHOD_OFFER => {
				let offer = value.parse()
					.map_err(|e| anyhow!("{:?}", e))
					.context("invalid offer")?;
				Ok(PaymentMethod::Offer(offer))
			},
			PAYMENT_METHOD_LIGHTNING_ADDRESS => {
				let addr = LightningAddress::from_str(value)
					.context("invalid lightning address")?;
				Ok(PaymentMethod::LightningAddress(addr))
			},
			PAYMENT_METHOD_CUSTOM => {
				Ok(PaymentMethod::Custom(value.to_string()))
			},
			_ => bail!("unknown payment method type: {}", type_str),
		}
	}
}

impl From<ark::Address> for PaymentMethod {
	fn from(addr: ark::Address) -> Self {
		PaymentMethod::Ark(addr)
	}
}

impl From<bitcoin::Address<NetworkUnchecked>> for PaymentMethod {
	fn from(addr: bitcoin::Address<NetworkUnchecked>) -> Self {
		PaymentMethod::Bitcoin(addr)
	}
}

impl From<bitcoin::Address<NetworkChecked>> for PaymentMethod {
	fn from(addr: bitcoin::Address<NetworkChecked>) -> Self {
		PaymentMethod::Bitcoin(addr.into_unchecked())
	}
}

impl From<Bolt11Invoice> for PaymentMethod {
	fn from(invoice: Bolt11Invoice) -> Self {
		PaymentMethod::Invoice(invoice.into())
	}
}

impl From<Bolt12Invoice> for PaymentMethod {
	fn from(invoice: Bolt12Invoice) -> Self {
		PaymentMethod::Invoice(invoice.into())
	}
}

impl From<Invoice> for PaymentMethod {
	fn from(invoice: Invoice) -> Self {
		PaymentMethod::Invoice(invoice)
	}
}

impl From<Offer> for PaymentMethod {
	fn from(offer: Offer) -> Self {
		PaymentMethod::Offer(offer)
	}
}

impl From<LightningAddress> for PaymentMethod {
	fn from(addr: LightningAddress) -> Self {
		PaymentMethod::LightningAddress(addr)
	}
}

impl Serialize for PaymentMethod {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: serde::Serializer,
	{
		use serde::ser::SerializeStruct;
		let mut state = serializer.serialize_struct("PaymentMethod", 2)?;
		state.serialize_field(PAYMENT_METHOD_TAG, self.type_str())?;
		state.serialize_field(PAYMENT_METHOD_VALUE, &self.value_string())?;
		state.end()
	}
}

impl<'de> Deserialize<'de> for PaymentMethod {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: serde::Deserializer<'de>,
	{
		use serde::de::{self, MapAccess, Visitor};
		use std::fmt;

		struct PaymentMethodVisitor;

		impl<'de> Visitor<'de> for PaymentMethodVisitor {
			type Value = PaymentMethod;

			fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
				formatter.write_str(&format!(
					"a PaymentMethod with {} and {} fields", PAYMENT_METHOD_TAG, PAYMENT_METHOD_VALUE,
				))
			}

			fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
			where
				A: MapAccess<'de>,
			{
				let mut type_value: Option<String> = None;
				let mut value_string: Option<String> = None;

				while let Some(key) = map.next_key::<String>()? {
					match key.as_str() {
						PAYMENT_METHOD_TAG => {
							if type_value.is_some() {
								return Err(de::Error::duplicate_field(PAYMENT_METHOD_TAG));
							}
							type_value = Some(map.next_value()?);
						}
						PAYMENT_METHOD_VALUE => {
							if value_string.is_some() {
								return Err(de::Error::duplicate_field(PAYMENT_METHOD_VALUE));
							}
							value_string = Some(map.next_value()?);
						}
						_ => {
							let _: de::IgnoredAny = map.next_value()?;
						}
					}
				}

				let type_str = type_value.ok_or_else(|| de::Error::missing_field(PAYMENT_METHOD_TAG))?;
				let value = value_string.ok_or_else(|| de::Error::missing_field(PAYMENT_METHOD_VALUE))?;

				PaymentMethod::from_type_value(&type_str, &value).map_err(de::Error::custom)
			}
		}

		deserializer.deserialize_struct(
			"PaymentMethod", &[PAYMENT_METHOD_TAG, PAYMENT_METHOD_VALUE], PaymentMethodVisitor,
		)
	}
}

#[cfg(test)]
mod test {
	use std::str::FromStr;

	use super::*;

	#[test]
	fn test_serialization() {
		let ark_str = "tark1pwh9vsmezqqpjy9akejayl2vvcse6he97rn40g84xrlvrlnhayuuyefrp9nse2y3zqqpjy9akejayl2vvcse6he97rn40g84xrlvrlnhayuuyefrp9nse2yscufs5u";
		let serialised = r#"{"type":"ark","value":"tark1pwh9vsmezqqpjy9akejayl2vvcse6he97rn40g84xrlvrlnhayuuyefrp9nse2y3zqqpjy9akejayl2vvcse6he97rn40g84xrlvrlnhayuuyefrp9nse2yscufs5u"}"#;
		let ark_method = PaymentMethod::Ark(ark::Address::from_str(ark_str).unwrap());
		assert_eq!(serde_json::to_string(&ark_method).unwrap(), serialised);
		assert_eq!(serde_json::from_str::<PaymentMethod>(serialised).unwrap(), ark_method);

		let bitcoin_str = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";
		let serialised = r#"{"type":"bitcoin","value":"1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"}"#;
		let bitcoin_method = PaymentMethod::Bitcoin(bitcoin::Address::from_str(bitcoin_str).unwrap());
		assert_eq!(serde_json::to_string(&bitcoin_method).unwrap(), serialised);
		assert_eq!(serde_json::from_str::<PaymentMethod>(serialised).unwrap(), bitcoin_method);

		let script_str = "6a0474657374"; // OP_RETURN, push 4 bytes with the string "test"
		let serialised = r#"{"type":"output-script","value":"6a0474657374"}"#;
		let output_method = PaymentMethod::OutputScript(bitcoin::ScriptBuf::from_hex(script_str).unwrap());
		assert_eq!(serde_json::to_string(&output_method).unwrap(), serialised);
		assert_eq!(serde_json::from_str::<PaymentMethod>(serialised).unwrap(), output_method);

		let invoice_str = "lntbs100u1p5j0x82sp5d0rwfh7tgrrlwsegy9rx3tzpt36cqwjqza5x4wvcjxjzscfaf6jspp5d8q7354dg3p8h0kywhqq5dq984r8f5en98hf9ln85ug0w8fx6hhsdqqcqzpc9qyysgqyk54v7tpzprxll7e0jyvtxcpgwttzk84wqsfjsqvcdtq47zt2wssxsmtjhz8dka62mdnf9jafhu3l4cpyfnsx449v4wstrwzzql2w5qqs8uh7p";
		let serialised = r#"{"type":"invoice","value":"lntbs100u1p5j0x82sp5d0rwfh7tgrrlwsegy9rx3tzpt36cqwjqza5x4wvcjxjzscfaf6jspp5d8q7354dg3p8h0kywhqq5dq984r8f5en98hf9ln85ug0w8fx6hhsdqqcqzpc9qyysgqyk54v7tpzprxll7e0jyvtxcpgwttzk84wqsfjsqvcdtq47zt2wssxsmtjhz8dka62mdnf9jafhu3l4cpyfnsx449v4wstrwzzql2w5qqs8uh7p"}"#;
		let invoice_method = PaymentMethod::Invoice(Bolt11Invoice::from_str(invoice_str).unwrap().into());
		assert_eq!(serde_json::to_string(&invoice_method).unwrap(), serialised);
		assert_eq!(serde_json::from_str::<PaymentMethod>(serialised).unwrap(), invoice_method);

		let offer_str = "lno1qgsyxjtl6luzd9t3pr62xr7eemp6awnejusgf6gw45q75vcfqqqqqqq2p32x2um5ypmx2cm5dae8x93pqthvwfzadd7jejes8q9lhc4rvjxd022zv5l44g6qah82ru5rdpnpj";
		let serialised = r#"{"type":"offer","value":"lno1qgsyxjtl6luzd9t3pr62xr7eemp6awnejusgf6gw45q75vcfqqqqqqq2p32x2um5ypmx2cm5dae8x93pqthvwfzadd7jejes8q9lhc4rvjxd022zv5l44g6qah82ru5rdpnpj"}"#;
		let offer_method = PaymentMethod::Offer(Offer::from_str(offer_str).unwrap());
		assert_eq!(serde_json::to_string(&offer_method).unwrap(), serialised);
		assert_eq!(serde_json::from_str::<PaymentMethod>(serialised).unwrap(), offer_method);

		let lnaddr_str = "byte@second.tech";
		let serialised = r#"{"type":"lightning-address","value":"byte@second.tech"}"#;
		let lnaddr_method = PaymentMethod::LightningAddress(LightningAddress::from_str(lnaddr_str).unwrap());
		assert_eq!(serde_json::to_string(&lnaddr_method).unwrap(), serialised);
		assert_eq!(serde_json::from_str::<PaymentMethod>(serialised).unwrap(), lnaddr_method);

		let custom_str = "THIS IS AN EXAMPLE OF A CUSTOM STRING";
		let serialised = r#"{"type":"custom","value":"THIS IS AN EXAMPLE OF A CUSTOM STRING"}"#;
		let custom_method = PaymentMethod::Custom(String::from(custom_str));
		assert_eq!(serde_json::to_string(&custom_method).unwrap(), serialised);
		assert_eq!(serde_json::from_str::<PaymentMethod>(serialised).unwrap(), custom_method);
	}
}

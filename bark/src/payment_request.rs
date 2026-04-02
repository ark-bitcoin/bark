//! Payment string parsing and BIP 321 URI construction for bark wallets.
//!
//! This module provides two main capabilities:
//!
//! - **Parsing**: [`Wallet::parse_payment_details`] accepts any payment string
//!   the wallet understands (BIP 321 URIs, BOLT11 invoices, BOLT12 offers,
//!   lightning addresses, output scripts, bitcoin addresses, ark addresses)
//!   and returns structured [`PaymentRequest`] with per-method validation
//!   errors.

pub use crate::movement::PaymentMethod;

use std::str::FromStr;

use anyhow::Context;
use bitcoin::{Amount, Network};
use bitcoin::constants::ChainHash;
use lnurllib::lightning_address::LightningAddress;

use ark::lightning::{Bolt11Invoice, Invoice, Offer, OfferAmountExt};
use bip321::{Bip321Error, Bip321Uri, ExtensionHandler, FieldWithAttributes};
use bitcoin_ext::AmountExt;

use crate::Wallet;
use crate::arkoor::ArkoorAddressError;

#[derive(Default, Clone, PartialEq, Eq, Debug)]
struct BarkExtension {
	ark: Vec<FieldWithAttributes<ark::Address>>,
}

impl ExtensionHandler for BarkExtension {
	fn handle_param(
		&mut self,
		key: &str,
		value: &str,
		required: bool,
	) -> Result<bool, Bip321Error> {
		if key == "ark" {
			let address = ark::Address::from_str(value)
				.map_err(|e| Bip321Error::ExtensionError(e.to_string()))?;
			self.ark.push(FieldWithAttributes::new(address, required));
			Ok(true)
		} else {
			Ok(false)
		}
	}

	fn is_empty(&self) -> bool {
		self.ark.is_empty()
	}

	fn serialize_params(&self) -> Vec<(String, String)> {
		self.ark.iter()
			.map(|a| ("ark".to_string(), a.inner().to_string()))
			.collect()
	}
}

type BarkBip321Uri = Bip321Uri<BarkExtension>;

/// A non-fatal issue detected while validating a single payment option.
///
/// These are collected per-option in [`AvailablePaymentMethod::errors`] so
/// callers can present all options to the user and let them choose, rather
/// than failing on the first problem.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PaymentMethodParsingError {
	/// The payment target uses a different bitcoin network than the wallet.
	#[error("network mismatch")]
	NetworkMismatch,
	/// The Ark address is invalid.
	#[error("invalid ark address: {0}")]
	InvalidArkAddress(#[from] ArkoorAddressError),
	/// An amount is required but was not provided and cannot be inferred.
	#[error("amount required")]
	MissingAmount,
	/// The provided amount does not satisfy the payment target's requirements.
	#[error("amount mismatch: expected {expected}, got {got}")]
	AmountMismatch { expected: Amount, got: Amount },
	/// The payment target's amount is invalid.
	#[error("invalid amount")]
	InvalidAmount,
	/// The payment option is not supported.
	#[error("unsupported payment option")]
	Unsupported,
}

/// A single payment option with its validation issues.
///
/// A option with a non-empty [`errors`](Self::errors) list may still be
/// presented to the user, but should be flagged as problematic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AvailablePaymentMethod {
	pub method: PaymentMethod,
	pub errors: Vec<PaymentMethodParsingError>,
}

/// The result of parsing a payment string.
///
/// Contains optional BIP 321 metadata (`amount`, `label`, `message`) and
/// one or more [`AvailablePaymentMethod`] the caller can present to the user.
/// When parsed from a bare string (not a BIP 321 URI), `label` and `message`
/// are `None` and `methods` contains a single entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaymentRequest {
	pub amount: Option<Amount>,
	pub label: Option<String>,
	pub message: Option<String>,
	pub options: Vec<AvailablePaymentMethod>,
}

impl From<AvailablePaymentMethod> for PaymentRequest {
	fn from(option: AvailablePaymentMethod) -> Self {
		Self {
			amount: None,
			label: None,
			message: None,
			options: vec![option],
		}
	}
}

impl Wallet {
	fn details_for_bolt11(
		bolt11: &Bolt11Invoice,
		network: Network,
		uri_amount: Option<Amount>,
	) -> AvailablePaymentMethod {
		let mut errors = vec![];

		if bolt11.network() != network {
			errors.push(PaymentMethodParsingError::NetworkMismatch);
		}

		let bolt11_amount = bolt11.amount_milli_satoshis().map(|a| Amount::from_msat_ceil(a));
		match (bolt11_amount, uri_amount) {
			(Some(bolt11_amount), Some(amount)) => {
				if bolt11_amount != amount {
					errors.push(PaymentMethodParsingError::AmountMismatch {
						expected: bolt11_amount,
						got: amount,
					});
				}
			},
			_ => {},
		}

		AvailablePaymentMethod {
			method: PaymentMethod::Invoice(Invoice::Bolt11(bolt11.clone())),
			errors,
		}
	}

	fn details_for_offer(
		offer: &Offer,
		network: Network,
		uri_amount: Option<Amount>,
	) -> AvailablePaymentMethod {
		let mut errors = vec![];

		// Check network
		let network_chain = ChainHash::using_genesis_block_const(network);
		if offer.chains().iter().all(|c| *c != network_chain) {
			errors.push(PaymentMethodParsingError::NetworkMismatch);
		}

		let offer_amount = offer.amount().map(|a| a.to_bitcoin_amount().unwrap());
		match (offer_amount, uri_amount) {
			(Some(offer_amount), Some(amount)) => {
				if offer_amount != amount {
					errors.push(PaymentMethodParsingError::AmountMismatch { expected: offer_amount, got: amount });
				}
			},
			_ => {},
		}

		AvailablePaymentMethod {
			method: PaymentMethod::Offer(offer.clone()),
			errors,
		}
	}

	fn details_for_lightning_address(addr: &LightningAddress) -> AvailablePaymentMethod {
		// We cannot validate network without fetching the invoice
		AvailablePaymentMethod {
			method: PaymentMethod::LightningAddress(addr.clone()),
			errors: vec![],
		}
	}

	fn details_for_bitcoin_address(
		address: &bitcoin::Address<bitcoin::address::NetworkUnchecked>,
		network: Network,
	) -> AvailablePaymentMethod {
		let mut errors = vec![];

		if !address.is_valid_for_network(network) {
			errors.push(PaymentMethodParsingError::NetworkMismatch);
		}

		AvailablePaymentMethod {
			method: PaymentMethod::Bitcoin(address.clone()),
			errors,
		}
	}

	fn details_for_output_script(script: &bitcoin::ScriptBuf) -> AvailablePaymentMethod {

		AvailablePaymentMethod {
			method: PaymentMethod::OutputScript(script.clone()),
			// We don't support sending to output scripts yet
			errors: vec![PaymentMethodParsingError::Unsupported],
		}
	}

	async fn details_for_ark_address(
		&self,
		ark_address: &ark::Address,
	) -> AvailablePaymentMethod {
		let mut errors = vec![];

		match self.validate_arkoor_address(ark_address).await.err() {
			None => {},
			Some(e) => {
				errors.push(PaymentMethodParsingError::InvalidArkAddress(e));
			},
		}

		AvailablePaymentMethod {
			method: PaymentMethod::Ark(ark_address.clone()),
			errors,
		}
	}

	async fn parse_bip321_uri(
		&self,
		network: Network,
		uri: &BarkBip321Uri,
	) -> anyhow::Result<PaymentRequest> {
		let amount = uri.amount().map(|a| *a);
		let label = uri.label().map(|l| l.clone());
		let message = uri.message().map(|m| m.clone());

		let mut options = Vec::new();

		for extension in uri.bc() {
			let details = Self::details_for_bitcoin_address(
				&extension.inner().as_unchecked(), network
			);
			options.push(details);
		}

		for extension in uri.tb() {
			let details = Self::details_for_bitcoin_address(
				&extension.inner().as_unchecked(), network
			);
			options.push(details);
		}

		for extension in uri.lightning() {
			let details = Self::details_for_bolt11(extension.inner(), network, amount);
			options.push(details);
		}

		for extension in uri.lno() {
			let details = Self::details_for_offer(extension.inner(), network, amount);
			options.push(details);
		}

		for extension in uri.sp() {
			if extension.required() {
				bail!("Silent payment is required in URI but unsupported on Bark");
			}
		}

		for extension in uri.pay() {
			if extension.required() {
				bail!("Private payment is required in URI but unsupported on Bark");
			}
		}

		for extension in &uri.extensions().ark {
			let details = self.details_for_ark_address(&extension.inner()).await;
			options.push(details);
		}

		if let Some(address) = uri.address() {
			let details = Self::details_for_bitcoin_address(
				address.as_unchecked(), network
			);
			options.push(details);
		}

		return Ok(PaymentRequest { amount, label, message, options })
	}

	/// Try each supported payment format in priority order and return the
	/// first successful parse as a [`PaymentRequest`].
	///
	/// Formats are attempted in this order:
	/// 1. BIP 321 `bitcoin:` URI (may yield multiple options from destinations)
	/// 2. Bare BOLT11 invoice
	/// 3. Bare BOLT12 offer
	/// 4. Lightning address (`user@domain`)
	/// 5. Ark address
	/// 6. Bare bitcoin address
	/// 7. Hex-encoded output script
	///
	/// Returns `None` when `payment_str` does not match any known format.
	async fn inner_parse_payment_request(
		&self,
		network: Network,
		payment_str: &str,
	) -> anyhow::Result<PaymentRequest> {
		// BIP 321 URI
		if let Ok(uri) = BarkBip321Uri::from_str(payment_str) {
			return self.parse_bip321_uri(network, &uri).await;
		}

		// Bare BOLT11 invoice
		if let Ok(bolt11) = Bolt11Invoice::from_str(payment_str) {
			let details = Self::details_for_bolt11(&bolt11, network, None);

			return Ok(PaymentRequest {
				label: None,
				amount: bolt11.amount_milli_satoshis().map(|a| Amount::from_msat_ceil(a)),
				message: Some(bolt11.description().to_string()),
				options: vec![details],
			});
		}

		// Bare BOLT12 offer
		if let Ok(offer) = Offer::from_str(payment_str) {
			let details = Self::details_for_offer(&offer, network, None);

			return Ok(PaymentRequest {
				label: None,
				amount: offer.amount().map(|a| a.to_bitcoin_amount().unwrap()),
				message: offer.description().map(|d| d.to_string()),
				options: vec![details],
			});
		}

		// Lightning address
		if let Ok(addr) = LightningAddress::from_str(payment_str) {
			return Ok(Self::details_for_lightning_address(&addr).into());
		}

		// Ark address
		if let Ok(ark_address) = ark::Address::from_str(payment_str) {
			return Ok(self.details_for_ark_address(&ark_address).await.into());
		}

		// Bare bitcoin address
		if let Ok(address) = bitcoin::Address::from_str(payment_str) {
			return Ok(Self::details_for_bitcoin_address(&address, network).into());
		}

		// Hex-encoded output script
		if let Ok(script) = bitcoin::ScriptBuf::from_hex(payment_str) {
			return Ok(Self::details_for_output_script(&script).into());
		}

		bail!("No valid payment option found")
	}

	/// Parse a payment request into structured payment options.
	///
	/// Accepts any format supported by the wallet: BIP 321 URIs, BOLT11
	/// invoices, BOLT12 offers, lightning addresses, hex output scripts,
	/// bare bitcoin addresses, and ark addresses.
	///
	/// Formats are attempted in this order:
	/// 1. BIP 321 `bitcoin:` URI (may yield multiple options from destinations)
	/// 2. Bare BOLT11 invoice
	/// 3. Bare BOLT12 offer
	/// 4. Lightning address (`user@domain`)
	/// 5. Ark address
	/// 6. Bare bitcoin address
	/// 7. Hex-encoded output script
	///
	/// Returns a [`PaymentRequest`] with one or more [`AvailablePaymentMethod`]
	/// the caller can present to the user. Returns an error if no valid payment
	/// option is found.
	pub async fn parse_payment_request(&self, payment_str: &str)
		-> anyhow::Result<PaymentRequest>
	{
		let network = self.network().await?;
		let req = self.inner_parse_payment_request(
			network, payment_str
		).await.context("Invalid payment request")?;
		debug_assert!(req.options.len() > 0, "Parser should bail if no valid payment option is found");

		Ok(req)
	}
}

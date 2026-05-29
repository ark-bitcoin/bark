//! Payment string parsing and BIP 321 URI construction for bark wallets.
//!
//! This module provides two main capabilities:
//!
//! - **Parsing**: [`Wallet::parse_payment_request`] accepts any payment string
//!   the wallet understands (BIP 321 URIs, BOLT11 invoices, BOLT12 offers,
//!   lightning addresses, output scripts, bitcoin addresses, ark addresses)
//!   and returns structured [`PaymentRequest`] with per-method validation
//!   errors.
//!
//! - **Construction**: [`Wallet::bip321_uri`] returns a [`BarkBip321UriBuilder`]
//!   for creating BIP 321 URIs backed by the wallet's Ark and Lightning
//!   capabilities.

pub use crate::movement::PaymentMethod;

use std::str::FromStr;

use anyhow::Context;
use ark::address::ParseAddressError;
use bitcoin::{Amount, Network};
use bitcoin::constants::ChainHash;
use lnurllib::lightning_address::LightningAddress;
use lnurllib::lnurl::LnUrl;

use ark::lightning::{Bolt11Invoice, Invoice, Offer, OfferAmountExt};
use bip321::{Bip321Error, Bip321Uri, ExtensionHandler, FieldWithAttributes};
use bitcoin_ext::AmountExt;
use log::debug;

use crate::{FeeEstimate, Wallet};
use crate::arkoor::ArkoorAddressError;
use crate::onchain::OnchainWalletTrait;

/// Enum for representing either a bark address ([ark::Address]) or an arkade address.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ArkAddressType {
	Bark(ark::Address),
	Arkade(String),
}

impl From<ark::Address> for ArkAddressType {
	fn from(addr: ark::Address) -> Self {
		ArkAddressType::Bark(addr)
	}
}

impl std::fmt::Display for ArkAddressType {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			ArkAddressType::Bark(addr) => write!(f, "{}", addr),
			ArkAddressType::Arkade(addr) => write!(f, "{}", addr),
		}
	}
}

impl FromStr for ArkAddressType {
	type Err = ParseAddressError;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		match ark::Address::from_str(s) {
			Ok(addr) => Ok(ArkAddressType::Bark(addr)),
			Err(ParseAddressError::Arkade) => Ok(ArkAddressType::Arkade(s.to_string())),
			Err(e) => Err(e),
		}
	}
}

#[derive(Default, Clone, PartialEq, Eq, Debug)]
pub struct BarkExtension {
	ark: Vec<FieldWithAttributes<ArkAddressType>>,
}

impl BarkExtension {
	/// The Ark addresses carried by the URI's `ark=` parameters.
	pub fn ark(&self) -> &[FieldWithAttributes<ArkAddressType>] {
		&self.ark
	}
}

impl ExtensionHandler for BarkExtension {
	fn handle_param(
		&mut self,
		key: &str,
		value: &str,
		required: bool,
	) -> Result<bool, Bip321Error> {
		if key == "ark" {
			let addr = match ArkAddressType::from_str(value) {
				Ok(addr) => addr,
				Err(e) => return Err(Bip321Error::ExtensionError(e.to_string())),
			};

			self.ark.push(FieldWithAttributes::new(addr, required));
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

pub type BarkBip321Uri = Bip321Uri<BarkExtension>;

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

/// Builder for constructing a [`Bip321Uri`] backed by a bark [`Wallet`].
///
/// Each setter records the intent; the actual address/invoice generation
/// happens in [`build`](Self::build).
///
/// # Example
///
/// ```no_run
/// # use bitcoin::Amount;
/// # use bark::Wallet;
/// # async fn example(wallet: &mut Wallet) -> anyhow::Result<()> {
/// // Default URI has all options that don't require amount
/// let uri = wallet.bip321_uri().build().await?;
///
/// // bitcoin:?ark=tark1pwh9vsmezqqpharv69q4z8m6x364d5m5prnmcalcalq9pdmzw0y7mpveck4pcfhezqypczkrrj3lkx5ue4qrf4jc7ztpt9htdttmh2judhqnu7aue8p0y9mq47jn9z
/// println!("{}", uri.to_string());
///
/// // Add an amount to enable BOLT-11 invoice; can disable options as well
/// let uri = wallet.bip321_uri()
/// 	.amount(Amount::from_sat(100_000))
/// 	.ark(false)
/// 	.build().await?;
///
/// // bitcoin:?amount=100000&lightning=lnbc20m1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygshp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqfp4qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q9qrsgq9vlvyj8cqvq6ggvpwd53jncp9nwc47xlrsnenq2zp70fq83qlgesn4u3uyf4tesfkkwwfg3qs54qe426hp3tz7z6sweqdjg05axsrjqp9yrrwc
/// println!("{}", uri.to_string());
///
/// # Ok(())
/// # }
/// ```
pub struct BarkBip321UriBuilder<'a> {
	wallet: &'a mut Wallet,
	// context such as the REST server.
	onchain_wallet: Option<&'a mut dyn OnchainWalletTrait>,

	amount: Option<Amount>,
	label: Option<String>,
	message: Option<String>,

	ark: bool,
	onchain: bool,
	bolt11: bool,
}

impl<'a> BarkBip321UriBuilder<'a> {
	pub fn new(wallet: &'a mut Wallet) -> Self {
		Self {
			wallet,
			onchain_wallet: None,

			amount: None,
			label: None,
			message: None,

			ark: true,
			onchain: true,
			bolt11: true,
		}
	}

	pub fn label(mut self, label: String) -> Self {
		self.label = Some(label);
		self
	}

	pub fn message(mut self, message: String) -> Self {
		self.message = Some(message);
		self
	}

	pub fn amount(mut self, amount: Amount) -> Self {
		self.amount = Some(amount);
		self
	}

	pub fn amount_sat(self, amount_sat: u64) -> Self {
		self.amount(Amount::from_sat(amount_sat))
	}

	/// Disable all payment methods
	///
	/// You can then enable them one by one.
	pub fn disable_all(self) -> Self {
		self.onchain(false).ark(false).lightning_bolt11(false)
	}

	/// Include an onchain address destination in the URI
	///
	/// This will only work if the builder has an onchain wallet.
	pub fn onchain(mut self, enabled: bool) -> Self {
		self.onchain = enabled;
		self
	}

	/// Set the onchain wallet to fetch onchain address from
	///
	/// Setting this will also set the flag to include an onchain address.
	pub fn onchain_wallet(mut self, onchain: &'a mut dyn OnchainWalletTrait) -> Self {
		self.onchain_wallet = Some(onchain);
		self.onchain = true;
		self
	}

	/// Include an Ark address destination in the URI.
	///
	/// They are enabled by default.
	pub fn ark(mut self, enabled: bool) -> Self {
		self.ark = enabled;
		self
	}

	/// Include a BOLT11 Lightning invoice destination in the URI.
	///
	/// Requires [`amount`](Self::amount) to have been called first,
	/// because the builder needs an amount to generate the invoice.
	///
	/// This is enabled by default when an amount is given.
	pub fn lightning_bolt11(mut self, enabled: bool) -> Self {
		self.bolt11 = enabled;
		self
	}

	/// Consume the builder, generate addresses/invoices, and return the URI.
	pub async fn build(self) -> anyhow::Result<BarkBip321Uri> {
		let mut uri = BarkBip321Uri::new();

		if let Some(amount) = self.amount {
			if amount == Amount::ZERO {
				bail!("amount cannot be zero")
			}
			uri.set_amount(amount).context("failed to set amount")?;
		}
		if let Some(label) = self.label {
			uri.set_label(label);
		}
		if let Some(message) = self.message {
			uri.set_message(message);
		}

		if self.onchain {
			if let Some(onchain) = self.onchain_wallet {
				let address = onchain.address().await
					.context("failed to get onchain address")?;
				// As per BIP 321, onchain addresses are only supported on mainnet.
				if self.wallet.network().await? == Network::Bitcoin {
					uri.set_address(address.into_unchecked())
						.context("failed to set address")?;
				} else {
					uri.push_tb(address.into_unchecked(), false)?;
				}
			}
		}

		if self.ark {
			let address = self.wallet.new_address().await
				.context("failed to generate new ark address")?;

			uri.extensions_mut().ark.push(FieldWithAttributes::new(address.into(), false));
		}

		if self.bolt11 {
			if let Some(amount) = self.amount {
				let invoice = self.wallet.bolt11_invoice(amount, None, None).await
					.context("failed to generate lightning invoice")?;

				uri.push_lightning(invoice, false);
			} else {
				debug!("amount is required to enable lightning invoice payment method");
			}
		}

		let res = uri.validate();
		debug_assert!(res.is_ok());

		Ok(uri)
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

	fn details_for_lnurl(lnurl: &LnUrl) -> Option<AvailablePaymentMethod> {
		// Only LNURL-Pay is supported.
		if lnurl.is_lnurl_auth() {
			return None
		}

		Some(AvailablePaymentMethod {
			method: PaymentMethod::Lnurl(lnurl.clone()),
			errors: vec![],
		})
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
		ark_address: &ArkAddressType,
	) -> AvailablePaymentMethod {
		let bark_address = match ark_address {
			ArkAddressType::Bark(addr) => addr,
			ArkAddressType::Arkade(addr) => {
				return AvailablePaymentMethod {
					method: PaymentMethod::Custom(addr.clone()),
					errors: vec![
						PaymentMethodParsingError::InvalidArkAddress(ArkoorAddressError::ServerMismatch),
					],
				}
			},
		};

		let mut errors = vec![];
		match self.validate_arkoor_address(bark_address).await.err() {
			None => {},
			Some(e) => {
				errors.push(PaymentMethodParsingError::InvalidArkAddress(e));
			},
		}

		AvailablePaymentMethod {
			method: PaymentMethod::Ark(bark_address.clone()),
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
	/// 5. Raw LNURL-pay link (`lnurl1…`)
	/// 6. Ark address
	/// 7. Bare bitcoin address
	/// 8. Hex-encoded output script
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

		// Raw LNURL link (`lnurl1…`). Only matches the `lnurl` HRP, so it
		// won't collide with bolt11 (`lnbc…`) handled above.
		if let Ok(lnurl) = LnUrl::from_str(payment_str) {
			if let Some(details) = Self::details_for_lnurl(&lnurl) {
				return Ok(details.into());
			}
		}

		// Ark address
		if let Ok(addr) = ArkAddressType::from_str(payment_str) {
			return Ok(self.details_for_ark_address(&addr).await.into());
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
	/// 5. Raw LNURL-pay link (`lnurl1…`)
	/// 6. Ark address
	/// 7. Bare bitcoin address
	/// 8. Hex-encoded output script
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

	/// Estimate fees for a single payment option.
	///
	/// Returns a [`FeeEstimate`] for the given [`AvailablePaymentMethod`] and amount.
	pub async fn estimate_payment_fee(&self, option: &AvailablePaymentMethod, amount: Amount)
		-> anyhow::Result<FeeEstimate>
	{
		match &option.method {
			PaymentMethod::Invoice(_) => self.estimate_lightning_send_fee(amount).await,
			PaymentMethod::Offer(_) => self.estimate_lightning_send_fee(amount).await,
			PaymentMethod::LightningAddress(_) => self.estimate_lightning_send_fee(amount).await,
			PaymentMethod::Lnurl(_) => self.estimate_lightning_send_fee(amount).await,
			PaymentMethod::Bitcoin(address) => {
				let addr = address.assume_checked_ref();
				self.estimate_send_onchain(addr, amount).await
			},
			PaymentMethod::Ark(_) => self.estimate_arkoor_payment_fee(amount).await,
			PaymentMethod::OutputScript(_) => bail!("Sending to output scripts is not supported yet"),
			PaymentMethod::Custom(_) => bail!("Cannot estimate fees for custom payment method"),
		}
	}

	/// Estimate fees for all payment options in a [`PaymentRequest`].
	///
	/// Returns a list of tuples containing the [`AvailablePaymentMethod`] and its [`FeeEstimate`].
	/// The list is sorted by the gross amount of the fee estimate in ascending order.
	pub async fn estimate_payment_fees(&self, request: PaymentRequest, amount: Option<Amount>)
		-> anyhow::Result<Vec<(AvailablePaymentMethod, FeeEstimate)>>
	{
		let amount = match (amount, request.amount) {
			(Some(amount), _) => amount,
			(None, Some(amount)) => amount,
			(None, None) => bail!("Amount is required to estimate fees"),
		};

		let mut options_with_fees = Vec::new();
		for option in request.options {
			let fee = self.estimate_payment_fee(&option, amount).await?;
			options_with_fees.push((option, fee));
		}

		options_with_fees.sort_by_key(|(_, fee)| fee.gross_amount);

		Ok(options_with_fees)
	}

	/// Create a builder for constructing a BIP 321 payment URI.
	///
	/// # Example
	///
	/// ```no_run
	/// # use bitcoin::Amount;
	/// # use bark::Wallet;
	/// # async fn example(wallet: &mut Wallet) -> anyhow::Result<()> {
	/// let mut builder = wallet.bip321_uri();
	/// let uri = builder
	///		.amount(Amount::from_sat(100_000))
	/// 	.build().await?;
	///
	/// // bitcoin:?amount=100000&ark=tark1pwh9vsmezqqpharv69q4z8m6x364d5m5prnmcalcalq9pdmzw0y7mpveck4pcfhezqypczkrrj3lkx5ue4qrf4jc7ztpt9htdttmh2judhqnu7aue8p0y9mq47jn9z&lightning=lnbc20m1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygshp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqfp4qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q9qrsgq9vlvyj8cqvq6ggvpwd53jncp9nwc47xlrsnenq2zp70fq83qlgesn4u3uyf4tesfkkwwfg3qs54qe426hp3tz7z6sweqdjg05axsrjqp9yrrwc
	/// println!("{}", uri.to_string());
	///
	/// # Ok(())
	/// # }
	/// ```
	pub fn bip321_uri<'a>(&'a mut self) -> BarkBip321UriBuilder<'a> {
		BarkBip321UriBuilder::new(self)
	}
}

#[cfg(test)]
mod test {
	use std::str::FromStr;

	use ark::{SECP, VtxoPolicy};
	use bitcoin::Amount;
	use bitcoin::secp256k1::Keypair;
	use bitcoin::secp256k1::rand::thread_rng;

	use super::*;

	fn dummy_ark_address(testnet: bool) -> ark::Address {
		let server = Keypair::new(&SECP, &mut thread_rng()).public_key();
		let user = Keypair::new(&SECP, &mut thread_rng()).public_key();
		ark::Address::new(testnet, server, VtxoPolicy::new_pubkey(user), vec![])
	}

	/// The upper-cased URI must parse back to an equal URI, which only holds
	/// if `ark::Address::from_str` accepts the upper-cased bech32m form.
	#[test]
	fn ark_uppercase_uri_roundtrips() {
		let addr = ArkAddressType::Bark(dummy_ark_address(false));
		let mut uri = BarkBip321Uri::new();
		uri.set_amount(Amount::from_sat(100_000)).unwrap();

		uri.extensions_mut().ark.push(FieldWithAttributes::new(addr.clone(), false));

		let upper = uri.checked_uppercase().unwrap();
		assert!(upper.starts_with("BITCOIN:?AMOUNT="), "{}", upper);
		assert!(upper.contains("&ARK=ARK1"), "{}", upper);

		let reparsed = BarkBip321Uri::from_str(&upper).unwrap();
		assert_eq!(reparsed, uri);
		assert_eq!(reparsed.extensions().ark()[0].inner(), &addr);
	}
}

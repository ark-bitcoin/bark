//! Fiat amounts and conversion to sats.
//!
//! Fiat values are exact decimals, never floats: a fiat amount on a receipt
//! must match what the staff typed.

use std::fmt;
use std::str::FromStr;

use bitcoin::Amount;


/// The fiat currencies the Bull Bitcoin price API quotes, with their
/// decimal places.
pub const CURRENCIES: &[(&str, u32)] = &[
	("USD", 2),
	("CAD", 2),
	("MXN", 2),
	("CRC", 2),
	("EUR", 2),
	("ARS", 2),
	("COP", 0),
];

/// The decimal places of a supported currency.
pub fn currency_decimals(code: &str) -> Option<u32> {
	CURRENCIES.iter().find(|(c, _)| *c == code).map(|(_, d)| *d)
}

/// A non-negative decimal number, stored as `value / 10^scale`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Decimal {
	value: u128,
	scale: u32,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("not a valid decimal amount: {0}")]
pub struct DecimalError(String);

const MAX_SCALE: u32 = 18;

impl Decimal {
	pub fn new(value: u128, scale: u32) -> Decimal {
		Decimal { value, scale }
	}

	pub fn scale(&self) -> u32 {
		self.scale
	}

	pub fn is_zero(&self) -> bool {
		self.value == 0
	}

	/// Rounds half up to `scale` decimal places.
	pub fn round(&self, scale: u32) -> Decimal {
		if scale >= self.scale {
			return Decimal { value: self.value * 10u128.pow(scale - self.scale), scale };
		}
		let div = 10u128.pow(self.scale - scale);
		Decimal { value: (self.value + div / 2) / div, scale }
	}

	/// Converts a fiat amount to sats at `btc_price` (fiat per bitcoin),
	/// rounded half up. `None` on overflow or a zero price.
	pub fn fiat_to_sat(&self, btc_price: &Decimal) -> Option<Amount> {
		if btc_price.value == 0 {
			return None;
		}
		// sat = fiat * 10^8 / price
		//     = (f / 10^fs) * 10^8 / (p / 10^ps)
		//     = f * 10^(8 + ps) / (p * 10^fs)
		let num = self.value.checked_mul(10u128.checked_pow(8 + btc_price.scale)?)?;
		let den = btc_price.value.checked_mul(10u128.checked_pow(self.scale)?)?;
		let sat = num.checked_add(den / 2)? / den;
		Some(Amount::from_sat(u64::try_from(sat).ok()?))
	}
}

impl FromStr for Decimal {
	type Err = DecimalError;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		let err = || DecimalError(s.to_string());
		let (int, frac) = match s.split_once('.') {
			Some((i, f)) => (i, f),
			None => (s, ""),
		};
		if int.is_empty() || !int.bytes().all(|b| b.is_ascii_digit())
			|| !frac.bytes().all(|b| b.is_ascii_digit())
			|| (s.contains('.') && frac.is_empty())
		{
			return Err(err());
		}
		let scale = frac.len() as u32;
		if scale > MAX_SCALE || int.len() > 20 {
			return Err(err());
		}
		let value = format!("{}{}", int, frac).parse::<u128>().map_err(|_| err())?;
		Ok(Decimal { value, scale })
	}
}

impl fmt::Display for Decimal {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		if self.scale == 0 {
			return write!(f, "{}", self.value);
		}
		let div = 10u128.pow(self.scale);
		write!(f, "{}.{:0width$}", self.value / div, self.value % div, width = self.scale as usize)
	}
}

#[cfg(test)]
mod test {
	use super::*;

	fn d(s: &str) -> Decimal {
		s.parse().unwrap()
	}

	#[test]
	fn parse_and_display() {
		assert_eq!(d("12.50").to_string(), "12.50");
		assert_eq!(d("0.05").to_string(), "0.05");
		assert_eq!(d("7").to_string(), "7");
		for bad in ["", ".5", "5.", "-1", "1e3", "1.2.3", "abc", " 1"] {
			assert!(bad.parse::<Decimal>().is_err(), "{bad}");
		}
	}

	#[test]
	fn round_half_up() {
		assert_eq!(d("1.005").round(2).to_string(), "1.01");
		assert_eq!(d("1.004").round(2).to_string(), "1.00");
		assert_eq!(d("3").round(2).to_string(), "3.00");
	}

	#[test]
	fn converts_fiat_to_sats() {
		// 12,500.00 at 62,500,000.00 per bitcoin is 20,000 sats.
		assert_eq!(d("12500.00").fiat_to_sat(&d("62500000.00")), Some(Amount::from_sat(20_000)));
		assert_eq!(d("12.50").fiat_to_sat(&d("62500000.00")), Some(Amount::from_sat(20)));
		// 1 USD at 100,000 USD per bitcoin is 1,000 sats.
		assert_eq!(d("1").fiat_to_sat(&d("100000")), Some(Amount::from_sat(1_000)));
		// Rounds half up: 1 / 300,000 BTC is 333.33 sats.
		assert_eq!(d("1").fiat_to_sat(&d("300000")), Some(Amount::from_sat(333)));
		assert_eq!(d("2").fiat_to_sat(&d("300000")), Some(Amount::from_sat(667)));
		assert_eq!(d("1").fiat_to_sat(&d("0")), None);
	}

	#[test]
	fn currencies() {
		assert_eq!(currency_decimals("CRC"), Some(2));
		assert_eq!(currency_decimals("COP"), Some(0));
		assert_eq!(currency_decimals("XYZ"), None);
	}
}

//! The bitcoin price, from the Bull Bitcoin public price API.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use anyhow::{Context, bail};
use chrono::{DateTime, Utc};
use serde_json::json;
use tokio::sync::Mutex;

use crate::config;
use crate::money::Decimal;


#[derive(Debug, Clone)]
pub struct Quote {
	pub currency: String,
	/// The price of one bitcoin in `currency`.
	pub btc_price: Decimal,
	pub fetched_at: DateTime<Utc>,
}

pub struct PriceFeed {
	cfg: config::Price,
	http: reqwest::Client,
	cache: Mutex<HashMap<String, (Instant, Quote)>>,
}

impl PriceFeed {
	pub fn new(cfg: config::Price) -> anyhow::Result<PriceFeed> {
		let http = reqwest::Client::builder()
			.timeout(Duration::from_secs(10))
			.build()?;
		Ok(PriceFeed { cfg, http, cache: Mutex::new(HashMap::new()) })
	}

	/// The current price of one bitcoin in `currency`, at most
	/// `cache_secs` old.
	pub async fn quote(&self, currency: &str) -> anyhow::Result<Quote> {
		if let Some(fixed) = &self.cfg.fixed_btc_price {
			return Ok(Quote {
				currency: currency.to_string(),
				btc_price: fixed.parse().context("fixed_btc_price is not a decimal")?,
				fetched_at: Utc::now(),
			});
		}

		let max_age = Duration::from_secs(self.cfg.cache_secs);
		let mut cache = self.cache.lock().await;
		if let Some((at, quote)) = cache.get(currency) {
			if at.elapsed() < max_age {
				return Ok(quote.clone());
			}
		}

		let body = json!({
			"id": 1,
			"jsonrpc": "2.0",
			"method": "getRate",
			"params": { "element": { "fromCurrency": "BTC", "toCurrency": currency } },
		});
		let resp = self.http.post(&self.cfg.url).json(&body).send().await
			.context("price API request failed")?
			.error_for_status().context("price API returned an error status")?
			.json::<serde_json::Value>().await
			.context("price API returned no JSON")?;
		let quote = Quote {
			currency: currency.to_string(),
			btc_price: parse_price(&resp)?,
			fetched_at: Utc::now(),
		};
		cache.insert(currency.to_string(), (Instant::now(), quote.clone()));
		Ok(quote)
	}
}

/// Reads the price from a `getRate` answer: `indexPrice / 10^precision`.
fn parse_price(resp: &serde_json::Value) -> anyhow::Result<Decimal> {
	if let Some(err) = resp.get("error") {
		bail!("price API error: {}", err);
	}
	let element = resp.pointer("/result/element").context("price API answer has no element")?;
	let index = element.get("indexPrice").and_then(|v| v.as_u64())
		.context("price API answer has no integer indexPrice")?;
	let precision = element.get("precision").and_then(|v| v.as_u64()).unwrap_or(2);
	if index == 0 || precision > 18 {
		bail!("price API answer is not usable: {}", element);
	}
	Ok(Decimal::new(index as u128, precision as u32))
}

#[cfg(test)]
mod test {
	use super::*;

	#[test]
	fn parses_get_rate() {
		let resp = json!({"result": {"element": {"indexPrice": 6250000000u64, "precision": 2}}});
		assert_eq!(parse_price(&resp).unwrap().to_string(), "62500000.00");
		let no_precision = json!({"result": {"element": {"indexPrice": 100000}}});
		assert_eq!(parse_price(&no_precision).unwrap().to_string(), "1000.00");
		assert!(parse_price(&json!({"error": {"code": 1}})).is_err());
		assert!(parse_price(&json!({"result": {"element": {"indexPrice": 0}}})).is_err());
		assert!(parse_price(&json!({"result": {}})).is_err());
	}
}

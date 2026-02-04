#[macro_use] extern crate serde;

#[macro_use]
mod macros;
mod msgs;
mod serde_utils;

use std::borrow::Cow;
use std::collections::HashMap;
use std::fmt;
use serde::de::DeserializeOwned;
use serde::Serialize;
pub use crate::msgs::*;


/// Trait implemented by all our trace log messages.
pub trait LogMsg: Sized + Send + fmt::Debug + Serialize + DeserializeOwned + 'static {
	const LOGID: &'static str;
	const LEVEL: tracing::Level;
	const MSG: &'static str;
}

#[derive(Debug)]
pub enum RecordParseError {
	WrongType,
	Json(serde_json::Error),
}

pub fn parse_record(record: &str) -> Result<ParsedRecord<'_>, RecordParseError> {
	Ok(serde_json::from_str(record).map_err(RecordParseError::Json)?)
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ParsedRecord<'a> {
	pub timestamp: chrono::DateTime<chrono::Local>,
	pub message: Cow<'a, str>,
	pub level: Cow<'a, str>,
	pub target: Option<&'a str>,
	pub filename: Option<&'a str>,
	pub line_number: Option<u32>,
	pub slog_id: Option<&'a str>,
	pub slog_data_json: Option<String>,
	pub span: Option<HashMap<String, serde_json::Value>>,
	// pub spans:
	// pub open_telemetry:
	#[serde(flatten)]
	pub extra: HashMap<String, serde_json::Value>,
}

impl ParsedRecord<'_> {
	/// Whether this is a structured log message
	pub fn is_slog(&self) -> bool {
		self.slog_id.is_some()
	}

	/// Check whether this log message if of the given structure log type.
	pub fn is<T: LogMsg>(&self) -> bool {
		self.slog_id.as_ref().unwrap_or(&"").to_string() == T::LOGID
	}

	/// Try to parse the log message into the given structured log type.
	pub fn try_as<T: LogMsg>(&self) -> Result<T, RecordParseError> {
		if !self.is::<T>() {
			return Err(RecordParseError::WrongType);
		}

		let json = self.slog_data_json.clone().unwrap_or("{}".to_string());
		Ok(serde_json::from_str(&json).map_err(RecordParseError::Json)?)
	}
}


#[cfg(test)]
mod test {
	use super::*;

	#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
	struct TestLog {
		nb: usize,
		name: String,
	}
	impl_slog!(TestLog, INFO, "test log message");

	#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
	struct EmptyLog;
	impl_slog!(EmptyLog, DEBUG, "empty log");

	#[test]
	fn test_log_msg_trait() {
		assert_eq!(TestLog::LOGID, "TestLog");
		assert_eq!(TestLog::LEVEL, tracing::Level::INFO);
		assert_eq!(TestLog::MSG, "test log message");

		assert_eq!(EmptyLog::LOGID, "EmptyLog");
		assert_eq!(EmptyLog::LEVEL, tracing::Level::DEBUG);
		assert_eq!(EmptyLog::MSG, "empty log");
	}

	#[test]
	fn test_serde_roundtrip() {
		let original = TestLog { nb: 42, name: "test".to_string() };
		let json = serde_json::to_string(&original).unwrap();
		let parsed: TestLog = serde_json::from_str(&json).unwrap();
		assert_eq!(original, parsed);
		let json = "{\"nb\":42,\"name\":\"test\"}";
		let parsed: TestLog = serde_json::from_str(&json).unwrap();
		assert_eq!(original, parsed);
	}

	#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
	struct TestTLog { }
	impl_slog!(TestTLog, INFO, "test log message");

	#[test]
	fn json_slog_roundtrip() {
		let json_data = r#"
			{
				"target": "bark-server-slog",
				"timestamp": "2025-09-01T17:06:57.586378832+01:00",
				"level": "ERROR",
				"file": "file.rs",
				"line": 35,
				"message": "test log message",
				"slog_id": "TestTLog",
				"span": {
					"nb": 42,
					"name": "test"
				}
			}"#;
		let parsed = parse_record(json_data).unwrap();
		assert!(parsed.is::<TestTLog>());
	}

	#[test]
	fn json_slog_parse() {
		// Check that we can parse messages with extra values.
		let json_data = r#"{
			"timestamp": "2025-09-01T17:06:57.586378832+01:00",
			"message": "test log message",
			"level": "INFO",
			"file": "test.rs",
			"line": 35,
			"slog_id": "TestTLog",
			"span": {
				"nb": 35,
				"name": "test"
			},
			"extra": {"extra": 3}
		}"#;
		let parsed = parse_record(json_data).unwrap();
		assert!(parsed.is::<TestTLog>());

		// And without slog stuff
		let json = serde_json::to_string(&serde_json::json!({
			"timestamp": "2025-09-01T17:06:57.586378832+01:00",
			"message": "test",
			"level": "INFO",
			"file": "test.rs",
			"line": 35,
			"extra": {"extra": 3},
		})).unwrap();
		let parsed = parse_record(json.as_str()).unwrap();
		assert!(!parsed.is::<TestTLog>());
	}

	#[test]
	fn json_parse() {
		// Check that we can parse messages with extra values.
		let slog_data = serde_json::json!({
			"name": "test",
			"nb": 35
		});
		let json = serde_json::to_string(&serde_json::json!({
			"timestamp": "2025-09-01T17:06:57.586378832+01:00",
			"message": "test",
			"level": "info",
			"file": "test.rs",
			"line": 35,
			"slog_id": "TestLog",
			"slog_data_json": slog_data.to_string(),
			"extra": {"extra": 3},
		})).unwrap();
		let parsed = serde_json::from_str::<ParsedRecord>(&json).unwrap();
		assert!(parsed.is::<TestLog>());
		let tl = parsed.try_as::<TestLog>().unwrap();
		assert_eq!(tl.nb, 35);
		assert_eq!(tl.name, "test".to_string());

		// And without slog stuff
		let json = serde_json::to_string(&serde_json::json!({
			"timestamp": "2025-09-01T17:06:57.586378832+01:00",
			"message": "test",
			"level": "info",
			"file": "test.rs",
			"line": 35,
			"extra": {"extra": 3},
		})).unwrap();
		let parsed = serde_json::from_str::<ParsedRecord>(&json).unwrap();
		assert!(!parsed.is::<TestLog>());
	}
}

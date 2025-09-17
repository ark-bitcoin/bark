
#[macro_use] extern crate serde;

#[macro_use]
mod macros;
mod msgs;
mod serde_utils;

pub use crate::msgs::*;
pub use opentelemetry::trace::TraceId;

use std::borrow::Cow;
use std::{fmt, io};
use opentelemetry::trace::TraceContextExt;
use serde::de::{Deserialize, DeserializeOwned};
use serde::ser::{Serialize, Serializer, SerializeMap};
use tracing_opentelemetry::OpenTelemetrySpanExt;

/// The "target" field used for structured logging.
pub const SLOG_TARGET: &str = "bark-server-slog";

pub const LOGID_FIELD: &str = "slog_id";
pub const TRACEID_FIELD: &str = "slog_trace_id";
pub const DATA_FIELD: &str = "slog_data";

/// Retrieves the current trace ID from OpenTelemetry
pub fn get_trace_id() -> Option<TraceId> {
	let context = tracing::Span::current().context();
	let span = context.span();
	let span_context = span.span_context();
	span_context.is_valid().then(|| span_context.trace_id())
}

/// Trait implemented by all our slog structured log messages.
pub trait LogMsg: Sized + Send + fmt::Debug + Serialize + DeserializeOwned + 'static {
	const LOGID: &'static str;
	const LEVEL: log::Level;
	const MSG: &'static str;
}


pub fn log<T: LogMsg>(
	obj: &T,
	module: &str,
	file: &str,
	line: u32,
	trace_id: Option<TraceId>,
) {
	log::logger().log(&log::Record::builder()
		.args(format_args!("{}", T::MSG))
		.target(SLOG_TARGET)
		.level(T::LEVEL)
		.module_path(Some(module))
		.file(Some(file))
		.line(Some(line))
		.key_values(&LogMsgSourceWrapper {
			log_msg: obj,
			trace_id: trace_id,
		})
		.build());
}


/// A wrapper around our [LogMsg] structs that implements [log::kv::Source]
/// so that we can pass them into the kv structure of a log record.
struct LogMsgSourceWrapper<'a, T: LogMsg> {
	log_msg: &'a T,
	trace_id: Option<TraceId>,
}

impl<'a, T: LogMsg> log::kv::Source for LogMsgSourceWrapper<'a, T> {
	fn visit<'k>(
		&'k self,
		visitor: &mut dyn log::kv::VisitSource<'k>,
	) -> Result<(), log::kv::Error> {
		visitor.visit_pair(
			LOGID_FIELD.into(),
			T::LOGID.into(),
		)?;
		visitor.visit_pair(
			DATA_FIELD.into(),
			log::kv::Value::from_serde(self.log_msg),
		)?;
		if let Some(ref trace_id) = self.trace_id {
			visitor.visit_pair(
				TRACEID_FIELD.into(),
				log::kv::Value::from_display(trace_id),
			)?;
		}
		Ok(())
	}
}

#[derive(Debug)]
pub enum RecordParseError {
	WrongType,
	Json(serde_json::Error),
}

#[derive(Debug, Deserialize)]
pub struct ParsedRecordKv<'a> {
	#[serde(rename = "slog_id")]
	pub id: &'a str,
	#[serde(default, rename = "slog_trace_id", with = "serde_utils::trace_id::opt")]
	pub trace_id: Option<TraceId>,
	#[serde(rename = "slog_data")]
	pub data: &'a serde_json::value::RawValue,
}

// Custom deserializer for the `kv` field.
fn deserialize_kv<'de, D>(d: D) -> Result<Option<ParsedRecordKv<'de>>, D::Error>
where
	D: serde::Deserializer<'de>,
{
	// Attempt to deserialize `ParsedRecordKv`, returning `None` if deserialization fails due to missing fields.
	Ok(ParsedRecordKv::<'de>::deserialize(d).ok())
}

#[derive(Debug, Deserialize)]
pub struct ParsedRecord<'a> {
	pub timestamp: chrono::DateTime<chrono::Local>,
	// NB needs to be Cow to handle built-in escaping of newlines if any
	pub message: Cow<'a, str>,
	pub level: log::Level,
	pub module: Option<&'a str>,
	pub file: Option<&'a str>,
	pub line: Option<u32>,
	#[serde(default, deserialize_with = "deserialize_kv")]
	pub kv: Option<ParsedRecordKv<'a>>,
}

impl<'a> ParsedRecord<'a> {
	/// Whether this is a structured log message
	pub fn is_slog(&self) -> bool {
		self.kv.is_some()
	}

	/// Check whether this log message if of the given structure log type.
	pub fn is<T: LogMsg>(&self) -> bool {
		if let Some(ref kv) = self.kv {
			kv.id == T::LOGID
		} else {
			false
		}
	}

	/// Try to parse the log message into the given structured log type.
	pub fn try_as<T: LogMsg>(&self) -> Result<T, RecordParseError> {
		if !self.is::<T>() {
			return Err(RecordParseError::WrongType);
		}

		Ok(serde_json::from_str(self.kv.as_ref().map(|v| v.data.get()).unwrap_or(""))
			.map_err(RecordParseError::Json)?)
	}

	pub fn trace_id<T: LogMsg>(&self) -> Option<TraceId> {
		if let Some(ref kv) = self.kv {
			kv.trace_id
		} else {
			None
		}
	}
}

/// Encode the record compatible with [ParsedRecord].
pub fn encode_record<'a>(
	out: impl io::Write,
	timestamp: chrono::DateTime<chrono::Local>,
	record: &'a log::Record<'a>,
) -> Result<(), io::Error> {
	#[derive(serde::Serialize)]
	struct Rec<'a> {
		timestamp: chrono::DateTime<chrono::Local>,
		#[serde(flatten)]
		rec: RecordSerializeWrapper<'a>,
	}

	let rec = Rec {
		timestamp: timestamp,
		rec: RecordSerializeWrapper(record),
	};

	serde_json::to_writer(out, &rec)?;
	Ok(())
}


/// A wrapper around a [log::kv::Source] that implements [serde::Serialize].
pub struct SourceSerializeWrapper<'a>(pub &'a dyn log::kv::Source);

impl<'a> Serialize for SourceSerializeWrapper<'a> {
	fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
		use serde::ser::Error;

		struct Visitor<'a, S: Serializer>(&'a mut <S as Serializer>::SerializeMap);
		impl<'a, S: Serializer> log::kv::VisitSource<'a> for Visitor<'a, S> {
			fn visit_pair(
				&mut self, key: log::kv::Key<'a>, value: log::kv::Value<'a>,
			) -> Result<(), log::kv::Error> {
				self.0.serialize_entry(&key, &value).map_err(|e| {
					log::kv::Error::boxed(format!("serialize error: {:?}", e))
				})?;
				Ok(())
			}
		}

		let mut m = s.serialize_map(None)?;
		let mut v = Visitor::<S>(&mut m);
		self.0.visit(&mut v).map_err(S::Error::custom)?;
		m.end()
	}
}

/// A wrapper around a [log::Record] that implements [serde::Serialize].
struct RecordSerializeWrapper<'a>(pub &'a log::Record<'a>);

impl<'a> Serialize for RecordSerializeWrapper<'a> {
	fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
		let mut m = s.serialize_map(None)?;
		m.serialize_entry("message", self.0.args())?;
		m.serialize_entry("level", &self.0.level())?;
		if let Some(module) = self.0.module_path() {
			m.serialize_entry("module", module)?;
		}
		if let Some(file) = self.0.file() {
			m.serialize_entry("file", file)?;
		}
		if let Some(line) = self.0.line() {
			m.serialize_entry("line", &line)?;
		}
		let kv = self.0.key_values();
		if kv.count() > 0 {
			m.serialize_entry("kv", &SourceSerializeWrapper(kv))?;
		}
		m.end()
	}
}

/// Extension trait for [log::kv::Source]
pub trait KvSourceExt: log::kv::Source {
	fn is_empty(&self) -> bool {
		// Visitor that throws an error to swiftly indicate the source is not empty.
		struct Visitor;

		impl<'kvs> log::kv::VisitSource<'kvs> for Visitor {
			fn visit_pair(
				&mut self, _: log::kv::Key<'kvs>, _: log::kv::Value<'kvs>,
			) -> Result<(), log::kv::Error> {
				Err(log::kv::Error::msg(""))
			}
		}

		self.visit(&mut Visitor).is_ok()
	}
}
impl<T: log::kv::Source> KvSourceExt for T {}

#[cfg(test)]
mod test {
	use crate::*;

	#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
	struct TestLog {
		nb: usize,
	}
	impl_slog!(TestLog, Info, "testlog");

	#[test]
	fn json_roundtrip() {
		let m = TestLog { nb: 42 };
		let kv = LogMsgSourceWrapper{
			log_msg: &m,
			trace_id: Some(TraceId::from_hex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap()),
		};
		let record = log::Record::builder()
			.target(SLOG_TARGET)
			.level(RoundStarted::LEVEL)
			.file(Some("some_file.rs"))
			.line(Some(35))
			.key_values(&kv)
			.build();
		let json = {
			let mut buf = Vec::new();
			encode_record(&mut buf, chrono::Local::now(), &record).unwrap();
			String::from_utf8(buf).unwrap()
		};

		let parsed = serde_json::from_str::<ParsedRecord>(&json).unwrap();
		assert!(parsed.is::<TestLog>());
		let inner = parsed.try_as::<TestLog>().unwrap();
		assert_eq!(inner, m);
		assert_eq!(parsed.trace_id::<TestLog>().unwrap(), kv.trace_id.unwrap());
	}

	#[test]
	fn json_parse() {
		// Check that we can parse messages with extra values.
		let json = serde_json::to_string(&serde_json::json!({
			"timestamp": "2025-09-01T17:06:57.586378832+01:00",
			"message": "test",
			"level": "info",
			"file": "test.rs",
			"line": 35,
			"kv": {
				"slog_id": "TestLog",
				"slog_data": {"nb": 35},
				"slog_trace_id": "abababababababababababababababab",
				"extra": {"extra": 3},
			},
		})).unwrap();
		let parsed = serde_json::from_str::<ParsedRecord>(&json).unwrap();
		assert!(parsed.is::<TestLog>());
		let _ = parsed.try_as::<TestLog>().unwrap();
		let trace_id = parsed.trace_id::<TestLog>();
		assert_eq!(trace_id, Some(TraceId::from_hex("abababababababababababababababab").unwrap()));

		// Check that deserialization works if trace_id is missing
		let json = serde_json::to_string(&serde_json::json!({
			"timestamp": "2025-09-01T17:06:57.586378832+01:00",
			"message": "test",
			"level": "info",
			"file": "test.rs",
			"line": 35,
			"kv": {
				"slog_id": "TestLog",
				"slog_data": {"nb": 35},
				"extra": {"extra": 3},
			},
		})).unwrap();
		let parsed = serde_json::from_str::<ParsedRecord>(&json).unwrap();
		assert!(parsed.is::<TestLog>(), "not recognized: {:?}", parsed.kv);
		let _ = parsed.try_as::<TestLog>().unwrap();
		let trace_id = parsed.trace_id::<TestLog>();
		assert_eq!(trace_id, None);

		// And without slog stuff
		let json = serde_json::to_string(&serde_json::json!({
			"timestamp": "2025-09-01T17:06:57.586378832+01:00",
			"message": "test",
			"level": "info",
			"file": "test.rs",
			"line": 35,
			"kv": {
				"extra": {"extra": 3},
			},
		})).unwrap();
		let parsed = serde_json::from_str::<ParsedRecord>(&json).unwrap();
		assert!(!parsed.is::<TestLog>());
		let trace_id = parsed.trace_id::<TestLog>();
		assert_eq!(trace_id, None);
	}

	#[test]
	fn source_is_empty() {
		let source = &[("a", 1)] as &[_];
		assert!(!KvSourceExt::is_empty(&source));

		let source = None::<(&str, i32)>;
		assert!(KvSourceExt::is_empty(&source));
	}
}

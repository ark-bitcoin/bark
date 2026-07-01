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
use tracing_subscriber::fmt::format::Writer;
use tracing_subscriber::fmt::time::FormatTime;
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
	/// The fields of the structured log struct
	#[serde(borrow)]
	pub slog_data: Option<&'a serde_json::value::RawValue>,
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

		let data = self.slog_data.unwrap_or_else(|| serde_json::value::RawValue::NULL);
		Ok(serde_json::from_str(data.get()).map_err(RecordParseError::Json)?)
	}
}

struct MillisTimer;

impl FormatTime for MillisTimer {
	fn format_time(&self, w: &mut Writer<'_>) -> std::fmt::Result {
		let now = chrono::Local::now();
		write!(w, "{}", now.to_rfc3339_opts(chrono::SecondsFormat::Millis, true))
	}
}

/// Visitor that flattens all fields of a tracing event into a top-level JSON map.
///
/// This replaces `json_subscriber`'s default event flattening so we can give our
/// structured logs special treatment: the `slog!` macro (see the `server-log`
/// crate) records the serialized slog struct as a `slog_data_json` string field.
/// We parse that string back into a real JSON object and emit it under the
/// `slog_data` key, so its inner fields become queryable instead of being an
/// opaque, escaped JSON string.
#[derive(Default)]
struct SlogFlattenVisitor {
	fields: std::collections::HashMap<String, serde_json::Value>,
}

impl SlogFlattenVisitor {
	/// Field name recorded by the `slog!` macro holding the serialized slog struct.
	const SLOG_DATA_JSON: &'static str = "slog_data_json";
	/// Key under which we emit the parsed slog struct as a real JSON object.
	const SLOG_DATA: &'static str = "slog_data";

	fn insert(&mut self, name: &str, value: serde_json::Value) {
		self.fields.insert(name.to_owned(), value);
	}
}

impl tracing_core::field::Visit for SlogFlattenVisitor {
	fn record_f64(&mut self, field: &tracing_core::Field, value: f64) {
		self.insert(field.name(), value.into());
	}

	fn record_i64(&mut self, field: &tracing_core::Field, value: i64) {
		self.insert(field.name(), value.into());
	}

	fn record_u64(&mut self, field: &tracing_core::Field, value: u64) {
		self.insert(field.name(), value.into());
	}

	fn record_bool(&mut self, field: &tracing_core::Field, value: bool) {
		self.insert(field.name(), value.into());
	}

	fn record_str(&mut self, field: &tracing_core::Field, value: &str) {
		if field.name() == Self::SLOG_DATA_JSON {
			// Turn the serialized slog struct into a real JSON object. If parsing
			// somehow fails, fall back to keeping the raw string so we never drop data.
			if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(value) {
				self.insert(Self::SLOG_DATA, parsed);
			} else {
				self.insert(Self::SLOG_DATA_JSON, value.into());
			}
		} else {
			self.insert(field.name(), value.into());
		}
	}

	fn record_debug(&mut self, field: &tracing_core::Field, value: &dyn std::fmt::Debug) {
		// Mirror `tracing_serde`'s `SerdeMapVisitor` (what `flatten_event(true)` used):
		// serialize the field straight through with no name munging or filtering, so
		// every non-slog field is emitted exactly as it was before.
		self.insert(field.name(), format!("{:?}", value).into());
	}
}

/// Build the JSON logging layer used for all server output.
///
/// This mirrors `tracing_subscriber::fmt().json()` (via the `json_subscriber`
/// crate) but flattens the event fields to the top level ourselves so we can
/// turn our structured logs' `slog_data_json` string field into a real,
/// queryable `slog_data` JSON object (see `SlogFlattenVisitor`).
pub fn slog_json_layer<S, W>(make_writer: W) -> json_subscriber::fmt::Layer<S, W>
where
	S: tracing_core::Subscriber + for<'lookup> tracing_subscriber::registry::LookupSpan<'lookup>,
	W: for<'writer> tracing_subscriber::fmt::MakeWriter<'writer> + 'static,
{
	let mut layer = json_subscriber::layer()
		.with_timer(MillisTimer)
		.with_writer(make_writer)
		.with_target(true)
		.with_thread_ids(false)
		.with_thread_names(false)
		.with_file(true)
		.with_line_number(true)
		.with_current_span(true)
		.with_span_list(true)
		.flatten_event(false) // we do it ourselves below
		.with_opentelemetry_ids(true);

	// `json_subscriber::layer()` nests all event fields under a "fields" key by
	// default (via `with_event`). The `.flatten_event(true)` builder we used to
	// call removed that and hoisted the fields to the top level; we now do the
	// flattening ourselves to special-case `slog_data_json`, so we must remove
	// the default "fields" entry explicitly, otherwise the fields are emitted
	// twice (once nested under "fields", once flattened at the top level).
	let inner = layer.inner_layer_mut();
	inner.remove_field("fields");
	inner.add_multiple_dynamic_fields(|event, _ctx| {
		let mut visitor = SlogFlattenVisitor::default();
		event.record(&mut visitor);
		visitor.fields
	});

	layer
}


#[cfg(test)]
mod test {
	use std::io;
	use std::sync::{Arc, Mutex};

	use tracing_subscriber::layer::SubscriberExt;
	use tracing_subscriber::fmt::MakeWriter;

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
			"slog_data": slog_data,
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

	/// A `MakeWriter` that captures everything written to it into a shared buffer
	/// so tests can inspect the JSON the layer actually produces.
	#[derive(Clone, Default)]
	struct BufferWriter(Arc<Mutex<Vec<u8>>>);

	impl BufferWriter {
		fn contents(&self) -> String {
			String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
		}
	}

	impl io::Write for BufferWriter {
		fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
			self.0.lock().unwrap().extend_from_slice(buf);
			Ok(buf.len())
		}
		fn flush(&mut self) -> io::Result<()> { Ok(()) }
	}

	impl<'a> MakeWriter<'a> for BufferWriter {
		type Writer = BufferWriter;
		fn make_writer(&'a self) -> Self::Writer { self.clone() }
	}

	/// Capture the JSON emitted for a single event produced by `f`.
	fn capture(f: impl FnOnce()) -> serde_json::Value {
		let buffer = BufferWriter::default();
		let subscriber = tracing_subscriber::registry().with(slog_json_layer(buffer.clone()));
		tracing::subscriber::with_default(subscriber, f);
		let out = buffer.contents();
		let line = out.lines().next().expect("expected a log line");
		serde_json::from_str(line).expect("log line must be valid JSON")
	}

	#[test]
	fn slog_data_is_a_real_object() {
		// Mimics what the `slog!` macro emits: a `slog_id` and a `slog_data_json`
		// string holding the serialized slog struct.
		let json = capture(|| {
			tracing::info!(
				slog_id = "RegisteredBoard",
				slog_data_json = r#"{"vtxo":"abc:0","amount":50083}"#,
				"registered board vtxo",
			);
		});

		// The slog data is hoisted to a top-level `slog_data` object with queryable fields...
		assert_eq!(json["slog_data"]["vtxo"], serde_json::json!("abc:0"));
		assert_eq!(json["slog_data"]["amount"], serde_json::json!(50083));
		// ...and the raw escaped string field is gone.
		assert!(json.get("slog_data_json").is_none(), "raw string should be replaced: {json}");
		// Regression guard: fields are flattened to the top level, not nested
		// under a leftover default "fields" key, and not duplicated.
		assert!(json.get("fields").is_none(), "fields must not be nested: {json}");
		assert_eq!(json["slog_id"], serde_json::json!("RegisteredBoard"));
		assert_eq!(json["message"], serde_json::json!("registered board vtxo"));
	}

	#[test]
	fn non_slog_event_fields_are_untouched() {
		let json = capture(|| {
			tracing::info!(count = 7, name = "alice", "plain event");
		});

		assert!(json.get("fields").is_none(), "fields must not be nested: {json}");
		assert!(json.get("slog_data").is_none());
		assert_eq!(json["count"], serde_json::json!(7));
		assert_eq!(json["name"], serde_json::json!("alice"));
		assert_eq!(json["message"], serde_json::json!("plain event"));
	}
}

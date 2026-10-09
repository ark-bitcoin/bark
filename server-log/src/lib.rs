#[macro_use] extern crate serde;

#[macro_use]
mod macros;
mod msgs;
mod serde_utils;

pub use crate::msgs::*;


use std::borrow::Cow;
use std::collections::HashMap;
use std::fmt;

use serde::de::DeserializeOwned;
use serde::Serialize;
use tracing_core::{Event, Field, Subscriber};
use tracing_core::span::{Attributes, Id, Record};
use tracing_subscriber::fmt::format::Writer;
use tracing_subscriber::fmt::time::FormatTime;
use tracing_subscriber::layer::{Context, Layer};
use tracing_subscriber::registry::LookupSpan;


/// Span field holding the raw `x-user-agent` of the client whose RPC is being
/// served. See [InheritedFields].
pub const USER_AGENT_FIELD: &str = "user_agent";

/// Span field holding the protocol version of the RPC being served.
/// See [InheritedFields].
pub const PVER_FIELD: &str = "pver";


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
	/// raw `x-user-agent` for RPC requests
	pub user_agent: Option<Cow<'a, str>>,
	/// pver for RPC requests
	pub pver: Option<u64>,
	/// The fields of the innermost span the line was emitted in
	pub span: Option<HashMap<String, serde_json::Value>>,
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

/// Span fields that every event emitted inside the span inherits.
///
/// Events only carry their own fields, and the enclosing spans are emitted
/// as a list, which makes a field set on the outermost RPC span awkward to
/// query. [InheritedFieldsLayer] stores these fields in the span's
/// extensions when the span declares them and [slog_json_layer] hoists them
/// onto every event emitted inside the span as top-level fields. The gRPC
/// middleware sets both on the span wrapping each RPC, so every log line
/// emitted while serving a request carries them.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct InheritedFields {
	pub user_agent: Option<String>,
	pub pver: Option<u64>,
}

impl InheritedFields {
	fn is_empty(&self) -> bool {
		self.user_agent.is_none() && self.pver.is_none()
	}

	/// Overwrite our fields with the ones set in `other`.
	fn update_from(&mut self, other: InheritedFields) {
		if other.user_agent.is_some() {
			self.user_agent = other.user_agent;
		}
		if other.pver.is_some() {
			self.pver = other.pver;
		}
	}
}

impl tracing_core::field::Visit for InheritedFields {
	fn record_u64(&mut self, field: &Field, value: u64) {
		if field.name() == PVER_FIELD {
			self.pver = Some(value);
		}
	}

	fn record_i64(&mut self, field: &Field, value: i64) {
		if field.name() == PVER_FIELD {
			self.pver = u64::try_from(value).ok();
		}
	}

	fn record_str(&mut self, field: &Field, value: &str) {
		if field.name() == USER_AGENT_FIELD {
			self.user_agent = Some(value.to_owned());
		}
	}

	fn record_debug(&mut self, _field: &Field, _value: &dyn fmt::Debug) {
		// don't do anything for other fields
	}
}

/// Stores the [InheritedFields] a span declares in the span's extensions, so
/// that [slog_json_layer] can hoist them onto the events emitted inside it.
///
/// Must be registered alongside [slog_json_layer].
pub struct InheritedFieldsLayer;

impl<S> Layer<S> for InheritedFieldsLayer
where
	S: Subscriber + for<'lookup> LookupSpan<'lookup>,
{
	fn on_new_span(&self, attrs: &Attributes<'_>, id: &Id, ctx: Context<'_, S>) {
		let mut fields = InheritedFields::default();
		attrs.record(&mut fields);
		if fields.is_empty() {
			return;
		}
		if let Some(span) = ctx.span(id) {
			span.extensions_mut().insert(fields);
		}
	}

	fn on_record(&self, id: &Id, values: &Record<'_>, ctx: Context<'_, S>) {
		let mut fields = InheritedFields::default();
		values.record(&mut fields);
		if fields.is_empty() {
			return;
		}
		let Some(span) = ctx.span(id) else {
			return;
		};
		let mut extensions = span.extensions_mut();
		match extensions.get_mut::<InheritedFields>() {
			Some(existing) => existing.update_from(fields),
			None => extensions.insert(fields),
		}
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

	/// Add the [InheritedFields] of the spans enclosing `event`, nearest span
	/// first, without overriding fields the event recorded itself.
	fn inherit_from_spans<S>(&mut self, event: &Event<'_>, ctx: &Context<'_, S>)
	where
		S: Subscriber + for<'lookup> LookupSpan<'lookup>,
	{
		let Some(scope) = ctx.event_scope(event) else {
			return;
		};
		for span in scope {
			let extensions = span.extensions();
			let Some(inherited) = extensions.get::<InheritedFields>() else {
				continue;
			};
			if let Some(user_agent) = &inherited.user_agent {
				self.fields.entry(USER_AGENT_FIELD.to_owned())
					.or_insert_with(|| user_agent.clone().into());
			}
			if let Some(pver) = inherited.pver {
				self.fields.entry(PVER_FIELD.to_owned()).or_insert(pver.into());
			}
			if self.fields.contains_key(USER_AGENT_FIELD) && self.fields.contains_key(PVER_FIELD) {
				break;
			}
		}
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
/// queryable `slog_data` JSON object (see `SlogFlattenVisitor`), and so we can
/// hoist the [InheritedFields] of the enclosing spans onto every event.
/// Register [InheritedFieldsLayer] alongside this layer for the latter.
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
	inner.add_multiple_dynamic_fields(|event, ctx| {
		let mut visitor = SlogFlattenVisitor::default();
		event.record(&mut visitor);
		visitor.inherit_from_spans(event, ctx);
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

	/// Capture the JSON emitted for every event produced by `f`.
	fn capture_all(f: impl FnOnce()) -> Vec<serde_json::Value> {
		let buffer = BufferWriter::default();
		let subscriber = tracing_subscriber::registry()
			.with(slog_json_layer(buffer.clone()))
			.with(InheritedFieldsLayer);
		tracing::subscriber::with_default(subscriber, f);
		let out = buffer.contents();
		out.lines()
			.map(|line| serde_json::from_str(line).expect("log line must be valid JSON"))
			.collect()
	}

	/// Capture the JSON emitted for a single event produced by `f`.
	fn capture(f: impl FnOnce()) -> serde_json::Value {
		capture_all(f).into_iter().next().expect("expected a log line")
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
	fn inherited_fields_are_hoisted_onto_events() {
		let lines = capture_all(|| {
			tracing::info!("outside");
			let rpc = tracing::info_span!("grpc", user_agent = "bark/0.2.3", pver = 5u64);
			let _rpc = rpc.enter();
			tracing::info!("in rpc span");
			let inner = tracing::info_span!("handler", amount = 42);
			let _inner = inner.enter();
			tracing::info!(slog_id = "RegisteredBoard", "nested in handler span");
		});
		assert_eq!(lines.len(), 3, "{lines:?}");

		// Outside any span: nothing to inherit.
		assert!(lines[0].get("user_agent").is_none(), "{}", lines[0]);
		assert!(lines[0].get("pver").is_none(), "{}", lines[0]);

		// Directly inside the span that declares the fields.
		assert_eq!(lines[1]["user_agent"], serde_json::json!("bark/0.2.3"));
		assert_eq!(lines[1]["pver"], serde_json::json!(5));

		// Nested in a span that doesn't declare them: still inherited, and
		// the fields are top-level so they're queryable alongside `slog_id`.
		assert_eq!(lines[2]["user_agent"], serde_json::json!("bark/0.2.3"));
		assert_eq!(lines[2]["pver"], serde_json::json!(5));
		assert_eq!(lines[2]["slog_id"], serde_json::json!("RegisteredBoard"));

		let line = serde_json::to_string(&lines[2]).unwrap();
		let parsed = parse_record(&line).unwrap();
		assert_eq!(parsed.user_agent.as_deref(), Some("bark/0.2.3"));
		assert_eq!(parsed.pver, Some(5));
	}

	#[test]
	fn nearest_span_and_event_fields_win() {
		let lines = capture_all(|| {
			let rpc = tracing::info_span!("grpc", user_agent = "bark/0.2.3", pver = 5u64);
			let _rpc = rpc.enter();
			// A handler that takes `pver` as an instrumented argument.
			let inner = tracing::info_span!("claim_lightning_receive", pver = 6u64);
			let _inner = inner.enter();
			tracing::info!("inherits nearest pver");
			tracing::info!(pver = 7u64, "event field wins");
		});
		assert_eq!(lines.len(), 2, "{lines:?}");

		assert_eq!(lines[0]["user_agent"], serde_json::json!("bark/0.2.3"));
		assert_eq!(lines[0]["pver"], serde_json::json!(6));

		assert_eq!(lines[1]["user_agent"], serde_json::json!("bark/0.2.3"));
		assert_eq!(lines[1]["pver"], serde_json::json!(7));
	}

	#[test]
	fn inherited_fields_can_be_recorded_later() {
		let lines = capture_all(|| {
			let rpc = tracing::info_span!(
				"grpc", user_agent = tracing::field::Empty, pver = tracing::field::Empty,
			);
			let _rpc = rpc.enter();
			tracing::info!("before record");
			rpc.record("user_agent", "bark-wasm/1.0");
			rpc.record("pver", 4u64);
			tracing::info!("after record");
		});
		assert_eq!(lines.len(), 2, "{lines:?}");

		assert!(lines[0].get("user_agent").is_none(), "{}", lines[0]);
		assert!(lines[0].get("pver").is_none(), "{}", lines[0]);
		assert_eq!(lines[1]["user_agent"], serde_json::json!("bark-wasm/1.0"));
		assert_eq!(lines[1]["pver"], serde_json::json!(4));
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

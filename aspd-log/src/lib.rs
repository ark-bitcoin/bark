
#[macro_use] extern crate serde;

mod msgs;
pub use crate::msgs::*;


use serde::de::DeserializeOwned;
use serde::ser::{Serialize, SerializeMap, Serializer};


/// The "target" field used for structured logging.
pub const SLOG_TARGET: &str = "aspd-slog";

const LOGID_FIELD: &str = "logid";

pub trait LogMsg: Sized + Send + Serialize + DeserializeOwned + 'static {
	const LOGID: &'static str;
	const LEVEL: log::Level;

	fn from_source<'a>(s: &'a dyn log::kv::Source) -> Result<Self, log::kv::Error>;
}

pub fn log(
	obj: &dyn log::kv::Source,
	level: log::Level,
	file: &str,
	line: u32,
) {
	let record = log::Record::builder()
		.level(level)
		.target("aspd-slog")
		.file(Some(file))
		.line(Some(line))
		.key_values(obj)
		.build();
	log::logger().log(&record);
}

#[macro_export]
macro_rules! filename {
    () => (file!().rsplit("aspd/").next().unwrap())
}

#[macro_export]
macro_rules! slog {
    ($struct:ident) => {{
		if log::log_enabled!(<$crate::$struct as $crate::LogMsg>::LEVEL) {
			$crate::log(
				&$crate::$struct {},
				<$crate::$struct as $crate::LogMsg>::LEVEL,
				$crate::filename!(),
				line!(),
			);
		}
    }};
    ($struct:ident, $( $args:tt )*) => {{
		if log::log_enabled!(<$crate::$struct as $crate::LogMsg>::LEVEL) {
			$crate::log(
				&$crate::$struct { $( $args )* },
				<$crate::$struct as $crate::LogMsg>::LEVEL,
				$crate::filename!(),
				line!(),
			);
		}
    }};
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
pub struct RecordSerializeWrapper<'a>(pub &'a log::Record<'a>);

impl<'a> Serialize for RecordSerializeWrapper<'a> {
	fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
		let mut m = s.serialize_map(None)?;
		m.serialize_entry("msg", self.0.args())?;
		m.serialize_entry("level", &self.0.level())?;
		m.serialize_entry("target", self.0.target())?;
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
		let id = kv.get(LOGID_FIELD.into()).and_then(|v| v.to_borrowed_str()).unwrap_or("");
		m.serialize_entry("id", id)?;
		if kv.count() > 0 {
			m.serialize_entry("kv", &SourceSerializeWrapper(kv))?;
		}
		m.end()
	}
}

#[derive(Debug)]
pub enum RecordParseError {
	WrongType,
	Json(serde_json::Error),
}

#[derive(Debug, Deserialize)]
pub struct ParsedRecord<'a> {
	pub msg: &'a str,
	pub level: log::Level,
	pub target: &'a str,
	pub module: Option<&'a str>,
	pub file: Option<&'a str>,
	pub line: Option<u32>,
	// structured stuff
	pub id: &'a str,
	pub kv: Option<&'a serde_json::value::RawValue>,
}

impl<'a> ParsedRecord<'a> {
	/// Check whether this log message if of the given structure log type.
	pub fn is<T: LogMsg>(&self) -> bool {
		T::LOGID == self.id
	}

	/// Try to parse the log message into the given structured log type.
	pub fn try_as<T: LogMsg>(&self) -> Result<T, RecordParseError> {
		if self.id != T::LOGID {
			return Err(RecordParseError::WrongType);
		}

		Ok(serde_json::from_str(self.kv.map(|v| v.get()).unwrap_or(""))
			.map_err(RecordParseError::Json)?)
	}
}

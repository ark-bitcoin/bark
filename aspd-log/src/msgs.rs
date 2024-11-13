
//! In this module, we define all our log messages.
//!
//! TODO(stevenroose) ideally we'd do this a bit more efficiently
//! I'd like to improve to
//! - have the struct definitions be independent, so we can easily add docs
//! - let the macro just do the impls
//! - somehow build a wrapper that uses serde to be a `Source` and use serde also
//!   to deserialize from the log message

use serde::{Deserialize, Serialize};

macro_rules! logmsg {
	($name:ident, $lvl:ident $(, $field:ident: $tp:ty)*) => {

		#[derive(Debug, Clone, Serialize, Deserialize)]
		pub struct $name {
			$(
				pub $field: $tp,
			)*
		}

		impl $crate::LogMsg for $name {
			//TODO(stevenroose) consider not using the struct name but something static
			const LOGID: &'static str = stringify!($name);
			const LEVEL: log::Level = log::Level::$lvl;

			fn from_source<'a>(s: &'a dyn log::kv::Source) -> Result<$name, log::kv::Error> {
				Ok($name {
					$(
						$field: s.get(stringify!($field).into())
							.ok_or_else(|| log::kv::Error::msg(stringify!(missing field $field)))?
							.to_string() //TODO(stevenroose) optimize
							.parse()
							.map_err(|e| log::kv::Error::boxed(e))?,
					)*
				})
			}
		}

		impl log::kv::Source for $name {
			fn visit<'a>(
				&'a self,
				visitor: &mut dyn log::kv::VisitSource<'a>,
			) -> Result<(), log::kv::Error> {
				visitor.visit_pair(
					$crate::LOGID_FIELD.into(),
					<$name as $crate::LogMsg>::LOGID.into(),
				)?;

				$(
					visitor.visit_pair(
						stringify!($field).into(),
						log::kv::Value::from_display(&self.$field),
					)?;
				)*

				Ok(())
			}
		}
	};
}

logmsg!(RoundStarted, Info, round_id: u64);



#[macro_export]
macro_rules! impl_slog {
	($name:ident, $lvl:ident, $msg:expr $(,)?) => {
		impl $crate::LogMsg for $name {
			const LOGID: &'static str = stringify!($name);
			const LEVEL: tracing::Level = tracing::Level::$lvl;
			const MSG: &'static str = $msg;
		}
	};
}

#[macro_export]
macro_rules! slog {
	($struct:ident) => {{
		tracing::event!(
			target: $crate::SLOG_TARGET,
			<$crate::$struct as $crate::LogMsg>::LEVEL,
			{
				slog_id = <$crate::$struct as $crate::LogMsg>::LOGID
			},
			"{}",
			<$crate::$struct as $crate::LogMsg>::MSG
		);
	}};
	($struct:ident, $($args:tt)+) => {{
		let temp = $crate::$struct { $($args)* };
		let data_json = serde_json::to_string(&temp)
			.unwrap_or_else(|_| "json serialization error".into());
		tracing::event!(
			target: $crate::SLOG_TARGET,
			<$crate::$struct as $crate::LogMsg>::LEVEL,
			{
				slog_id = <$crate::$struct as $crate::LogMsg>::LOGID,
				slog_data_json = data_json
			},
			"{}",
			<$crate::$struct as $crate::LogMsg>::MSG
		);
	}};
}
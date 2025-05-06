

#[macro_export]
macro_rules! impl_slog {
	($name:ident, $lvl:ident, $msg:expr) => {
		impl $crate::LogMsg for $name {
			//TODO(stevenroose) consider not using the struct name but something static
			const LOGID: &'static str = stringify!($name);
			const LEVEL: log::Level = log::Level::$lvl;
			const MSG: &'static str = $msg;
		}
	};
}

#[macro_export]
macro_rules! filename {
	() => (file!().rsplit("bark/").next().unwrap())
}

#[macro_export]
macro_rules! slog {
	($struct:ident) => {{
		if log::log_enabled!(<$crate::$struct as $crate::LogMsg>::LEVEL) {
			$crate::log(
				&$crate::$struct {},
				module_path!(),
				$crate::filename!(),
				line!(),
				$crate::get_trace_id(),
			);
		}
	}};
	($struct:ident, $( $args:tt )*) => {{
		if log::log_enabled!(<$crate::$struct as $crate::LogMsg>::LEVEL) {
			$crate::log(
				&$crate::$struct { $( $args )* },
				module_path!(),
				$crate::filename!(),
				line!(),
				$crate::get_trace_id(),
			);
		}
	}};
}


#[cfg(not(feature = "wasm-web"))]
pub fn timestamp_secs() -> u64 {
	std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.expect("time went backwards")
		.as_secs()
}

#[cfg(feature = "wasm-web")]
pub fn timestamp_secs() -> u64 {
	(js_sys::Date::now() as u64) / 1_000
}

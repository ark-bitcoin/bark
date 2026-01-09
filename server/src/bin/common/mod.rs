
pub fn set_panic_hook() {
	// Set a custom panic hook to make sure we print stack traces
	// when one of our background processes panic.
	std::panic::set_hook(Box::new(|panic_info| {
		let backtrace = std::backtrace::Backtrace::force_capture();
		eprintln!("Panic occurred: {}\n\nBacktrace:\n{}", panic_info, backtrace);
	}));
}

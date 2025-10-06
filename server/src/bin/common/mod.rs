
use std::io::Write;


pub fn init_logging() {
	let env = env_logger::Env::new().filter("CAPTAIND_LOG");

	env_logger::Builder::new()
		.filter_level(log::LevelFilter::Trace)
		.filter_module("rustls", log::LevelFilter::Warn)
		.filter_module("bitcoincore_rpc", log::LevelFilter::Warn)
		.filter_module("tokio_postgres", log::LevelFilter::Info)
		.parse_env(env)
		.format(|mut out, rec| {
			let ts = chrono::Local::now();
			server_log::encode_record(&mut out, ts, rec)?;
			out.write_all(&[b'\n'])
		})
		.target(env_logger::Target::Stdout)
		.init();
}

pub fn set_panic_hook() {
	// Set a custom panic hook to make sure we print stack traces
	// when one of our background processes panic.
	std::panic::set_hook(Box::new(|panic_info| {
		let backtrace = std::backtrace::Backtrace::force_capture();
		eprintln!("Panic occurred: {}\n\nBacktrace:\n{}", panic_info, backtrace);
	}));
}

use rand::RngCore;

pub fn random_string() -> String {
	// Generate a few random bytes and base58 encode them
	// The entropy should be sufficient to generate unique test-names
	let mut entropy :[u8; 8] = [0; 8];
	rand::thread_rng().fill_bytes(&mut entropy);
	bitcoin::base58::encode(&entropy)
}

pub fn init_logging() -> anyhow::Result<()> {
	// We ignore the output
	// An error is returned if the logger is initiated twice
	// Note, that every test tries to initiate the logger
	let _ = fern::Dispatch::new()
		.format(|out, msg, rec| {
			let now = chrono::Local::now();
			let stamp = now.format("%H:%M:%S.%3f");
			out.finish(format_args!("[{} {: >5}] {}", stamp, rec.level(), msg))
		})
		.level(log::LevelFilter::Trace)
		.chain(std::io::stdout())
		.apply();
	Ok(())
}

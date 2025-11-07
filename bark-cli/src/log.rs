
use std::{cmp, process};
use std::io::Write;
use std::path::Path;

/// Simple logger that splits into two logger
struct SplitLogger {
	log1: env_logger::Logger,
	log2: env_logger::Logger,
}

impl SplitLogger {
	fn init(log1: env_logger::Logger, log2: env_logger::Logger) {
		let max_level = cmp::max(log1.filter(), log2.filter());
		log::set_boxed_logger(Box::new(SplitLogger {
			log1: log1,
			log2: log2,
		})).expect("error initializing split logger");
		log::set_max_level(max_level);
	}
}

impl log::Log for SplitLogger {
	fn enabled(&self, m: &log::Metadata) -> bool {
	    self.log1.enabled(m) || self.log2.enabled(m)
	}

	fn flush(&self) {
	    self.log1.flush();
		self.log2.flush();
	}

	fn log(&self, rec: &log::Record) {
		self.log1.log(rec);
		self.log2.log(rec);
	}
}

pub fn init_logging(verbose: bool, quiet: bool, datadir: &Path) {
	if verbose && quiet {
		println!("Can't set both --verbose and --quiet");
		process::exit(1);
	}

	let env = env_logger::Env::new().filter("BARK_LOG");

	// Builder has no clone and we don't want to repeat this
	fn base() -> env_logger::Builder {
		let mut builder = env_logger::Builder::new();
		builder
			.filter_module("rusqlite", log::LevelFilter::Warn)
			.filter_module("rustls", log::LevelFilter::Warn)
			.filter_module("reqwest", log::LevelFilter::Warn);
		builder
	}

	let terminal = if !quiet {
		let mut logger = base();

		// We first set the default and then let the env_logger
		// env overwrite it.
		logger.filter_level(if verbose {
			log::LevelFilter::Trace
		} else {
			log::LevelFilter::Info
		});

		logger.parse_env(env)
			.format(move |out, rec| {
				let now = chrono::Local::now();
				let ts = now.format("%Y-%m-%d %H:%M:%S.%3f");
				let lvl = rec.level();
				let msg = rec.args();
				if verbose {
					let module = rec.module_path().expect("no module");
					if module.starts_with("bark") {
						let file = rec.file().expect("our macro provides file");
						let file = file.split("bark/src/").last().unwrap();
						let line = rec.line().expect("our macro provides line");
						writeln!(out, "[{ts} {lvl: >5} {module} {file}:{line}] {msg}")
					} else {
						writeln!(out, "[{ts} {lvl: >5} {module}] {msg}")
					}
				} else {
					writeln!(out, "[{ts} {lvl: >5}] {msg}")
				}
			})
			.target(env_logger::Target::Stderr);
		Some(logger)
	} else {
		None
	};

	let logfile = if datadir.exists() {
		let path = datadir.join("debug.log");
		match std::fs::File::options().create(true).append(true).open(path) {
			Ok(mut file) => {
				// try write a newline into the file to separate commands
				let _ = file.write_all("\n\n".as_bytes());
				let mut logger = base();
				logger
					.filter_level(log::LevelFilter::Trace)
					.format_timestamp_millis()
					.format_module_path(true)
					.format_file(true)
					.format_line_number(true)
					.target(env_logger::Target::Pipe(Box::new(file)));
				Some(logger)
			},
			Err(e) => {
				eprintln!("Failed to open debug.log file: {:#}", e);
				None
			},
		}
	} else {
		None
	};

	match (terminal, logfile) {
		(Some(mut l1), Some(mut l2)) => SplitLogger::init(l1.build(), l2.build()),
		(Some(mut l), None) => l.init(),
		(None, Some(mut l)) => l.init(),
		(None, None) => {},
	}
}

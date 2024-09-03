
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;

use crate::daemon::LogHandler;

#[derive(Debug)]
pub struct FileLogger {
	path: PathBuf,
	file: Option<File>
}

impl FileLogger {
	pub fn new(path: PathBuf) -> Self {
		Self { path, file: None }
	}
}

impl LogHandler for FileLogger {
	fn process_log(&mut self, line: &str) {
		// Create the file if it doesn't exist yet
		if self.file.is_none() {
			let file = OpenOptions::new()
				.create_new(true)
				.append(true)
				.open(&self.path).unwrap();
			self.file = Some(file);
		}

		let file = self.file.as_mut().unwrap();
		match writeln!(file, "{}", line) {
			Ok(()) => {},
			Err(_) => error!("Failed to write to lig-file")
		}
	}
}

use std::env;
use std::path::PathBuf;
use std::process::Command;

use which::which;

use crate::constants::env::LIGHTNINGD_EXEC;

struct Lightningd;

impl Lightningd {

	pub fn exec() -> PathBuf {
		if let Ok(e) = std::env::var(&LIGHTNINGD_EXEC) {
			e.into()
		} else if let Ok(e) = which::which("lightningd") {
			e.into()
		} else {
			panic!("LIGHTNIGND_EXEC env not set")
		}
	}
}

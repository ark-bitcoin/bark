use std::env;
use std::process::Command;

use which::which;

use crate::constants::env::LIGHTNINGD_EXE;

pub fn get_lightningd_base_cmd() -> anyhow::Result<Command> {
	match env::var(LIGHTNINGD_EXE) {
		Ok(lightningd_exe) => {
			let lightningd_exe = which(lightningd_exe).expect("Failed to find `lightingd` in `LIGHTNINGD_EXE`");
			Ok(Command::new(lightningd_exe))
		},
		Err(env::VarError::NotPresent) => {
			let lightningd_exe = which("lightningd").expect("Failed to find `lightnignd`");
			let cmd = Command::new(lightningd_exe);
			Ok(cmd)
		},
		Err(_) => panic!("Failed to read `LIGHTNIGND_EXE`"),
	}
}

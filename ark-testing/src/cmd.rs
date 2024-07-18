use std::process::Command;

#[derive(Debug, Clone)]
pub struct BaseCommand {
	exe_path: String,
	default_args: Vec<String>
}

impl BaseCommand {

	pub fn new(exe_path: String, default_args: Vec<String>) -> Self {
		Self { exe_path, default_args}
	}

	pub fn get_cmd(&self) -> std::process::Command {
		let mut cmd = Command::new(self.exe_path.clone());
		cmd.args(&self.default_args);
		cmd
	}
}

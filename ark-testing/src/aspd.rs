use std::borrow::Borrow;
use std::env::VarError;
use std::process::Command;

use std::fmt;
use std::fs;
use std::fs::create_dir_all;
use std::sync::{Arc, Mutex};
use std::path::PathBuf;
use std::io::prelude::*;

use anyhow::Result;

use crate::cmd::BaseCommand;
use crate::constants::env::ASPD_EXEC;
use crate::error::Error;
use crate::runner::{RuntimeData, RunnerHelper, DaemonRunner};

pub fn get_base_cmd() -> anyhow::Result<BaseCommand> {
	match std::env::var(ASPD_EXEC) {
		Ok(var) => {
			Ok(BaseCommand::new(var, vec![]))
		},
		Err(VarError::NotPresent) => {
			let cmd = BaseCommand::new(
				"cargo".to_string(),
				["run", "--package", "bark-aspd", "--"]
				.iter()
				.map(|x| x.to_string())
				.collect()
			);
			Ok(cmd)
		},
		Err(VarError::NotUnicode(_)) => {
			Err(anyhow::anyhow!("{} is not valid unicode", ASPD_EXEC))
		}
	}
}

pub struct AspD {
	name: String,
	arkd_cmd: BaseCommand,
	datadir: PathBuf,
	bitcoind_cookie: PathBuf,
	bitcoind_url: String,
	network: bitcoin::Network,
	runtime_data: Option<Arc<Mutex<RuntimeData<State>>>>
}

impl AspD {

	pub fn new<B>(name: String, arkd_cmd: BaseCommand, datadir: PathBuf, bitcoind: B) -> Self 
		where B : Borrow<bitcoind::BitcoinD>
	{
		Self {
			name,
			arkd_cmd,
			datadir,
			bitcoind_cookie: bitcoind.borrow().params.cookie_file.clone(),
			bitcoind_url: bitcoind.borrow().params.rpc_socket.to_string(),
			network: bitcoin::Network::Regtest,
			runtime_data: None,
		}
	}
}

impl fmt::Debug for AspD {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		write!(f, "{:?} --datadir {:?}", self.arkd_cmd, self.datadir)
	}
}

#[derive(Debug)]
pub struct State{
	stdout: Option<fs::File>,
	stderr: Option<fs::File>
}

impl State {

	fn process_stdout(&mut self, name: &str, line: &str) {
		match &mut self.stdout {
			Some(file) => { 
				let _ = write!(file, "{} - {}\n", name, line);},
			_ => {}
		}
	}

	fn process_stderr(&mut self, line: &str) {
		match &mut self.stderr {
			Some(file) => {
				let _ = write!(file, "{}\n", line);
			},
			None => {}
		}
	}
}

impl RunnerHelper for AspD {
	type State = State;

	fn _prepare(&mut self) -> Result<(), Error> {
		trace!("_prepare {}", self.name);
		create_dir_all(self.datadir.clone()).unwrap();

		// Create and initialize the datadir
		let network = self.network.to_string();
		let mut cmd = self.arkd_cmd.get_cmd();
		cmd
			.arg("create")
			.arg("--datadir")
			.arg(self.datadir.clone())
			.arg("--bitcoind-url")
			.arg(self.bitcoind_url.clone())
			.arg("--bitcoind-cookie")
			.arg(self.bitcoind_cookie.clone())
			.arg("--network")
			.arg(network);

		let output = cmd.output()?;
		if output.status.success() {
			info!("Created {}", self.name)
		}
		else {
			error!("Created arkd with stderr: {}", std::str::from_utf8(&output.stderr).unwrap());
			panic!("Failed to create {}", self.name)
		}

		Ok(())
	}

	fn _command(&self) -> Command {
		let mut command = self.arkd_cmd.get_cmd();
		command
			.arg("start")
			.arg("--datadir")
			.arg(self.datadir.clone());

		command
	}


	fn _process_stdout(name: &str, state: &mut Self::State, line: &str) {
		state.process_stdout(name, line);
	}


	fn _process_stderr(state: &mut Self::State, line: &str) {
		state.process_stderr(line);
	}

	fn _init_state(&self) -> Self::State {
		// Create the log-files
		let stdout = fs::OpenOptions::new()
			.append(true)
			.create(true)
			.open(self.datadir.join("stdout.log")).unwrap();

		let stderr = fs::OpenOptions::new()
			.append(true)
			.create(true)
			.open(self.datadir.join("stderr.log")).unwrap();


		Self::State { 
			stdout: Some(stdout),
			stderr: Some(stderr)
		}
	}

	fn _get_runtime(&self) -> Option<Arc<Mutex<RuntimeData<Self::State>>>>	{
		self.runtime_data.clone()
	}

	fn _notif_started(&mut self, runtime_data: Arc<Mutex<RuntimeData<Self::State>>>) {
		self.runtime_data.replace(runtime_data);
	}
}

impl DaemonRunner for AspD {

}

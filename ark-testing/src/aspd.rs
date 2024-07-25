use anyhow::Context;

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

	pub fn client_rpc_port(&self) -> anyhow::Result<u16> {
		match &self.runtime_data {
			Some(data) => {
				let mutex = data.lock().expect("We can acquire the lock");
				return mutex.state.client_rpc_port.context("aspd has no client port yet. Is it running?")
			},
			None => { panic!("Server not yet started!"); }
		}
	}


	pub fn admin_rpc_port(&self) -> anyhow::Result<u16> {
		match &self.runtime_data {
			Some(data) => {
				let mutex = data.lock().expect("We can acquire the lock");
				return mutex.state.admin_rpc_port.context("aspd has no admin rpc port yet. Is it running?")
			},
			None => { panic!("Server not yet started!"); }
		}
	}

	pub fn run_cmd_with_args(&self, args: &[&str]) -> anyhow::Result<String>
	{
		let mut cmd = self.arkd_cmd.get_cmd();
		cmd
			.arg("--datadir")
			.arg(self.datadir.clone())
			.args(args);

		trace!("Executing {:?}", &cmd);

		let result = cmd.output().with_context(|| format!("Failed to execute {:?}", cmd))?;

		// TODO: ensure you write the full command, stdout, stderr to the directory
		// This makes debuggin a lot easier
		let stdout_str = String::from_utf8(result.stdout)?;
		let stderr_str = String::from_utf8(result.stderr)?;

		if result.status.success() {
			Ok(stdout_str)
		}
		else {
			// Ensure we print the logs
			error!("{}", stderr_str);
			error!("{}", stdout_str);
			return Err(anyhow::anyhow!("Command failed to execute"))
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
	client_rpc_port: Option<u16>,
	admin_rpc_port: Option<u16>,
	stdout: Option<fs::File>,
	stderr: Option<fs::File>
}

impl State {

	fn process_stdout(&mut self, name: &str, line: &str) {
		if let Some(file) = &mut self.stdout {
			let _ = writeln!(file, "{} - {}", name, line);
		};
	}

	fn process_stderr(&mut self, line: &str) {
		if let Some(file) = &mut self.stderr {
			let _ = writeln!(file, "{}", line);
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
			error!("Failed to create arkd with stderr: {}", std::str::from_utf8(&output.stderr).unwrap());
			panic!("Failed to create {}", self.name)
		}

		Ok(())
	}

	fn _command(&self) -> Command {
		// TODO: Pick a port and perform retries
		let locked_data = self.runtime_data.clone().unwrap();
		let mut data = locked_data.lock().unwrap();

		let client_rpc_port = portpicker::pick_unused_port().expect("No port free");
		let admin_rpc_port = portpicker::pick_unused_port().expect("No port free");

		data.state.client_rpc_port = Some(client_rpc_port);
		data.state.admin_rpc_port = Some(admin_rpc_port);

		let client_rpc_address = format!("0.0.0.0:{}", client_rpc_port);
		let admin_rpc_address = format!("127.0.0.1:{}", admin_rpc_port);

		// Update the configuration and use the port
		self.run_cmd_with_args(
			&["set-config", "--public-rpc-address", &client_rpc_address, "--admin-rpc-address", &admin_rpc_address]
		).expect("set-config should be able to set a port");

		let mut cmd = self.arkd_cmd.get_cmd();
		cmd
			.arg("--datadir")
			.arg(self.datadir.clone())
			.arg("start");

		cmd
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
			stderr: Some(stderr),
			admin_rpc_port: None,
			client_rpc_port: None
		}
	}


	fn _notif_starting(&mut self, runtime_data: Arc<Mutex<RuntimeData<Self::State>>>) {
		trace!("I've replaced the init");
		self.runtime_data.replace(runtime_data);
	}

	fn _get_runtime(&self) -> Option<Arc<Mutex<RuntimeData<State>>>> {
		self.runtime_data.clone()
	}
}

impl DaemonRunner for AspD {

}

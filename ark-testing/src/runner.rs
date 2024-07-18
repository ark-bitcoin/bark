use std::io::BufRead;
use std::sync::{Arc, Mutex};
use std::{fmt, io, ops, process, thread, time};

use crate::error::Error;

/// An wrapper for child that is killed when it's dropped.
struct KillOnDropChild(process::Child);

impl KillOnDropChild {
	pub fn get(&self) -> &process::Child {
		&self.0
	}
	pub fn get_mut(&mut self) -> &mut process::Child {
		&mut self.0
	}
}

impl ops::Drop for KillOnDropChild {
	fn drop(&mut self) {
		// We don't care about the error here because we probably
		// already safely stopped the process.
		let _ = self.0.kill();
	}
}

pub struct RuntimeData<S> {
	pub state: S,

	process: Option<KillOnDropChild>,
	stdout_thread: Option<thread::JoinHandle<()>>,
	stderr_thread: Option<thread::JoinHandle<()>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
	Init,
	Running,
	Stopped(process::ExitStatus),
}

/// Methods in this trait are intended to be used only
/// by the [DaemonRunner] implementation.
#[doc(hidden)]
pub trait RunnerHelper {
	type State;

	/// Prepare the daemon for running.
	///
	/// This is called before the [_init_state] method is called.
	fn _prepare(&mut self) -> Result<(), Error>;

	/// The command to run.
	fn _command(&self) -> process::Command;

	/// Create the initial state.
	///
	/// This is called after the [_prepare] method is called.
	fn _init_state(&self) -> Self::State;

	/// Notify that the daemon has started.
	fn _notif_started(&mut self, runtime_data: Arc<Mutex<RuntimeData<Self::State>>>);

	/// Get the current runtime data.
	fn _get_runtime(&self) -> Option<Arc<Mutex<RuntimeData<Self::State>>>>;

	/// Process some lines of stdout output.
	/// All lines not processed will be discarded.
	fn _process_stdout(name: &str, state: &mut Self::State, line: &str);

	/// Process some lines of stderr output.
	/// All lines not processed will be discarded.
	fn _process_stderr(state: &mut Self::State, line: &str);
}

pub trait DaemonRunner: RunnerHelper + fmt::Debug + Sized
where
	<Self as RunnerHelper>::State: 'static + Send,
{
	/// The actual startup function.
	/// This intended for internal use only, use [start] and [restart] instead.
	fn _start_up(&self, rt: Arc<Mutex<RuntimeData<Self::State>>>) -> Result<(), Error> {
		info!("Starting daemon {:?}...", self);

		let mut cmd = self._command();
		cmd.stdout(process::Stdio::piped());
		cmd.stderr(process::Stdio::piped());
		debug!("Launching daemon {:?} with command: {:?}", self, cmd);
		let mut process = KillOnDropChild(cmd.spawn().map_err(|e| Error::RunCommand(e, cmd))?);
		let pid = process.get().id();

		let stdout = process.0.stdout.take().unwrap();
		let stderr = process.0.stderr.take().unwrap();

		let mut rt_lock = rt.lock().unwrap();
		rt_lock.process = Some(process);

		// Start stdout processing thread.
		let rt_cloned = rt.clone();
		rt_lock.stdout_thread.replace(
			thread::Builder::new()
				.name(format!("{:?}_stdout", self))
				.spawn(move || {
					thread::sleep(time::Duration::from_secs(1));
					let buf_read = io::BufReader::new(stdout);
					for line in buf_read.lines() {
						Self::_process_stdout(
							thread::current().name().unwrap(),
							&mut rt_cloned.lock().unwrap().state,
							&line.unwrap(),
						);
					}
					trace!("Thread {} stopped", thread::current().name().unwrap());
				})
				.expect(&format!("failed to start stdout read thread")),
		);

		// Start stderr processing thread.
		let rt_cloned = rt.clone();
		rt_lock.stderr_thread.replace(
			thread::Builder::new()
				.name(format!("{:?}_stderr", self))
				.spawn(move || {
					thread::sleep(time::Duration::from_secs(1));
					let buf_read = io::BufReader::new(stderr);
					for line in buf_read.lines() {
						Self::_process_stderr(&mut rt_cloned.lock().unwrap().state, &line.unwrap());
					}
					trace!("Thread {} stopped", thread::current().name().unwrap());
				})
				.expect(&format!("failed to start stderr read thread")),
		);

		info!("Daemon {:?} started. PID: {}", self, pid);
		Ok(())
	}

	/// Start the daemon for the first time.
	///
	/// If the daemon was previously stopped, this method simply restarts it.
	fn start(&mut self) -> Result<(), Error> {
		match self.status()? {
			Status::Running => return Ok(()), // already running
			Status::Stopped(_) => {
				// Simply restart.
				return self._start_up(self._get_runtime().unwrap());
			}
			Status::Init => {} // fall through
		}

		self._prepare()?;

		let rt = Arc::new(Mutex::new(RuntimeData {
			process: None,
			stdout_thread: None,
			stderr_thread: None,
			state: self._init_state(),
		}));

		self._start_up(rt.clone())?;
		self._notif_started(rt);
		Ok(())
	}

	/// Stop the daemon.
	/// State is preserved so that it can be restarted with [restart].
	/// If the daemon already stopped, this is a no-op.
	fn stop(&self) -> Result<(), Error> {
		match self.status()? {
			Status::Init => return Err(Error::InvalidState(Status::Init)),
			Status::Running => {}
			Status::Stopped(_) => return Ok(()),
		}

		let rt_ref = self._get_runtime().unwrap();
		let mut rt = rt_ref.lock().unwrap();

		info!("Stopping daemon {:?}...", self);
		let proc = rt.process.as_mut().unwrap().get_mut();
		proc.kill()?;
		proc.wait()?;

		info!("Daemon {:?} stopped", self);
		Ok(())
	}

	/// The the running status of the daemon.
	fn status(&self) -> Result<Status, Error> {
		let rt = match self._get_runtime() {
			Some(rt) => rt,
			None => return Ok(Status::Init),
		};

		let mut lock = rt.lock().unwrap();
		match lock.process.as_mut().unwrap().0.try_wait()? {
			None => Ok(Status::Running),
			Some(c) => Ok(Status::Stopped(c)),
		}
	}

	/// Get the OS process ID of the daemon.
	fn pid(&self) -> Option<u32> {
		self._get_runtime().map(|rt| rt.lock().unwrap().process.as_ref().unwrap().get().id())
	}

	//TODO(stevenroose) try make a generic method
	// fn state(&self) -> Option<XXX> where XXX has Deref<Self::State> somehow
}

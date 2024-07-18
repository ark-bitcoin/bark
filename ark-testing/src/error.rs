use std::{error, fmt, io, process};

#[derive(Debug)]
pub enum Error {
	/// An I/O error.
	Io(io::Error),
	/// Invalid configuration provided.
	Config(&'static str),
	/// A Bitcoin Core RPC error.
	/// Any other error.
	Custom(&'static str),
	/// The daemon is not in the appropriate state for this action.
	InvalidState(crate::runner::Status),
	/// Error running a command.
	RunCommand(io::Error, process::Command),
}

impl From<io::Error> for Error {
	fn from(e: io::Error) -> Error {
		Error::Io(e)
	}
}

impl fmt::Display for Error {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		fmt::Debug::fmt(self, f)
	}
}

impl error::Error for Error {
	fn source(&self) -> Option<&(dyn error::Error + 'static)> {
		match *self {
			Error::Io(ref e) => Some(e),
			Error::RunCommand(ref e, ..) => Some(e),
			Error::Config(_) | Error::Custom(_) | Error::InvalidState(_) => None,
		}
	}
}

use std::fmt;
use std::str::FromStr;

const UNREGISTERED_BOARD : &'static str = "UnregisteredBoard";
const READY: &'static str = "Ready";
const SPENT: &'static str = "Spent";

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum VtxoState {
	Ready,
	Spent,
	UnregisteredBoard,
}

impl fmt::Display for VtxoState {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		write!(f, "{}", self.as_str())
	}
}

impl FromStr for VtxoState {

	type Err = anyhow::Error;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		match s {
			UNREGISTERED_BOARD => Ok(VtxoState::UnregisteredBoard),
			READY => Ok(VtxoState::Ready),
			SPENT => Ok(VtxoState::Spent),
			_ => bail!("Invalid VtxoState: {}", s)
		}
	}
}

impl VtxoState {
	pub fn as_str(&self) -> &str {
		match self {
			Self::UnregisteredBoard => UNREGISTERED_BOARD,
			Self::Ready => READY,
			Self::Spent => SPENT,
		}
	}
}

#[cfg(test)]
mod test {
	use super::*;

	#[test]
	fn convert_vtxo_state_and_back() {
		// From str to vtxostate
		assert_eq!(VtxoState::from_str("Ready").unwrap(), VtxoState::Ready);
		assert_eq!(VtxoState::from_str("Spent").unwrap(), VtxoState::Spent);
		assert_eq!(VtxoState::from_str("UnregisteredBoard").unwrap(), VtxoState::UnregisteredBoard);

		// From VtxoState to str
		assert_eq!(VtxoState::Ready.as_str(), "Ready");
		assert_eq!(VtxoState::Spent.as_str(), "Spent");
		assert_eq!(VtxoState::UnregisteredBoard.as_str(), "UnregisteredBoard");

		// If a compiler error occurs,
		// This is a reminder that you should update the test above
		match VtxoState::Spent {
			VtxoState::Ready => {},
			VtxoState::Spent => {},
			VtxoState::UnregisteredBoard => (),
		}
	}
}

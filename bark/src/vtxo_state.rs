use std::fmt;
use std::str::FromStr;

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum VtxoState {
	Ready,
	Spent
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
			"Ready" => Ok(VtxoState::Ready),
			"Spent" => Ok(VtxoState::Spent),
			_ => bail!("Invalid VtxoState: {}", s)
		}
	}
}

impl VtxoState {
	pub fn as_str(&self) -> &str {
		match self {
			Self::Ready => "Ready",
			Self::Spent => "Spent"
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

		// From VtxoState to str
		assert_eq!(VtxoState::Ready.as_str(), "Ready");
		assert_eq!(VtxoState::Spent.as_str(), "Spent");

		// If a compiler error occurs,
		// TThis is a reminder that you should update the test above
		match VtxoState::Spent {
			VtxoState::Ready => {},
			VtxoState::Spent => {}
		}
	}
}

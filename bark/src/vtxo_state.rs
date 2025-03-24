use std::fmt;
use std::str::FromStr;

const SPENDABLE: &'static str = "Spendable";
const UNREGISTERED_BOARD : &'static str = "UnregisteredBoard";
const SPENT: &'static str = "Spent";

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum VtxoState {
	Spendable,
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
			SPENDABLE => Ok(VtxoState::Spendable),
			SPENT => Ok(VtxoState::Spent),
			_ => bail!("Invalid VtxoState: {}", s)
		}
	}
}

impl VtxoState {
	pub fn as_str(&self) -> &str {
		match self {
			Self::UnregisteredBoard => UNREGISTERED_BOARD,
			Self::Spendable => SPENDABLE,
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
		assert_eq!(VtxoState::from_str(SPENDABLE).unwrap(), VtxoState::Spendable);
		assert_eq!(VtxoState::from_str(SPENT).unwrap(), VtxoState::Spent);
		assert_eq!(VtxoState::from_str(UNREGISTERED_BOARD).unwrap(), VtxoState::UnregisteredBoard);

		// From VtxoState to str
		assert_eq!(VtxoState::Spendable.as_str(), SPENDABLE);
		assert_eq!(VtxoState::Spent.as_str(), SPENT);
		assert_eq!(VtxoState::UnregisteredBoard.as_str(), UNREGISTERED_BOARD);

		// If a compiler error occurs,
		// This is a reminder that you should update the test above
		match VtxoState::Spent {
			VtxoState::Spendable => {},
			VtxoState::Spent => {},
			VtxoState::UnregisteredBoard => (),
		}
	}

	#[test]
	fn convert_serialize() {
		let states = [VtxoState::Spendable, VtxoState::Spent, VtxoState::UnregisteredBoard];

		assert_eq!(
			serde_json::to_string(&states).unwrap(),
			serde_json::to_string(&[SPENDABLE, SPENT, UNREGISTERED_BOARD]).unwrap(),
		);

		// If a compiler error occurs,
		// This is a reminder that you should update the test above
		match VtxoState::Spent {
			VtxoState::Spendable => {},
			VtxoState::Spent => {},
			VtxoState::UnregisteredBoard => (),
		}
	}
}

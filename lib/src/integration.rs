
use std::fmt;
use std::str::FromStr;

// When adding token types don't forget to update `ParseTokenTypeError`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Hash, PartialEq, Eq)]
pub enum TokenType {
	SingleUseBoard,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid token type: Pick single-use-board")]
pub struct ParseTokenTypeError {
}

impl FromStr for TokenType {
	type Err = ParseTokenTypeError;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		match s {
			"single-use-board" => Ok(TokenType::SingleUseBoard),
			_ => Err(ParseTokenTypeError {}),
		}
	}
}

impl fmt::Display for TokenType {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			TokenType::SingleUseBoard => f.write_str("single-use-board"),
		}
	}
}


#[derive(Debug, Clone, Copy, Serialize, Deserialize, Hash, PartialEq, Eq)]
pub enum TokenStatus {
	Unused,
	Used,
	Abused,
	Disabled,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid token status")]
pub struct ParseTokenStatusError {
	pub msg: &'static str,
}

impl FromStr for TokenStatus {
	type Err = ParseTokenStatusError;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		match s {
			"unused" => Ok(TokenStatus::Unused),
			"used" => Ok(TokenStatus::Used),
			"abused" => Ok(TokenStatus::Abused),
			"disabled" => Ok(TokenStatus::Disabled),
			_ => Err(ParseTokenStatusError { msg: "invalid token status" }),
		}
	}
}

impl fmt::Display for TokenStatus {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			TokenStatus::Unused => f.write_str("unused"),
			TokenStatus::Used => f.write_str("used"),
			TokenStatus::Abused => f.write_str("abused"),
			TokenStatus::Disabled => f.write_str("disabled"),
		}
	}
}

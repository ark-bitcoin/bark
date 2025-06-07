use std::env::{self, VarError};

use crate::constants::env::TEST_POSTGRES_HOST;

pub fn postgres_host() -> Option<String> {
	match env::var(TEST_POSTGRES_HOST) {
		Ok(host) => Some(host),
		Err(VarError::NotPresent) => None,
		Err(VarError::NotUnicode(_)) => panic!("{} is not unicode", TEST_POSTGRES_HOST),
	}
}

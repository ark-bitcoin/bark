use std::env::VarError;

use crate::cmd::BaseCommand;
use crate::constants::env::ASPD_EXEC;

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

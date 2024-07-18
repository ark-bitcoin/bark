use std::env::VarError;

use crate::cmd::BaseCommand;
use crate::constants::env::BARK_EXEC;

pub fn get_base_cmd() -> anyhow::Result<BaseCommand> {
	match std::env::var(BARK_EXEC) {
		Ok(var) => {
			Ok(BaseCommand::new(var, vec![]))
		},
		Err(VarError::NotPresent) => {
			let cmd = BaseCommand::new(
				"cargo".to_string(),
				["run", "--package", "bark-client", "--"]
					.iter()
					.map(|x| x.to_string())
					.collect()
			);
			Ok(cmd)
		},
		Err(VarError::NotUnicode(_)) => {
			Err(anyhow::anyhow!("{} is not valid unicode", BARK_EXEC))
		}
	}
}

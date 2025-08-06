use std::fs;
use std::path::PathBuf;
use std::process;

use aspd::database::Db;

use ark_testing::postgres::PostgresDatabaseManager;

#[tokio::main]
async fn main() {
	let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));

	let tmp_pg_datadir = root.join("tmp-pg-data");
	if tmp_pg_datadir.exists() != false {
		fs::remove_dir_all(&tmp_pg_datadir).expect("failed to remove existing temporary db file");
	}

	let db_manager = PostgresDatabaseManager::init(tmp_pg_datadir.clone()).await;
	let db_config = db_manager.request_database("bark-server-schema-dump").await;

	Db::create(&db_config).await.expect("Can initialize database");

	let mut cmd = process::Command::new("pg_dump");
	cmd
		.arg("--host")
		.arg(db_config.host)
		.arg("--port")
		.arg(db_config.port.to_string())
		.arg("--dbname")
		.arg(db_config.name)
		.arg("--schema-only")
		.arg("--no-owner")
		.arg("--no-comments")
		.arg("--no-publications")
		.arg("--no-security-labels")
		.arg("--no-table-access-method")
		.arg("--no-tablespaces")
		// Do not prompt the password
		.arg("--no-password");


	if db_config.user.is_some() {
		cmd.arg("--username");
		cmd.arg(db_config.user.unwrap());
	}

	if db_config.password.is_some() {
		cmd.env("PGPASSWORD", db_config.password.unwrap());
	}

	let status = cmd
		.stdout(process::Stdio::inherit())
		.spawn().expect("Failed to spawn pg_dump")
		.wait().expect("Failed to wait for pgdump")
		.code().unwrap_or(1);

	// Clean the file
	if tmp_pg_datadir.exists() {
		fs::remove_dir_all(&tmp_pg_datadir).expect("failed to remove existing temporary db file");
	}

	process::exit(status);
}


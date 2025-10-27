use tokio_postgres::Client;

/// Drops a database if it exists
pub async fn drop_database(client: &Client, db_name: &str) {
	client.execute(&format!("DROP DATABASE IF EXISTS \"{}\"", db_name), &[]).await
		.expect(&format!("failed to drop database '{}'", db_name));
}

/// Creates a database
pub async fn create_database(client: &Client, db_name: &str) {
	client.execute(&format!("CREATE DATABASE \"{}\"", db_name), &[]).await
		.expect(&format!("failed to create database '{}'", db_name));
}

/// Drop and create a database
/// This ensures each test can run with an empty database
pub async fn drop_and_create_database(client: &Client, db_name: &str) {
	drop_database(client, db_name).await;
	create_database(client, db_name).await;
}

pub async fn enable_verbose_logging(client: &Client) {
	client.execute("ALTER SYSTEM SET log_statement = 'all';", &[]).await
		.expect("failed to enable verbose logging");
	client.execute("ALTER SYSTEM SET logging_collector = 'on';", &[]).await
		.expect("failed to enable logging collector");
	client.execute("ALTER SYSTEM SET log_destination = 'stderr';", &[]).await
		.expect("failed to enable logging destination");
	client.execute("SELECT pg_reload_conf();", &[]).await
		.expect("failed to reload configuration");
}

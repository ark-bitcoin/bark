use tokio_postgres::Client;

/// Drops a database if it exists
pub async fn drop_database(client: &Client, db_name: &str) {
	client.execute(&format!("DROP DATABASE IF EXISTS \"{}\"", db_name), &[]).await
		.expect("failed to drop db during cleanup");
}

/// Creates a database
pub async fn create_database(client: &Client, db_name: &str) {
	client.execute(&format!("CREATE DATABASE \"{}\"", db_name), &[]).await
		.expect("Failed to create database");
}

/// Drop and create a database
/// This ensures each test can run with an empty database
pub async fn drop_and_create_database(client: &Client, db_name: &str) {
	drop_database(client, db_name).await;
	create_database(client, db_name).await;
}

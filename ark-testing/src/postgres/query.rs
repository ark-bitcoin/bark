use tokio_postgres::Client;

/// Drops a database if it exists
pub async fn drop_database(client: &Client, db_name: &str) {
	client.execute(&format!("DROP DATABASE IF EXISTS \"{}\"", db_name), &[]).await
		.expect("failed to drop db during cleanup");
}

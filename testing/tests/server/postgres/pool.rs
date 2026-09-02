
use server::database::Db;

use ark_testing::TestContext;

/// The pool never re-grants a connection whose previous borrower left a
/// transaction open: the abandoned work is rolled back on checkout instead
/// of being committed by the next borrower.
#[tokio::test]
#[ignore = "fails until the pool clears inherited transactions on checkout"]
async fn checkout_clears_abandoned_transaction() {
	let mut ctx = TestContext::new_minimal("postgresd/pool/checkout_clears_abandoned_transaction").await;
	ctx.init_central_postgres().await;
	let mut postgres_cfg = ctx.new_postgres(&ctx.test_name).await;
	// One connection, so the poisoned session is the one granted next.
	postgres_cfg.max_connections = 1;
	Db::create(&postgres_cfg).await.expect("Database created");
	let db = Db::connect(&postgres_cfg).await.expect("Connected to database");

	db.write(async |t| {
		t.execute("CREATE TABLE poison (id INT)", &[]).await?;
		Ok(())
	}).await.expect("create table");

	// A future cancelled mid-transaction sends BEGIN but never constructs
	// the guard whose drop would roll back: the connection returns to the
	// pool with the insert pending inside an open transaction.
	let conn = db.raw_conn().await.expect("raw connection");
	conn.batch_execute("BEGIN; INSERT INTO poison (id) VALUES (1)").await
		.expect("poisoning statements");
	drop(conn);

	// An unrelated write on the reused connection must not adopt the
	// abandoned transaction; committing it would make the insert durable.
	db.write(async |t| {
		t.execute("SELECT 1", &[]).await?;
		Ok(())
	}).await.expect("write on reused connection");

	let count = db.read(async |t| {
		Ok(t.query_one("SELECT COUNT(*) FROM poison", &[]).await?.get::<_, i64>(0))
	}).await.expect("count rows");
	assert_eq!(count, 0, "abandoned transaction was committed instead of rolled back");
}

use std::sync::Arc;

use bitcoin::Network;

use bark::{Config, SqliteClient, Wallet};

async fn example() -> anyhow::Result<()> {
	let mnemonic = "super secret ...".parse()?;
	let cfg = Config {
		server_address: "https://ark.signet.2nd.dev".into(),
		esplora_address: Some("https://esplora.signet.2nd.dev".into()),
		..Config::network_default(Network::Signet)
	};
	let db = Arc::new(SqliteClient::open("./bark_db")?);
	let wallet = Wallet::create(&mnemonic, Network::Signet, cfg, db, false).await?;

	let address = wallet.new_address()?;
	println!("My first Ark address: {}", address);

	let invoice = wallet.bolt11_invoice("10000sat".parse()?).await?;
	println!("Send me some sats: {}", invoice);

	// Wait for someone to send the sats...
	wallet.try_claim_all_lightning_receives(true).await?;

	let balance = wallet.balance()?;
	println!("I now have sats: {}!", balance.spendable);

	// Let's give back!
	let invoice = "lnbc1... get this from someone you like";
	wallet.pay_lightning_invoice(invoice, None).await?;

	Ok(())
}


#[tokio::main]
async fn main() {
	example().await.unwrap();
}

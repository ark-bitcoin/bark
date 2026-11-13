mod binding;

use std::sync::OnceLock;

use bitcoin::secp256k1::Keypair;

use ark::{ProtocolEncoding, Vtxo, VtxoPolicy};
use ark::mailbox::MailboxIdentifier;
use ark::vtxo::Full;
use bark::Wallet;
use server_rpc::protos;

use ark_testing::Captaind;

/// The mailbox key the database tests bind their VTXOs to.
pub(crate) fn test_server_mailbox_key() -> &'static Keypair {
	static KEY: OnceLock<Keypair> = OnceLock::new();
	KEY.get_or_init(|| Keypair::from_seckey_slice(&ark::SECP, &[251; 32]).unwrap())
}

/// The blinded id of `mailbox` for an output whose key is `key`.
async fn blinded_mailbox(srv: &Captaind, key: &Keypair, mailbox: MailboxIdentifier) -> Vec<u8> {
	let server_mailbox = srv.ark_info().await.mailbox_pubkey;
	mailbox.to_blinded(server_mailbox, key).unwrap().as_ref().to_vec()
}

/// Bind every output of `package` to `mailbox`.
async fn bind_outputs(
	srv: &Captaind, package: &mut protos::ArkoorPackageCosignRequest, key: &Keypair, mailbox: MailboxIdentifier,
) {
	let blinded = blinded_mailbox(srv, key, mailbox).await;
	for output in package.parts.iter_mut().flat_map(|p| p.outputs.iter_mut().chain(&mut p.isolated_outputs)) {
		output.blinded_mailbox_id = blinded.clone();
	}
}

/// Bind each unbound output of `package` to the mailbox of the wallet that
/// holds its key.
async fn bind_to_wallets(
	srv: &Captaind, wallets: &[&Wallet], mut package: protos::ArkoorPackageCosignRequest,
) -> protos::ArkoorPackageCosignRequest {
	for output in package.parts.iter_mut().flat_map(|p| p.outputs.iter_mut().chain(&mut p.isolated_outputs)) {
		if !output.blinded_mailbox_id.is_empty() {
			continue;
		}
		let key = VtxoPolicy::deserialize(&output.policy).unwrap().user_pubkey();
		let mut owner = None;
		for wallet in wallets {
			if let Some((_, keypair)) = wallet.pubkey_keypair(&key).await.unwrap() {
				owner = Some((keypair, wallet.mailbox_identifier()));
				break;
			}
		}
		let (keypair, mailbox) = owner.unwrap_or_else(|| panic!("no wallet holds the key of output {key}"));
		output.blinded_mailbox_id = blinded_mailbox(srv, &keypair, mailbox).await;
	}
	package
}

/// Record VTXOs as decided for an expiry payout: one operator share each in
/// a new allocation.
pub(crate) async fn decide_for_payout(t: &tokio_postgres::Transaction<'_>, ids: &[String]) -> anyhow::Result<()> {
	let id: i64 = t.query_one("INSERT INTO expiry_payout(expiry_height) VALUES(0) RETURNING id", &[])
		.await?.get(0);
	t.execute("
		INSERT INTO expiry_payout_vtxo(expiry_payout_id, vtxo_id, disposition, gross_sat, fee_sat, payout_sat, replannable)
		SELECT $1, UNNEST($2::TEXT[]), 'operator', 1, 0, 0, FALSE
	", &[&id, &ids]).await?;
	Ok(())
}

/// The spendable VTXOs of `wallet`.
async fn full_vtxos(wallet: &Wallet) -> Vec<Vtxo<Full>> {
	let mut vtxos = Vec::new();
	for vtxo in wallet.spendable_vtxos().await.unwrap() {
		vtxos.push(wallet.get_full_vtxo(vtxo.id()).await.unwrap());
	}
	vtxos
}

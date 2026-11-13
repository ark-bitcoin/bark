mod binding;

use std::sync::OnceLock;

use bitcoin::secp256k1::Keypair;

use ark::Vtxo;
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

/// The spendable VTXOs of `wallet`.
async fn full_vtxos(wallet: &Wallet) -> Vec<Vtxo<Full>> {
	let mut vtxos = Vec::new();
	for vtxo in wallet.spendable_vtxos().await.unwrap() {
		vtxos.push(wallet.get_full_vtxo(vtxo.id()).await.unwrap());
	}
	vtxos
}

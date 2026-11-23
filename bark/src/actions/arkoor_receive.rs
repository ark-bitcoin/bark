//! Arkoor receive.
//!
//! The checks that decide whether a received arkoor VTXO is a payment to this
//! wallet.

use anyhow::Context;
use log::{error, warn};

use ark::{Vtxo, VtxoId};
use ark::vtxo::Full;
use ark::vtxo::policy::VtxoPolicyKind;
use ark::vtxo::policy::signing::VtxoSigner;

use crate::Wallet;

/// Refuses the received arkoor VTXOs that are not a payment to this wallet,
/// logging why.
///
/// Returns the refused VTXOs, sorted. Only returns an error when it cannot
/// validate any VTXO, for example when the server is down or the chain tip is
/// unknown.
pub(crate) async fn validate_arkoor_receive(
	wallet: &Wallet,
	vtxos: &[Vtxo<Full>],
) -> anyhow::Result<Vec<VtxoId>> {
	let (_, ark_info) = wallet.require_server().await
		.context("refuse_htlc_send_vtxo_posted_to_arkoor_mailbox")?;
	let tip = wallet.inner.chain.tip().await
		.context("cannot vet received arkoor VTXOs, no chain tip")?;

	let mut invalid = Vec::new();
	for vtxo in vtxos {
		if let Err(e) = wallet.validate_vtxo(vtxo).await {
			error!("Received invalid arkoor VTXO {} from server: {}", vtxo.id(), e);
			invalid.push(vtxo.id());
			continue;
		}
		if let Err(e) = check_arkoor_receive_policy(vtxo, ark_info.server_pubkey) {
			error!("Refusing received arkoor VTXO {}: {}", vtxo.id(), e);
			invalid.push(vtxo.id());
			continue;
		}
		if wallet.find_signable_clause(vtxo).await.is_none() {
			error!("Refusing received arkoor VTXO {}: not owned by this wallet", vtxo.id());
			invalid.push(vtxo.id());
			continue;
		}
		if vtxo.expiry_height() <= tip {
			warn!("Received arkoor VTXO {} that expired at height {} (tip {}); \
				keeping it, it needs a refresh", vtxo.id(), vtxo.expiry_height(), tip,
			);
		}
	}

	if !invalid.is_empty() {
		error!("Received {} invalid arkoor VTXOs out of {} from server",
			invalid.len(), vtxos.len(),
		);
	}
	invalid.sort_unstable();
	Ok(invalid)
}

/// Whether a structurally-valid arkoor vtxo is safe to store as a spendable
/// received payment.
///
/// [`Wallet::validate_vtxo`] only proves the vtxo's genesis chain was cosigned
/// by the server pubkey embedded in the vtxo. A received payment additionally
/// has to be a final, self-custodial coin, so we require that:
///
/// - the policy is [`VtxoPolicyKind::Pubkey`]: an in-flight HTLC (or any other
///   server contract) is not a payment, and the server refuses to let us spend
///   it as an arkoor/round/offboard input;
/// - the vtxo commits to *our* server's pubkey, not a foreign server's.
///
/// Expiry is not a reason to refuse. The sender paid with a vtxo that was
/// valid when the server cosigned it; if we only sync after it expired, the
/// payment is still ours and the coin needs a refresh, not a rejection.
/// Refusing would drop the payment, since the mailbox checkpoint advances.
///
/// Ownership (that the wallet holds a signable key) is checked by the caller,
/// which has async database access.
fn check_arkoor_receive_policy(
	vtxo: &Vtxo<Full>,
	server_pubkey: bitcoin::secp256k1::PublicKey,
) -> anyhow::Result<()> {
	let kind = vtxo.policy().policy_type();
	if kind != VtxoPolicyKind::Pubkey {
		bail!("not a final payment VTXO (policy: {})", kind);
	}
	if vtxo.server_pubkey() != server_pubkey {
		bail!("VTXO commits to a foreign server pubkey {}", vtxo.server_pubkey());
	}
	Ok(())
}

#[cfg(test)]
mod test {
	use super::*;

	use ark::SECP;
	use ark::test_util::VTXO_VECTORS;
	use bitcoin::secp256k1::Keypair;

	/// The arkoor receive path must only store final, self-custodial coins for
	/// our own server. This pins the two ways a received vtxo can be unsafe.
	#[test]
	fn arkoor_receive_policy_gate() {
		let vectors = &*VTXO_VECTORS;
		let server_pubkey = vectors.server_key.public_key();

		// A final Pubkey payment vtxo committing to our server is acceptable.
		let good = &vectors.board_vtxo;
		check_arkoor_receive_policy(good, server_pubkey)
			.expect("a Pubkey vtxo must be accepted");

		// An HTLC-send vtxo is an in-flight contract, not a payment.
		let htlc = &vectors.arkoor_htlc_out_vtxo;
		check_arkoor_receive_policy(htlc, server_pubkey)
			.expect_err("an HTLC-send vtxo must be refused as a payment");

		// A vtxo committing to some other server's key is not ours to trust.
		let foreign_server = Keypair::from_seckey_slice(&SECP, &[0x11; 32])
			.unwrap().public_key();
		check_arkoor_receive_policy(good, foreign_server)
			.expect_err("a vtxo for a foreign server must be refused");
	}
}

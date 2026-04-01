
use bitcoin::hashes::sha256;
use bitcoin::secp256k1::schnorr;
use bitcoin::secp256k1::Keypair;
use bitcoin::taproot::ControlBlock;
use bitcoin::TapSighash;
use bitcoin::Witness;
use tracing::error;

use ark::{ServerVtxoPolicy, Vtxo};
use ark::vtxo::policy::clause::{TapScriptClause, VtxoClause};
use ark::vtxo::policy::signing::VtxoSigner;
use bitcoin_ext::KeypairExt;

use crate::database::Db;
use crate::secret::Secret;
use crate::SECP;

/// Signer for server-side VTXO spending (claims).
///
/// Signs VTXOs where the server pubkey is authorized to spend.
/// This includes all [ServerVtxoPolicy](ark::vtxo::policy::ServerVtxoPolicy) variants:
/// - **Checkpoint**: Server can sweep after expiry height via `TimelockSign`
/// - **Expiry**: Server can sweep after expiry height via `TimelockSign`
/// - **ServerHtlcSend**: Server reveals preimage via `HashDelaySign`
/// - **ServerHtlcRecv**: Server claims after HTLC expiry via `DelayedTimelockSign`
///
/// For HashDelaySign clauses, preimages are retrieved from the database.
pub struct WatchmanSigner {
	server_keypair: Secret<Keypair>,
	db: Db,
}

impl WatchmanSigner {
	pub fn new(server_keypair: Secret<Keypair>, db: Db) -> Self {
		Self { server_keypair, db }
	}

	/// Get the preimage for a hash from the database
	async fn get_preimage(
		&self,
		hash: sha256::Hash,
	) -> Option<Secret<[u8; 32]>> {
		// NB we have multiple possible sources of the hash/preimage pair
		// In order to protect against attackers trying to use an unlock hash
		// in a LN payment in order to extract the secret on-chain,
		// we refuse to act when a hash exists in multiple sources.

		// first payment preimages for lightning receives
		let htlc = self.db.get_lightning_invoice_by_payment_hash(hash.into()).await.ok()?;

		// then hark unlock hashes
		let hark = self.db.get_round_participation_by_unlock_hash(hash).await.ok()?;

		if htlc.is_some() && hark.is_some() {
			slog!(DuplicateSecretHash, hash);
			return None;
		}

		let htlc = htlc.and_then(|i| i.preimage.map(|p| Secret::new(p.into())));
		let hark = hark.map(|p| p.unlock_preimage);

		htlc.or(hark)
	}
}

#[async_trait::async_trait]
impl VtxoSigner<ServerVtxoPolicy> for WatchmanSigner {
	async fn sign_keyspend<G: Sync + Send>(
		&self,
		vtxo: &Vtxo<G, ServerVtxoPolicy>,
		sighash: TapSighash,
	) -> Option<schnorr::Signature> {
		let tap_merkle_root = vtxo.output_taproot().merkle_root();
		let key = self.server_keypair.leak_ref().for_keyspend(&*SECP, tap_merkle_root);
		if vtxo.output_taproot().internal_key() != key.public_key().x_only_public_key().0 {
			error!("Watchman asked to sign VTXO {} which has internal key {} but our key is {}",
				vtxo.id(), vtxo.output_taproot().internal_key(), key.public_key(),
			);
			return None;
		}
		Some(ark::SECP.sign_schnorr(&sighash.into(), &key))
	}

	async fn witness(
		&self,
		clause: &VtxoClause,
		control_block: &ControlBlock,
		sighash: TapSighash,
	) -> Option<Witness> {
		// Only sign if the clause pubkey matches our server pubkey
		if clause.pubkey() != self.server_keypair.leak_ref().public_key() {
			return None;
		}

		// Sign the sighash
		let signature = ark::SECP.sign_schnorr(&sighash.into(), self.server_keypair.leak_ref());

		// Construct witness based on clause type
		match clause {
			VtxoClause::TimelockSign(c) => Some(c.witness(&signature, control_block)),
			VtxoClause::DelayedSign(c) => Some(c.witness(&signature, control_block)),
			VtxoClause::DelayedTimelockSign(c) => Some(c.witness(&signature, control_block)),
			VtxoClause::HashDelaySign(c) => {
				let preimage = self.get_preimage(c.hash).await?;
				Some(c.witness(&(signature, *preimage.leak_ref()), control_block))
			},
			VtxoClause::HashSign(c) => {
				let preimage = self.get_preimage(c.hash).await?;
				Some(c.witness(&(signature, *preimage.leak_ref()), control_block))
			},
		}
	}
}


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
	ephemeral_master_key: Secret<Keypair>,
	db: Db,
}

impl WatchmanSigner {
	pub fn new(
		server_keypair: Secret<Keypair>,
		ephemeral_master_key: Secret<Keypair>,
		db: Db,
	) -> Self {
		Self { server_keypair, ephemeral_master_key, db }
	}

	/// Get the preimage for a hash-locked clause from the database.
	///
	/// The same secret can exist in `htlc_settlement` (a settled LN payment)
	/// and `round_participation` (an hArk unlock preimage) at once through
	/// legitimate flows. Resolve strictly by clause domain: HashSign (hArk
	/// forfeit) uses the participation preimage, HashDelaySign (LN HTLC) the
	/// settlement preimage. Refusing on ambiguity let users plant that state
	/// and reclaim forfeits or refund paid HTLCs on-chain while we stood by.
	async fn get_preimage(&self, clause: &VtxoClause) -> Option<Secret<[u8; 32]>> {
		match clause {
			VtxoClause::HashSign(c) => {
				let hark = self.db.read(async |t|
					t.get_round_participation_by_unlock_hash(c.hash).await
				).await.ok()??;
				self.log_if_duplicate_hash(c.hash, true).await;
				Some(hark.unlock_preimage)
			},
			VtxoClause::HashDelaySign(c) => {
				let settlement = self.db.read(async |t|
					t.get_htlc_settlement_by_payment_hash(c.hash.into()).await
				).await.ok()??;
				self.log_if_duplicate_hash(c.hash, false).await;
				Some(Secret::new(settlement.into()))
			},
			_ => None,
		}
	}

	/// Log when a hash exists in both secret domains. The state is reachable
	/// through legitimate flows and never blocks signing; the log exists for
	/// visibility only.
	async fn log_if_duplicate_hash(&self, hash: sha256::Hash, in_hark: bool) {
		let duplicate = if in_hark {
			self.db.read(async |t| t.get_htlc_settlement_by_payment_hash(hash.into()).await).await
				.ok().flatten().is_some()
		} else {
			self.db.read(async |t| t.get_round_participation_by_unlock_hash(hash).await).await
				.ok().flatten().is_some()
		};
		if duplicate {
			slog!(DuplicateSecretHash, hash);
		}
	}
}

#[async_trait::async_trait]
impl VtxoSigner<ServerVtxoPolicy> for WatchmanSigner {
	async fn can_sign<G: Sync + Send>(
		&self, clause: &VtxoClause, _vtxo: &Vtxo<G, ServerVtxoPolicy>,
	) -> bool {
		// first check for the key to sign
		let have_key = if clause.pubkey() == self.server_keypair.leak_ref().public_key() {
			true
		} else {
			self.db.read(async |t| t.fetch_ephemeral_tweak(clause.pubkey()).await).await
				.ok().flatten().is_some()
		};
		if !have_key {
			return false;
		}

		// then check for other witness items
		match clause {
			VtxoClause::HashDelaySign(_) => self.get_preimage(clause).await.is_some(),
			VtxoClause::HashSign(_) => self.get_preimage(clause).await.is_some(),
			// others are simple signatures
			VtxoClause::DelayedSign(_) => true,
			VtxoClause::DelayedTimelockSign(_) => true,
			VtxoClause::TimelockSign(_) => true,
		}
	}

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
		let key = if clause.pubkey() == self.server_keypair.leak_ref().public_key() {
			self.server_keypair.leak_owned()
		} else {
			let tweak = self.db.read(async |t| t.fetch_ephemeral_tweak(clause.pubkey()).await).await.ok()??;
			let seckey = self.ephemeral_master_key.leak_ref().secret_key()
				.add_tweak(&tweak).expect("tweak error");
			Keypair::from_secret_key(&*SECP, &seckey)
		};

		// Sign the sighash
		let signature = ark::SECP.sign_schnorr(&sighash.into(), &key);

		// Construct witness based on clause type
		match clause {
			VtxoClause::TimelockSign(c) => Some(c.witness(&signature, control_block)),
			VtxoClause::DelayedSign(c) => Some(c.witness(&signature, control_block)),
			VtxoClause::DelayedTimelockSign(c) => Some(c.witness(&signature, control_block)),
			VtxoClause::HashDelaySign(c) => {
				let preimage = self.get_preimage(clause).await?;
				Some(c.witness(&(signature, *preimage.leak_ref()), control_block))
			},
			VtxoClause::HashSign(c) => {
				let preimage = self.get_preimage(clause).await?;
				Some(c.witness(&(signature, *preimage.leak_ref()), control_block))
			},
		}
	}
}

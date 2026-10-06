
use std::time::Duration;


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XpubRecoveryScanned {
	/// First xpub child index scanned.
	pub start_index: u32,
	/// Number of xpub children derived and looked up.
	pub nb_keys: u32,
	/// Number of VTXOs found for those keys.
	pub nb_vtxos: usize,
	pub duration: Duration,
}
impl_slog!(XpubRecoveryScanned, INFO, "scanned xpub children for recoverable VTXOs");

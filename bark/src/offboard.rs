
use bitcoin::ScriptBuf;

use ark::vtxo::VtxoRef;

use crate::round::RoundStatus;
use crate::Wallet;



impl Wallet {
	pub async fn offboard<V: VtxoRef>(
		&self,
		_vtxos: impl IntoIterator<Item = V>,
		_destination: ScriptBuf,
	) -> anyhow::Result<RoundStatus> {
		unimplemented!("offboards are currently unsupported");
	}

	/// Offboard all VTXOs to a given [bitcoin::Address].
	pub async fn offboard_all(&self, address: bitcoin::Address) -> anyhow::Result<RoundStatus> {
		let input_vtxos = self.spendable_vtxos().await?;
		Ok(self.offboard(input_vtxos, address.script_pubkey()).await?)
	}

	/// Offboard the given VTXOs to a given [bitcoin::Address].
	pub async fn offboard_vtxos<V: VtxoRef>(
		&self,
		vtxos: impl IntoIterator<Item = V>,
		address: bitcoin::Address,
	) -> anyhow::Result<RoundStatus> {
		let mut input_vtxos = vec![];
		for v in vtxos {
			let id = v.vtxo_id();
			let vtxo = match self.db.get_wallet_vtxo(id).await? {
				Some(vtxo) => vtxo.vtxo,
				_ => bail!("cannot find requested vtxo: {}", id),
			};
			input_vtxos.push(vtxo);
		}

		Ok(self.offboard(input_vtxos, address.script_pubkey()).await?)
	}
}

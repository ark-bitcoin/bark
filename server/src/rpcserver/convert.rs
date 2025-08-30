
use server_rpc::protos;

use crate::database::ln::LightningHtlcSubscription;


impl From<LightningHtlcSubscription> for protos::SubscribeLightningReceiveResponse {
	fn from(v: LightningHtlcSubscription) -> Self {
		protos::SubscribeLightningReceiveResponse {
			invoice: v.invoice.to_string(),
			amount_sat: v.amount().to_sat(),
			status: protos::LightningReceiveStatus::from(v.status) as i32,
			htlc_vtxos: v.htlc_vtxos.into_iter().map(|v| v.to_bytes().to_vec()).collect(),
		}
	}
}

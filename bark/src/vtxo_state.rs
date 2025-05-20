use ark::{lightning::{Invoice, PaymentHash}, Vtxo};
use bitcoin::Amount;

const SPENDABLE: &'static str = "Spendable";
const UNREGISTERED_BOARD : &'static str = "UnregisteredBoard";
const SPENT: &'static str = "Spent";
const PENDING_LIGHTNING_SEND: &'static str = "PendingLightningSend";
const PENDING_LIGHTNING_RECV: &'static str = "PendingLightningRecv";

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum VtxoStateKind {
	Spendable,
	UnregisteredBoard,
	Spent,
	PendingLightningSend,
	PendingLightningRecv,
}

impl VtxoStateKind {
	pub fn as_str(&self) -> &str {
		match self {
			VtxoStateKind::UnregisteredBoard => UNREGISTERED_BOARD,
			VtxoStateKind::Spendable => SPENDABLE,
			VtxoStateKind::Spent => SPENT,
			VtxoStateKind::PendingLightningSend => PENDING_LIGHTNING_SEND,
			VtxoStateKind::PendingLightningRecv => PENDING_LIGHTNING_RECV,
		}
	}
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum VtxoState {
	Spendable,
	Spent,
	UnregisteredBoard,
	/// The current vtxo is spent in a pending lightning payment
	///
	/// The VTXO hold by the state is the HTLC vtxo that can be
	/// used to either revoke the payment if the lightning part fails,
	/// or exit the Ark if the ASP don't accept to revoke the payment
	PendingLightningSend {
		invoice: Invoice,
		amount: Amount,
	},
	/// The current vtxo is pending claim from recipient
	///
	/// The VTXO hold by the state is the HTLC vtxo that can be
	/// used to either revoke the board if the lightning part fails
	PendingLightningRecv {
		payment_hash: PaymentHash,
	},
}

impl VtxoState {
	pub fn as_kind(&self) -> VtxoStateKind {
		match self {
			VtxoState::UnregisteredBoard => VtxoStateKind::UnregisteredBoard,
			VtxoState::Spendable => VtxoStateKind::Spendable,
			VtxoState::Spent => VtxoStateKind::Spent,
			VtxoState::PendingLightningSend { .. } => VtxoStateKind::PendingLightningSend,
			VtxoState::PendingLightningRecv { .. } => VtxoStateKind::PendingLightningRecv,
		}
	}

	pub fn as_pending_lightning_send(&self) -> Option<(&Invoice, &Amount)> {
		match self {
			VtxoState::PendingLightningSend { invoice, amount } => Some((invoice, amount)),
			_ => None,
		}
	}

	pub fn as_pending_lightning_recv(&self) -> Option<&PaymentHash> {
		match self {
			VtxoState::PendingLightningRecv { payment_hash } => Some(payment_hash),
			_ => None,
		}
	}
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WalletVtxo {
	pub vtxo: Vtxo,
	pub state: VtxoState,
}

#[cfg(test)]
mod test {
	use super::*;

	#[test]
	fn convert_serialize() {
		let states = [
			VtxoStateKind::Spendable,
			VtxoStateKind::Spent,
			VtxoStateKind::UnregisteredBoard,
			VtxoStateKind::PendingLightningSend,
			VtxoStateKind::PendingLightningRecv,
		];

		assert_eq!(
			serde_json::to_string(&states).unwrap(),
			serde_json::to_string(&[SPENDABLE, SPENT, UNREGISTERED_BOARD, PENDING_LIGHTNING_SEND, PENDING_LIGHTNING_RECV]).unwrap(),
		);

		// If a compiler error occurs,
		// This is a reminder that you should update the test above
		match VtxoState::Spent {
			VtxoState::Spendable => {},
			VtxoState::Spent => {},
			VtxoState::UnregisteredBoard => (),
			VtxoState::PendingLightningSend { .. } => (),
			VtxoState::PendingLightningRecv { .. } => (),
		}
	}
}

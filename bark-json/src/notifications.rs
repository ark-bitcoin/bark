
use crate::movements::Movement;




/// A notification of something happening in the wallet
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub enum WalletNotification {
	/// A new movement was created
	MovementCreated {
		movement: Movement,
	},
	/// An existing movement was updated
	MovementUpdated {
		movement: Movement,
	},
	/// Some notifications were lost because they are not handled fast enough
	ChannelLagging,
}

impl From<bark::WalletNotification> for WalletNotification {
	fn from(v: bark::WalletNotification) -> Self {
		match v {
			bark::WalletNotification::MovementCreated { movement } => {
				WalletNotification::MovementCreated { movement: movement.into() }
			},
			bark::WalletNotification::MovementUpdated { movement } => {
				WalletNotification::MovementUpdated { movement: movement.into() }
			},
			bark::WalletNotification::ChannelLagging => WalletNotification::ChannelLagging,
		}
	}
}

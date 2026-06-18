
use chrono::{DateTime, Local};


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MailboxAuthorizationExpired {
	pub expiry: DateTime<Local>,
	pub now: DateTime<Local>,
	pub late_by_secs: i64,
}
impl_slog!(MailboxAuthorizationExpired, TRACE, "mailbox authorization expired");

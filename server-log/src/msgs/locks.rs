
use std::borrow::Cow;
use std::time::Duration;


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockAcquired {
	pub name: Cow<'static, str>,
	#[serde(with = "crate::serde_utils::duration_millis")]
	pub waited: Duration,
}
impl_slog!(LockAcquired, TRACE, "instrumented lock acquired");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockReleased {
	pub name: Cow<'static, str>,
	#[serde(with = "crate::serde_utils::duration_millis")]
	pub held: Duration,
}
impl_slog!(LockReleased, TRACE, "instrumented lock released");

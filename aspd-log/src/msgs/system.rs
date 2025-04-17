
use std::borrow::Cow;


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AspdTerminated {}
impl_slog!(AspdTerminated, Info, "ASPD Terminated: Shutdown Completed");


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerStarted {
	pub name: Cow<'static, str>,
}
impl_slog!(WorkerStarted, Trace, "a worker thread started");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerStopped {
	pub name: Cow<'static, str>,
}
impl_slog!(WorkerStopped, Trace, "a worker thread stopped");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CriticalWorkerStopped {
	pub name: Cow<'static, str>,
}
impl_slog!(CriticalWorkerStopped, Error, "a critical worker stopped unexpectedly");

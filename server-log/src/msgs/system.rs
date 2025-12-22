

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerTerminated {}
impl_slog!(ServerTerminated, INFO, "server terminated: shutdown completed");


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerStarted {
	pub name: String,
	pub critical: bool,
}
impl_slog!(WorkerStarted, TRACE, "a worker thread started");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerStopped {
	pub name: String,
}
impl_slog!(WorkerStopped, TRACE, "a worker thread stopped");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CriticalWorkerStopped {
	pub name: String,
}
impl_slog!(CriticalWorkerStopped, ERROR, "a critical worker stopped unexpectedly");


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostgresPoolError {
	pub err: String,
	pub code: Option<String>,
}
impl_slog!(PostgresPoolError, ERROR, "a bb8 postgresql pool error");

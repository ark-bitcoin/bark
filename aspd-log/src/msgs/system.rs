
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AspdTerminated {}
impl_slog!(AspdTerminated, Info, "ASPD Terminated: Shutdown Completed");



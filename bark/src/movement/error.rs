use crate::movement::MovementId;
use crate::subsystem::Subsystem;

#[derive(Debug, thiserror::Error)]
pub enum MovementError {
	#[error("Movement Cache Error: Movement missing from cache ({id})")]
	CacheError { id: MovementId },

	#[error("Movement Creation Error: {e}")]
	CreationError { e: anyhow::Error },

	#[error("Incorrect Pending Status: Attempt to incorrectly set movement status to pending")]
	IncorrectPendingStatus,

	#[error("Invalid Movement ID: {id} does not exist")]
	InvalidMovementId { id: MovementId },

	#[error("Movement Load Error: Unable to load movement ({id}) from persister: {e}")]
	LoadError { id: MovementId, e: anyhow::Error },

	#[error("Persist Movement Failed: Unable to persist changes to movement ({id}): {e}")]
	PersisterError { id: MovementId, e: anyhow::Error },

	#[error("Subsystem Error ({id}): {error}")]
	SubsystemError { id: Subsystem, error: String },
}

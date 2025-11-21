use thiserror::Error;

use crate::movement::MovementId;
use crate::subsystem::SubsystemId;

#[derive(Debug, Error)]
pub enum MovementError {
	#[error("Movement Cache Error: Movement missing from cache ({id})")]
	CacheError { id: MovementId },

	#[error("Movement Creation Error: {e}")]
	CreationError { e: anyhow::Error },

	#[error("Incorrect Status Error: Attempt to incorrectly set movement to {status}")]
	IncorrectStatus { status: String },

	#[error("Invalid Subsystem ID: {id} does not exist")]
	InvalidSubsystemId { id: SubsystemId },

	#[error("Invalid Movement ID: {id} does not exist")]
	InvalidMovementId { id: MovementId },

	#[error("Movement Load Error: Unable to load movement ({id}) from persister: {e}")]
	LoadError { id: MovementId, e: anyhow::Error },

	#[error("Persist Movement Failed: Unable to persist changes to movement ({id}): {e}")]
	PersisterError { id: MovementId, e: anyhow::Error },

	#[error("Subsystem Error ({name}): {error}")]
	SubsystemError { name: String, error: String },
}

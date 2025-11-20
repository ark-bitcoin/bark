use std::cmp::PartialEq;
use std::collections::HashMap;
use std::sync::Arc;

use chrono::DateTime;
use tokio::sync::RwLock;

use crate::movement::{Movement, MovementId, MovementStatus, MovementSubsystem};
use crate::movement::error::MovementError;
use crate::movement::update::MovementUpdate;
use crate::persist::BarkPersister;
use crate::subsystem::SubsystemId;

/// A minimalist helper class to handle movement registration and updating based on unique
/// [SubsystemId] values.
pub struct MovementManager {
	db: Arc<dyn BarkPersister>,
	subsystem_ids: RwLock<HashMap<SubsystemId, String>>,
	active_movements: RwLock<HashMap<MovementId, Arc<RwLock<Movement>>>>,
}

impl MovementManager {
	/// Creates an instances of the [MovementManager].
	pub fn new(db: Arc<dyn BarkPersister>) -> Self {
		Self {
			db,
			subsystem_ids: RwLock::new(HashMap::new()),
			active_movements: RwLock::new(HashMap::new()),
		}
	}

	/// Registers a subsystem with the movement manager. Subsystems are identified using unique
	/// names, to maintain this guarantee a unique [SubsystemId] will be generated and returned by
	/// this function. Future calls to register or modify movements must provide this ID.
	pub async fn register_subsystem(&self, name: String) -> anyhow::Result<SubsystemId, MovementError> {
		let exists = self.subsystem_ids.read().await.iter().any(|(_, n)| n == &name);
		if exists {
			Err(MovementError::SubsystemError {
				name, error: "Subsystem already registered".into(),
			})
		} else {
			let mut ids = self.subsystem_ids.write().await;
			let id = SubsystemId::new(ids.len() as u32);
				ids.insert(id, name);
				Ok(id)
			}
	}

	/// Similar to [MovementManager::new_movement_at] but it sets the [Movement::created_at] field
	/// to the current time.
	pub async fn new_movement(
		&self,
		subsystem_id: SubsystemId,
		movement_kind: String,
	) -> anyhow::Result<MovementId, MovementError> {
		self.new_movement_at(subsystem_id, movement_kind, chrono::Local::now()).await
	}

	/// Begins the process of creating a new movement. This newly created movement will be defaulted
	/// to a [MovementStatus::Pending] state. It can then be updated by using [MovementUpdate] in
	/// combination with [MovementManager::update_movement].
	///
	/// [MovementManager::finish_movement] can be used once a movement has finished (whether
	/// successful or not).
	///
	/// Parameters:
	/// - subsystem_id: The ID of the subsystem that wishes to start a new movement.
	/// - movement_kind: A descriptor for the type of movement being performed, e.g. "send",
	///   "receive", "round".
	/// - at: The timestamp to set the [MovementTimestamp::created_at] field to.
	///
	/// Errors:
	/// - If the subsystem ID is not recognized.
	/// - If a database error occurs.
	pub async fn new_movement_at(
		&self,
		subsystem_id: SubsystemId,
		movement_kind: String,
		at: DateTime<chrono::Local>,
	) -> anyhow::Result<MovementId, MovementError> {
		self.db.create_new_movement(
			MovementStatus::Pending,
			&MovementSubsystem {
				name: self.get_subsystem_name(subsystem_id).await?,
				kind: movement_kind,
			},
			at,
		).map_err(|e| MovementError::CreationError { e })
	}

	/// Similar to [MovementManager::new_finished_movement_at] but it sets the
	/// [Movement::created_at] field to the current time.
	pub async fn new_finished_movement(
		&self,
		subsystem_id: SubsystemId,
		movement_kind: String,
		status: MovementStatus,
		details: MovementUpdate,
	) -> anyhow::Result<MovementId, MovementError> {
		self.new_finished_movement_at(
			subsystem_id, movement_kind, status, details, chrono::Local::now(),
		).await
	}

	/// Creates and marks a [Movement] as finished based on the given parameters. This is useful for
	/// one-shot movements where the details are known at time of creation, an example would be when
	/// receiving funds asynchronously from a third party.
	///
	/// Parameters:
	/// - subsystem_id: The ID of the subsystem that wishes to start a new movement.
	/// - movement_kind: A descriptor for the type of movement being performed, e.g. "send",
	///   "receive", "round".
	/// - status: The [MovementStatus] to set. This can't be [MovementStatus::Pending].
	/// - details: Contains information about the movement, e.g. what VTXOs were consumed or
	///   produced.
	/// - at: The timestamp to set the [Movement::time] field to.
	///
	/// Errors:
	/// - If the subsystem ID is not recognized.
	/// - If [MovementStatus::Pending] is given.
	/// - If a database error occurs.
	pub async fn new_finished_movement_at(
		&self,
		subsystem_id: SubsystemId,
		movement_kind: String,
		status: MovementStatus,
		details: MovementUpdate,
		at: DateTime<chrono::Local>,
	) -> anyhow::Result<MovementId, MovementError> {
		if status == MovementStatus::Pending {
			return Err(MovementError::IncorrectStatus { status: status.as_str().into() });
		}
		let id = self.new_movement_at(subsystem_id, movement_kind, at).await?;
		let mut movement = self.db.get_movement(id)
			.map_err(|e| MovementError::LoadError { id, e })?;
		details.apply_to(&mut movement, at);
		movement.status = status;
		movement.time.completed_at = Some(at);
		self.db.update_movement(&movement)
			.map_err(|e| MovementError::PersisterError { id, e })?;
		Ok(id)
	}

	/// Similar to [MovementManager::update_movement_at] but it sets the
	/// [MovementTimestamp::updated_at] field to the current time.
	pub async fn update_movement(
		&self,
		id: MovementId,
		update: MovementUpdate,
	) -> anyhow::Result<(), MovementError> {
		self.update_movement_at(id, update, chrono::Local::now()).await
	}

	/// Updates a movement with the given parameters.
	///
	/// See also: [MovementManager::create_movement] and [MovementManager::finish_movement]
	///
	/// Parameters:
	/// - id: The ID of the movement previously created by [MovementManager::new_movement].
	/// - update: Specifies properties to set on the movement. `Option` fields will be ignored if
	///   they are `None`. `Some` will result in that particular field being overwritten.
	/// - at: The timestamp to set the [MovementTimestamp::completed_at] field to.
	///
	/// Errors:
	/// - If the [MovementId] is not recognized.
	/// - If a movement is not [MovementStatus::Pending].
	/// - If a database error occurs.
	pub async fn update_movement_at(
		&self,
		id: MovementId,
		update: MovementUpdate,
		at: DateTime<chrono::Local>,
	) -> anyhow::Result<(), MovementError> {

		// Ensure the movement is loaded.
		self.load_movement_into_cache(id).await?;

		// Apply the update to the movement.
		update.apply_to(&mut *self.get_movement_lock(id).await?.write().await, at);

		// Persist the changes using a read lock.
		let lock = self.get_movement_lock(id).await?;
		let movement = lock.read().await;
		self.db.update_movement(&movement)
			.map_err(|e| MovementError::PersisterError { id, e })?;

		// Drop the movement if it's in a finished state as this was likely a one-time update.
		if movement.status != MovementStatus::Pending {
			self.unload_movement_from_cache(id).await?;
		}
		Ok(())
	}

	/// Similar to [MovementManager::finish_movement] but it sets the
	/// [MovementTimestamp::completed_at] field to the current time.
	pub async fn finish_movement(
		&self,
		id: MovementId,
		new_status: MovementStatus,
	) -> anyhow::Result<(), MovementError> {
		self.finish_movement_at(id, new_status, chrono::Local::now()).await
	}

	/// Finalizes a movement, setting it to the given [MovementStatus].
	///
	/// See also: [MovementManager::create_movement] and [MovementManager::update_movement]
	///
	/// Parameters:
	/// - id: The ID of the movement previously created by [MovementManager::new_movement].
	/// - new_status: The final [MovementStatus] to set. This can't be [MovementStatus::Pending].
	/// - at: The timestamp to set the [MovementTimestamp::completed_at] field to.
	///
	/// Errors:
	/// - If the movement ID is not recognized.
	/// - If [MovementStatus::Pending] is given.
	/// - If a database error occurs.
	pub async fn finish_movement_at(
		&self,
		id: MovementId,
		new_status: MovementStatus,
		at: DateTime<chrono::Local>,
	) -> anyhow::Result<(), MovementError> {
		if new_status == MovementStatus::Pending {
			return Err(MovementError::IncorrectStatus { status: new_status.as_str().into() });
		}

		// Ensure the movement is loaded.
		self.load_movement_into_cache(id).await?;

		// Update the status and persist it.
		let lock = self.get_movement_lock(id).await?;
		let mut movement = lock.write().await;
		movement.status = new_status;
		movement.time.completed_at = Some(at);
		self.db.update_movement(&*movement)
			.map_err(|e| MovementError::PersisterError { id, e })?;
		self.unload_movement_from_cache(id).await
	}

	async fn get_movement_lock(
		&self,
		id: MovementId,
	) -> anyhow::Result<Arc<RwLock<Movement>>, MovementError> {
		self.active_movements
			.read()
			.await
			.get(&id)
			.cloned()
			.ok_or(MovementError::CacheError { id })
	}

	async fn get_subsystem_name(&self, id: SubsystemId) -> anyhow::Result<String, MovementError> {
		self.subsystem_ids
			.read()
			.await
			.get(&id)
			.cloned()
			.ok_or(MovementError::InvalidSubsystemId { id })
	}

	async fn load_movement_into_cache(&self, id: MovementId) -> anyhow::Result<(), MovementError> {
		if self.active_movements.read().await.contains_key(&id) {
			return Ok(());
		}
		// Acquire a write lock and check if another thread already loaded the movement.
		let mut movements = self.active_movements.write().await;
		if movements.contains_key(&id) {
			return Ok(());
		}
		let movement = self.db.get_movement(id)
			.map_err(|e| MovementError::LoadError { id, e })?;
		movements.insert(id, Arc::new(RwLock::new(movement)));
		Ok(())
	}

	async fn unload_movement_from_cache(&self, id: MovementId) -> anyhow::Result<(), MovementError> {
		let mut lock = self.active_movements.write().await;
		lock.remove(&id);
		Ok(())
	}
}

/// Determines the state to set a [Movement] to when a [MovementGuard] is dropped.
///
/// See [MovementGuard::new_movement] for more information.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum OnDropStatus {
	/// Marks the [Movement] as [MovementStatus::Cancelled].
	Cancelled,
	/// Marks the [Movement] as [MovementStatus::Failed].
	Failed,
}

impl From<OnDropStatus> for MovementStatus {
	fn from(status: OnDropStatus) -> Self {
		match status {
			OnDropStatus::Cancelled => MovementStatus::Cancelled,
			OnDropStatus::Failed => MovementStatus::Failed,
		}
	}
}

/// A RAII helper class to ensure that pending movements get marked as finished in case an error
/// occurs. You can construct a guard for an existing [Movement] with [MovementGuard::new].
/// Alternatively, a [MovementGuard] can be coupled to a movement using
/// [MovementGuard::new_movement].
///
/// When the [MovementGuard] is dropped from the stack, it will finalize the movement according to
/// the configured [OnDropStatus] unless [MovementGuard::finish] has already been called.
pub struct MovementGuard {
	id: MovementId,
	manager: Arc<MovementManager>,
	on_drop: OnDropStatus,
	has_finished: bool,
}

impl<'a> MovementGuard {
	/// Constructs a [MovementGuard] to manage a pre-existing [Movement].
	///
	/// Parameters:
	/// - id: The ID of the [Movement] to update.
	/// - manager: A reference to the [MovementManager] so the guard can update the [Movement].
	pub fn new(
		id: MovementId,
		manager: Arc<MovementManager>,
	) -> Self {
		Self {
			id,
			manager,
			on_drop: OnDropStatus::Failed,
			has_finished: false,
		}
	}

	/// Constructs a [MovementGuard] and creates a new [Movement] for the guard to manage.
	///
	/// See [MovementManager::new_movement] for more information.
	///
	/// Parameters:
	/// - manager: A reference to the [MovementManager] so the guard can update the [Movement].
	/// - subsystem_id: The ID of the subsystem that wishes to start a new movement.
	/// - movement_kind: A descriptor for the type of movement being performed, e.g. "send",
	///   "receive", "round".
	pub async fn new_movement(
		manager: Arc<MovementManager>,
		subsystem_id: SubsystemId,
		movement_kind: String,
	) -> anyhow::Result<Self, MovementError> {
		let id = manager.new_movement(subsystem_id, movement_kind).await?;
		Ok(Self {
			id,
			manager,
			on_drop: OnDropStatus::Failed,
			has_finished: false,
		})
	}

	/// Similar to [MovementGuard::new_movement] with the ability to set a custom timestamp.
	///
	/// Parameters:
	/// - manager: A reference to the [MovementManager] so the guard can update the [Movement].
	/// - subsystem_id: The ID of the subsystem that wishes to start a new movement.
	/// - movement_kind: A descriptor for the type of movement being performed, e.g. "send",
	///   "receive", "round".
	/// - at: The timestamp to set the [MovementTimestamp::created_at] field to.
	pub async fn new_movement_at(
		manager: Arc<MovementManager>,
		subsystem_id: SubsystemId,
		movement_kind: String,
		at: DateTime<chrono::Local>,
	) -> anyhow::Result<Self, MovementError> {
		let id = manager.new_movement_at(subsystem_id, movement_kind, at).await?;
		Ok(Self {
			id,
			manager,
			on_drop: OnDropStatus::Failed,
			has_finished: false,
		})
	}

	/// Gets the [MovementId] stored by this guard.
	pub fn id(&self) -> MovementId {
		self.id
	}

	/// Sets a different [OnDropStatus] to apply to the movement upon dropping the [MovementGuard].
	///
	/// Parameters:
	/// - on_drop: Determines what status the movement will be set to when the guard is dropped.
	pub fn set_on_drop_status(&mut self, status: OnDropStatus) {
		self.on_drop = status;
	}

	/// Applies an update to the managed [Movement].
	///
	/// See [MovementManager::update_movement] for more information.
	///
	/// Parameters:
	/// - update: Specifies properties to set on the movement. `Option` fields will be ignored if
	///   they are `None`. `Some` will result in that particular field being overwritten.
	pub async fn apply_update(
		&self,
		update: MovementUpdate,
	) -> anyhow::Result<(), MovementError> {
		self.manager.update_movement(self.id, update).await
	}

	/// Similar to [MovementGuard::apply_update] with the ability to set a custom timestamp.
	///
	/// Parameters:
	/// - update: Specifies properties to set on the movement. `Option` fields will be ignored if
	///   they are `None`. `Some` will result in that particular field being overwritten.
	/// - at: The timestamp to set the [MovementTimestamp::completed_at] field to.
	pub async fn apply_update_at(
		&self,
		update: MovementUpdate,
		at: DateTime<chrono::Local>,
	) -> anyhow::Result<(), MovementError> {
		self.manager.update_movement_at(self.id, update, at).await
	}

	/// Finalizes a movement, setting it to the given [MovementStatus]. If the [MovementGuard] is
	/// dropped after calling this function, no further changes will be made to the [Movement].
	///
	/// See [MovementManager::finish_movement] for more information.
	///
	/// Parameters:
	/// - status: The final [MovementStatus] to set. Must not be [MovementStatus::Pending].
	pub async fn finish(
		&mut self,
		status: MovementStatus,
	) -> anyhow::Result<(), MovementError> {
		self.manager.finish_movement(self.id, status).await?;
		self.has_finished = true;
		Ok(())
	}

	/// Finalizes a movement, setting it to the given [MovementStatus]. If the [MovementGuard] is
	/// dropped after calling this function, no further changes will be made to the [Movement].
	///
	/// See [MovementManager::finish_movement] for more information.
	///
	/// Parameters:
	/// - status: The final [MovementStatus] to set. Must not be [MovementStatus::Pending].
	/// - at: The timestamp to set the [MovementTimestamp::completed_at] field to.
	pub async fn finish_at(
		&mut self,
		status: MovementStatus,
		at: DateTime<chrono::Local>,
	) -> anyhow::Result<(), MovementError> {
		self.manager.finish_movement_at(self.id, status, at).await?;
		self.has_finished = true;
		Ok(())
	}

	/// Prevents the guard from making further changes to the movement after being dropped. Manual
	/// actions such as [MovementGuard::apply_update] will continue to work.
	pub fn stop(&mut self) {
		self.has_finished = true;
	}
}

impl Drop for MovementGuard {
	fn drop(&mut self) {
		if !self.has_finished {
			// Asynchronously mark the movement as finished since we are being dropped.
			let manager = self.manager.clone();
			let id = self.id;
			let on_drop = self.on_drop;
			tokio::spawn(async move {
				if let Err(e) = manager.finish_movement(id, on_drop.into()).await {
					log::error!("An error occurred in MovementGuard::drop(): {:#}", e);
				}
			});
		}
	}
}

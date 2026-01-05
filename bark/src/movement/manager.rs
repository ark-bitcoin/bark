use std::cmp::PartialEq;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

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
	subsystem_ids: RwLock<HashSet<SubsystemId>>,
	active_movements: RwLock<HashMap<MovementId, Arc<RwLock<Movement>>>>,
}

impl MovementManager {
	/// Creates an instances of the [MovementManager].
	pub fn new(db: Arc<dyn BarkPersister>) -> Self {
		Self {
			db,
			subsystem_ids: RwLock::new(HashSet::new()),
			active_movements: RwLock::new(HashMap::new()),
		}
	}

	/// Registers a subsystem with the movement manager. Subsystems are identified using unique
	/// names, to maintain this guarantee a unique [SubsystemId] will be generated and returned by
	/// this function. Future calls to register or modify movements must provide this ID.
	pub async fn register_subsystem(&self, name: &'static str) -> anyhow::Result<SubsystemId, MovementError> {
		let id = SubsystemId::new(name);
		let exists = self.subsystem_ids.read().await.contains(&id);
		if exists {
			Err(MovementError::SubsystemError {
				name: name.to_string(), error: "Subsystem already registered".into(),
			})
		} else {
			let mut ids = self.subsystem_ids.write().await;
			ids.insert(id);
			Ok(id)
		}
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
	///
	/// Errors:
	/// - If the subsystem ID is not recognized.
	/// - If a database error occurs.
	pub async fn new_movement(
		&self,
		subsystem_id: SubsystemId,
		movement_kind: String,
	) -> anyhow::Result<MovementId, MovementError> {
		self.db.create_new_movement(
			MovementStatus::Pending,
			&MovementSubsystem {
				name: subsystem_id.as_name().to_string(),
				kind: movement_kind,
			},
			chrono::Local::now(),
		).map_err(|e| MovementError::CreationError { e })
	}

	/// Creates a new [Movement] and returns a [MovementGuard] to manage it. The guard will call
	/// [MovementManager::finish_movement] on drop unless [MovementGuard::success] has already been
	/// called.
	///
	/// See [MovementManager::new_movement] and [MovementGuard::new] for more information.
	///
	/// Parameters:
	/// - subsystem_id: The ID of the subsystem that wishes to start a new movement.
	/// - movement_kind: A descriptor for the type of movement being performed, e.g. "send",
	///   "receive", "round".
	/// - on_drop: Determines what status the movement will be set to when the guard is dropped.
	pub async fn new_guarded_movement(
		self: &Arc<Self>,
		subsystem_id: SubsystemId,
		movement_kind: String,
		on_drop: OnDropStatus,
	) -> anyhow::Result<MovementGuard, MovementError> {
		Ok(MovementGuard::new(
			self.new_movement(subsystem_id, movement_kind).await?, self.clone(), on_drop,
		))
	}

	/// Similar to [MovementManager::new_movement] but it immediately calls
	/// [MovementManager::update_movement] afterward.
	///
	/// Parameters:
	/// - subsystem_id: The ID of the subsystem that wishes to start a new movement.
	/// - movement_kind: A descriptor for the type of movement being performed, e.g. "send",
	///   "receive", "round".
	/// - update: Describes the initial state of the movement.
	///
	/// Errors:
	/// - If the subsystem ID is not recognized.
	/// - If a database error occurs.
	pub async fn new_movement_with_update(
		&self,
		subsystem_id: SubsystemId,
		movement_kind: String,
		update: MovementUpdate,
	) -> anyhow::Result<MovementId, MovementError> {
		let id = self.new_movement(subsystem_id, movement_kind).await?;
		self.update_movement(id, update).await?;
		Ok(id)
	}

	/// Similar to [MovementManager::new_guarded_movement] but it immediately calls
	/// [MovementManager::update_movement] after creating the [Movement].
	///
	/// Parameters:
	/// - subsystem_id: The ID of the subsystem that wishes to start a new movement.
	/// - movement_kind: A descriptor for the type of movement being performed, e.g. "send",
	///   "receive", "round".
	/// - on_drop: Determines what status the movement will be set to when the guard is dropped.
	/// - update: Describes the initial state of the movement.
	///
	/// Errors:
	/// - If the subsystem ID is not recognized.
	/// - If a database error occurs.
	pub async fn new_guarded_movement_with_update(
		self: &Arc<Self>,
		subsystem_id: SubsystemId,
		movement_kind: String,
		on_drop: OnDropStatus,
		update: MovementUpdate,
	) -> anyhow::Result<MovementGuard, MovementError> {
		Ok(MovementGuard::new(
			self.new_movement_with_update(subsystem_id, movement_kind, update).await?,
			self.clone(),
			on_drop,
		))
	}

	/// Creates and marks a [Movement] as finished based on the given parameters. This is useful for
	/// one-shot movements where the details are known at the time of creation, an example would be
	/// when receiving funds asynchronously from a third party.
	///
	/// Parameters:
	/// - subsystem_id: The ID of the subsystem that wishes to start a new movement.
	/// - movement_kind: A descriptor for the type of movement being performed, e.g. "send",
	///   "receive", "round".
	/// - status: The [MovementStatus] to set. This can't be [MovementStatus::Pending].
	/// - details: Contains information about the movement, e.g. what VTXOs were consumed or
	///   produced.
	///
	/// Errors:
	/// - If the subsystem ID is not recognized.
	/// - If [MovementStatus::Pending] is given.
	/// - If a database error occurs.
	pub async fn new_finished_movement(
		&self,
		subsystem_id: SubsystemId,
		movement_kind: String,
		status: MovementStatus,
		details: MovementUpdate,
	) -> anyhow::Result<MovementId, MovementError> {
		if status == MovementStatus::Pending {
			return Err(MovementError::IncorrectPendingStatus);
		}
		let id = self.new_movement(subsystem_id, movement_kind).await?;
		let mut movement = self.db.get_movement_by_id(id)
			.map_err(|e| MovementError::LoadError { id, e })?;
		let at = chrono::Local::now();
		details.apply_to(&mut movement, at);
		movement.status = status;
		movement.time.completed_at = Some(at);
		self.db.update_movement(&movement)
			.map_err(|e| MovementError::PersisterError { id, e })?;
		Ok(id)
	}

	/// Updates a movement with the given parameters.
	///
	/// See also: [MovementManager::new_movement] and [MovementManager::finish_movement]
	///
	/// Parameters:
	/// - id: The ID of the movement previously created by [MovementManager::new_movement].
	/// - update: Specifies properties to set on the movement. `Option` fields will be ignored if
	///   they are `None`. `Some` will result in that particular field being overwritten.
	///
	/// Errors:
	/// - If the [MovementId] is not recognized.
	/// - If a movement is not [MovementStatus::Pending].
	/// - If a database error occurs.
	pub async fn update_movement(
		&self,
		id: MovementId,
		update: MovementUpdate,
	) -> anyhow::Result<(), MovementError> {
		// Ensure the movement is loaded.
		self.load_movement_into_cache(id).await?;

		// Apply the update to the movement.
		update.apply_to(&mut *self.get_movement_lock(id).await?.write().await, chrono::Local::now());

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

	/// Finalizes a movement, setting it to the given [MovementStatus].
	///
	/// See also: [MovementManager::new_movement] and [MovementManager::update_movement]
	///
	/// Parameters:
	/// - id: The ID of the movement previously created by [MovementManager::new_movement].
	/// - new_status: The final [MovementStatus] to set. This can't be [MovementStatus::Pending].
	///
	/// Errors:
	/// - If the movement ID is not recognized.
	/// - If [MovementStatus::Pending] is given.
	/// - If a database error occurs.
	pub async fn finish_movement(
		&self,
		id: MovementId,
		new_status: MovementStatus,
	) -> anyhow::Result<(), MovementError> {
		if new_status == MovementStatus::Pending {
			return Err(MovementError::IncorrectPendingStatus);
		}

		// Ensure the movement is loaded.
		self.load_movement_into_cache(id).await?;

		// Update the status and persist it.
		let lock = self.get_movement_lock(id).await?;
		let mut movement = lock.write().await;
		movement.status = new_status;
		movement.time.completed_at = Some(chrono::Local::now());
		self.db.update_movement(&*movement)
			.map_err(|e| MovementError::PersisterError { id, e })?;
		self.unload_movement_from_cache(id).await
	}

	/// Applies a [MovementUpdate] before finalizing the movement with
	/// [MovementManager::finish_movement].
	///
	/// Parameters:
	/// - id: The ID of the movement previously created by [MovementManager::new_movement].
	/// - new_status: The final [MovementStatus] to set. This can't be [MovementStatus::Pending].
	/// - update: Contains information to apply to the movement before finalizing it.
	///
	/// Errors:
	/// - If the movement ID is not recognized.
	/// - If [MovementStatus::Pending] is given.
	/// - If a database error occurs.
	pub async fn finish_movement_with_update(
		&self,
		id: MovementId,
		new_status: MovementStatus,
		update: MovementUpdate,
	) -> anyhow::Result<(), MovementError> {
		self.update_movement(id, update).await?;
		self.finish_movement(id, new_status).await
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

	async fn load_movement_into_cache(&self, id: MovementId) -> anyhow::Result<(), MovementError> {
		if self.active_movements.read().await.contains_key(&id) {
			return Ok(());
		}
		// Acquire a write lock and check if another thread already loaded the movement.
		let mut movements = self.active_movements.write().await;
		if movements.contains_key(&id) {
			return Ok(());
		}
		let movement = self.db.get_movement_by_id(id)
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
/// See [MovementGuard::new] for more information.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum OnDropStatus {
	/// Marks the [Movement] as [MovementStatus::Canceled].
	Canceled,
	/// Marks the [Movement] as [MovementStatus::Failed].
	Failed,
}

impl From<OnDropStatus> for MovementStatus {
	fn from(status: OnDropStatus) -> Self {
		match status {
			OnDropStatus::Canceled => MovementStatus::Canceled,
			OnDropStatus::Failed => MovementStatus::Failed,
		}
	}
}

/// A RAII helper class to ensure that pending movements get marked as finished in case an error
/// occurs. You can construct a guard for an existing [Movement] with [MovementGuard::new].
/// Alternatively, a [MovementGuard] can be coupled to a movement using
/// [MovementGuard::new].
///
/// When the [MovementGuard] is dropped from the stack, it will finalize the movement according to
/// the configured [OnDropStatus] unless [MovementGuard::success] has already been called.
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
	/// - on_drop: Determines what status the movement will be set to when the guard is dropped.
	pub fn new(
		id: MovementId,
		manager: Arc<MovementManager>,
		on_drop: OnDropStatus,
	) -> Self {
		Self {
			id,
			manager,
			on_drop,
			has_finished: false,
		}
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

	/// Same as [MovementGuard::success] but sets [Movement::status] to [MovementStatus::Canceled].
	pub async fn cancel(&mut self) -> anyhow::Result<(), MovementError> {
		self.stop();
		self.manager.finish_movement(self.id, MovementStatus::Canceled).await
	}

	/// Same as [MovementGuard::success] but sets [Movement::status] to [MovementStatus::Failed].
	pub async fn fail(&mut self) -> anyhow::Result<(), MovementError> {
		self.stop();
		self.manager.finish_movement(self.id, MovementStatus::Failed).await
	}

	/// Finalizes a movement, setting it to [MovementStatus::Successful]. If the [MovementGuard] is
	/// dropped after calling this function, no further changes will be made to the [Movement].
	///
	/// See [MovementManager::finish_movement] for more information.
	pub async fn success(
		&mut self,
	) -> anyhow::Result<(), MovementError> {
		self.stop();
		self.manager.finish_movement(self.id, MovementStatus::Successful).await
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

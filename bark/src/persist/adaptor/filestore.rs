//! Simple file-based storage for testing, built on top of the memory storage adaptor.

use std::path::{Path, PathBuf};

use tokio::fs;

use crate::persist::adaptor::{Query, QueryRange, Record, StorageAdaptor};

use super::memory::MemoryStorageAdaptor;

#[derive(Debug)]
pub struct FileStorageAdaptor {
	file_path: PathBuf,
}

impl FileStorageAdaptor {
	pub async fn open(file_path: impl AsRef<Path>) -> anyhow::Result<Self> {
		let file_path = file_path.as_ref().to_path_buf();
		Ok(Self { file_path })
	}

	pub async fn read(&self) -> anyhow::Result<MemoryStorageAdaptor> {
		let data = match fs::read_to_string(&self.file_path).await {
			Ok(contents) => {
				let records = serde_json::from_str::<Vec<Record>>(&contents)?;

				let mut data = MemoryStorageAdaptor::new();
				for record in records {
					data.put(record).await?;
				}
				data
			}
			Err(e) if e.kind() == std::io::ErrorKind::NotFound => MemoryStorageAdaptor::new(),
			Err(e) => return Err(e.into()),
		};

		Ok(data)
	}

	async fn persist(&self, data: &MemoryStorageAdaptor) -> anyhow::Result<()> {
		let records = data.partitions().values()
			.map(|p| p.values())
			.flatten().collect::<Vec<_>>();
		fs::write(&self.file_path, serde_json::to_string(&records)?).await?;
		Ok(())
	}
}

#[async_trait]
impl StorageAdaptor for FileStorageAdaptor {
	async fn put(&mut self, record: Record) -> anyhow::Result<()> {
		let mut data = self.read().await?;
		data.put(record).await?;
		self.persist(&data).await
	}

	async fn get(&self, partition: u8, pk: &[u8]) -> anyhow::Result<Option<Record>> {
		let data = self.read().await?;
		data.get(partition, pk).await
	}

	async fn delete(&mut self, partition: u8, pk: &[u8]) -> anyhow::Result<Option<Record>> {
		let mut data = self.read().await?;
		let deleted_record = data.delete(partition, pk).await?;
		self.persist(&data).await?;
		Ok(deleted_record)
	}

	async fn query_sorted<R: QueryRange>(&self, query: Query<R>) -> anyhow::Result<Vec<Record>> {
		let data = self.read().await?;
		data.query_sorted(query).await
	}

	async fn get_all(&self, partition: u8) -> anyhow::Result<Vec<Record>> {
		let data = self.read().await?;
		data.get_all(partition).await
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::persist::adaptor::test_suite;

	#[tokio::test]
	async fn file_adaptor_test_suite() {
		let temp_dir = tempfile::tempdir().unwrap();
		let mut storage = FileStorageAdaptor::open(temp_dir.path().join("test.json")).await.unwrap();
		test_suite::run_all(&mut storage).await;
	}
}

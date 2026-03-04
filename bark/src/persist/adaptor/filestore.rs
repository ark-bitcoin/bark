//! Simple file-based storage for testing, built on top of the memory storage adaptor.

use std::path::{Path, PathBuf};

use tokio::fs;

use crate::persist::adaptor::{Query, Record, StorageAdaptor};

use super::memory::MemoryStorageAdaptor;

#[derive(Debug)]
pub struct FileStorageAdaptor {
	file_path: PathBuf,
	data: MemoryStorageAdaptor,
}

impl FileStorageAdaptor {
	pub async fn open(file_path: impl AsRef<Path>) -> anyhow::Result<Self> {
		let file_path = file_path.as_ref().to_path_buf();

		let data = match fs::read_to_string(&file_path).await {
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

		Ok(Self { file_path, data })
	}

	async fn persist(&self) -> anyhow::Result<()> {
		let records = self.data.partitions().values()
			.map(|p| p.values())
			.flatten().collect::<Vec<_>>();
		fs::write(&self.file_path, serde_json::to_string(&records)?).await?;
		Ok(())
	}
}

#[async_trait]
impl StorageAdaptor for FileStorageAdaptor {
	async fn put(&mut self, record: Record) -> anyhow::Result<()> {
		self.data.put(record).await?;
		self.persist().await
	}

	async fn get(&self, partition: u8, pk: &[u8]) -> anyhow::Result<Option<Record>> {
		self.data.get(partition, pk).await
	}

	async fn delete(&mut self, partition: u8, pk: &[u8]) -> anyhow::Result<Option<Record>> {
		let deleted_record = self.data.delete(partition, pk).await?;
		self.persist().await?;
		Ok(deleted_record)
	}

	async fn query(&self, query: Query) -> anyhow::Result<Vec<Record>> {
		self.data.query(query).await
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

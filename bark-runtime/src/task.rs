use std::future::Future;

use crate::MaybeSend;

/// Spawn a task on the current runtime.
///
/// On native platforms, uses `tokio::spawn`.
/// On WASM, uses `wasm_bindgen_futures::spawn_local`.
pub fn spawn<F>(future: F)
where
	F: Future<Output = ()> + MaybeSend + 'static,
{
	#[cfg(not(target_arch = "wasm32"))]
	tokio::spawn(future);

	#[cfg(target_arch = "wasm32")]
	wasm_bindgen_futures::spawn_local(future);
}

#[cfg(test)]
mod test {
	use std::time::Duration;

	use tokio::sync::{mpsc, oneshot};

	use crate::timeout;

	use super::*;

	#[cfg(target_arch = "wasm32")]
	use wasm_bindgen_test::wasm_bindgen_test;
	#[cfg(target_arch = "wasm32")]
	wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

	/// A spawned task runs and its result reaches the spawner.
	#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
	#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
	async fn spawned_task_runs() {
		let (tx, rx) = oneshot::channel();
		spawn(async move {
			tx.send(42).unwrap();
		});

		let received = timeout(Duration::from_secs(5), rx).await
			.expect("the spawned task should have sent its value")
			.expect("the sender should not have been dropped");
		assert_eq!(42, received);
	}

	/// A spawned task keeps running after an await point.
	#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
	#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
	async fn spawned_task_continues_after_awaiting() {
		let (tx, mut rx) = mpsc::channel(2);
		spawn(async move {
			tx.send(1).await.unwrap();
			crate::sleep(Duration::from_millis(10)).await;
			tx.send(2).await.unwrap();
		});

		assert_eq!(Some(1), rx.recv().await);
		assert_eq!(Some(2), rx.recv().await);
	}

	/// Several spawned tasks all run.
	#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
	#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
	async fn all_spawned_tasks_run() {
		let (tx, mut rx) = mpsc::channel(3);
		for i in 0..3 {
			let tx = tx.clone();
			spawn(async move {
				tx.send(i).await.unwrap();
			});
		}
		drop(tx);

		let mut received = Vec::new();
		while let Some(i) = rx.recv().await {
			received.push(i);
		}
		received.sort();
		assert_eq!(vec![0, 1, 2], received);
	}
}


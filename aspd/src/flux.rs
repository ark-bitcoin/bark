
use std::borrow::Borrow;
use std::ops;
use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use ark::VtxoId;


#[derive(Debug)]
struct VtxosInFluxInner {
	vtxos: HashSet<VtxoId>,
}

/// Simple locking structure to keep track of vtxos that are currently in flux.
#[derive(Debug, Clone)]
pub struct VtxosInFlux {
	inner: Arc<Mutex<VtxosInFluxInner>>,
}

impl VtxosInFlux {
	pub fn new() -> VtxosInFlux {
		VtxosInFlux {
			inner: Arc::new(Mutex::new(VtxosInFluxInner {
				vtxos: HashSet::new(),
			}))
		}
	}

	/// Create a new [VtxoFluxLock] without any vtxos locked.
	pub fn empty_lock(&self) -> VtxoFluxLock {
		VtxoFluxLock {
			inner: VtxoFluxLockInner {
				flux: self,
				vtxos: HashSet::new(),
			}
		}
	}

	/// Lock the given vtxos and return a lock. The vtxos remain
	/// in flux until either [release_all] is called on the lock, or
	/// the lock is dropped.
	pub fn lock<V>(
		&self,
		ids: impl IntoIterator<Item = V> + Clone,
	) -> Result<VtxoFluxLock, VtxoId>
	where
		V: Borrow<VtxoId>,
	{
		self.atomic_check_put(ids.clone())?;
		let mut ret = self.empty_lock();
		ret.add_locked(ids.into_iter().map(|v| *v.borrow()));
		Ok(ret)
	}

	fn atomic_check_put<V>(&self, ids: impl IntoIterator<Item = V>) -> Result<(), VtxoId>
	where
		V: Borrow<VtxoId>,
	{
		let ids = ids.into_iter();
		let mut buf = Vec::with_capacity(ids.size_hint().0);
		let mut inner = self.inner.lock().unwrap();
		for id in ids {
			let id = *id.borrow();
			if !inner.vtxos.insert(id) {
				// abort
				for take in buf {
					inner.vtxos.remove(&take);
				}
				return Err(id);
			}
			buf.push(id);
		}
		Ok(())
	}

	fn release<V: Borrow<VtxoId>>(&self, ids: impl IntoIterator<Item = V>) {
		let mut inner = self.inner.lock().unwrap();
		for id in ids {
			inner.vtxos.remove(id.borrow());
		}
	}

	#[cfg(test)]
	fn vtxos(&self) -> Vec<VtxoId> {
		let mut ret = self.inner.lock().unwrap().vtxos.iter().copied().collect::<Vec<_>>();
		ret.sort();
		ret
	}
}

#[derive(Debug)]
struct VtxoFluxLockInner<F: Borrow<VtxosInFlux> = VtxosInFlux> {
	flux: F,
	vtxos: HashSet<VtxoId>,
}

impl<F: Borrow<VtxosInFlux>> VtxoFluxLockInner<F> {
	fn add_locked(&mut self, vtxos: impl IntoIterator<Item = VtxoId>) {
		self.vtxos.extend(vtxos);
	}

	fn release_all(&mut self) {
		if !self.vtxos.is_empty() {
			let drain = self.vtxos.drain();
			self.flux.borrow().release(drain);
		}
	}

	fn absorb(&mut self, mut other: VtxoFluxLock) {
		self.vtxos.extend(other.inner.vtxos.drain());
	}
}

impl<F: Borrow<VtxosInFlux>> ops::Drop for VtxoFluxLockInner<F> {
	fn drop(&mut self) {
		self.release_all();
	}
}

/// Represents a sort-of "lock" on vtxos that are in flux.
///
/// Used to automatically release the vtxos from the flux lock when
/// this structure is dropped.
#[derive(Debug)]
pub struct VtxoFluxLock<'a> {
	inner: VtxoFluxLockInner<&'a VtxosInFlux>,
}

impl<'a> VtxoFluxLock<'a> {
	/// Add new vtxos that are already marked as in-flux.
	pub fn add_locked(&mut self, vtxos: impl IntoIterator<Item = VtxoId>) {
		self.inner.add_locked(vtxos)
	}

	pub fn into_owned(mut self) -> OwnedVtxoFluxLock {
		// we need to drain the vtxos so that they aren't released on Drop
		let vtxos = self.inner.vtxos.drain().collect();
		OwnedVtxoFluxLock {
			inner: VtxoFluxLockInner {
				flux: self.inner.flux.clone(),
				vtxos,
			},
		}
	}
}

/// Owned variant of [VtxoFluxLock].
#[derive(Debug)]
pub struct OwnedVtxoFluxLock {
	inner: VtxoFluxLockInner<VtxosInFlux>,
}

impl OwnedVtxoFluxLock {
	/// Release and drop all vtxos from the lock.
	pub fn release_all(&mut self) {
		self.inner.release_all()
	}

	/// Absorb all locked vtxos into this one.
	pub fn absorb(&mut self, other: VtxoFluxLock) {
		self.inner.absorb(other)
	}

	#[cfg(test)]
	pub fn dummy() -> Self {
		Self {
			inner: VtxoFluxLockInner {
				flux: VtxosInFlux::new(),
				vtxos: HashSet::new(),
			}
		}
	}
}

#[cfg(test)]
mod test {
	use super::*;

	fn gen_vtxoid(i: u8) -> VtxoId {
		VtxoId::from_slice(&[i; 36]).unwrap()
	}

	#[test]
	fn test_in_flux() {
		let flux = VtxosInFlux::new();
		let vtxos = (0..10).map(gen_vtxoid).collect::<Vec<_>>();

		flux.atomic_check_put([vtxos[0], vtxos[1]]).unwrap();
		flux.atomic_check_put([vtxos[2], vtxos[3]]).unwrap();
		assert_eq!(4, flux.inner.lock().unwrap().vtxos.len());
		flux.atomic_check_put([vtxos[0], vtxos[4]]).unwrap_err();
		assert_eq!(4, flux.inner.lock().unwrap().vtxos.len());
		flux.release([vtxos[0]]);
		assert_eq!(3, flux.inner.lock().unwrap().vtxos.len());
		flux.atomic_check_put([vtxos[0], vtxos[4]]).unwrap();
		assert_eq!(5, flux.inner.lock().unwrap().vtxos.len());

		flux.atomic_check_put([vtxos[1], vtxos[5]]).unwrap_err();
		assert_eq!(5, flux.inner.lock().unwrap().vtxos.len());
		assert!(!flux.inner.lock().unwrap().vtxos.contains(&vtxos[5]));
	}

	#[test]
	fn test_flux_lock() {
		let flux = VtxosInFlux::new();
		let vtxos = (0..10).map(gen_vtxoid).collect::<Vec<_>>();

		let l1 = flux.lock([vtxos[0], vtxos[1]]).unwrap();
		let _l2 = flux.lock([vtxos[2], vtxos[3]]).unwrap();
		assert_eq!(vec![vtxos[0], vtxos[1], vtxos[2], vtxos[3]], flux.vtxos());
		flux.lock([vtxos[0], vtxos[4]]).unwrap_err();
		assert_eq!(vec![vtxos[0], vtxos[1], vtxos[2], vtxos[3]], flux.vtxos());
		drop(l1);
		assert_eq!(vec![vtxos[2], vtxos[3]], flux.vtxos());
		let _l3 = flux.lock([vtxos[0], vtxos[4]]).unwrap();
		assert_eq!(vec![vtxos[0], vtxos[2], vtxos[3], vtxos[4]], flux.vtxos());

		flux.lock(&[vtxos[2], vtxos[5]]).unwrap_err();
		assert_eq!(vec![vtxos[0], vtxos[2], vtxos[3], vtxos[4]], flux.vtxos());
		assert!(!flux.vtxos().contains(&vtxos[5]));
	}
}

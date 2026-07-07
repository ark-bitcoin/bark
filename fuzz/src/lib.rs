//! Shared fuzz harness — models captaind's per-request fault boundary.
//!
//! captaind uses `panic = "unwind"` with a log-only hook and serves each gRPC
//! request in its own tonic task, so a panic in a handler unwinds that one
//! request without taking the server down. A bare honggfuzz target instead files
//! any panic as a process crash, over-stating severity and halting on the first
//! contained panic. [`harness::guard`](harness::guard) applies the server's
//! boundary:
//!
//! * An unwinding panic in the target body is a *contained* robustness finding:
//!   recorded (logged when `HFUZZ_LOG_CONTAINED=1`), never filed as a crash,
//!   execution continues. Still a real no-panic-on-untrusted-input bug to fix.
//! * Conditions that crash regardless of unwind isolation — `abort()`, a panic
//!   across the secp256k1 C FFI, double-panic, stack overflow, OOM — are not
//!   catchable, so honggfuzz still files them.
//! * Oracle violations (round-trips, determinism, refinement, "must verify"),
//!   raised via [`oracle_assert!`]/[`oracle_assert_eq!`]/[`oracle_unreachable!`]
//!   and [`harness::OracleResultExt::oracle`], are always re-raised as crashes.

pub mod harness {
	use std::cell::{Cell, RefCell};
	use std::panic::{self, AssertUnwindSafe};
	use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

	/// Number of contained (unwinding, non-oracle) panics swallowed so far.
	static CONTAINED_COUNT: AtomicU64 = AtomicU64::new(0);
	static HOOK_INSTALLED: AtomicBool = AtomicBool::new(false);

	thread_local! {
		/// Set by [`oracle_fail`] just before it panics, so [`guard`] can tell a
		/// fuzzer-asserted invariant violation apart from a library panic on
		/// untrusted input.
		static ORACLE_VIOLATION: Cell<bool> = const { Cell::new(false) };
		/// Captured `file:line:col: message` of the most recent panic, set by our
		/// hook so [`guard`] can log a precise location without the default hook's
		/// per-iteration backtrace spam.
		static LAST_PANIC: RefCell<Option<String>> = const { RefCell::new(None) };
	}

	fn install_hook_once() {
		if HOOK_INSTALLED.swap(true, Ordering::SeqCst) {
			return;
		}
		panic::set_hook(Box::new(|info| {
			let loc = info.location()
				.map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()))
				.unwrap_or_else(|| "<unknown location>".to_string());
			let msg = panic_message(info.payload());
			LAST_PANIC.with(|c| *c.borrow_mut() = Some(format!("{loc}: {msg}")));
			// Stay quiet otherwise: contained panics can fire millions of times in
			// a campaign, and `guard` prints its own structured line for the cases
			// that matter.
		}));
	}

	fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
		if let Some(s) = payload.downcast_ref::<&str>() {
			(*s).to_string()
		} else if let Some(s) = payload.downcast_ref::<String>() {
			s.clone()
		} else {
			"<non-string panic payload>".to_string()
		}
	}

	/// Run one fuzz iteration behind the server's per-request fault boundary.
	///
	/// See the crate docs. `target` is the target name, used only for log lines.
	pub fn guard<F: FnOnce(&[u8])>(target: &str, data: &[u8], f: F) {
		install_hook_once();
		ORACLE_VIOLATION.with(|c| c.set(false));

		let result = panic::catch_unwind(AssertUnwindSafe(|| f(data)));
		let payload = match result {
			Ok(()) => return,
			Err(payload) => payload,
		};

		let was_oracle = ORACLE_VIOLATION.with(|c| c.replace(false));
		let detail = LAST_PANIC.with(|c| c.borrow_mut().take())
			.unwrap_or_else(|| panic_message(&*payload));

		if was_oracle {
			// A fuzzer invariant broke. This is a genuine finding regardless of
			// the server's unwind isolation, so propagate it: honggfuzz files the
			// crash.
			eprintln!("ORACLE-VIOLATION target={target} {detail} input={}", hex(data));
			panic::resume_unwind(payload);
		}

		// A contained library panic: the server would unwind this single request
		// and keep serving (see crate docs). This is ALWAYS contained — the
		// harness is unconditionally server-realistic, so a panic here is never
		// filed as a crash. Record it and carry on. (The genuinely server-fatal
		// conditions — abort, secp256k1 C-FFI abort, double-panic, stack
		// overflow, OOM — are uncatchable here and still crash the process.)
		let _ = payload;
		let n = CONTAINED_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
		if std::env::var_os("HFUZZ_LOG_CONTAINED").is_some() {
			eprintln!(
				"CONTAINED-PANIC #{n} target={target} (server survives via unwind \
				 isolation; robustness bug, not a DoS) {detail} input={}",
				hex(data),
			);
		}
		// File sink: honggfuzz swallows the child's stderr, so when
		// HFUZZ_CONTAINED_FILE is set, append the panic location there for
		// fuzz.sh's --replay to read. Best-effort, non-panicking (we are inside a
		// caught panic). A single O_APPEND write() is atomic, so concurrent
		// threads can't interleave; the "CONTAINED\t" sentinel lets the reader
		// drop malformed lines.
		if let Some(path) = std::env::var_os("HFUZZ_CONTAINED_FILE") {
			use std::io::Write as _;
			if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
				let _ = f.write_all(format!("CONTAINED\t{detail}\n").as_bytes());
			}
		}

		// Input sink: honggfuzz -M is blind to contained panics and can prune a
		// reproducer that adds no coverage. When HFUZZ_CONTAINED_DIR is set, save
		// the triggering bytes once per distinct panic location so `fuzz.sh
		// --minimize` can re-inject them. Best-effort, non-panicking; `create_new`
		// gives first-writer-wins without locks.
		if let Some(dir) = std::env::var_os("HFUZZ_CONTAINED_DIR") {
			use std::io::Write as _;
			// `detail` is "file:line:col: msg"; keep just the location for the name.
			let loc = detail.split_once(": ").map(|(l, _)| l).unwrap_or(&detail);
			let name: String = loc.chars()
				.map(|c| if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') { c } else { '_' })
				.collect();
			if !name.is_empty() {
				let mut path = std::path::PathBuf::from(dir);
				path.push(name);
				if let Ok(mut f) = std::fs::OpenOptions::new().write(true).create_new(true).open(&path) {
					let _ = f.write_all(data);
				}
			}
		}
	}

	/// Total contained panics swallowed this process (for end-of-run reporting).
	pub fn contained_panic_count() -> u64 {
		CONTAINED_COUNT.load(Ordering::Relaxed)
	}

	/// Fail a fuzzer correctness invariant. Always reported by [`guard`] (it is
	/// not a contained library panic). Use for properties the *server* does not
	/// check but the fuzzer does: encoding round-trips, determinism, refinement.
	#[track_caller]
	pub fn oracle_fail(msg: impl std::fmt::Display) -> ! {
		ORACLE_VIOLATION.with(|c| c.set(true));
		panic!("oracle violation: {msg}");
	}

	/// Unwrap a `Result` as a fuzzer invariant (the operation *must* succeed).
	#[track_caller]
	pub fn oracle_ok<T, E: std::fmt::Debug>(result: Result<T, E>, msg: &str) -> T {
		match result {
			Ok(v) => v,
			Err(e) => oracle_fail(format_args!("{msg}: {e:?}")),
		}
	}

	/// Extension to raise a `Result`/`Option` failure through the oracle channel
	/// (always reported by [`guard`]). Use in place of `.expect(..)` for
	/// post-decode operations that must not fail on a valid object.
	pub trait OracleResultExt {
		type Output;
		fn oracle(self, msg: &str) -> Self::Output;
	}

	impl<T, E: std::fmt::Debug> OracleResultExt for Result<T, E> {
		type Output = T;
		#[track_caller]
		fn oracle(self, msg: &str) -> T {
			oracle_ok(self, msg)
		}
	}

	impl<T> OracleResultExt for Option<T> {
		type Output = T;
		#[track_caller]
		fn oracle(self, msg: &str) -> T {
			match self {
				Some(v) => v,
				None => oracle_fail(msg),
			}
		}
	}

	fn hex(data: &[u8]) -> String {
		use std::fmt::Write;
		let mut s = String::with_capacity(data.len() * 2);
		for b in data {
			let _ = write!(s, "{b:02x}");
		}
		s
	}
}

/// `assert!` that reports through the oracle channel (see
/// [`harness::oracle_fail`]).
#[macro_export]
macro_rules! oracle_assert {
	($cond:expr $(,)?) => {
		if !$cond { $crate::harness::oracle_fail("assertion failed"); }
	};
	($cond:expr, $($msg:tt)+) => {
		if !$cond { $crate::harness::oracle_fail(::std::format_args!($($msg)+)); }
	};
}

/// `assert_eq!` that reports through the oracle channel (see
/// [`harness::oracle_fail`]).
#[macro_export]
macro_rules! oracle_assert_eq {
	($a:expr, $b:expr $(,)?) => {{
		let (a, b) = (&$a, &$b);
		if a != b {
			$crate::harness::oracle_fail(::std::format_args!(
				"assertion failed: {:?} != {:?}", a, b));
		}
	}};
	($a:expr, $b:expr, $($msg:tt)+) => {{
		let (a, b) = (&$a, &$b);
		if a != b {
			$crate::harness::oracle_fail(::std::format_args!(
				"{}: {:?} != {:?}", ::std::format_args!($($msg)+), a, b));
		}
	}};
}

/// `unreachable!`-style check that reports through the oracle channel.
#[macro_export]
macro_rules! oracle_unreachable {
	() => { $crate::harness::oracle_fail("entered unreachable code") };
	($($msg:tt)+) => { $crate::harness::oracle_fail(::std::format_args!($($msg)+)) };
}

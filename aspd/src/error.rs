
use std::fmt::{self, Write};
use std::borrow::Borrow;
use std::error::Error as StdError;

use anyhow::Context;


pub trait AnyhowErrorExt: Borrow<anyhow::Error> {
	fn full_msg(&self) -> String {
		let mut ret = String::new();
		for (i, e) in self.borrow().chain().enumerate() {
			if i == 0 {
				write!(ret, "{}", e).expect("write to buf");
			} else {
				write!(ret, ": {}", e).expect("write to buf");
			}
		}
		ret
	}
}
impl AnyhowErrorExt for anyhow::Error {}


/// An error type to add context to anyhow to indicate any form
/// of incorrect user input.
pub struct BadArgument {
	context: Box<dyn fmt::Display + Send + Sync + 'static>,
}

impl BadArgument {
	pub fn new(context: impl fmt::Display + Send + Sync + 'static) -> BadArgument {
		BadArgument {
			context: Box::new(context),
		}
	}
}

impl fmt::Debug for BadArgument {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		fmt::Display::fmt(self, f)
	}
}

impl fmt::Display for BadArgument {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		write!(f, "bad user input: {}", self.context)
	}
}

impl StdError for BadArgument {}

/// An error type to add context to anyhow to indicate any form
/// of incorrect user input.
pub struct NotFound {
	ids: Vec<String>,
	context: Box<dyn fmt::Display + Send + Sync + 'static>,
}

impl NotFound {
	pub fn new(
		ids: impl IntoIterator<Item = impl fmt::Display>,
		context: impl fmt::Display + Send + Sync + 'static,
	) -> NotFound {
		NotFound {
			ids: ids.into_iter().map(|i| i.to_string()).collect(),
			context: Box::new(context),
		}
	}

	pub fn identifiers(&self) -> &Vec<String> {
		&self.ids
	}
}

impl fmt::Debug for NotFound {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		fmt::Display::fmt(self, f)
	}
}

impl fmt::Display for NotFound {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		write!(f, "not found: {}", self.context)
	}
}

impl StdError for NotFound {}


/// Return an [mod@anyhow] error tagged with [BadArgument].
macro_rules! badarg {
	($($arg:tt)*) => {
		Err($crate::anyhow::Error::from($crate::error::BadArgument::new(format!($($arg)*))))
	};
}
pub(crate) use badarg;

/// Return an [mod@anyhow] error tagged with [NotFound].
macro_rules! not_found {
	($ids:expr, $($arg:tt)*) => {
		Err($crate::anyhow::Error::from($crate::error::NotFound::new($ids, format!($($arg)*))))
	};
}
#[allow(unused)]
pub(crate) use not_found;


/// Extension trait for adding aspd-specific error info.
pub trait ContextExt<T, E>: Context<T, E> {
	/// Tag an error with [BadArgument].
	fn badarg<C>(self, context: C) -> anyhow::Result<T>
		where C: fmt::Display + Send + Sync + 'static;

	/// Tag an error with [BadArgument].
	#[allow(unused)]
	fn with_badarg<C, F>(self, f: F) -> anyhow::Result<T>
	where
		C: fmt::Display + Send + Sync + 'static,
		F: FnOnce() -> C;

	/// Tag an error with [NotFound].
	fn not_found<I, V, C>(self, ids: V, context: C) -> anyhow::Result<T>
	where
		V: IntoIterator<Item = I>,
		I: fmt::Display,
		C: fmt::Display + Send + Sync + 'static;

	/// Tag an error with [NotFound].
	#[allow(unused)]
	fn with_not_found<I, V, C, F>(self, ids: V, f: F) -> anyhow::Result<T>
	where
		V: IntoIterator<Item = I>,
		I: fmt::Display,
		C: fmt::Display + Send + Sync + 'static,
		F: FnOnce() -> C;
}

impl<R, T, E> ContextExt<T, E> for R
where
	R: Context<T, E>,
{
	fn badarg<C>(self, context: C) -> anyhow::Result<T>
	where
		C: fmt::Display + Send + Sync + 'static,
	{
		self.context(BadArgument::new(context))
	}

	fn with_badarg<C, F>(self, f: F) -> anyhow::Result<T>
	where
		C: fmt::Display + Send + Sync + 'static,
		F: FnOnce() -> C,
	{
		self.with_context(|| BadArgument::new(f()))
	}

	fn not_found<I, V, C>(self, ids: V, context: C) -> anyhow::Result<T>
	where
		V: IntoIterator<Item = I>,
		I: fmt::Display,
		C: fmt::Display + Send + Sync + 'static,
	{
		self.context(NotFound::new(ids, context))
	}

	fn with_not_found<I, V, C, F>(self, ids: V, f: F) -> anyhow::Result<T>
	where
		V: IntoIterator<Item = I>,
		I: fmt::Display,
		C: fmt::Display + Send + Sync + 'static,
		F: FnOnce() -> C,
	{
		self.with_context(|| NotFound::new(ids, f()))
	}
}

#[cfg(test)]
mod test {
	use super::*;

	struct TestError;
	impl fmt::Debug for TestError {
		fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
			write!(f, "TestErrorDebug")
		}
	}
	impl fmt::Display for TestError {
		fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
			write!(f, "TestErrorDisplay")
		}
	}
	impl StdError for TestError {}

	#[test]
	fn error_downcast() {
		let e = Result::<(), _>::Err(TestError)
			.context("inner_context")
			.badarg("badarg1_context")
			.badarg("badarg2_context")
			.context("outer_context")
			.unwrap_err();
		let b = e.downcast_ref::<BadArgument>().unwrap();
		assert_eq!(format!("{}", b), "bad user input: badarg2_context");
		assert_eq!(format!("{:?}", b), "bad user input: badarg2_context");

		let r: anyhow::Result<()> = badarg!("badarg")
			.context("inner_context")
			.context("outer_context");
		let e = r.unwrap_err();
		let b = e.downcast_ref::<BadArgument>().unwrap();
		assert_eq!(format!("{}", b), "bad user input: badarg");
		assert_eq!(format!("{:?}", b), "bad user input: badarg");

		// both
		let e = Result::<(), _>::Err(TestError)
			.context("inner_context")
			.badarg("badarg_context")
			.context("middle_context")
			.not_found([42], "notfound_context")
			.context("outer_context")
			.unwrap_err();
		let _ = e.downcast_ref::<BadArgument>().unwrap();
		let nf = e.downcast_ref::<NotFound>().unwrap();
		assert_eq!(nf.identifiers(), &vec!["42".to_owned()])
	}

	#[test]
	fn print_format() {
		let e = Result::<(), _>::Err(TestError)
			.context("inner_context")
			.badarg("badarg_context")
			.context("outer_context")
			.unwrap_err();

		let display = format!("{}", e);
		assert_eq!(display, "outer_context");

		let debug = format!("{:?}", e);
		assert!(debug.starts_with(
			"outer_context\n\nCaused by:\n    0: bad user input: badarg_context\n    \
				1: inner_context\n    2: TestErrorDisplay",
		), "actual: {}", debug);
	}

	#[test]
	fn macros() {
		let _: anyhow::Result<()> = badarg!("bla: {}", 15);
		let _: anyhow::Result<()> = not_found!([12], "bla: {}", 15);
	}
}

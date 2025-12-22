/// A utility to keep secrets safe and prevent us from
/// accidentally writing them into the logs.
///
/// Note, that anyone who has access to the [Secret] can
/// access the inner value. This only prevents a developer
/// from accidentally writing the secret to logs when doing
/// a [std::fmt::Debug]-print.
///
/// Wraps a [Secret] and ensures and hides it in [std::fmt::Debug]-logs.
///
/// # Usage
/// The developer can access the secret using [leak_ref] or [leak_owned].
/// You should only do this when passing the secret to an external library.
///
/// ```
/// # fn connect(user: &str, pass: &str) {
/// #    // This is a sturb
/// # }
/// use server::secret::Secret;
///
/// let user = String::from("my-user");
/// let pass = Secret::new(String::from("my-password"));
///
/// connect(&user, pass.leak_ref());
/// ```
///
/// # Debug formatted strings are safe
///
/// ```
/// use server::secret::Secret;
/// use tracing::debug;
///
/// #[derive(Debug)]
/// struct Config {
///     user: String,
///     pass: Secret<String>
/// }
///
/// let config = Config {
///    user: String::from("user") ,
///    pass: Secret::new(String::from("my-secret-password")),
/// };
///
/// // The secret will be redacted when writing the debug log
/// debug!("Initiating connection with config {:?}", &config)
/// ````

use serde::{Serialize, Deserialize};


pub struct Secret<T> {
	inner: T,
}

impl<T> Secret<T> {
	pub fn new(inner: T) -> Self {
		Self { inner }
	}

	pub fn leak_mut(&mut self) -> &mut T {
		&mut self.inner
	}

	pub fn leak_ref(&self) -> &T {
		&self.inner
	}

	pub fn leak_owned(self) -> T {
		self.inner
	}
}

impl<T> std::fmt::Debug for Secret<T> {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "[redacted]")
	}
}

impl<T: Clone> Clone for Secret<T> {
	fn clone(&self) -> Self {
		Self {
			inner: self.inner.clone()
		}
	}
}

impl <T: Copy> Copy for Secret<T> {}

impl<T: PartialEq> PartialEq for Secret<T> {
	fn eq(&self, other: &Self) -> bool {
		T::eq(&self.inner, &other.inner)
	}

	fn ne(&self, other: &Self) -> bool {
		T::ne(&self.inner, &other.inner)
	}
}

impl<T: Eq> Eq for Secret<T> {}

impl<T: Serialize> Serialize for Secret<T> {
	fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
		self.inner.serialize(serializer)
	}
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for Secret<T> {
	fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
		T::deserialize(deserializer).map(|x| Secret::new(x))
	}
}

impl<T> From<T> for Secret<T> {
	fn from(value: T) -> Self {
		Secret::new(value)
	}
}

#[cfg(test)]
mod test {

	use super::Secret;
	use std::io::Write;

	#[test]
	fn debug_format_is_redacted() {
		let secret = Secret::new(String::from("my-secret"));

		let mut vec = Vec::new();
		write!(vec, "{:?}", &secret).expect("Can write to Vec");
		assert_eq!(String::from_utf8(vec).unwrap(), "[redacted]");
	}

	#[test]
	fn cannot_pretty_print_by_accident() {
		let secret = Secret::new(String::from("my-secret"));

		let mut vec = Vec::new();
		write!(vec, "{:#?}", &secret).expect("Can write to vec");
		assert_eq!(String::from_utf8(vec).unwrap(), "[redacted]");
	}

	// #[test]
	// #[ignore = "Does not compile"]
	// fn cannot_display_by_accident() {
	// 	let secret = Secret::new(String::from("my-secret"));

	// 		let mut vec = Vec::new();
	// 		write!(vec, "{}", &secret).expect("Can write to vec");
	// 		assert_eq!(String::from_utf8(vec).unwrap(), "[redacted]");
	// }
}

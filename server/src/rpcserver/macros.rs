
macro_rules! badarg {
	($($arg:tt)*) => { return $crate::error::badarg!($($arg)*).to_status(); };
}
pub(crate) use badarg;

macro_rules! not_found {
	($($arg:tt)*) => { return $crate::error::not_found!($($arg)*).to_status(); };
}
pub(crate) use not_found;

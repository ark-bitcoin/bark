use postgres_types::ToSql;

/// Convert a slice of references to `ToSql` to an iterator of `ToSql`.
///
/// Taken from [tokio-postgres](https://github.com/sfackler/rust-postgres/blob/e1cd6beef3a1530642a2abaf3584d6bd8ed6cd45/tokio-postgres/src/lib.rs#L257)
pub(crate) fn slice_iter<'a>(
	s: &'a [&'a (dyn ToSql + Sync)],
) -> impl ExactSizeIterator<Item = &'a dyn ToSql> + 'a {
	s.iter().map(|s| *s as _)
}
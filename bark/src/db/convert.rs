use rusqlite::Result;
use rusqlite::types::{ToSql, ToSqlOutput};

use crate::VtxoState;

impl ToSql for VtxoState {
	fn to_sql(&self) -> Result<ToSqlOutput<'_>> {
		self.as_str().to_sql()
	}
}


# Database Schema

When you need the full DDL (table definitions, indexes, constraints) for the
server or bark database, read the corresponding `schema.sql` file:

- **Server**: `server/schema.sql`
- **Bark**: `bark/schema.sql`

These files contain the complete, up-to-date schema in a single place.

**Do not** aggregate or piece together the migration files in
`server/src/database/migrations/` (or the bark equivalent) to reconstruct the
schema. The migrations are incremental changes and reading them all is slow,
error-prone, and unnecessary.
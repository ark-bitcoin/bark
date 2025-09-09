# Postgres guidelines

We trust in the quality of engineers working on the Ark Server. 

These are just guidelines and can be broken.
If you break any of these guidelines.
You should at least leave a comment to motivate your choice.

## Schema design

### Naming conventions

1. Table names should be singular
**Do**: `CREATE TABLE round ...`
**Don't**: `CREATE TABLE rounds ...`
**Why**: Be consistent
2. Primary keys are named `id`
**Don't** Repeat the table-name for a primary key
`CREATE TABLE round (round_id BIGSERIAL primary key)`
**Why**: Readability

### Data types

1. Use a synthetic primary key
  **Don't**: Use a SHA-256 hash or protocol id
  `CREATE TABLE round (id bytea primary key)`
  **Why**: Keeps all schema's consistent and it doesn't trigger data-engineers
2. Store pubkeys and hashes as hex
  **Why** We can query pubkeys when debugging
3. Be careful with binary dumps
  **Why** Once you dump binary data in the database you have 
  to ensure we can manage backwards compatibility.
  **Not Okay**: Serializing an external dependency
  **Okay**: Put well-defined protocol encodings in the database
  Eg: bitcoin transaction, VTXO-policy, ...
  **Okay**: Use a specific struct for database encoding and write
  unit tests to ensure backward compatibility.
5. Avoid boolean types. Usually, there is more info to convery.
  **Do**: Create a `deleted_at` column timestamp
  **Don't**: Create a `deleted` bool column

## Binary dumps

## Writing queries

1. Avoid using wildcard selectors
**Do**: `SELECT (id, created_at) FROM round`
**Don't**: `SELECT * FROM round`
**Why**: Be explicit
2. Use the `RETURNING` statement when inserting or updating values
**Do** `INSERT INTO table (values) VALUES (values) RETURNING`
**Don't**: Insert the data in the first query and request the id in a follow-up query

## Keeping history

For some tables, it is useful to have a history

**Do**: Create a table named `vtxo_state` and `vtxo_state_history`.
The `vtxo_state_history` is updated using database triggers.

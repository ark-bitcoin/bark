-- Rename the existing block table to captaind_block
ALTER TABLE block RENAME TO captaind_block;

-- Rename the primary key constraint to match the new table name
ALTER INDEX block_pkey RENAME TO captaind_block_pkey;

-- Recreate the index with the new table name
DROP INDEX IF EXISTS idx_block_hash;
CREATE INDEX idx_captaind_block_hash ON captaind_block(hash);

-- Create watchmand_block table with identical schema
CREATE TABLE watchmand_block (
    height BIGINT PRIMARY KEY,
    hash TEXT NOT NULL
);

CREATE INDEX idx_watchmand_block_hash ON watchmand_block(hash);

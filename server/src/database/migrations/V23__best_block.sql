CREATE TABLE block (
    height BIGINT PRIMARY KEY,
    hash TEXT NOT NULL
);

CREATE INDEX idx_block_hash ON block(hash);

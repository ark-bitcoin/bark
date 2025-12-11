-- MAILBOX SEQUENCE
CREATE TABLE checkpoint_state (
  type_id     INTEGER PRIMARY KEY CHECK (type_id = 1),
  last_time   BIGINT  NOT NULL,   -- last used timestamp (ms)
  last_counter INT    NOT NULL,   -- counter for same ms
  max_time    BIGINT  NOT NULL    -- highest clock value ever seen
);

INSERT INTO checkpoint_state (type_id, last_time, last_counter, max_time)
VALUES (1, 0, 0, 0);

CREATE OR REPLACE FUNCTION next_checkpoint()
RETURNS BIGINT AS $$
DECLARE
  now_ms      BIGINT;
  rec         RECORD;
  new_time    BIGINT;
  new_counter INT;
  resp        BIGINT;
BEGIN
  now_ms := EXTRACT(EPOCH FROM clock_timestamp()) * 1000;

  LOOP
    -- Lock the specific sequence row
    SELECT last_time, last_counter, max_time
      INTO rec
    FROM checkpoint_state
    WHERE type_id = 1
    FOR UPDATE;

    -- If a row doesn't exist, create it (should never happen, but it's safe)
    IF NOT FOUND THEN
      INSERT INTO checkpoint_state (id, last_time, last_counter, max_time)
      VALUES (1, 0, 0, 0)
      RETURNING last_time, last_counter, max_time INTO rec;
    END IF;

    -- Use max_time to resist clock rollback
    new_time := GREATEST(now_ms, rec.max_time);

    IF new_time > rec.last_time THEN
      new_counter := 0;
    ELSE
      new_counter := rec.last_counter + 1;

      -- Prevent overflow: 20-bit counter = 1,048,575
      IF new_counter >= 1048576 THEN
        PERFORM pg_sleep(0.001);
        CONTINUE;
      END IF;
    END IF;

    -- Build 64-bit ID: [44-bit time] [20-bit counter]
    resp := (new_time << 20) | new_counter;

    -- Update atomically
    UPDATE checkpoint_state
    SET
      last_time = new_time,
      last_counter = new_counter,
      max_time = GREATEST(max_time, now_ms)
    WHERE type_id = 1 AND
      last_time = rec.last_time AND
      last_counter = rec.last_counter AND
      max_time = rec.max_time;

    EXIT WHEN FOUND;
  END LOOP;

  RETURN resp;
END;
$$ LANGUAGE plpgsql;

CREATE TABLE vtxo_mailbox (
  id BIGSERIAL PRIMARY KEY,
  unblinded_mailbox_id TEXT NOT NULL,
  vtxo_id TEXT NOT NULL REFERENCES vtxo(vtxo_id),
  vtxo BYTEA NOT NULL,
  checkpoint BIGINT NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL
);

CREATE INDEX vtxo_mailbox_unblinded_mailbox_id_checkpoint_ix ON vtxo_mailbox(unblinded_mailbox_id, checkpoint);
CREATE UNIQUE INDEX vtxo_mailbox_vtxo_id ON vtxo_mailbox(vtxo_id);

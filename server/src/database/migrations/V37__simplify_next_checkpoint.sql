-- Simplify next_checkpoint() function.
-- The advisory lock in Rust code already serializes all mailbox writes,
-- so we don't need internal SELECT FOR UPDATE or optimistic locking.

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

  -- Read current state (advisory lock in caller ensures exclusive access)
  SELECT last_time, last_counter, max_time
    INTO rec
  FROM checkpoint_state
  WHERE type_id = 1;

  -- Use max_time to resist clock rollback
  new_time := GREATEST(now_ms, rec.max_time);

  IF new_time > rec.last_time THEN
    new_counter := 0;
  ELSE
    new_counter := rec.last_counter + 1;

    -- Prevent overflow: 20-bit counter = 1,048,575
    -- With advisory lock serialization, this should never happen in practice
    IF new_counter >= 1048576 THEN
      RAISE EXCEPTION 'checkpoint counter overflow - too many writes in same millisecond';
    END IF;
  END IF;

  -- Build 64-bit ID: [44-bit time] [20-bit counter]
  resp := (new_time << 20) | new_counter;

  -- Update state (advisory lock in caller ensures no concurrent modification)
  UPDATE checkpoint_state
  SET
    last_time = new_time,
    last_counter = new_counter,
    max_time = GREATEST(max_time, now_ms)
  WHERE type_id = 1;

  RETURN resp;
END;
$$ LANGUAGE plpgsql;

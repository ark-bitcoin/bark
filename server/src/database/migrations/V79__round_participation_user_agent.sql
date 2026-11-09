-- `user_agent` is the raw `x-user-agent` of the client that submitted the
-- participation, as for the lightning tables in V66. The round picks a
-- delegated participation up later, off the RPC task, and reads the client
-- back from here to attribute it in telemetry. NULL when the client sent no
-- header, and for rows created before this migration.

ALTER TABLE round_participation ADD COLUMN user_agent TEXT;

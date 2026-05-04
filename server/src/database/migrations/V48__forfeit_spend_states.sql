-- Add round-forfeit spend state
ALTER TYPE spend_state ADD VALUE 'round-forfeit';

-- Add offboard-forfeit spend state
ALTER TYPE spend_state ADD VALUE 'offboard-forfeit';

-- Add offboard-connector spend state
ALTER TYPE spend_state ADD VALUE 'offboard-connector';
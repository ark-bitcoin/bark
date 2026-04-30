-- Add pool spend state
ALTER TYPE spend_state ADD VALUE 'pool';

-- Add htlc-recv-unclaimed spend state
ALTER TYPE spend_state ADD VALUE 'htlc-recv-unclaimed';
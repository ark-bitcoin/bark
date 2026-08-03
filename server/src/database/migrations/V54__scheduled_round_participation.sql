-- Block height at which a delegated round participation should be included
-- in a round; NULL means the next round.

ALTER TABLE round_participation ADD COLUMN scheduled_height INTEGER;

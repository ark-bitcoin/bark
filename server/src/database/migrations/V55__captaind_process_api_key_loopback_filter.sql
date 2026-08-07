-- V19 seeded the built-in captaind API keys with names inverted relative to
-- the source constants: CAPTAIND_API_KEY (uuid = 2) is the daemon process key
-- and CAPTAIND_CLI_API_KEY (uuid = 3) is the CLI key. Swap the names so the DB
-- matches the code, and tighten the CLI key filters to loopback-only.
--
-- clock_timestamp() is used instead of CURRENT_TIMESTAMP because migrations
-- run inside a single transaction: CURRENT_TIMESTAMP is fixed at transaction
-- start, which would make the second UPDATE on either row hit the
-- integration_api_key trigger's "updated_at must be updated" check.

UPDATE integration_api_key
SET name = 'captaind_swap_tmp', updated_at = clock_timestamp()
WHERE api_key = '00000000-0000-0000-0000-000000000002';

UPDATE integration_api_key
SET name = 'captaind_cli', updated_at = clock_timestamp()
WHERE api_key = '00000000-0000-0000-0000-000000000003';

UPDATE integration_api_key
SET name = 'captaind_process', updated_at = clock_timestamp()
WHERE api_key = '00000000-0000-0000-0000-000000000002';

UPDATE integration_api_key
SET filters = '{"ip": ["127.0.0.1"], "dns": ["localhost"]}',
    updated_at = clock_timestamp()
WHERE api_key = '00000000-0000-0000-0000-000000000003';

-- Tighten the captaind_process API key (00000000-0000-0000-0000-000000000003)
-- loopback-only.
--

UPDATE integration_api_key
SET filters = '{"ip": ["127.0.0.1"], "dns": ["localhost"]}',
    updated_at = CURRENT_TIMESTAMP
WHERE api_key = '00000000-0000-0000-0000-000000000003'

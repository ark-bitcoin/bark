-- Create hardcoded captaind integration and its process/CLI API keys to track operations done by captaind

INSERT INTO integration(name, created_at)
VALUES('captaind', CURRENT_TIMESTAMP)
ON CONFLICT DO NOTHING;

INSERT INTO integration_api_key(name, api_key,
    filters,
    integration_id, expires_at, created_at, updated_at)
SELECT 'captaind_cli', '00000000-0000-0000-0000-000000000002',
    '{"ip": ["127.0.0.1"], "dns": ["localhost"]}',
    id, '2999-01-01 00:00:00.000000', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
FROM integration
WHERE name='captaind'
ON CONFLICT DO NOTHING;

INSERT INTO integration_api_key(name, api_key,
    filters,
    integration_id, expires_at, created_at, updated_at)
SELECT 'captaind_process', '00000000-0000-0000-0000-000000000003',
    '{"ip": [], "dns": []}',
    id, '2999-01-01 00:00:00.000000', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
FROM integration
WHERE name='captaind'
ON CONFLICT DO NOTHING;

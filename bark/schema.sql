CREATE TABLE migrations (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				created_at DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now')),
				value INTEGER NOT NULL
			);
CREATE TABLE sqlite_sequence(name,seq);
CREATE TABLE bark_vtxo (
				id TEXT PRIMARY KEY,
				expiry_height INTEGER,
				amount_sat INTEGER,
				raw_vtxo BLOB,
				created_at DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now'))
			, received_in TEXT NOT NULL REFERENCES bark_movement(id), spent_in TEXT REFERENCES bark_movement(id));
CREATE TABLE bark_vtxo_state (
				id INTEGER PRIMARY KEY,
				created_at DATETIME NOT NULL DEFAULT  (strftime('%Y-%m-%d %H:%M:%f', 'now')),
				vtxo_id TEXT REFERENCES bark_vtxo(id),
				state_kind TEXT NOT NULL,
				state BLOB NOT NULL
			);
CREATE TABLE bark_ark_sync (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				sync_height INTEGER,
				created_at DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now'))
			);
CREATE VIEW most_recent_vtxo_state
				(id, last_updated_at, vtxo_id, state_kind, state)
			AS
			WITH most_recent AS (SELECT MAX(id) as id FROM bark_vtxo_state GROUP BY vtxo_id)
			SELECT
					most_recent.id,
					vs.created_at,
					vs.vtxo_id,
					vs.state_kind,
					vs.state
					FROM most_recent JOIN bark_vtxo_state as vs
						ON vs.id = most_recent.id
/* most_recent_vtxo_state(id,last_updated_at,vtxo_id,state_kind,state) */;
CREATE VIEW vtxo_view
			AS SELECT
				v.id,
				v.expiry_height,
				v.amount_sat,
				vs.state_kind,
				vs.state,
				v.raw_vtxo,
				v.created_at,
				vs.last_updated_at
			FROM bark_vtxo as v
			JOIN most_recent_vtxo_state as vs
				ON v.id = vs.vtxo_id
/* vtxo_view(id,expiry_height,amount_sat,state_kind,state,raw_vtxo,created_at,last_updated_at) */;
CREATE TABLE bark_config (
				id TEXT PRIMARY KEY,
				created_at DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now')),

				server_address TEXT NOT NULL,
				esplora_address ,
				bitcoind_address ,
				bitcoind_cookiefile ,
				bitcoind_user ,
				bitcoind_pass ,
				vtxo_refresh_expiry_threshold INTEGER NOT NULL
			, fallback_fee_kwu INTEGER);
CREATE TABLE bark_properties (
				id TEXT PRIMARY KEY,
				created_at DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now')),

				network TEXT NOT NULL,
				fingerprint TEXT NOT NULL
			);
CREATE TABLE bark_movement (
				id INTEGER PRIMARY KEY,
				fees_sat INTEGER NOT NULL,
				created_at DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now'))
			, kind TEXT NOT NULL);
CREATE TABLE bark_recipient (
				id INTEGER PRIMARY KEY,
				movement REFERENCES bark_movement(id),
				recipient TEXT NOT NULL,
				amount_sat INTEGER NOT NULL
			);
CREATE VIEW movement_view AS
				SELECT
					*,
					(
						SELECT JSON_GROUP_ARRAY(JSON_OBJECT(
							'id', bark_vtxo.id,
							'amount_sat', bark_vtxo.amount_sat
						)) FROM bark_vtxo WHERE bark_vtxo.spent_in = bark_movement.id
					) AS spends,
					(
						SELECT JSON_GROUP_ARRAY(JSON_OBJECT(
							'id', bark_vtxo.id,
							'amount_sat', bark_vtxo.amount_sat
						)) FROM bark_vtxo WHERE bark_vtxo.received_in = bark_movement.id
					) AS receives,
					(
						SELECT JSON_GROUP_ARRAY(JSON_OBJECT(
							'recipient', bark_recipient.recipient,
							'amount_sat', bark_recipient.amount_sat
						)) FROM bark_recipient WHERE bark_recipient.movement = bark_movement.id
					) AS recipients
				FROM bark_movement
/* movement_view(id,fees_sat,created_at,kind,spends,receives,recipients) */;
CREATE TABLE bark_lightning_receive (
			payment_hash BLOB NOT NULL PRIMARY KEY,
			preimage BLOB NOT NULL UNIQUE,
			preimage_revealed_at TIMESTAMP,
			invoice TEXT NOT NULL,
			created_at DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now'))
		);
CREATE TABLE bark_exit_states (
				vtxo_id TEXT PRIMARY KEY,
				state TEXT NOT NULL,
				history TEXT NOT NULL
			);
CREATE TABLE bark_vtxo_key (
				public_key TEXT NOT NULL PRIMARY KEY,
				idx INTEGER NOT NULL UNIQUE
			);
CREATE TABLE bark_exit_child_transactions (
				exit_id TEXT PRIMARY KEY,
				child_tx BLOB NOT NULL,
				tx_origin TEXT NOT NULL
			);

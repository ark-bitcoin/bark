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
			, received_in TEXT NOT NULL REFERENCES bark_movement(id), spent_in TEXT REFERENCES bark_movement(id), locked_in_round_attempt_id INTEGER REFERENCES bark_round_attempt(id));
CREATE TABLE bark_vtxo_state (
				id INTEGER PRIMARY KEY,
				created_at DATETIME NOT NULL DEFAULT  (strftime('%Y-%m-%d %H:%M:%f', 'now')),
				vtxo_id TEXT REFERENCES bark_vtxo(id),
				state_kind TEXT NOT NULL,
				state BLOB NOT NULL
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
						SELECT JSON_GROUP_ARRAY(hex(bark_vtxo.raw_vtxo))
						FROM bark_vtxo
						WHERE bark_vtxo.spent_in = bark_movement.id
					) AS spends,
					(
						SELECT JSON_GROUP_ARRAY(hex(bark_vtxo.raw_vtxo))
						FROM bark_vtxo
						WHERE bark_vtxo.received_in = bark_movement.id
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
CREATE TABLE bark_round_attempt (
				id INTEGER PRIMARY KEY,
				round_seq INTEGER NOT NULL,
				attempt_seq INTEGER NOT NULL,
				status TEXT NOT NULL,
				round_txid TEXT UNIQUE,
				round_tx TEXT,
				payment_requests BLOB NOT NULL,
				offboard_requests BLOB NOT NULL,
				cosign_keys BLOB,
				secret_nonces BLOB,
				vtxos BLOB,
				vtxo_tree BLOB,
				created_at DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now')),
				updated_at DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now')),
				UNIQUE(round_seq, attempt_seq)
			);
CREATE TABLE vtxo_forfeited_in_round (
				id INTEGER PRIMARY KEY,
				double_spend_txid TEXT,
				vtxo_id TEXT NOT NULL REFERENCES bark_vtxo(id),
				round_attempt_id INTEGER NOT NULL REFERENCES bark_round_attempt(id),
				UNIQUE(round_attempt_id, vtxo_id)
			);
CREATE VIEW vtxo_view
			AS SELECT
				v.id,
				v.expiry_height,
				v.amount_sat,
				v.raw_vtxo,
				v.created_at,
				v.locked_in_round_attempt_id,
				vs.state,
				vs.state_kind,
				vs.last_updated_at
			FROM bark_vtxo as v
			JOIN most_recent_vtxo_state as vs
				ON v.id = vs.vtxo_id
/* vtxo_view(id,expiry_height,amount_sat,raw_vtxo,created_at,locked_in_round_attempt_id,state,state_kind,last_updated_at) */;
CREATE VIEW round_view
			AS SELECT
				r.id,
				r.round_seq,
				r.attempt_seq,
				r.status,
				r.round_txid,
				r.round_tx,
				r.payment_requests,
				r.offboard_requests,
				r.cosign_keys,
				r.secret_nonces,
				r.vtxos,
				r.vtxo_tree,
				r.updated_at,
				(
					SELECT JSON_GROUP_ARRAY(hex(bark_vtxo.raw_vtxo))
					FROM bark_vtxo
					WHERE bark_vtxo.locked_in_round_attempt_id = r.id
				) AS inputs,
				(
					SELECT JSON_GROUP_ARRAY(JSON_OBJECT(
						'round_attempt_id', f.round_attempt_id,
						'vtxo_id', f.vtxo_id,
						'double_spend_txid', f.double_spend_txid
					)) FROM vtxo_forfeited_in_round as f WHERE f.round_attempt_id = r.id
				) AS vtxo_forfeited_in_round
			FROM bark_round_attempt as r
/* round_view(id,round_seq,attempt_seq,status,round_txid,round_tx,payment_requests,offboard_requests,cosign_keys,secret_nonces,vtxos,vtxo_tree,updated_at,inputs,vtxo_forfeited_in_round) */;
CREATE TABLE bark_synced_round (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				round_txid TEXT,
				created_at DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now'))
			);

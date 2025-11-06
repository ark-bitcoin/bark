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
CREATE TABLE vtxo_forfeited_in_round (
				id INTEGER PRIMARY KEY,
				double_spend_txid TEXT,
				vtxo_id TEXT NOT NULL REFERENCES bark_vtxo(id),
				round_attempt_id INTEGER NOT NULL REFERENCES bark_round_attempt(id),
				UNIQUE(round_attempt_id, vtxo_id)
			);
CREATE TABLE bark_pending_board (
				id INTEGER PRIMARY KEY,
				vtxo_id TEXT NOT NULL REFERENCES bark_vtxo(id) ON DELETE CASCADE,
				funding_tx TEXT NOT NULL UNIQUE,
				created_at DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now')),
				UNIQUE (vtxo_id)
			);
CREATE TABLE bark_pending_lightning_send (
				id INTEGER PRIMARY KEY,
				invoice TEXT NOT NULL UNIQUE,
				payment_hash TEXT NOT NULL UNIQUE,
				amount_sats INTEGER NOT NULL,
				htlc_vtxo_ids TEXT NOT NULL,
				created_at DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now'))
			);
CREATE TABLE bark_round_state (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				state BLOB NOT NULL
			);
CREATE VIEW vtxo_view
			AS SELECT
				v.id,
				v.expiry_height,
				v.amount_sat,
				v.raw_vtxo,
				v.created_at,
				vs.state,
				vs.state_kind,
				vs.last_updated_at
			FROM bark_vtxo as v
			JOIN most_recent_vtxo_state as vs
				ON v.id = vs.vtxo_id
/* vtxo_view(id,expiry_height,amount_sat,raw_vtxo,created_at,state,state_kind,last_updated_at) */;
CREATE TABLE bark_recovered_past_round (
				funding_txid TEXT PRIMARY KEY,
				past_round_state BLOB NOT NULL
			);
CREATE TABLE bark_pending_lightning_receive (
				payment_hash TEXT NOT NULL PRIMARY KEY,
				preimage TEXT NOT NULL UNIQUE,
				invoice TEXT NOT NULL,
				htlc_recv_cltv_delta INTEGER NOT NULL,
				htlc_vtxo_ids TEXT,
				preimage_revealed_at DATETIME,
				created_at DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now'))
			);

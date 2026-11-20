-- A store is registered by the Ark address that receives its payments.
CREATE TABLE store (
	id BIGSERIAL PRIMARY KEY,
	name TEXT NOT NULL,
	ark_address TEXT NOT NULL UNIQUE,
	claim_pubkey TEXT NOT NULL,
	mailbox_id TEXT NOT NULL,
	onchain_descriptor TEXT NOT NULL,
	-- The next derivation index to reserve for an on-chain sale.
	next_onchain_index BIGINT NOT NULL DEFAULT 0,
	currency TEXT NOT NULL,
	onchain_min_sat BIGINT NOT NULL,
	lightning_address_name TEXT UNIQUE,
	registration_signature TEXT NOT NULL,
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- A paired terminal. Only the hash of its token is stored.
CREATE TABLE device (
	id BIGSERIAL PRIMARY KEY,
	store_id BIGINT NOT NULL REFERENCES store(id),
	name TEXT NOT NULL,
	token_hash TEXT NOT NULL UNIQUE,
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	revoked_at TIMESTAMPTZ
);
CREATE INDEX device_store_id_idx ON device (store_id);

-- A single-use pairing code.
CREATE TABLE invite (
	id BIGSERIAL PRIMARY KEY,
	store_id BIGINT NOT NULL REFERENCES store(id),
	code_hash TEXT NOT NULL UNIQUE,
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	expires_at TIMESTAMPTZ NOT NULL,
	redeemed_at TIMESTAMPTZ,
	device_id BIGINT REFERENCES device(id)
);

CREATE TABLE owner_challenge (
	id BIGSERIAL PRIMARY KEY,
	ark_address TEXT NOT NULL,
	challenge TEXT NOT NULL UNIQUE,
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	expires_at TIMESTAMPTZ NOT NULL,
	used_at TIMESTAMPTZ
);

CREATE TABLE owner_session (
	id BIGSERIAL PRIMARY KEY,
	store_id BIGINT NOT NULL REFERENCES store(id),
	token_hash TEXT NOT NULL UNIQUE,
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	expires_at TIMESTAMPTZ NOT NULL
);

CREATE TYPE sale_state AS ENUM ('open', 'in-progress', 'paid', 'expired', 'canceled');
CREATE TYPE payment_rail AS ENUM ('lightning', 'ark', 'onchain');

CREATE TABLE sale (
	id BIGSERIAL PRIMARY KEY,
	-- The identifier the API shows. It is random so that sales cannot be
	-- enumerated.
	public_id TEXT NOT NULL UNIQUE,
	store_id BIGINT NOT NULL REFERENCES store(id),
	-- No device for a Lightning address payment.
	device_id BIGINT REFERENCES device(id),
	amount_sat BIGINT NOT NULL,
	fiat_amount TEXT,
	currency TEXT,
	btc_price TEXT,
	memo TEXT,
	state sale_state NOT NULL DEFAULT 'open',
	paid_rail payment_rail,
	received_sat BIGINT NOT NULL DEFAULT 0,
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	expires_at TIMESTAMPTZ NOT NULL,
	paid_at TIMESTAMPTZ,
	updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX sale_store_id_idx ON sale (store_id, id DESC);
CREATE INDEX sale_watch_idx ON sale (state, expires_at);

-- One row per payment rail offered for a sale.
CREATE TABLE sale_payment (
	id BIGSERIAL PRIMARY KEY,
	sale_id BIGINT NOT NULL REFERENCES sale(id),
	rail payment_rail NOT NULL,
	payment_hash TEXT UNIQUE,
	invoice TEXT,
	onchain_index BIGINT,
	onchain_address TEXT,
	-- The amount this rail delivered: the invoice amount once delivered, or
	-- the sum of the confirmed outputs to the address.
	received_sat BIGINT NOT NULL DEFAULT 0,
	-- The amount in unconfirmed outputs to the address.
	pending_sat BIGINT NOT NULL DEFAULT 0,
	vtxo_ids TEXT[],
	txids TEXT[],
	settled_at TIMESTAMPTZ,
	UNIQUE (sale_id, rail)
);

--
-- PostgreSQL database dump
--


SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: lightning_htlc_subscription_status; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.lightning_htlc_subscription_status AS ENUM (
    'created',
    'accepted',
    'settled',
    'cancelled'
);


--
-- Name: lightning_payment_status; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.lightning_payment_status AS ENUM (
    'requested',
    'submitted',
    'succeeded',
    'failed'
);


--
-- Name: token_status; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.token_status AS ENUM (
    'unused',
    'used',
    'abused',
    'disabled'
);


--
-- Name: token_type; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.token_type AS ENUM (
    'single-use-board'
);


--
-- Name: wallet_kind; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.wallet_kind AS ENUM (
    'rounds',
    'forfeits'
);


--
-- Name: integration_api_key_update_trigger(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.integration_api_key_update_trigger() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    INSERT INTO integration_api_key_history (
        id, name, api_key, filters, integration_id, expires_at,
        created_at, updated_at, deleted_at
    ) VALUES (
        OLD.id, OLD.name, OLD.api_key, OLD.filters, OLD.integration_id, OLD.expires_at,
        OLD.created_at, OLD.updated_at, OLD.deleted_at
    );

    IF NEW.updated_at = OLD.updated_at THEN
        RAISE EXCEPTION 'updated_at must be updated';
    END IF;

    IF NEW.created_at <> OLD.created_at THEN
        RAISE EXCEPTION 'created_at cannot be updated';
    END IF;

    RETURN NEW;
END;
$$;


--
-- Name: integration_token_config_update_trigger(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.integration_token_config_update_trigger() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    INSERT INTO integration_token_config_history (
        id, type, maximum_open_tokens, active_seconds,
        integration_id,
        created_at, updated_at, deleted_at
    ) VALUES (
        OLD.id, OLD.type, OLD.maximum_open_tokens, OLD.active_seconds,
        OLD.integration_id,
        OLD.created_at, OLD.updated_at, OLD.deleted_at
    );

    IF NEW.updated_at = OLD.updated_at THEN
        RAISE EXCEPTION 'updated_at must be updated';
    END IF;

    IF NEW.created_at <> OLD.created_at THEN
        RAISE EXCEPTION 'created_at cannot be updated';
    END IF;

    RETURN NEW;
END;
$$;


--
-- Name: integration_token_update_trigger(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.integration_token_update_trigger() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    INSERT INTO integration_token_history (
        id, token, type, status, filters, integration_id,
        expires_at,
        created_at, created_by_api_key_id, updated_at, updated_by_api_key_id
    ) VALUES (
        OLD.id, OLD.token, OLD.type, OLD.status, OLD.filters, OLD.integration_id,
        OLD.expires_at,
        OLD.created_at, OLD.created_by_api_key_id, OLD.updated_at, OLD.updated_by_api_key_id
    );

    IF NEW.updated_at = OLD.updated_at THEN
        RAISE EXCEPTION 'updated_at must be updated';
    END IF;

    IF NEW.created_at <> OLD.created_at THEN
        RAISE EXCEPTION 'created_at cannot be updated';
    END IF;

    IF NEW.created_by_api_key_id <> OLD.created_by_api_key_id THEN
        RAISE EXCEPTION 'created_by_api_key_id cannot be updated';
    END IF;

    RETURN NEW;
END;
$$;


--
-- Name: lightning_htlc_subscription_update_trigger(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.lightning_htlc_subscription_update_trigger() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    INSERT INTO lightning_htlc_subscription_history (
        id, lightning_invoice_id, lightning_node_id,
        status, created_at, updated_at
    ) VALUES (
        OLD.id, OLD.lightning_invoice_id, OLD.lightning_node_id,
        OLD.status, OLD.created_at, OLD.updated_at
    );

    IF NEW.updated_at = OLD.updated_at THEN
        RAISE EXCEPTION 'updated_at must be updated';
    END IF;

    IF NEW.created_at <> OLD.created_at THEN
        RAISE EXCEPTION 'created_at cannot be updated';
    END IF;

    RETURN NEW;
END;
$$;


--
-- Name: lightning_invoice_update_trigger(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.lightning_invoice_update_trigger() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    INSERT INTO lightning_invoice_history (
        id, invoice, payment_hash, final_amount_msat, preimage,
        created_at, updated_at
    ) VALUES (
        OLD.id, OLD.invoice, OLD.payment_hash, OLD.final_amount_msat, OLD.preimage,
        OLD.created_at, OLD.updated_at
    );

    IF NEW.updated_at = OLD.updated_at THEN
        RAISE EXCEPTION 'updated_at must be updated';
    END IF;

    IF NEW.created_at <> OLD.created_at THEN
        RAISE EXCEPTION 'created_at cannot be updated';
    END IF;

    RETURN NEW;
END;
$$;


--
-- Name: lightning_node_update_trigger(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.lightning_node_update_trigger() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    INSERT INTO lightning_node_history (
        id, pubkey, payment_created_index, payment_updated_index,
        created_at, updated_at
    ) VALUES (
        OLD.id, OLD.pubkey, OLD.payment_created_index, OLD.payment_updated_index,
        OLD.created_at, OLD.updated_at
    );

    IF NEW.updated_at = OLD.updated_at THEN
        RAISE EXCEPTION 'updated_at must be updated';
    END IF;

    IF NEW.created_at <> OLD.created_at THEN
        RAISE EXCEPTION 'created_at cannot be updated';
    END IF;

    RETURN NEW;
END;
$$;


--
-- Name: lightning_payment_attempt_update_trigger(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.lightning_payment_attempt_update_trigger() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    INSERT INTO lightning_payment_attempt_history (
        id, lightning_invoice_id, lightning_node_id, amount_msat,
        status, error, created_at, updated_at
    ) VALUES (
        OLD.id, OLD.lightning_invoice_id, OLD.lightning_node_id,
        OLD.amount_msat, OLD.status, OLD.error, OLD.created_at, OLD.updated_at
    );

    IF NEW.updated_at = OLD.updated_at THEN
        RAISE EXCEPTION 'updated_at must be updated';
    END IF;

    IF NEW.created_at <> OLD.created_at THEN
        RAISE EXCEPTION 'created_at cannot be updated';
    END IF;

    RETURN NEW;
END;
$$;


--
-- Name: vtxo_update_trigger(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.vtxo_update_trigger() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    INSERT INTO vtxo_history (
        id, vtxo_id, vtxo, expiry, oor_spent_txid, forfeit_state, forfeit_round_id, board_swept_at,
        created_at, updated_at
    ) VALUES (
        OLD.id, OLD.vtxo_id, OLD.vtxo, OLD.expiry, OLD.oor_spent_txid, OLD.forfeit_state, OLD.forfeit_round_id, OLD.board_swept_at,
        OLD.created_at, OLD.updated_at
    );

    IF NEW.updated_at = OLD.updated_at THEN
        RAISE EXCEPTION 'updated_at must be updated';
    END IF;

    IF NEW.created_at <> OLD.created_at THEN
        RAISE EXCEPTION 'created_at cannot be updated';
    END IF;

    RETURN NEW;
END;
$$;


--
-- Name: arkoor_mailbox; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.arkoor_mailbox (
    id bigint NOT NULL,
    pubkey bytea NOT NULL,
    vtxo_id bigint NOT NULL,
    vtxo bytea NOT NULL,
    arkoor_package_id bytea NOT NULL,
    processed_at timestamp with time zone,
    created_at timestamp with time zone NOT NULL
);


--
-- Name: arkoor_mailbox_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.arkoor_mailbox_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: arkoor_mailbox_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.arkoor_mailbox_id_seq OWNED BY public.arkoor_mailbox.id;


--
-- Name: bitcoin_transaction; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.bitcoin_transaction (
    id bigint NOT NULL,
    txid text NOT NULL,
    tx bytea NOT NULL,
    created_at timestamp with time zone NOT NULL
);


--
-- Name: bitcoin_transaction_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

ALTER TABLE public.bitcoin_transaction ALTER COLUMN id ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME public.bitcoin_transaction_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);


--
-- Name: ephemeral_tweak; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ephemeral_tweak (
    id bigint NOT NULL,
    pubkey text NOT NULL,
    tweak bytea NOT NULL,
    created_at timestamp with time zone NOT NULL,
    expires_at timestamp with time zone NOT NULL
);


--
-- Name: ephemeral_tweak_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.ephemeral_tweak_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: ephemeral_tweak_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.ephemeral_tweak_id_seq OWNED BY public.ephemeral_tweak.id;


--
-- Name: integration; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.integration (
    id bigint NOT NULL,
    name text NOT NULL,
    created_at timestamp with time zone NOT NULL,
    deleted_at timestamp with time zone
);


--
-- Name: integration_api_key; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.integration_api_key (
    id bigint NOT NULL,
    name text NOT NULL,
    api_key text NOT NULL,
    filters text,
    integration_id bigint NOT NULL,
    created_at timestamp with time zone NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    deleted_at timestamp with time zone
);


--
-- Name: integration_api_key_history; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.integration_api_key_history (
    id bigint NOT NULL,
    name text NOT NULL,
    api_key text NOT NULL,
    filters text,
    integration_id bigint NOT NULL,
    created_at timestamp with time zone NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    deleted_at timestamp with time zone,
    history_created_at timestamp with time zone DEFAULT (CURRENT_TIMESTAMP AT TIME ZONE 'UTC'::text) NOT NULL
);


--
-- Name: integration_api_key_integration_api_key_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.integration_api_key_integration_api_key_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: integration_api_key_integration_api_key_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.integration_api_key_integration_api_key_id_seq OWNED BY public.integration_api_key.id;


--
-- Name: integration_integration_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.integration_integration_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: integration_integration_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.integration_integration_id_seq OWNED BY public.integration.id;


--
-- Name: integration_token; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.integration_token (
    id bigint NOT NULL,
    token text NOT NULL,
    type public.token_type NOT NULL,
    status public.token_status NOT NULL,
    filters text,
    integration_id bigint NOT NULL,
    created_at timestamp with time zone NOT NULL,
    created_by_api_key_id bigint NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    updated_by_api_key_id bigint NOT NULL
);


--
-- Name: integration_token_config; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.integration_token_config (
    id bigint NOT NULL,
    type public.token_type NOT NULL,
    maximum_open_tokens integer NOT NULL,
    active_seconds integer NOT NULL,
    integration_id bigint NOT NULL,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    deleted_at timestamp with time zone
);


--
-- Name: integration_token_config_history; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.integration_token_config_history (
    id bigint NOT NULL,
    type public.token_type NOT NULL,
    maximum_open_tokens integer NOT NULL,
    active_seconds integer NOT NULL,
    integration_id bigint NOT NULL,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    deleted_at timestamp with time zone,
    history_created_at timestamp with time zone DEFAULT (CURRENT_TIMESTAMP AT TIME ZONE 'UTC'::text) NOT NULL
);


--
-- Name: integration_token_config_integration_token_config_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.integration_token_config_integration_token_config_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: integration_token_config_integration_token_config_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.integration_token_config_integration_token_config_id_seq OWNED BY public.integration_token_config.id;


--
-- Name: integration_token_history; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.integration_token_history (
    id bigint NOT NULL,
    token text NOT NULL,
    type public.token_type NOT NULL,
    status public.token_status NOT NULL,
    filters text,
    integration_id bigint NOT NULL,
    created_at timestamp with time zone NOT NULL,
    created_by_api_key_id bigint NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    updated_by_api_key_id bigint NOT NULL,
    history_created_at timestamp with time zone DEFAULT (CURRENT_TIMESTAMP AT TIME ZONE 'UTC'::text) NOT NULL
);


--
-- Name: integration_token_integration_token_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.integration_token_integration_token_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: integration_token_integration_token_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.integration_token_integration_token_id_seq OWNED BY public.integration_token.id;


--
-- Name: lightning_htlc_subscription; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.lightning_htlc_subscription (
    id bigint NOT NULL,
    lightning_invoice_id bigint NOT NULL,
    lightning_node_id bigint NOT NULL,
    status public.lightning_htlc_subscription_status NOT NULL,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL
);


--
-- Name: lightning_htlc_subscription_history; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.lightning_htlc_subscription_history (
    id bigint NOT NULL,
    lightning_invoice_id bigint NOT NULL,
    lightning_node_id bigint NOT NULL,
    status public.lightning_htlc_subscription_status NOT NULL,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    history_created_at timestamp with time zone DEFAULT (CURRENT_TIMESTAMP AT TIME ZONE 'UTC'::text) NOT NULL
);


--
-- Name: lightning_htlc_subscription_lightning_htlc_subscription_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.lightning_htlc_subscription_lightning_htlc_subscription_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: lightning_htlc_subscription_lightning_htlc_subscription_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.lightning_htlc_subscription_lightning_htlc_subscription_id_seq OWNED BY public.lightning_htlc_subscription.id;


--
-- Name: lightning_invoice; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.lightning_invoice (
    id bigint NOT NULL,
    invoice text NOT NULL,
    payment_hash bytea NOT NULL,
    final_amount_msat bigint,
    preimage bytea,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL
);


--
-- Name: lightning_invoice_history; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.lightning_invoice_history (
    id bigint NOT NULL,
    invoice text NOT NULL,
    payment_hash bytea NOT NULL,
    final_amount_msat bigint,
    preimage bytea,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    history_created_at timestamp with time zone DEFAULT (CURRENT_TIMESTAMP AT TIME ZONE 'UTC'::text) NOT NULL
);


--
-- Name: lightning_invoice_lightning_invoice_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.lightning_invoice_lightning_invoice_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: lightning_invoice_lightning_invoice_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.lightning_invoice_lightning_invoice_id_seq OWNED BY public.lightning_invoice.id;


--
-- Name: lightning_node; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.lightning_node (
    id bigint NOT NULL,
    pubkey bytea NOT NULL,
    payment_created_index bigint NOT NULL,
    payment_updated_index bigint NOT NULL,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL
);


--
-- Name: lightning_node_history; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.lightning_node_history (
    id bigint NOT NULL,
    pubkey bytea NOT NULL,
    payment_created_index bigint NOT NULL,
    payment_updated_index bigint NOT NULL,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    history_created_at timestamp with time zone DEFAULT (CURRENT_TIMESTAMP AT TIME ZONE 'UTC'::text) NOT NULL
);


--
-- Name: lightning_node_lightning_node_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.lightning_node_lightning_node_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: lightning_node_lightning_node_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.lightning_node_lightning_node_id_seq OWNED BY public.lightning_node.id;


--
-- Name: lightning_payment_attempt; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.lightning_payment_attempt (
    id bigint NOT NULL,
    lightning_invoice_id bigint NOT NULL,
    lightning_node_id bigint NOT NULL,
    amount_msat bigint NOT NULL,
    status public.lightning_payment_status NOT NULL,
    error text,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL
);


--
-- Name: lightning_payment_attempt_history; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.lightning_payment_attempt_history (
    id bigint NOT NULL,
    lightning_invoice_id bigint NOT NULL,
    lightning_node_id bigint NOT NULL,
    amount_msat bigint NOT NULL,
    status public.lightning_payment_status NOT NULL,
    error text,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    history_created_at timestamp with time zone DEFAULT (CURRENT_TIMESTAMP AT TIME ZONE 'UTC'::text) NOT NULL
);


--
-- Name: lightning_payment_attempt_lightning_payment_attempt_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.lightning_payment_attempt_lightning_payment_attempt_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: lightning_payment_attempt_lightning_payment_attempt_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.lightning_payment_attempt_lightning_payment_attempt_id_seq OWNED BY public.lightning_payment_attempt.id;


--
-- Name: refinery_schema_history; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.refinery_schema_history (
    version integer NOT NULL,
    name character varying(255),
    applied_on character varying(255),
    checksum character varying(255)
);


--
-- Name: round; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.round (
    id bigint NOT NULL,
    seq bigint NOT NULL,
    funding_txid text NOT NULL,
    funding_tx bytea NOT NULL,
    signed_tree bytea NOT NULL,
    nb_input_vtxos integer NOT NULL,
    connector_key bytea NOT NULL,
    expiry integer NOT NULL,
    swept_at timestamp with time zone,
    created_at timestamp with time zone NOT NULL
);


--
-- Name: round_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.round_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: round_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.round_id_seq OWNED BY public.round.id;


--
-- Name: sweep; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sweep (
    id bigint NOT NULL,
    txid text NOT NULL,
    tx bytea NOT NULL,
    confirmed_at timestamp with time zone,
    abandoned_at timestamp with time zone,
    created_at timestamp with time zone NOT NULL
);


--
-- Name: sweep_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.sweep_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: sweep_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.sweep_id_seq OWNED BY public.sweep.id;


--
-- Name: vtxo; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.vtxo (
    id bigint NOT NULL,
    vtxo_id text NOT NULL,
    vtxo bytea NOT NULL,
    expiry integer NOT NULL,
    oor_spent_txid text,
    forfeit_state bytea,
    forfeit_round_id bigint,
    board_swept_at timestamp with time zone,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL
);


--
-- Name: vtxo_history; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.vtxo_history (
    id bigint NOT NULL,
    vtxo_id text NOT NULL,
    vtxo bytea NOT NULL,
    expiry integer NOT NULL,
    oor_spent_txid text,
    forfeit_state bytea,
    forfeit_round_id bigint,
    board_swept_at timestamp with time zone,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    history_created_at timestamp with time zone DEFAULT (CURRENT_TIMESTAMP AT TIME ZONE 'UTC'::text) NOT NULL
);


--
-- Name: vtxo_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.vtxo_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: vtxo_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.vtxo_id_seq OWNED BY public.vtxo.id;


--
-- Name: wallet_changeset; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.wallet_changeset (
    id bigint NOT NULL,
    kind public.wallet_kind NOT NULL,
    content bytea,
    created_at timestamp with time zone NOT NULL
);


--
-- Name: wallet_changeset_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.wallet_changeset_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: wallet_changeset_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.wallet_changeset_id_seq OWNED BY public.wallet_changeset.id;


--
-- Name: arkoor_mailbox id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.arkoor_mailbox ALTER COLUMN id SET DEFAULT nextval('public.arkoor_mailbox_id_seq'::regclass);


--
-- Name: ephemeral_tweak id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ephemeral_tweak ALTER COLUMN id SET DEFAULT nextval('public.ephemeral_tweak_id_seq'::regclass);


--
-- Name: integration id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.integration ALTER COLUMN id SET DEFAULT nextval('public.integration_integration_id_seq'::regclass);


--
-- Name: integration_api_key id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.integration_api_key ALTER COLUMN id SET DEFAULT nextval('public.integration_api_key_integration_api_key_id_seq'::regclass);


--
-- Name: integration_token id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.integration_token ALTER COLUMN id SET DEFAULT nextval('public.integration_token_integration_token_id_seq'::regclass);


--
-- Name: integration_token_config id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.integration_token_config ALTER COLUMN id SET DEFAULT nextval('public.integration_token_config_integration_token_config_id_seq'::regclass);


--
-- Name: lightning_htlc_subscription id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.lightning_htlc_subscription ALTER COLUMN id SET DEFAULT nextval('public.lightning_htlc_subscription_lightning_htlc_subscription_id_seq'::regclass);


--
-- Name: lightning_invoice id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.lightning_invoice ALTER COLUMN id SET DEFAULT nextval('public.lightning_invoice_lightning_invoice_id_seq'::regclass);


--
-- Name: lightning_node id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.lightning_node ALTER COLUMN id SET DEFAULT nextval('public.lightning_node_lightning_node_id_seq'::regclass);


--
-- Name: lightning_payment_attempt id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.lightning_payment_attempt ALTER COLUMN id SET DEFAULT nextval('public.lightning_payment_attempt_lightning_payment_attempt_id_seq'::regclass);


--
-- Name: round id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.round ALTER COLUMN id SET DEFAULT nextval('public.round_id_seq'::regclass);


--
-- Name: sweep id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sweep ALTER COLUMN id SET DEFAULT nextval('public.sweep_id_seq'::regclass);


--
-- Name: vtxo id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vtxo ALTER COLUMN id SET DEFAULT nextval('public.vtxo_id_seq'::regclass);


--
-- Name: wallet_changeset id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.wallet_changeset ALTER COLUMN id SET DEFAULT nextval('public.wallet_changeset_id_seq'::regclass);


--
-- Name: arkoor_mailbox arkoor_mailbox_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.arkoor_mailbox
    ADD CONSTRAINT arkoor_mailbox_pkey PRIMARY KEY (id);


--
-- Name: bitcoin_transaction bitcoin_transaction_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.bitcoin_transaction
    ADD CONSTRAINT bitcoin_transaction_pkey PRIMARY KEY (id);


--
-- Name: bitcoin_transaction bitcoin_transaction_txid_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.bitcoin_transaction
    ADD CONSTRAINT bitcoin_transaction_txid_key UNIQUE (txid);


--
-- Name: ephemeral_tweak ephemeral_tweak_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ephemeral_tweak
    ADD CONSTRAINT ephemeral_tweak_pkey PRIMARY KEY (id);


--
-- Name: ephemeral_tweak ephemeral_tweak_pubkey_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ephemeral_tweak
    ADD CONSTRAINT ephemeral_tweak_pubkey_key UNIQUE (pubkey);


--
-- Name: integration_api_key integration_api_key_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.integration_api_key
    ADD CONSTRAINT integration_api_key_pkey PRIMARY KEY (id);


--
-- Name: integration integration_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.integration
    ADD CONSTRAINT integration_pkey PRIMARY KEY (id);


--
-- Name: integration_token_config integration_token_config_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.integration_token_config
    ADD CONSTRAINT integration_token_config_pkey PRIMARY KEY (id);


--
-- Name: integration_token integration_token_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.integration_token
    ADD CONSTRAINT integration_token_pkey PRIMARY KEY (id);


--
-- Name: lightning_htlc_subscription lightning_htlc_subscription_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.lightning_htlc_subscription
    ADD CONSTRAINT lightning_htlc_subscription_pkey PRIMARY KEY (id);


--
-- Name: lightning_invoice lightning_invoice_payment_hash_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.lightning_invoice
    ADD CONSTRAINT lightning_invoice_payment_hash_key UNIQUE (payment_hash);


--
-- Name: lightning_invoice lightning_invoice_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.lightning_invoice
    ADD CONSTRAINT lightning_invoice_pkey PRIMARY KEY (id);


--
-- Name: lightning_invoice lightning_invoice_preimage_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.lightning_invoice
    ADD CONSTRAINT lightning_invoice_preimage_key UNIQUE (preimage);


--
-- Name: lightning_node lightning_node_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.lightning_node
    ADD CONSTRAINT lightning_node_pkey PRIMARY KEY (id);


--
-- Name: lightning_payment_attempt lightning_payment_attempt_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.lightning_payment_attempt
    ADD CONSTRAINT lightning_payment_attempt_pkey PRIMARY KEY (id);


--
-- Name: refinery_schema_history refinery_schema_history_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.refinery_schema_history
    ADD CONSTRAINT refinery_schema_history_pkey PRIMARY KEY (version);


--
-- Name: round round_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.round
    ADD CONSTRAINT round_pkey PRIMARY KEY (id);


--
-- Name: sweep sweep_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sweep
    ADD CONSTRAINT sweep_pkey PRIMARY KEY (id);


--
-- Name: vtxo vtxo_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vtxo
    ADD CONSTRAINT vtxo_pkey PRIMARY KEY (id);


--
-- Name: wallet_changeset wallet_changeset_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.wallet_changeset
    ADD CONSTRAINT wallet_changeset_pkey PRIMARY KEY (id);


--
-- Name: arkoor_mailbox_pubkey_ix; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX arkoor_mailbox_pubkey_ix ON public.arkoor_mailbox USING btree (pubkey, ((processed_at IS NULL)));


--
-- Name: arkoor_mailbox_vtxo_id_uix; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX arkoor_mailbox_vtxo_id_uix ON public.arkoor_mailbox USING btree (vtxo_id);


--
-- Name: integration_api_key_api_key_uix; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX integration_api_key_api_key_uix ON public.integration_api_key USING btree (api_key);


--
-- Name: integration_api_key_name_uix; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX integration_api_key_name_uix ON public.integration_api_key USING btree (integration_id, name);


--
-- Name: integration_name_uix; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX integration_name_uix ON public.integration USING btree (name);


--
-- Name: integration_token_config_uix; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX integration_token_config_uix ON public.integration_token_config USING btree (type, integration_id);


--
-- Name: integration_token_status_expires_at_ix; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX integration_token_status_expires_at_ix ON public.integration_token USING btree (status, expires_at);


--
-- Name: integration_token_token_uix; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX integration_token_token_uix ON public.integration_token USING btree (token);


--
-- Name: integration_token_type_status_integration_expires_at_ix; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX integration_token_type_status_integration_expires_at_ix ON public.integration_token USING btree (type, status, integration_id, expires_at);


--
-- Name: lightning_htlc_subscription_status_ix; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX lightning_htlc_subscription_status_ix ON public.lightning_htlc_subscription USING btree (status, lightning_node_id, lightning_invoice_id);


--
-- Name: lightning_invoice_invoice_uix; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX lightning_invoice_invoice_uix ON public.lightning_invoice USING btree (invoice) INCLUDE (id);


--
-- Name: lightning_node_public_key_uix; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX lightning_node_public_key_uix ON public.lightning_node USING btree (pubkey);


--
-- Name: lightning_payment_attempt_status_ix; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX lightning_payment_attempt_status_ix ON public.lightning_payment_attempt USING btree (status, lightning_node_id, lightning_invoice_id);


--
-- Name: lightning_payment_hash_uix; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX lightning_payment_hash_uix ON public.lightning_invoice USING btree (payment_hash) INCLUDE (id);


--
-- Name: round_expiry_ix; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX round_expiry_ix ON public.round USING btree (expiry, ((swept_at IS NULL)), funding_txid);


--
-- Name: round_funding_tx_id_uix; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX round_funding_tx_id_uix ON public.round USING btree (funding_txid) INCLUDE (swept_at);


--
-- Name: round_seq_uix; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX round_seq_uix ON public.round USING btree (seq);


--
-- Name: sweep_txid_pending_uix; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX sweep_txid_pending_uix ON public.sweep USING btree (txid) INCLUDE (abandoned_at, confirmed_at);


--
-- Name: vtxo_board_not_swept_expiry_ix; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX vtxo_board_not_swept_expiry_ix ON public.vtxo USING btree (((board_swept_at IS NULL)), expiry, vtxo_id);


--
-- Name: vtxo_has_forfeit_state_ix; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX vtxo_has_forfeit_state_ix ON public.vtxo USING btree (((forfeit_state IS NOT NULL)), vtxo_id);


--
-- Name: vtxo_spendable_ix; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX vtxo_spendable_ix ON public.vtxo USING btree (((oor_spent_txid IS NULL)), ((forfeit_state IS NULL)), vtxo_id);


--
-- Name: vtxo_vtxo_id_uix; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX vtxo_vtxo_id_uix ON public.vtxo USING btree (vtxo_id);


--
-- Name: wallet_changeset_kind_ix; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX wallet_changeset_kind_ix ON public.wallet_changeset USING btree (kind);


--
-- Name: integration_api_key integration_api_key_update; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER integration_api_key_update BEFORE UPDATE ON public.integration_api_key FOR EACH ROW EXECUTE FUNCTION public.integration_api_key_update_trigger();


--
-- Name: integration_token_config integration_token_config_update; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER integration_token_config_update BEFORE UPDATE ON public.integration_token_config FOR EACH ROW EXECUTE FUNCTION public.integration_token_config_update_trigger();


--
-- Name: integration_token integration_token_update; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER integration_token_update BEFORE UPDATE ON public.integration_token FOR EACH ROW EXECUTE FUNCTION public.integration_token_update_trigger();


--
-- Name: lightning_htlc_subscription lightning_htlc_subscription_update; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER lightning_htlc_subscription_update BEFORE UPDATE ON public.lightning_htlc_subscription FOR EACH ROW EXECUTE FUNCTION public.lightning_htlc_subscription_update_trigger();


--
-- Name: lightning_invoice lightning_invoice_update; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER lightning_invoice_update BEFORE UPDATE ON public.lightning_invoice FOR EACH ROW EXECUTE FUNCTION public.lightning_invoice_update_trigger();


--
-- Name: lightning_node lightning_node_update; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER lightning_node_update BEFORE UPDATE ON public.lightning_node FOR EACH ROW EXECUTE FUNCTION public.lightning_node_update_trigger();


--
-- Name: lightning_payment_attempt lightning_payment_attempt_update; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER lightning_payment_attempt_update BEFORE UPDATE ON public.lightning_payment_attempt FOR EACH ROW EXECUTE FUNCTION public.lightning_payment_attempt_update_trigger();


--
-- Name: vtxo vtxo_update; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER vtxo_update BEFORE UPDATE ON public.vtxo FOR EACH ROW EXECUTE FUNCTION public.vtxo_update_trigger();


--
-- Name: arkoor_mailbox arkoor_mailbox_vtxo_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.arkoor_mailbox
    ADD CONSTRAINT arkoor_mailbox_vtxo_id_fkey FOREIGN KEY (vtxo_id) REFERENCES public.vtxo(id);


--
-- Name: integration_api_key_history integration_api_key_history_integration_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.integration_api_key_history
    ADD CONSTRAINT integration_api_key_history_integration_id_fkey FOREIGN KEY (integration_id) REFERENCES public.integration(id);


--
-- Name: integration_api_key integration_api_key_integration_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.integration_api_key
    ADD CONSTRAINT integration_api_key_integration_id_fkey FOREIGN KEY (integration_id) REFERENCES public.integration(id);


--
-- Name: integration_token_config_history integration_token_config_history_integration_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.integration_token_config_history
    ADD CONSTRAINT integration_token_config_history_integration_id_fkey FOREIGN KEY (integration_id) REFERENCES public.integration(id);


--
-- Name: integration_token_config integration_token_config_integration_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.integration_token_config
    ADD CONSTRAINT integration_token_config_integration_id_fkey FOREIGN KEY (integration_id) REFERENCES public.integration(id);


--
-- Name: integration_token integration_token_created_by_api_key_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.integration_token
    ADD CONSTRAINT integration_token_created_by_api_key_id_fkey FOREIGN KEY (created_by_api_key_id) REFERENCES public.integration_api_key(id);


--
-- Name: integration_token_history integration_token_history_created_by_api_key_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.integration_token_history
    ADD CONSTRAINT integration_token_history_created_by_api_key_id_fkey FOREIGN KEY (created_by_api_key_id) REFERENCES public.integration_api_key(id);


--
-- Name: integration_token_history integration_token_history_integration_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.integration_token_history
    ADD CONSTRAINT integration_token_history_integration_id_fkey FOREIGN KEY (integration_id) REFERENCES public.integration(id);


--
-- Name: integration_token_history integration_token_history_updated_by_api_key_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.integration_token_history
    ADD CONSTRAINT integration_token_history_updated_by_api_key_id_fkey FOREIGN KEY (updated_by_api_key_id) REFERENCES public.integration_api_key(id);


--
-- Name: integration_token integration_token_integration_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.integration_token
    ADD CONSTRAINT integration_token_integration_id_fkey FOREIGN KEY (integration_id) REFERENCES public.integration(id);


--
-- Name: integration_token integration_token_updated_by_api_key_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.integration_token
    ADD CONSTRAINT integration_token_updated_by_api_key_id_fkey FOREIGN KEY (updated_by_api_key_id) REFERENCES public.integration_api_key(id);


--
-- Name: lightning_htlc_subscription lightning_htlc_subscription_lightning_invoice_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.lightning_htlc_subscription
    ADD CONSTRAINT lightning_htlc_subscription_lightning_invoice_id_fkey FOREIGN KEY (lightning_invoice_id) REFERENCES public.lightning_invoice(id);


--
-- Name: lightning_htlc_subscription lightning_htlc_subscription_lightning_node_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.lightning_htlc_subscription
    ADD CONSTRAINT lightning_htlc_subscription_lightning_node_id_fkey FOREIGN KEY (lightning_node_id) REFERENCES public.lightning_node(id);


--
-- Name: lightning_payment_attempt lightning_payment_attempt_lightning_invoice_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.lightning_payment_attempt
    ADD CONSTRAINT lightning_payment_attempt_lightning_invoice_id_fkey FOREIGN KEY (lightning_invoice_id) REFERENCES public.lightning_invoice(id);


--
-- Name: lightning_payment_attempt lightning_payment_attempt_lightning_node_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.lightning_payment_attempt
    ADD CONSTRAINT lightning_payment_attempt_lightning_node_id_fkey FOREIGN KEY (lightning_node_id) REFERENCES public.lightning_node(id);


--
-- Name: vtxo vtxo_forfeit_round_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vtxo
    ADD CONSTRAINT vtxo_forfeit_round_id_fkey FOREIGN KEY (forfeit_round_id) REFERENCES public.round(id);


--
-- PostgreSQL database dump complete
--


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
-- Name: lightning_htlc_subscription_update_trigger(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.lightning_htlc_subscription_update_trigger() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  INSERT INTO lightning_htlc_subscription_history (
    lightning_htlc_subscription_id, lightning_invoice_id, lightning_node_id,
	status, created_at, updated_at
  ) VALUES (
    OLD.lightning_htlc_subscription_id, OLD.lightning_invoice_id, OLD.lightning_node_id,
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
    lightning_invoice_id, invoice, payment_hash, final_amount_msat, preimage,
    created_at, updated_at
  ) VALUES (
    OLD.lightning_invoice_id, OLD.invoice, OLD.payment_hash, OLD.final_amount_msat, OLD.preimage,
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
    lightning_node_id, public_key, payment_created_index, payment_updated_index,
    created_at, updated_at
  ) VALUES (
    OLD.lightning_node_id, OLD.public_key, OLD.payment_created_index, OLD.payment_updated_index,
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
    lightning_payment_attempt_id, lightning_invoice_id, lightning_node_id, amount_msat,
	status, error, created_at, updated_at
  ) VALUES (
    OLD.lightning_payment_attempt_id, OLD.lightning_invoice_id, OLD.lightning_node_id, 
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
-- Name: all_arkoor_mailbox; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.all_arkoor_mailbox (
    id text NOT NULL,
    pubkey bytea NOT NULL,
    vtxo bytea NOT NULL,
    deleted_at timestamp with time zone
);


--
-- Name: all_pending_sweep; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.all_pending_sweep (
    txid text NOT NULL,
    tx bytea NOT NULL,
    deleted_at timestamp with time zone
);


--
-- Name: all_round; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.all_round (
    id text NOT NULL,
    tx bytea NOT NULL,
    signed_tree bytea NOT NULL,
    nb_input_vtxos integer NOT NULL,
    connector_key bytea NOT NULL,
    expiry integer NOT NULL,
    deleted_at timestamp with time zone
);


--
-- Name: all_vtxo; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.all_vtxo (
    id text NOT NULL,
    vtxo bytea NOT NULL,
    expiry integer NOT NULL,
    oor_spent bytea,
    deleted_at timestamp with time zone,
    board_swept boolean DEFAULT false NOT NULL,
    forfeit_state bytea
);


--
-- Name: arkoor_mailbox; Type: VIEW; Schema: public; Owner: -
--

CREATE VIEW public.arkoor_mailbox AS
 SELECT id,
    pubkey,
    vtxo,
    deleted_at
   FROM public.all_arkoor_mailbox
  WHERE (deleted_at IS NULL);


--
-- Name: forfeits_claim_state; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.forfeits_claim_state (
    vtxo_id text NOT NULL,
    connector_tx bytea,
    connector_cpfp bytea,
    connector_point bytea NOT NULL,
    forfeit_tx bytea NOT NULL,
    forfeit_cpfp bytea
);


--
-- Name: forfeits_round_state; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.forfeits_round_state (
    round_id text NOT NULL,
    nb_connectors_used integer NOT NULL
);


--
-- Name: forfeits_wallet_changeset; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.forfeits_wallet_changeset (
    id integer NOT NULL,
    content bytea
);


--
-- Name: forfeits_wallet_changeset_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.forfeits_wallet_changeset_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: forfeits_wallet_changeset_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.forfeits_wallet_changeset_id_seq OWNED BY public.forfeits_wallet_changeset.id;


--
-- Name: lightning_htlc_subscription; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.lightning_htlc_subscription (
    lightning_htlc_subscription_id bigint NOT NULL,
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
    lightning_htlc_subscription_id bigint NOT NULL,
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

ALTER SEQUENCE public.lightning_htlc_subscription_lightning_htlc_subscription_id_seq OWNED BY public.lightning_htlc_subscription.lightning_htlc_subscription_id;


--
-- Name: lightning_invoice; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.lightning_invoice (
    lightning_invoice_id bigint NOT NULL,
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
    lightning_invoice_id bigint NOT NULL,
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

ALTER SEQUENCE public.lightning_invoice_lightning_invoice_id_seq OWNED BY public.lightning_invoice.lightning_invoice_id;


--
-- Name: lightning_node; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.lightning_node (
    lightning_node_id bigint NOT NULL,
    public_key bytea NOT NULL,
    payment_created_index bigint NOT NULL,
    payment_updated_index bigint NOT NULL,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL
);


--
-- Name: lightning_node_history; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.lightning_node_history (
    lightning_node_id bigint NOT NULL,
    public_key bytea NOT NULL,
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

ALTER SEQUENCE public.lightning_node_lightning_node_id_seq OWNED BY public.lightning_node.lightning_node_id;


--
-- Name: lightning_payment_attempt; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.lightning_payment_attempt (
    lightning_payment_attempt_id bigint NOT NULL,
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
    lightning_payment_attempt_id bigint NOT NULL,
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

ALTER SEQUENCE public.lightning_payment_attempt_lightning_payment_attempt_id_seq OWNED BY public.lightning_payment_attempt.lightning_payment_attempt_id;


--
-- Name: pending_sweep; Type: VIEW; Schema: public; Owner: -
--

CREATE VIEW public.pending_sweep AS
 SELECT txid,
    tx,
    deleted_at
   FROM public.all_pending_sweep
  WHERE (deleted_at IS NULL);


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
-- Name: round; Type: VIEW; Schema: public; Owner: -
--

CREATE VIEW public.round AS
 SELECT id,
    tx,
    signed_tree,
    nb_input_vtxos,
    connector_key,
    expiry,
    deleted_at
   FROM public.all_round
  WHERE (deleted_at IS NULL);


--
-- Name: vtxo; Type: VIEW; Schema: public; Owner: -
--

CREATE VIEW public.vtxo AS
 SELECT id,
    vtxo,
    expiry,
    oor_spent,
    deleted_at,
    board_swept,
    forfeit_state,
    ((oor_spent IS NULL) AND (forfeit_state IS NULL)) AS spendable
   FROM public.all_vtxo
  WHERE (deleted_at IS NULL);


--
-- Name: wallet_changeset; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.wallet_changeset (
    id integer NOT NULL,
    content bytea
);


--
-- Name: wallet_changeset_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.wallet_changeset_id_seq
    AS integer
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
-- Name: forfeits_wallet_changeset id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.forfeits_wallet_changeset ALTER COLUMN id SET DEFAULT nextval('public.forfeits_wallet_changeset_id_seq'::regclass);


--
-- Name: lightning_htlc_subscription lightning_htlc_subscription_id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.lightning_htlc_subscription ALTER COLUMN lightning_htlc_subscription_id SET DEFAULT nextval('public.lightning_htlc_subscription_lightning_htlc_subscription_id_seq'::regclass);


--
-- Name: lightning_invoice lightning_invoice_id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.lightning_invoice ALTER COLUMN lightning_invoice_id SET DEFAULT nextval('public.lightning_invoice_lightning_invoice_id_seq'::regclass);


--
-- Name: lightning_node lightning_node_id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.lightning_node ALTER COLUMN lightning_node_id SET DEFAULT nextval('public.lightning_node_lightning_node_id_seq'::regclass);


--
-- Name: lightning_payment_attempt lightning_payment_attempt_id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.lightning_payment_attempt ALTER COLUMN lightning_payment_attempt_id SET DEFAULT nextval('public.lightning_payment_attempt_lightning_payment_attempt_id_seq'::regclass);


--
-- Name: wallet_changeset id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.wallet_changeset ALTER COLUMN id SET DEFAULT nextval('public.wallet_changeset_id_seq'::regclass);


--
-- Name: all_arkoor_mailbox all_arkoor_mailbox_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.all_arkoor_mailbox
    ADD CONSTRAINT all_arkoor_mailbox_pkey PRIMARY KEY (id);


--
-- Name: all_pending_sweep all_pending_sweep_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.all_pending_sweep
    ADD CONSTRAINT all_pending_sweep_pkey PRIMARY KEY (txid);


--
-- Name: all_round all_round_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.all_round
    ADD CONSTRAINT all_round_pkey PRIMARY KEY (id);


--
-- Name: all_vtxo all_vtxo_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.all_vtxo
    ADD CONSTRAINT all_vtxo_pkey PRIMARY KEY (id);


--
-- Name: forfeits_claim_state forfeits_claim_state_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.forfeits_claim_state
    ADD CONSTRAINT forfeits_claim_state_pkey PRIMARY KEY (vtxo_id);


--
-- Name: forfeits_round_state forfeits_round_state_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.forfeits_round_state
    ADD CONSTRAINT forfeits_round_state_pkey PRIMARY KEY (round_id);


--
-- Name: forfeits_wallet_changeset forfeits_wallet_changeset_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.forfeits_wallet_changeset
    ADD CONSTRAINT forfeits_wallet_changeset_pkey PRIMARY KEY (id);


--
-- Name: lightning_htlc_subscription lightning_htlc_subscription_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.lightning_htlc_subscription
    ADD CONSTRAINT lightning_htlc_subscription_pkey PRIMARY KEY (lightning_htlc_subscription_id);


--
-- Name: lightning_invoice lightning_invoice_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.lightning_invoice
    ADD CONSTRAINT lightning_invoice_pkey PRIMARY KEY (lightning_invoice_id);


--
-- Name: lightning_node lightning_node_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.lightning_node
    ADD CONSTRAINT lightning_node_pkey PRIMARY KEY (lightning_node_id);


--
-- Name: lightning_payment_attempt lightning_payment_attempt_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.lightning_payment_attempt
    ADD CONSTRAINT lightning_payment_attempt_pkey PRIMARY KEY (lightning_payment_attempt_id);


--
-- Name: refinery_schema_history refinery_schema_history_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.refinery_schema_history
    ADD CONSTRAINT refinery_schema_history_pkey PRIMARY KEY (version);


--
-- Name: wallet_changeset wallet_changeset_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.wallet_changeset
    ADD CONSTRAINT wallet_changeset_pkey PRIMARY KEY (id);


--
-- Name: all_arkoor_mailbox_pubkey_ix; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX all_arkoor_mailbox_pubkey_ix ON public.all_arkoor_mailbox USING btree (pubkey) WHERE (deleted_at IS NULL);


--
-- Name: all_round_expiry_ix; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX all_round_expiry_ix ON public.all_round USING btree (expiry) WHERE (deleted_at IS NULL);


--
-- Name: all_vtxo_board_swept_expiry_ix; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX all_vtxo_board_swept_expiry_ix ON public.all_vtxo USING btree (board_swept, expiry) WHERE (deleted_at IS NULL);


--
-- Name: lightning_htlc_subscription_status_ix; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX lightning_htlc_subscription_status_ix ON public.lightning_htlc_subscription USING btree (status, lightning_node_id, lightning_invoice_id);


--
-- Name: lightning_invoice_invoice_uix; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX lightning_invoice_invoice_uix ON public.lightning_invoice USING btree (invoice) INCLUDE (lightning_invoice_id);


--
-- Name: lightning_node_public_key_uix; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX lightning_node_public_key_uix ON public.lightning_node USING btree (public_key);


--
-- Name: lightning_payment_attempt_status_ix; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX lightning_payment_attempt_status_ix ON public.lightning_payment_attempt USING btree (status, lightning_node_id, lightning_invoice_id);


--
-- Name: lightning_payment_hash_uix; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX lightning_payment_hash_uix ON public.lightning_invoice USING btree (payment_hash) INCLUDE (lightning_invoice_id);


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
-- Name: lightning_htlc_subscription lightning_htlc_subscription_lightning_invoice_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.lightning_htlc_subscription
    ADD CONSTRAINT lightning_htlc_subscription_lightning_invoice_id_fkey FOREIGN KEY (lightning_invoice_id) REFERENCES public.lightning_invoice(lightning_invoice_id);


--
-- Name: lightning_htlc_subscription lightning_htlc_subscription_lightning_node_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.lightning_htlc_subscription
    ADD CONSTRAINT lightning_htlc_subscription_lightning_node_id_fkey FOREIGN KEY (lightning_node_id) REFERENCES public.lightning_node(lightning_node_id);


--
-- Name: lightning_payment_attempt lightning_payment_attempt_lightning_invoice_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.lightning_payment_attempt
    ADD CONSTRAINT lightning_payment_attempt_lightning_invoice_id_fkey FOREIGN KEY (lightning_invoice_id) REFERENCES public.lightning_invoice(lightning_invoice_id);


--
-- Name: lightning_payment_attempt lightning_payment_attempt_lightning_node_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.lightning_payment_attempt
    ADD CONSTRAINT lightning_payment_attempt_lightning_node_id_fkey FOREIGN KEY (lightning_node_id) REFERENCES public.lightning_node(lightning_node_id);


--
-- PostgreSQL database dump complete
--


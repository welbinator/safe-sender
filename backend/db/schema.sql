


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


CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public;


SET default_tablespace = '';

SET default_table_access_method = heap;


CREATE TABLE public.admin_audit_log (
    id bigint NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    ip text NOT NULL,
    method text NOT NULL,
    path text NOT NULL,
    status_code integer NOT NULL,
    detail jsonb
);



CREATE SEQUENCE public.admin_audit_log_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;



ALTER SEQUENCE public.admin_audit_log_id_seq OWNED BY public.admin_audit_log.id;



CREATE TABLE public.admin_rate_limit (
    ip text NOT NULL,
    window_start timestamp with time zone NOT NULL,
    request_count integer DEFAULT 0 NOT NULL
);





CREATE TABLE public.customers (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    domain text NOT NULL,
    name text,
    email text NOT NULL,
    google_sub text,
    plan text DEFAULT 'basic'::text NOT NULL,
    dashboard_config jsonb,
    active boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    domain_verification_token text,
    domain_verified boolean DEFAULT false NOT NULL,
    smtp_username text,
    smtp_password_hash text,
    subject_hash_salt bytea DEFAULT public.gen_random_bytes(32) NOT NULL
);



CREATE TABLE public.rules (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    customer_id uuid NOT NULL,
    pattern text NOT NULL,
    match_type text NOT NULL,
    scope text DEFAULT 'external'::text NOT NULL,
    applies_to_email text,
    is_exception boolean DEFAULT false NOT NULL,
    active boolean DEFAULT true NOT NULL,
    description text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    name text,
    CONSTRAINT rules_match_type_check CHECK ((match_type = ANY (ARRAY['string'::text, 'regex'::text]))),
    CONSTRAINT rules_scope_check CHECK ((scope = ANY (ARRAY['external'::text, 'internal'::text, 'both'::text])))
);



CREATE TABLE public.scan_logs (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    customer_id uuid NOT NULL,
    sender text NOT NULL,
    recipient text NOT NULL,
    subject_hash text,
    outcome text NOT NULL,
    matched_rule_id uuid,
    smtp_message_id text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT scan_logs_outcome_check CHECK ((outcome = ANY (ARRAY['allowed'::text, 'blocked'::text])))
);



CREATE TABLE public.suppressed_addresses (
    id bigint NOT NULL,
    email text NOT NULL,
    reason text NOT NULL,
    detail text,
    suppressed_at timestamp with time zone DEFAULT now() NOT NULL,
    customer_id uuid,
    CONSTRAINT suppressed_addresses_reason_check CHECK ((reason = ANY (ARRAY['bounce'::text, 'complaint'::text])))
);



CREATE SEQUENCE public.suppressed_addresses_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;



ALTER SEQUENCE public.suppressed_addresses_id_seq OWNED BY public.suppressed_addresses.id;



ALTER TABLE ONLY public.admin_audit_log ALTER COLUMN id SET DEFAULT nextval('public.admin_audit_log_id_seq'::regclass);



ALTER TABLE ONLY public.suppressed_addresses ALTER COLUMN id SET DEFAULT nextval('public.suppressed_addresses_id_seq'::regclass);



ALTER TABLE ONLY public.admin_audit_log
    ADD CONSTRAINT admin_audit_log_pkey PRIMARY KEY (id);



ALTER TABLE ONLY public.admin_rate_limit
    ADD CONSTRAINT admin_rate_limit_pkey PRIMARY KEY (ip, window_start);



ALTER TABLE ONLY public.alembic_version
    ADD CONSTRAINT alembic_version_pkc PRIMARY KEY (version_num);



ALTER TABLE ONLY public.customers
    ADD CONSTRAINT customers_domain_key UNIQUE (domain);



ALTER TABLE ONLY public.customers
    ADD CONSTRAINT customers_google_sub_key UNIQUE (google_sub);



ALTER TABLE ONLY public.customers
    ADD CONSTRAINT customers_pkey PRIMARY KEY (id);



ALTER TABLE ONLY public.customers
    ADD CONSTRAINT customers_smtp_username_key UNIQUE (smtp_username);



ALTER TABLE ONLY public.rules
    ADD CONSTRAINT rules_pkey PRIMARY KEY (id);



ALTER TABLE ONLY public.scan_logs
    ADD CONSTRAINT scan_logs_pkey PRIMARY KEY (id);



ALTER TABLE ONLY public.suppressed_addresses
    ADD CONSTRAINT suppressed_addresses_pkey PRIMARY KEY (id);



CREATE INDEX idx_admin_audit_created_at ON public.admin_audit_log USING btree (created_at DESC);



CREATE INDEX idx_admin_audit_ip ON public.admin_audit_log USING btree (ip, created_at DESC);



CREATE INDEX idx_admin_rate_limit_window ON public.admin_rate_limit USING btree (window_start);



CREATE INDEX idx_rules_active ON public.rules USING btree (customer_id, active);



CREATE INDEX idx_rules_customer_id ON public.rules USING btree (customer_id);



CREATE INDEX idx_scan_logs_created_at ON public.scan_logs USING btree (customer_id, created_at DESC);



CREATE INDEX idx_scan_logs_customer_id ON public.scan_logs USING btree (customer_id);



CREATE INDEX idx_suppressed_customer_email ON public.suppressed_addresses USING btree (customer_id, email);



CREATE INDEX idx_suppressed_email ON public.suppressed_addresses USING btree (email);



CREATE UNIQUE INDEX suppressed_addresses_customer_email_uq ON public.suppressed_addresses USING btree (customer_id, email) WHERE (customer_id IS NOT NULL);



CREATE UNIQUE INDEX suppressed_addresses_legacy_email_uq ON public.suppressed_addresses USING btree (email) WHERE (customer_id IS NULL);



ALTER TABLE ONLY public.rules
    ADD CONSTRAINT rules_customer_id_fkey FOREIGN KEY (customer_id) REFERENCES public.customers(id) ON DELETE CASCADE;



ALTER TABLE ONLY public.scan_logs
    ADD CONSTRAINT scan_logs_customer_id_fkey FOREIGN KEY (customer_id) REFERENCES public.customers(id) ON DELETE CASCADE;



ALTER TABLE ONLY public.scan_logs
    ADD CONSTRAINT scan_logs_matched_rule_id_fkey FOREIGN KEY (matched_rule_id) REFERENCES public.rules(id) ON DELETE SET NULL;



ALTER TABLE ONLY public.suppressed_addresses
    ADD CONSTRAINT suppressed_addresses_customer_id_fkey FOREIGN KEY (customer_id) REFERENCES public.customers(id) ON DELETE CASCADE;





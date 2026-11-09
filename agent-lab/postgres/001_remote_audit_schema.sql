-- Remote Audit PostgreSQL schema v1
-- Target: Supabase PostgreSQL (private schema; not exposed through PostgREST).
-- Apply only through a separately reviewed migration. This file is not auto-deployed.
-- Each append must acquire pg_advisory_xact_lock for the repository ID inside
-- its transaction before reading the chain or allocating a sequence. This also
-- serializes the first append when no head row exists; a row lock alone cannot.

BEGIN;

CREATE SCHEMA IF NOT EXISTS remote_audit;
REVOKE ALL ON SCHEMA remote_audit FROM PUBLIC;
REVOKE ALL ON SCHEMA remote_audit FROM anon, authenticated;

CREATE TABLE IF NOT EXISTS remote_audit.events (
    repository_id bigint NOT NULL CHECK (repository_id > 0),
    sequence bigint NOT NULL CHECK (sequence > 0),
    event_id uuid NOT NULL,
    event_document jsonb NOT NULL CHECK (jsonb_typeof(event_document) = 'object'),
    event_hash char(64) NOT NULL CHECK (event_hash ~ '^[0-9a-f]{64}$'),
    idempotency_key text NOT NULL CHECK (length(idempotency_key) BETWEEN 1 AND 200),
    request_hash char(64) NOT NULL CHECK (request_hash ~ '^[0-9a-f]{64}$'),
    event_type text NOT NULL CHECK (length(event_type) BETWEEN 1 AND 80),
    plan_token char(64) CHECK (plan_token IS NULL OR plan_token ~ '^[0-9a-f]{64}$'),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (repository_id, sequence),
    UNIQUE (repository_id, event_id),
    UNIQUE (repository_id, idempotency_key),
    CHECK ((event_document ->> 'sequence')::bigint = sequence),
    CHECK (event_document ->> 'event_id' = event_id::text),
    CHECK (event_document ->> 'event_hash' = event_hash),
    CHECK (event_document ->> 'idempotency_key' = idempotency_key),
    CHECK (event_document ->> 'request_hash' = request_hash)
);

CREATE TABLE IF NOT EXISTS remote_audit.heads (
    repository_id bigint PRIMARY KEY CHECK (repository_id > 0),
    sequence bigint NOT NULL CHECK (sequence > 0),
    event_hash char(64) NOT NULL CHECK (event_hash ~ '^[0-9a-f]{64}$'),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY (repository_id, sequence)
        REFERENCES remote_audit.events(repository_id, sequence)
        DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE IF NOT EXISTS remote_audit.plans (
    repository_id bigint NOT NULL CHECK (repository_id > 0),
    plan_token char(64) NOT NULL CHECK (plan_token ~ '^[0-9a-f]{64}$'),
    creator_actor_id bigint NOT NULL CHECK (creator_actor_id > 0),
    event_sequence bigint NOT NULL CHECK (event_sequence > 0),
    PRIMARY KEY (repository_id, plan_token),
    FOREIGN KEY (repository_id, event_sequence)
        REFERENCES remote_audit.events(repository_id, sequence)
);

CREATE TABLE IF NOT EXISTS remote_audit.decisions (
    repository_id bigint NOT NULL CHECK (repository_id > 0),
    plan_token char(64) NOT NULL CHECK (plan_token ~ '^[0-9a-f]{64}$'),
    event_sequence bigint NOT NULL CHECK (event_sequence > 0),
    PRIMARY KEY (repository_id, plan_token),
    FOREIGN KEY (repository_id, plan_token)
        REFERENCES remote_audit.plans(repository_id, plan_token),
    FOREIGN KEY (repository_id, event_sequence)
        REFERENCES remote_audit.events(repository_id, sequence)
);

CREATE TABLE IF NOT EXISTS remote_audit.consumed_evidence (
    repository_id bigint NOT NULL CHECK (repository_id > 0),
    issuer text NOT NULL CHECK (length(issuer) BETWEEN 1 AND 255),
    evidence_id text NOT NULL CHECK (length(evidence_id) BETWEEN 1 AND 512),
    evidence_digest char(64) NOT NULL CHECK (evidence_digest ~ '^[0-9a-f]{64}$'),
    plan_token char(64) NOT NULL CHECK (plan_token ~ '^[0-9a-f]{64}$'),
    event_sequence bigint NOT NULL CHECK (event_sequence > 0),
    PRIMARY KEY (repository_id, issuer, evidence_id),
    FOREIGN KEY (repository_id, plan_token)
        REFERENCES remote_audit.plans(repository_id, plan_token),
    FOREIGN KEY (repository_id, event_sequence)
        REFERENCES remote_audit.events(repository_id, sequence)
);

CREATE INDEX IF NOT EXISTS events_plan_sequence_idx
    ON remote_audit.events(repository_id, plan_token, sequence)
    WHERE plan_token IS NOT NULL;

REVOKE ALL ON ALL TABLES IN SCHEMA remote_audit FROM PUBLIC, anon, authenticated;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA remote_audit FROM PUBLIC, anon, authenticated;

COMMIT;

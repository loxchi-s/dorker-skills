# Supabase PostgreSQL Audit Store

## Status

**Schema drafted in GitHub only. Not deployed and not integration-tested.**

Target provider is the user's existing Supabase PostgreSQL project. This repository change does not connect to Supabase, inspect a project, apply SQL, create credentials, or incur costs.

The SQL migration creates a private `remote_audit` schema. It deliberately grants no access to `anon` or `authenticated` and does not expose these tables through the Data API. A future service-side adapter must connect using a server-side PostgreSQL connection and a dedicated least-privilege database role. Never place a database password, Supabase secret/service-role key, or connection string in GitHub source, Actions logs, or client-side configuration.

## Transaction contract for the adapter

Every write must execute as one PostgreSQL transaction:

1. Acquire a transaction-scoped advisory lock derived from the numeric repository ID. This serializes sequence allocation for one repository without serializing unrelated repositories.
2. Read and verify the stored chain and head. Fail closed if the head does not match the final event or any event hash/link is invalid.
3. Query `events` by `(repository_id, idempotency_key)`. Same request hash returns the original event; a different hash raises `idempotency_conflict`.
4. Check the event capacity limit, plan uniqueness, creator/reviewer separation, terminal-decision uniqueness, and one-time evidence consumption.
5. Allocate `sequence = head.sequence + 1` (or 1 for an empty repository), build the exact canonical event, and compute SHA-256 using the v1 contract.
6. Insert the event, update the head, and insert plan/decision/evidence-consumption rows in the same transaction.
7. Commit before returning success. A connection loss during commit is indeterminate; resolve only by retrying the exact request with the same idempotency key or looking it up.

The advisory lock is important for the first event as well as later writes: a row lock cannot lock a head row that does not exist yet. The database uniqueness constraints remain the final defense against duplicate keys, plan tokens, decisions, and evidence IDs.

## Read and recovery contract

- Read operations verify the full event chain and head before returning data.
- Pagination must use authenticated opaque cursors; do not expose unsigned offsets as an authorization boundary.
- If the service loses its connection after commit, the next process must find the original event by the same idempotency key.
- No SQLite fallback is allowed for remote writes.
- A database outage, integrity mismatch, or uncertain commit must never be reported as success.
- External signed checkpoints and backup/restore remain required to detect whole-database rollback/replacement.

## Deployment boundary

The SQL file at `postgres/001_remote_audit_schema.sql` is a reviewed source artifact, not a live migration. Before applying it to the existing Supabase project, separately verify the project identity, current schema/migration state, database role, backup/restore plan, and maintenance window. Do not apply it to production as part of this GitHub-only task.

## Remaining implementation work

- Implement a PostgreSQL DB-API repository adapter matching `AuditRepository`.
- Pin the PostgreSQL driver and lock its dependency.
- Add PostgreSQL integration tests for same-key replay/conflict, concurrent appends, competing decisions, evidence replay, transaction rollback, process restart, and lost response after commit.
- Run the complete FI-01..FI-14 and CR-01..CR-07 suites against an isolated Supabase PostgreSQL database using two independent service processes/runners.
- Add authenticated cursor signing, external integrity checkpoints, backup/restore, bounded request deadlines/rate limits, and production authorization/evidence configuration.
- Apply the migration only after explicit deployment approval; this GitHub change does not authorize that operation.

# Supabase PostgreSQL Audit Store

## Status

**Schema deployed to the user's Supabase Free project; PostgreSQL adapter is not implemented or integration-tested.**

- Supabase project: `dorker-skills-audit` (Singapore)
- Project ref: `ldqrztnihfguapsbwxpg`
- Private schema: `remote_audit`
- Tables: `events`, `heads`, `plans`, `decisions`, `consumed_evidence`
- RLS: enabled on all five tables
- Rows: zero at initial verification
- Policies: none; `anon` and `authenticated` have no access
- Current database grants observed: only `postgres` has table privileges

The migration is recorded in Supabase as `remote_audit_schema_v1`; a separate migration enabled RLS. The Supabase security advisor currently reports five informational `rls_enabled_no_policy` findings. This is intentional until a dedicated backend database role and narrowly scoped policies are designed. Do not add permissive policies for `anon` or `authenticated`.

The GitHub Actions workflow for the schema-contract commit completed successfully. That CI result validates repository checks only; it is not a PostgreSQL integration test.

## Security and connection boundary

The schema is private and is not intended for direct browser access through PostgREST. A future service-side adapter must use a dedicated server-side database login with only the privileges it requires, plus policies scoped to that database role. Do not use the `postgres` owner credential in GitHub Actions or application runtime. Never place a database password, Supabase secret/service-role key, or connection string in GitHub source, workflow logs, or client-side configuration.

GitHub Actions secrets cannot be populated through this repository workflow. Add any eventual connection secret through GitHub repository Settings > Secrets and variables > Actions, after the adapter and its least-privilege database role have been reviewed. Do not paste credentials into chat.

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

## Remaining implementation work

- Implement a PostgreSQL DB-API repository adapter matching `AuditRepository`.
- Pin the PostgreSQL driver and lock its dependency.
- Add PostgreSQL integration tests for same-key replay/conflict, concurrent appends, competing decisions, evidence replay, transaction rollback, process restart, and lost response after commit.
- Run the complete FI-01..FI-14 and CR-01..CR-07 suites against an isolated PostgreSQL database using two independent service processes/runners.
- Add authenticated cursor signing, external integrity checkpoints, backup/restore, bounded request deadlines/rate limits, and production authorization/evidence configuration.
- Create a dedicated backend database role and role-scoped RLS policies before any runtime connection is enabled.
- Do not connect the application to Supabase or write production audit events until adapter tests pass and deployment is explicitly approved.

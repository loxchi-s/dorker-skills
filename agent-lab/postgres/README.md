# Supabase PostgreSQL Audit Store

## Status

**PostgreSQL adapter implemented and CI-tested; schema, RLS, privilege role, indexes, and restricted LOGIN role deployed to Supabase. The live DSN is not yet configured in GitHub Actions and direct-login authentication remains unvalidated.**

- Supabase project: `dorker-skills-audit` (Singapore)
- Project ref: `ldqrztnihfguapsbwxpg`
- Private schema: `remote_audit`
- Tables: `events`, `heads`, `plans`, `decisions`, `consumed_evidence`
- RLS: enabled on all five tables
- Rows: zero at initial verification
- Policies: 11 role-scoped policies for `remote_audit_app`; no policies for `anon` or `authenticated`
- `remote_audit_app`: NOLOGIN, NOSUPERUSER, NOCREATEDB, NOCREATEROLE, NOREPLICATION, NOBYPASSRLS, NOINHERIT
- `remote_audit_login`: LOGIN, INHERIT, NOSUPERUSER, NOCREATEDB, NOCREATEROLE, NOREPLICATION, NOBYPASSRLS; only membership is `remote_audit_app`. The current metadata query reports a non-NULL password hash, but the credential's validity/availability is unknown; reset or confirm it through a secure credential workflow.
- Table grants: SELECT/INSERT on append-only tables; SELECT/INSERT/UPDATE on `heads`
- RLS enabled on all five tables; table owner remains `postgres`

Applied migrations: `remote_audit_schema_v1`, `enable_remote_audit_rls`, `remote_audit_app_role_v1`, `remote_audit_fk_indexes_v1`, and `remote_audit_login_role_v1`. Supabase Security Advisor returned no lints after role/policy deployment. Performance Advisor's five missing-FK-index findings were addressed by migration 003; recheck the advisor after its next refresh. The `remote_audit_app` role is repository-wide trusted service access, not tenant isolation.

The GitHub Actions workflow for the schema-contract commit completed successfully. That CI result validates repository checks only; it is not a PostgreSQL integration test.

## Security and connection boundary

The schema is private and is not intended for direct browser access through PostgREST. The service-side adapter uses `remote_audit_login`, which inherits only the `remote_audit_app` privilege role. Its password is intentionally unset; provision it through a secure credential workflow before testing a live connection. Do not use the `postgres` owner credential in GitHub Actions or application runtime. Never place a database password, Supabase secret/service-role key, or connection string in GitHub source, workflow logs, or client-side configuration.

GitHub Actions secrets cannot be populated through this repository workflow. Add `SUPABASE_AUDIT_DSN` through GitHub repository Settings > Secrets and variables > Actions. A manual, read-only smoke workflow is available at `.github/workflows/supabase-audit-live-smoke.yml`; it checks direct-login identity, role flags, membership, least-privilege grants, RLS, and `PostgresAuditRepository.verify(0)`. It performs no writes. Do not paste credentials into chat.

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

- Provision a strong password for `remote_audit_login` through Supabase's secure role/credential UI; never put it in SQL migration files, GitHub source, logs, or chat.
- Configure the runtime DSN only in the server-side secret manager and run a direct-login smoke test against Supabase.
- Extend integration coverage to separate OS processes/runners and process restart; current concurrency tests use independent DB connections from threads.
- Add authenticated cursor signing, external integrity checkpoints, backup/restore, bounded request deadlines/rate limits, and production authorization/evidence configuration.
- Configure production authorization/evidence policy, external signed integrity checkpoints, backup/restore, and bounded request deadlines/rate limits before production use.
- Do not connect the application to Supabase or write production audit events until adapter tests pass and deployment is explicitly approved.

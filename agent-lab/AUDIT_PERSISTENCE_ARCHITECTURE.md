# Cross-Run Artifact GC Audit Persistence

## Status

**Proposed architecture; not implemented.** The current `SQLiteArtifactIndex` is a durable single-host index. It uses SQLite transactions and a local hash chain, but a GitHub-hosted runner is ephemeral: a database file created by one run is not available to the next run unless explicitly transferred. Workflow artifacts and Actions caches are not the authoritative audit database.

No provider, credentials, database, workflow, or repository permission is configured by this document. The GC workflow remains disabled, CI remains read-only, and artifact deletion remains unavailable.

## Decision

Use a **transactional remote audit store** behind a narrow `AuditStore` interface. The production implementation should use a managed PostgreSQL-compatible database reached through a small, authenticated audit service or a provider-supported workload-identity flow. Do not connect a runner using a long-lived database password, and do not assume a GitHub OIDC token is itself a database credential.

Keep SQLite as a local development/test adapter only. Do not attempt to synchronize SQLite files between runners, and do not use GitHub Actions artifacts, caches, workflow logs, or repository commits as the authoritative mutable ledger.

The provider and hosting account are deliberately undecided. Select one only after reviewing trust boundaries, supported federated identity, transaction guarantees, backup/restore, retention, and cost. This document does not authorize provisioning a service or incurring cost.

## Data model

The authoritative store needs at least:

- `gc_plans`: immutable plan token (primary key), canonical plan payload, creator GitHub numeric ID, creation time, and status.
- `audit_events`: monotonically increasing sequence, event ID, idempotency key (unique), plan token, event type, actor numeric ID/login, timestamp, canonical details, previous hash, and event hash.
- `audit_head`: one serialized chain-head record containing the latest sequence and event hash.
- `audit_checkpoints`: externally verifiable checkpoint metadata, including sequence, event hash, signing key ID, signature, and publication time.

Never persist OIDC JWTs, GitHub runner bootstrap tokens, authorization headers, or database credentials. Store only verified identity claims needed for audit, not bearer credentials.

## Transaction and concurrency contract

Every write is one database transaction:

1. Begin a transaction at serializable isolation, or lock the single `audit_head` row for update.
2. Validate the plan exists and its canonical token/payload matches the requested operation.
3. Enforce immutable creator identity and a distinct verified approver ID for approval/rejection.
4. Enforce one terminal decision per plan with a database unique constraint, not only application-level checks.
5. Enforce unique idempotency key. A retry with the same key and same canonical request returns the original result; the same key with different content fails closed.
6. Allocate the next sequence, calculate the event hash from canonical fields and previous hash, insert the event, and update `audit_head`.
7. Commit before returning success. Any error rolls back the entire operation.

Use bounded connection pools, statement/transaction timeouts, bounded payload sizes, and explicit retry only for serialization/deadlock errors. Retries must reuse the same idempotency key. Never retry an ambiguous commit with a new key.

## Integrity and recovery

A hash chain detects edits and broken links inside the retained database, but cannot by itself detect deletion of the entire tail or replacement of the whole database with an older valid copy.

Therefore:

- Periodically sign the current sequence and event hash with a key held outside the database trust boundary.
- Publish signed checkpoints to a separate immutable or append-only destination.
- Verify the full chain and the latest trusted checkpoint on startup and before every privileged audit decision.
- Back up the database with point-in-time recovery; regularly test restore into an isolated environment and verify the chain against external checkpoints.
- Alert on sequence rollback, missing checkpoint, chain mismatch, restore drift, and backup age.
- Define and test explicit RPO/RTO before production. Do not claim zero data loss without evidence.

The audit service must fail closed if the remote store, checkpoint verifier, or backup-integrity state is unavailable or inconsistent.

## Identity and authorization boundary

The future workflow must continue to verify the exact repository ID, repository name, workflow ref, audience, environment subject, actor ID/login, signature, and token time claims. The OIDC token authenticates the workflow invocation; it does not independently prove a human review.

A separate trusted actor must authorize a plan. Since the current ruleset allows solo work and requires zero PR approvals, it does not enforce this separation. Do not silently change that policy. Before privileged audit operations, decide and configure an enforceable independent-actor approval mechanism, then validate its evidence server-side.

The runner must receive only the minimum short-lived permission needed to call the audit service. The service—not runner-supplied fields—must verify identity and enforce transaction rules. No deletion operation is in scope.

## Failure semantics

- Remote store unavailable: reject the operation; no local-only success.
- Commit outcome uncertain: retry with the same idempotency key and resolve by reading the stored event.
- Duplicate plan or decision: reject or return the original idempotent result; never create a second event.
- Actor mismatch, plan mismatch, invalid checkpoint, or chain gap: reject and emit an out-of-band alert without mutating the ledger.
- Backup/restore validation failure: keep the privileged workflow disabled.
- Audit capacity/retention limit reached: fail closed; never prune the authoritative chain silently.

## Implementation sequence

1. Define a provider-neutral `AuditStore` protocol and conformance tests.
2. Keep the SQLite adapter for local tests; test restart/reopen, transaction rollback, concurrent writers, idempotent retry, duplicate decision, and chain verification.
3. Select a managed provider only after explicit approval; implement the remote service and database schema with transactional constraints.
4. Add cross-run integration tests using two independent runner invocations and verify that the second can read and extend the first run's audit state.
5. Add external signed checkpoints, backup/restore drills, monitoring, and documented RPO/RTO.
6. Independently review identity, service authorization, and approval evidence.
7. Only after all gates pass, propose a dedicated `workflow_dispatch` workflow. Obtain explicit approval before granting `id-token: write`.

## Non-goals

This design does not add artifact deletion, object-store mutation, privileged shell execution, dynamic workflow inputs, or a live OIDC workflow. It does not select or provision Supabase, AWS, Azure, GCP, or another provider.

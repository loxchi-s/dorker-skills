# Cross-Run Artifact GC Audit Persistence

## Status

**Partially implemented; remote persistence remains proposed.** `AuditStore` defines a provider-neutral Python protocol for the existing GC plan, decision, event-read, and chain-verification operations. `SQLiteArtifactIndex` structurally satisfies this v1 protocol and is covered by local conformance tests. A provider-neutral synchronous HTTP client now implements bounded HTTPS requests, strict bounded JSON parsing, stable idempotency-key retries, and explicit indeterminate outcomes after transport failures; its mock-transport tests validate client behavior only. The client also paginates bounded event reads, verifies sequence/ID/previous-hash continuity, recomputes each event hash using the v1 canonical JSON contract, and supports verification from a trusted sequence/hash anchor. A fixed cross-language hash test vector is specified in `REMOTE_AUDIT_SERVICE_CONTRACT.md`. It remains a durable single-host index: a GitHub-hosted runner is ephemeral, so a database file created by one run is not available to the next run. Workflow artifacts and Actions caches are not the authoritative audit database.

No provider, credentials, database, workflow, or repository permission is configured by this document. The GC workflow remains disabled, CI remains read-only, and artifact deletion remains unavailable.

## Decision

Use a **transactional remote audit store** behind a narrow `AuditStore` interface. The production implementation should use a managed PostgreSQL-compatible database reached through a small, authenticated audit service or a provider-supported workload-identity flow. Do not connect a runner using a long-lived database password, and do not assume a GitHub OIDC token is itself a database credential.

Keep SQLite as a local development/test adapter only. Do not attempt to synchronize SQLite files between runners, and do not use GitHub Actions artifacts, caches, workflow logs, or repository commits as the authoritative mutable ledger.

The remote event contract now specifies canonical event hashing v1: SHA-256 over sorted-key compact ASCII JSON of the exact event fields, including `request_hash` and `previous_hash`; the client recomputes every hash and rejects payload tampering. The local `AuditStore` protocol now requires caller-supplied idempotency keys. The SQLite adapter persists a unique key and canonical request hash in the same transaction as each event. A retry with the same key and same request returns the original event hash; reuse with changed request content fails closed. This is local SQLite behavior only: ambiguous network commit recovery and cross-run remote semantics still require a remote adapter and integration tests.

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

1. **Implemented locally:** provider-neutral `AuditStore` protocol requires idempotency keys; SQLite persists a unique key and request hash atomically with each event. Conformance tests cover restart/reopen, same-key replay, changed-payload conflict, concurrent decisions, chain verification, and rollback behavior after capacity failure.
2. **Still required before remote use:** test ambiguous network commit recovery against a real transactional adapter, including retry with the same key across independent runner invocations. The local SQLite tests do not prove cross-run durability.
3. Select a managed provider only after explicit approval; implement the remote service and database schema with transactional constraints.
4. Add cross-run integration tests using two independent runner invocations and verify that the second can read and extend the first run's audit state.
5. Add external signed checkpoints, backup/restore drills, monitoring, and documented RPO/RTO.
6. Independently review identity, service authorization, and approval evidence.
7. Only after all gates pass, propose a dedicated `workflow_dispatch` workflow. Obtain explicit approval before granting `id-token: write`.

## Non-goals

This design does not add artifact deletion, object-store mutation, privileged shell execution, dynamic workflow inputs, or a live OIDC workflow. It does not select or provision Supabase, AWS, Azure, GCP, or another provider.

## Remote service contract and test gates

The provider-neutral HTTP boundary, OIDC trust boundary, request/response envelopes, transaction/idempotency semantics, and failure matrix are specified in [REMOTE_AUDIT_SERVICE_CONTRACT.md](REMOTE_AUDIT_SERVICE_CONTRACT.md). That document is design-only: it does not implement a remote adapter or establish cross-run durability.

Before remote use, implement the service/client against that contract and pass the full failure-injection (FI-01..FI-14) and cross-run (CR-01..CR-07) suite against a real transactional adapter using two independent runner invocations. A fake service can validate client behavior but is not evidence of remote durability. In particular, a lost response after commit must resolve to the original event by the same idempotency key; an unresolved outcome remains indeterminate and must never be reported as success.

Current status: local SQLite idempotency is implemented and CI-tested; the HTTP client is implemented with mock-transport tests but has not been tested against a live service; remote ambiguous-commit recovery, remote persistence, and cross-run integration remain unimplemented and unvalidated.


## In-memory Remote Audit Service Reference

PR #13 adds `dorker_agent.remote_audit_service.RemoteAuditService` and `InMemoryAuditRepository` as a contract-test harness. The service validates plan structure and recomputes approval tokens, derives actor claims from the bearer JWT and delegates signature/claim verification to an injected verifier, scopes idempotency by repository ID, serializes writes under a process-local lock, enforces distinct-actor approval and a single terminal decision, and emits v1 canonical event hashes. It exposes a WSGI callable and direct request handler for tests. The in-memory repository is non-durable, does not survive process restart, and does not establish cross-run correctness. Deterministic service-state tests use a fake verifier; separate service-boundary tests use the real RS256 verifier with a generated test key and static test JWKS. Neither test path contacts GitHub's live JWKS endpoint. Production deployment still requires a separately reviewed verifier policy, durable transactional adapter, authenticated opaque cursors, and the full FI/CR suite.
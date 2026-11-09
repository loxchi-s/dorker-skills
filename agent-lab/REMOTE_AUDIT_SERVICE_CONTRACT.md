# Remote Audit Service Contract v1

## Status and scope

**Contract + client + in-memory reference implementation.** PR #13 implements a provider-neutral HTTP client and a WSGI-compatible service reference backed only by a lock-serialized in-memory repository. The service tests exercise request validation, injected identity verification, idempotency, terminal-decision races, event pagination, and canonical hash-chain verification. This is a test harness: state is lost on process exit; it is not a durable store, deployed service, or production security boundary. The SQLite adapter remains the only durable implementation. No provider is selected, infrastructure provisioned, OIDC permission granted, or workflow enabled.

The service is the authority for audit state. A runner must never report success from a local cache or SQLite fallback.

## Trust boundary

- The runner sends a short-lived GitHub Actions OIDC JWT as a bearer credential over TLS.
- The service independently validates the JWT signature against GitHub's fixed JWKS issuer and enforces issuer, audience, repository name and numeric ID, exact workflow ref, environment subject, expiry, not-before, issued-at, and actor claims.
- The service derives actor ID/login from verified claims. Caller-supplied actor fields are informational only and must not authorize an operation.
- The service never stores the JWT, bearer header, runner bootstrap token, or database credentials. It stores only verified actor ID/login and the canonical operation.
- The service owns authorization, transaction boundaries, idempotency, sequence allocation, event hashing, and chain verification. Runner-side validation is defense in depth, not the trust boundary.
- OIDC authenticates the workflow invocation; it does not prove an independent human approval. A separate approval-evidence contract is required before privileged GC workflow use.

## HTTP contract

All endpoints are versioned under `/v1`. Require TLS, bounded request/response bodies, strict JSON (reject duplicate keys and unknown fields), bounded server processing time, and authenticated requests. No endpoint mutates artifact objects or deletes data.

### POST /v1/audit/plans

Request body:

```json
{
  "idempotency_key": "opaque-client-generated-key",
  "plan": {
    "approval_token": "sha256-token",
    "cutoff_unix_ns": 0,
    "total_bytes": 0,
    "candidates": [
      {"sha256": "64-lowercase-hex", "size_bytes": 0, "mtime_unix_ns": 0}
    ]
  }
}
```

The service validates canonical plan structure and recomputes the plan token. Creator identity comes only from verified OIDC claims. The plan and its initial audit event are committed atomically.

### POST /v1/audit/decisions

Request body:

```json
{
  "idempotency_key": "opaque-client-generated-key",
  "approval_token": "sha256-token",
  "decision": "approve"
}
```

`decision` is exactly `approve` or `reject`. The service loads the immutable plan, rejects creator self-approval, and enforces one terminal decision per plan with a database uniqueness constraint. The decision event and audit head update commit atomically.

### GET /v1/audit/events

Read-only, bounded pagination. The response includes exactly these event fields: `sequence`, `event_id`, `event_type`, `actor_id`, `actor_login`, `timestamp`, `details`, `idempotency_key`, `request_hash`, `previous_hash`, and `event_hash`. `timestamp` is UTC RFC 3339 with exactly millisecond precision (`YYYY-MM-DDTHH:MM:SS.sssZ`); `details` is a JSON object. Pagination uses an opaque cursor; clients must not infer missing events from page size.

### Canonical event hashing v1

Both service and client MUST compute `event_hash` as SHA-256 over UTF-8 bytes of the canonical JSON object containing every event field above except `event_hash`. The object contains exactly: `sequence`, `event_id`, `event_type`, `actor_id`, `actor_login`, `timestamp`, `details`, `idempotency_key`, `request_hash`, and `previous_hash`. Serialize with recursively sorted object keys, compact separators (`,` and `:`), ASCII escaping enabled, and non-finite numbers forbidden. Arrays preserve order. Strings are not Unicode-normalized; the exact timestamp string and all string values are hashed as received. Hash output is 64 lowercase hexadecimal characters. `event_hash` itself is excluded to avoid recursion. Unknown or missing event fields MUST be rejected.

The event hash therefore commits to the event identity, verified actor, timestamp, operation details, idempotency request hash, and previous chain link. A client MUST recompute this hash for every event before accepting the chain; checking only `previous_hash` links is insufficient.

Conformance vector (canonical JSON bytes shown as a single line):

```json
{"actor_id":123,"actor_login":"test-actor","details":{},"event_id":"evt-1","event_type":"gc_plan_created","idempotency_key":"key-1","previous_hash":"0000000000000000000000000000000000000000000000000000000000000000","request_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","sequence":1,"timestamp":"2026-11-09T00:00:00.000Z"}
```

Expected SHA-256: `17e28036da076b4525c94aae117e95987fa2fc5da820c7ee856e7300587ce1e1`.

A partial history read MUST be verified against a trusted anchor containing both the first expected sequence and the previous event hash. A full-history read starts at sequence 1 with an all-zero previous hash. A checkpoint head hash, when supplied, MUST match the final verified event hash.

### GET /v1/audit/idempotency/{key}

Returns the committed original operation result for that key, or an explicit not-found response. The lookup is authenticated and scoped to the repository. It must not reveal request payloads or actor data to an unauthorized principal.

### GET /v1/audit/health

Returns readiness only when the authoritative database is reachable and the configured integrity/checkpoint policy is satisfied. Liveness must be separate from readiness. A healthy process with an unavailable or unverified database is not ready to accept writes.

## Idempotency and transaction rules

1. Require an idempotency key on every write. Validate length and character set; never generate a replacement key during retry.
2. Compute a canonical request hash over API version, operation, repository ID, verified actor ID, and normalized request payload. The v1 encoding is UTF-8 JSON with recursively sorted keys, compact separators, ASCII escaping, and non-finite numbers forbidden. Exclude bearer credentials and volatile transport metadata.
3. Enforce a unique database constraint on repository ID plus idempotency key. Store request hash and final response/event hash in the same transaction as the event.
4. Same key + same request hash returns the original committed result, including original event hash and sequence. It must not append another event.
5. Same key + different request hash returns `409 idempotency_conflict`; it must not mutate state.
6. Plan/decision constraints, sequence allocation, event insert, hash-chain head update, and idempotency result are one atomic transaction.
7. A terminal decision is unique per plan. Concurrent decisions from different runners must result in exactly one committed terminal decision.
8. Return success only after commit acknowledgement. If the commit response is lost, the client resolves the outcome by retrying the exact request with the same key or querying the key.
9. Do not retry validation, authorization, idempotency-conflict, or integrity failures. Retry only explicitly classified transient failures, with bounded exponential backoff and jitter, preserving the same key and request bytes.
10. If outcome remains uncertain after the retry budget, return an explicit indeterminate result to the caller. Never claim success or failure without resolving the key.

## Response and error envelope

Success responses include `request_id`, `idempotency_key`, `event_id`, `sequence`, `event_hash`, and `replayed` (boolean). Replays return the original values with `replayed: true`.

Errors use a stable machine-readable envelope:

```json
{
  "error": {
    "code": "idempotency_conflict",
    "message": "idempotency key was used with a different request",
    "retryable": false,
    "request_id": "opaque-request-id"
  }
}
```

Required classes:
- `400 invalid_request`: malformed JSON, duplicate keys, unknown fields, invalid key or payload.
- `401 unauthenticated`: missing, expired, invalid, or unverifiable OIDC token.
- `403 forbidden`: verified identity outside repository/workflow/actor policy or prohibited self-approval.
- `404 not_found`: unknown plan or idempotency key.
- `409 idempotency_conflict`: key reused for different canonical request.
- `409 decision_conflict`: terminal decision already committed for the plan.
- `422 integrity_violation`: plan token, chain, or checkpoint verification failed.
- `429 rate_limited`: bounded retry with server-provided delay.
- `503 unavailable`: service/database unavailable before a definitive commit result.
- Transport timeout/reset after write submission is **indeterminate**, not a definitive failure. Resolve by the same idempotency key.

Do not include JWTs, authorization headers, raw SQL errors, secrets, or unbounded request payloads in errors or logs.

## Failure-injection and cross-run conformance suite

The suite must run against a real transactional adapter before any remote-use claim. A fake in-memory server may test client state handling, but cannot pass remote durability gates.

| ID | Injection / scenario | Required invariant |
|---|---|---|
| FI-01 | Drop connection before request reaches service | No event; same-key retry commits once |
| FI-02 | Service rejects before transaction begins | No event; classified non-retryable or transient as appropriate |
| FI-03 | Kill service after transaction begins, before commit | Transaction rolls back; same-key retry commits once |
| FI-04 | Commit succeeds, then drop response | Retry/query returns original sequence and hash; event count remains one |
| FI-05 | Database connection lost during commit acknowledgement | Client reports indeterminate, then resolves by same key; never creates a second event |
| FI-06 | Database unavailable | Fail closed; no local fallback and no success response |
| FI-07 | Unique-key race: same key, same payload from two runners | Both callers converge on one original result; one event only |
| FI-08 | Same key, different payload/actor/operation | One request may win; other receives conflict; no second event |
| FI-09 | Two different terminal decisions race for one plan | Exactly one terminal decision and one decision event |
| FI-10 | Service restarts after commit | New process reads event and idempotency result from durable store |
| FI-11 | Corrupt event, chain head, or checkpoint | Readiness/write path fails closed; no mutation |
| FI-12 | OIDC expired, wrong audience, repo ID, workflow ref, subject, or actor | Reject before transaction; no audit event |
| FI-13 | Oversized body, duplicate JSON keys, unknown fields | Reject within bounded resources; no transaction |
| FI-14 | Rate limit / transient serialization failure | Bounded retry with same key; no duplicate event |
| CR-01 | Runner A creates plan; runner B starts from a clean workspace | B reads A's plan and chain from remote authority |
| CR-02 | Runner A commits but loses response; runner B retries same key | B receives A's original event ID/sequence/hash |
| CR-03 | Runner A commits plan; runner B commits valid decision | Both events form one contiguous verifiable chain |
| CR-04 | Two independent runners race decisions | Database constraint permits exactly one terminal decision |
| CR-05 | Runner A exits; service process restarts; runner B resumes | State and idempotency results survive both restarts |
| CR-06 | Runner B presents a different repository/workflow identity | Service rejects; no state mutation |
| CR-07 | Paginate event history across runner instances | No gaps/duplicates; full chain verifies against trusted checkpoint |

### In-memory reference implementation boundary

`dorker_agent.remote_audit_service.RemoteAuditService` exposes a WSGI-compatible callable and a direct `handle()` test interface. `InMemoryAuditRepository` serializes mutations with a process-local lock and enforces same-key replay/conflict, one plan per token, creator/approver separation, and one terminal decision. The identity verifier is injected; production wiring must use `GitHubActionsOIDCVerifier` with a fixed `GitHubOIDCPolicy` and GitHub JWKS provider. The test verifier is deliberately fake and does not validate JWT signatures. The cursor encoding is a test-only offset and must be replaced by a server-authenticated opaque cursor for deployment. This implementation is intentionally non-durable and must never be used as an authoritative audit service.

### Required test topology

- Two independent GitHub-hosted runner invocations, with no shared filesystem, workspace, cache, or artifact dependency.
- A separately deployed test service and isolated transactional database, provisioned only after explicit provider approval.
- Deterministic fault-injection hooks at request receipt, transaction begin, event insert, head update, commit, and response write.
- A unique test namespace/repository fixture and cleanup that never touches production data.
- Capture request IDs, event IDs, idempotency keys, sequences, hashes, retry counts, and final database row counts. Redact bearer credentials.
- Verify the full event chain and idempotency table directly after each scenario.

### Pass criteria

- Every FI/CR case has an automated assertion and repeatable evidence.
- For each idempotency key, at most one committed event exists.
- A committed operation remains discoverable after runner and service restarts.
- An ambiguous commit always resolves to the original result or remains explicitly indeterminate; it never creates a duplicate.
- No runner-local persistence is required for correctness.
- No write succeeds when identity, database, chain, or checkpoint verification is unavailable.
- Test report identifies the exact adapter/database version and runner run IDs.

## Implementation gates

1. Freeze this contract and add schema/version compatibility tests.
2. Implement a provider-neutral HTTP client with bounded I/O, strict response parsing, and explicit indeterminate-commit handling. Do not include credentials or provider SDK dependencies in the domain layer.
3. The in-memory service reference and repository double are implemented for contract tests only. Implement a service-side deployment adapter and durable transactional repository only after provider approval; the in-memory repository does not satisfy durability, cross-process concurrency, or cross-run gates.
4. Run FI tests against the real adapter, then CR tests across two independent runner invocations.
5. Complete checkpoint, backup/restore, retention, monitoring, RPO/RTO, and independent authorization review.
6. Only then propose a workflow change. Any `id-token: write`, environment protection, service secret, or privileged operation requires separate explicit approval.

## Non-goals

No provider selection, infrastructure provisioning, database creation, workflow activation, OIDC permission change, artifact deletion, or production credential configuration.

# Remote Audit Service Adversarial Security Review

## Review scope

Review target: `agent-lab/dorker_agent/remote_audit_service.py`, its in-memory repository, OIDC verifier boundary, and service contract tests.

This is a code-level review of a test reference implementation. It is not a penetration test, deployment review, or approval for production use.

## Findings

### ASR-01 — Missing per-actor authorization and approval-evidence policy
**Severity: High — production blocker**

The service verifies repository ID, workflow ref, audience, subject, and signed actor identity through the injected OIDC verifier. It does not enforce an allowlist or role policy for who may create plans, read the complete audit history, or issue terminal decisions. Any actor able to obtain a token for the allowed workflow can call the read and decision endpoints; the only decision restriction is that the plan creator cannot approve/reject their own plan.

OIDC proves which workflow invocation and actor obtained the token. It does not prove that an independent human review occurred. The contract already requires a separate approval-evidence contract, but the reference service does not implement one.

**Required before deployment:** define and inject explicit per-operation authorization (plan creator, auditor/read access, approver/rejector), bind the approval evidence to the immutable plan token and decision, and test unauthorized actors and missing/forged approval evidence. Do not invent actor IDs or roles before the repository owner defines them.

### ASR-02 — Test cursor is unsigned and offset-based
**Severity: High — production blocker**

The cursor is a base64-encoded integer offset. It is neither authenticated nor bound to repository, query, page size, or a stable snapshot. A caller can alter offsets and page boundaries. Client-side chain verification detects many gaps when pages are assembled from the beginning, but this cursor is not suitable as a production pagination token.

**Required before deployment:** use an authenticated opaque cursor (for example, an HMAC-protected token containing repository ID, last sequence, query/version, and expiry), and define snapshot/head semantics. Continue to verify sequence and hash-chain continuity client-side.

### ASR-03 — Process-local repository is neither durable nor cross-process safe
**Severity: Critical — known test-only limitation**

The lock protects only one Python process. State is lost on restart and independent service workers do not share the lock or state. It cannot satisfy atomic durable idempotency, unique terminal decisions, or cross-run guarantees.

**Required before deployment:** implement a transactional database adapter with unique constraints and atomic event/head/idempotency writes; pass the FI/CR suite across independent service and runner processes.

### ASR-04 — No application-level rate limit or request deadline
**Severity: High — deployment blocker**

The WSGI callable bounds declared body length, target length, and query parsing, but does not enforce request rate, concurrent request count, or a processing deadline. Chain verification is linear in the number of events and is performed before repository reads/writes. A production server must not expose this reference directly without front-door controls.

**Required before deployment:** configure and test reverse-proxy/WSGI request-header and body limits, read timeouts, request deadlines, worker/concurrency limits, rate limits, and bounded database query/transaction timeouts. Readiness must use a bounded integrity/checkpoint check rather than re-hashing unbounded history on every probe.

### ASR-05 — WSGI server remains part of the request-size and transport trust boundary
**Severity: Medium — deployment requirement**

The application reads exactly `CONTENT_LENGTH` bytes and relies on the WSGI server to parse HTTP framing. Missing or malformed framing, chunked-body handling, slow uploads, header size, and socket timeouts must be handled by a configured WSGI server/reverse proxy, not assumed from this callable alone.

**Required before deployment:** test the selected server's framing behavior and enforce limits before the WSGI application receives the request.

### ASR-06 — Read endpoints expose repository-wide audit metadata to every accepted workflow identity
**Severity: High — production blocker; overlaps ASR-01**

`GET /v1/audit/events` returns all event details and `GET /v1/audit/idempotency/{key}` returns the event result to any identity accepted by the repository/workflow OIDC policy. There is no separate read authorization or per-key ownership policy.

**Required before deployment:** define audit-reader roles and scope, then test cross-actor and cross-repository access denial.

## Changes made during this review

- Strict base64url decoding for the untrusted JWT payload segment before the real verifier validates the signature and claims.
- Reject malformed request method/target/body/header shapes.
- Bound request target length and event query length/field count.
- Convert deeply nested JSON recursion failures into a bounded 400 response.
- Require OIDC authentication on the readiness endpoint.
- Added regression tests for malformed request shapes, invalid base64url, deeply nested JSON, and unauthenticated health requests.

These changes harden the test reference; they do not close the production blockers above.

## Verification status

- GitHub Actions run #245: registry validation/tests, Agent Lab tests, compile, and Docker integration all passed.
- No live HTTP server, reverse proxy, rate limiter, durable database, multi-process race test, or production OIDC/JWKS integration was exercised.
- No provider, infrastructure, credential, workflow permission, or artifact deletion was added.

## Gate decision

**Not approved for production or privileged artifact-GC use.** Proceed only with a separately designed authorization/approval-evidence policy and a provider-neutral transactional repository contract. Provider selection and provisioning remain separate decisions requiring explicit approval.


## Follow-up design contract

Per-operation authorization, default-deny behavior, independent approval evidence, replay prevention, atomic evidence consumption, and required conformance tests are specified in [REMOTE_AUDIT_AUTHORIZATION_CONTRACT.md](REMOTE_AUDIT_AUTHORIZATION_CONTRACT.md). This is design only; ASR-01 and ASR-06 remain open until runtime enforcement and tests are implemented.

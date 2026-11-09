# Remote Audit Authorization and Approval Evidence Contract v1

## Status

**Design contract only.** This document defines provider-neutral authorization and independent approval-evidence boundaries. It does not assign actors or roles, select a provider, implement a verifier, provision infrastructure, or authorize privileged artifact deletion.

The service MUST remain unavailable for privileged use until an explicit policy configuration and an independently reviewed evidence verifier are supplied. Missing, malformed, unavailable, or ambiguous policy/evidence MUST fail closed.

## Security objectives

1. Authenticate the workflow invocation and derive actor identity only from verified OIDC claims.
2. Authorize each operation independently; authentication MUST NOT imply authorization.
3. Separate plan creation, audit reading, and terminal decision privileges.
4. Require independent approval evidence for both approval and rejection decisions.
5. Bind evidence to the immutable plan, repository, decision, and verified decision-maker.
6. Prevent evidence replay, substitution, expiry bypass, and self-approval.
7. Preserve auditable verification metadata without storing bearer credentials or reusable secrets.

## Authorization policy

The service MUST call an injected AuthorizationPolicy for every protected operation after OIDC verification and before repository access or mutation.

Provider-neutral interface:

    class AuthorizationPolicy(Protocol):
        def authorize(*, actor, operation, repository_id, plan_token) -> AuthorizationResult: ...

Closed, versioned operation vocabulary:
- create_plan
- read_audit
- lookup_idempotency
- approve
- reject

Unknown operations MUST be denied. AuthorizationResult MUST distinguish allow from deny and carry a stable policy decision identifier/version for audit diagnostics; it MUST NOT expose secrets or policy internals.

### Default behavior

- No configured policy: deny every protected operation.
- Policy evaluation error, timeout, malformed result, or unknown policy version: deny.
- Empty actor/role mapping: deny.
- A grant for one operation MUST NOT imply any other operation.
- Authorization MUST be scoped to the configured repository ID.
- Audit-read permission MUST be separate from plan creation and decision permissions.
- The service MUST NOT infer authorization from repository membership, workflow invocation, token possession, login name, or client-supplied fields.
- No wildcard actor, implicit administrator, or default approver is defined.

The repository owner must supply explicit immutable GitHub numeric actor IDs and operation grants through separately reviewed configuration. Login names are display metadata, not stable authorization keys. This contract intentionally defines no actor IDs, role assignments, allowlists, or default grants.

## Independent approval evidence

OIDC identifies the actor executing the workflow. It does not prove that a human independently reviewed the exact plan. A terminal decision MUST therefore include evidence issued by a separately trusted approval system.

Provider-neutral evidence envelope (illustrative schema; values are placeholders, not accepted configuration):

    {
      "evidence_version": "v1",
      "issuer": "configured-trust-domain",
      "evidence_id": "provider-unique-immutable-id",
      "repository_id": 0,
      "plan_token": "64-lowercase-hex",
      "decision": "approve",
      "subject_actor_id": 0,
      "reviewer_actor_id": 0,
      "issued_at": "RFC3339-UTC",
      "expires_at": "RFC3339-UTC",
      "evidence_digest": "64-lowercase-hex",
      "proof": "opaque-provider-proof"
    }

The evidence verifier MUST validate issuer, proof/signature, relying-party binding where applicable, timestamps, immutable evidence ID, and all bindings. Reviewer identity MUST come from verified evidence, not an untrusted caller-supplied field.

### Mandatory bindings and checks

- Evidence repository ID equals the service's configured repository ID.
- Evidence plan token equals the immutable stored plan token.
- Evidence decision exactly equals the requested approve or reject.
- Evidence reviewer identity equals the independently authenticated decision actor, or an explicitly approved binding rule proves the relationship.
- Reviewer is not the plan creator.
- Evidence was issued by a configured trusted issuer and is within its validity interval, with bounded clock-skew policy.
- Evidence ID and digest have not been consumed by another decision.
- Evidence proof is cryptographically and semantically valid under the configured provider contract.
- Reviewer is authorized for the corresponding operation by the Authorization Policy.

Missing evidence, unknown issuer, invalid proof, expired evidence, mismatched binding, reused evidence ID, verifier error, or ambiguous result MUST deny the decision without mutating audit state.

The service MUST NOT accept a boolean approval flag, free-form comment, OIDC actor claim alone, workflow success status, or unverified URL as approval evidence.

## Decision transaction and replay semantics

Authorization and evidence verification occur before mutation. The repository transaction MUST then atomically:

1. Recheck that the plan exists and remains undecided.
2. Enforce creator/reviewer separation.
3. Enforce unique consumption of issuer + evidence ID (and digest where required).
4. Enforce one terminal decision per repository + plan token.
5. Append the decision event with evidence issuer, immutable evidence ID, evidence digest, policy decision ID/version, and verified actor ID.
6. Update the event-chain head and idempotency record.

The evidence proof itself SHOULD NOT be copied into the audit event. Persist only non-secret verification metadata and a digest sufficient for later audit, subject to provider retention/privacy constraints.

A retry with the same idempotency key and same canonical request hash MUST return the original committed result. Reusing the key with changed evidence or decision MUST return an idempotency conflict. Reusing consumed evidence under a new key MUST be rejected. Concurrent terminal decisions MUST result in at most one committed decision.

If the evidence provider has one-time challenge/nonce semantics, challenge consumption and decision commit require a documented atomicity or reservation protocol. A verifier-side check followed by an unrelated database write is insufficient to claim one-time use under concurrency.

## Required conformance tests

| ID | Scenario | Required result |
|---|---|---|
| AUTH-01 | No policy configured | All protected operations denied; no mutation |
| AUTH-02 | Authenticated actor lacks operation grant | Denied independently per operation |
| AUTH-03 | Actor has read grant only | Cannot create plan or decide |
| AUTH-04 | Wrong repository scope | Denied; no cross-repository disclosure |
| AUTH-05 | Policy throws, times out, or returns malformed result | Fail closed |
| EVD-01 | Decision has no evidence | Denied; no mutation |
| EVD-02 | Forged proof or unknown issuer | Denied |
| EVD-03 | Evidence plan/repository/decision binding differs | Denied |
| EVD-04 | Evidence reviewer differs from authenticated actor | Denied unless explicit reviewed binding rule applies |
| EVD-05 | Creator attempts to decide own plan | Denied |
| EVD-06 | Expired or not-yet-valid evidence | Denied |
| EVD-07 | Evidence ID replayed with a new idempotency key | Denied |
| EVD-08 | Concurrent decisions consume the same evidence | At most one terminal decision commits |
| EVD-09 | Verifier unavailable or ambiguous | Fail closed |
| EVD-10 | Same idempotency key, changed evidence | Conflict; no second event |
| EVD-11 | Audit event inspected after decision | Evidence ID/digest and policy version present; proof and bearer token absent |

These tests MUST run against the eventual transactional adapter with independent service processes. In-memory tests alone do not establish durable replay prevention or cross-process atomicity.

## Configuration and production gate

Before implementation can be enabled, the repository owner must explicitly approve immutable actor IDs and operation grants; policy configuration source/version/change control/break-glass procedure; trusted evidence issuer and cryptographic contract; reviewer-to-GitHub-actor binding; expiry, clock-skew, revocation, retention, and privacy rules; atomic evidence-consumption strategy; and audit-reader scope.

Until those decisions are supplied and tests pass, privileged operations MUST remain default-deny. No workflow permission, OIDC id-token: write, provider integration, database, or artifact deletion is authorized by this document.

## Runtime enforcement status (2026-11-09)

The reference service now accepts an injected AuthorizationPolicy and applies it after identity verification to create_plan, read_audit, lookup_idempotency, approve, reject, and the authenticated health/readiness endpoint. The built-in policy is DefaultDenyAuthorizationPolicy and denies all protected operations when no explicit policy is injected. Policy exceptions and malformed results fail closed with authorization_unavailable; explicit denials return forbidden. Test fixtures inject a test-only allow policy.

Remaining gaps: this change does not configure real actor grants, persist policy decision IDs/versions into audit events, implement independent approval evidence verification, or provide durable atomic evidence consumption. Therefore ASR-01 is only partially mitigated; approve/reject remain unsuitable for production and the production gate remains closed. The test-only allow policy MUST NOT be used in deployment.


## Runtime independent approval evidence and replay enforcement (2026-11-09)

The reference service now requires an `evidence` object on every approve/reject request and invokes an injected `ApprovalEvidenceVerifier` after operation authorization. With no verifier configured, decisions fail closed. The verifier must return a typed verified result bound to repository ID, immutable plan token, requested decision, and the authenticated GitHub actor ID; mismatches are rejected. The raw proof is not persisted. The in-memory repository atomically checks and consumes the (repository ID, issuer, evidence ID) tuple under its process-local lock, and records evidence issuer/ID/digest plus authorization decision ID/version in the event hash chain. The request hash includes the complete evidence envelope, so changed evidence under a reused idempotency key conflicts.

The test fixture uses a deterministic test-only verifier; it is not a cryptographic provider implementation. Replay prevention is process-local only. A production adapter must enforce unique evidence consumption and terminal decision in the same durable transaction across independent processes. No issuer, key, actor grant, provider, or production verifier is configured.

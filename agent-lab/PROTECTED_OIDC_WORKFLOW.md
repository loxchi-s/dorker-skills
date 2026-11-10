# Protected GitHub Actions OIDC Workflow Design

## Status and observed repository configuration

**Design only.** This document does not enable a workflow or grant credentials. The repository is currently **public**. The active `protect-main` ruleset targets `main`; its pull-request approval count is **0**, and its required status check is `test`. Do not describe this configuration as requiring an independent reviewer or CODEOWNERS approval.

The current CI workflow must remain read-only with `contents: read`; it must not receive `id-token: write`. No artifact deletion API exists. Artifact collection remains dry-run only.

## Approval policy: current limitation and future requirement

The repository owner may work alone under the current ruleset. GitHub does not permit a pull-request author to approve their own pull request, and an approval count of zero does not enforce independent review.

For any future privileged audit action, require a separate trusted actor whose immutable GitHub user ID differs from the plan author. Validate the review/decision evidence, PR author, reviewer, target branch, plan token, and plan contents before recording an audit decision. This is a **future policy requirement**, not a control currently enforced by the ruleset or implemented by a GitHub Actions adapter.

Do not claim that CODEOWNERS provides an approval gate: ownership declarations alone do not enforce review. Do not change repository visibility, rulesets, or reviewer requirements as part of this design update.

The current code has a durable single-host SQLite audit index, but no GitHub Actions adapter or remote transactional store that persists and reloads audit state across separate runs. The proposed provider-neutral architecture, transaction contract, idempotency rules, external checkpoints, and recovery requirements are documented in [AUDIT_PERSISTENCE_ARCHITECTURE.md](AUDIT_PERSISTENCE_ARCHITECTURE.md). This is design only: no provider is selected or provisioned. Do not assume runner-local SQLite persists between workflow runs. Do not add `id-token: write` or deletion capability until cross-run persistence and audit design have been implemented and tested.

## Security boundary

The OIDC verifier is intended to use a dedicated workflow identity, not the general CI workflow:

- Repository: `loxchi-s/dorker-skills`
- Dedicated workflow ref: `loxchi-s/dorker-skills/.github/workflows/artifact-gc-audit.yml@refs/heads/main`
- Audience: `dorker-artifact-gc`
- Environment: `artifact-gc`
- Environment subject: `repo:loxchi-s/dorker-skills:environment:artifact-gc`

These are proposed identity constraints, not proof that the workflow or environment protection is configured. Configure exact `allowed_workflow_refs` and `allowed_subjects` before enabling a workflow. Do not use wildcards. Keep repository name and immutable numeric repository ID checks enabled.

## Repository configuration: verified baseline and prerequisites

Verified baseline:

- Repository visibility: Public.
- Active ruleset: `protect-main`, targeting `refs/heads/main`.
- Required PR approval count: 0.
- Required status check: `test`.
- No independent reviewer is enforced by the current approval setting.

Before any privileged workflow is enabled, separately review and explicitly approve the required controls:

- Decide whether independent review must become a mandatory repository rule; do not silently change the existing solo-work policy.
- If independent review is required, add a trusted maintainer and configure enforceable review rules. The PR author cannot approve their own PR.
- Verify CODEOWNERS coverage and the ruleset's code-owner-review setting; CODEOWNERS alone is not enforcement.
- Review who may run Actions, environment protection, runner trust, and secret exposure.
- Pin every third-party action to a reviewed full commit SHA.

## Workflow contract (not yet implemented or enabled)

The eventual `.github/workflows/artifact-gc-audit.yml` must satisfy all of the following:

- Trigger only with `workflow_dispatch`; no `push`, `pull_request`, `schedule`, or reusable-call trigger.
- Use a single job bound to `environment: artifact-gc`.
- Set job-level permissions to `contents: read` and `id-token: write`; do not grant write permissions to repository contents, packages, deployments, or pull requests.
- Use fixed audience `dorker-artifact-gc`; never accept audience, repository, workflow-ref, or policy values from dispatch inputs.
- Accept only a bounded action selector and a lowercase 64-character plan token. Validate all inputs before token acquisition.
- Acquire the token only after any configured environment gate. Verify issuer, RS256 signature, key ID, audience, expiry/not-before/issued-at, repository name and immutable ID, exact workflow ref, exact environment subject, actor ID, and actor login.
- For plan creation, record a plan only. For approval/rejection, require the plan token and a different verified actor ID. Reject duplicate decisions and unknown plan tokens.
- Do not implement blob deletion, shell execution, arbitrary commands, dynamic action selection, or user-controlled network access.
- Use bounded timeout, concurrency group, minimal checkout, and sanitized logs. Never print JWTs, bootstrap request tokens, or authorization headers.
- Fail closed if identity verification, policy loading, remote audit persistence, idempotency resolution, checkpoint verification, or audit-chain verification fails.

## Pre-enable checklist

- [ ] Implement a dedicated workflow and exact verifier policy; leave general CI permissions unchanged.
- [ ] Add tests for environment subject and dedicated workflow-ref policy.
- [ ] Test plan creation and a separate-actor decision using synthetic signed JWTs.
- [ ] Verify no token or bootstrap credential is written to SQLite, artifacts, or logs.
- [ ] Verify environment protection, ruleset enforcement, and independent-review policy against live GitHub settings.
- [ ] Select and approve a persistence provider; review workload identity, database constraints, backup/restore, external checkpoints, and audit export.
- [ ] Prove cross-run read/append using separate runner invocations and run concurrent-writer/idempotency tests.
- [ ] Define and validate RPO/RTO; complete an isolated restore drill before enabling privileged workflow.
- [ ] Review action SHAs, dependency pins, runner trust, and database access policy.
- [ ] Obtain explicit approval before adding `id-token: write` to any workflow.
- [ ] Keep artifact deletion unavailable unless separately designed, reviewed, and explicitly authorized.

## Known limitations

The SQLite hash chain is tamper-evident only within the database; it is not an externally signed checkpoint. A GitHub environment approval is not currently imported as a separately verified reviewer identity. The current ruleset does not enforce independent approval. This design authorizes audit events only and does not authorize deletion.

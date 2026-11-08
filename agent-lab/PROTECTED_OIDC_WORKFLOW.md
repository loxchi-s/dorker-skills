# Protected GitHub Actions OIDC Workflow Design

## Status

**Design only.** No workflow is enabled by this document. The current CI workflow remains read-only with
`contents: read`; it must not receive `id-token: write`. No artifact deletion API exists.

## Private-repository approval path (GitHub Pro)

GitHub Environment Required reviewers are not available for this private repository on the Pro plan.
Do not change repository visibility to Public solely to obtain that feature.

Use a pull-request review as the human approval gate instead:

- A GC plan must be proposed in a dedicated pull request and include the canonical plan token and bounded candidate metadata.
- Protect `main` with required pull-request reviews and required status checks; require CODEOWNERS review for GC policy, OIDC verifier, audit code, and workflow files.
- The plan author and approving reviewer must be different immutable GitHub user IDs.
- Treat the GitHub pull-request review record as the durable approval evidence; do not assume a runner-local SQLite database persists between workflow runs.
- The approval workflow must validate the review event, PR author, reviewer, target branch, plan token, and plan contents before recording an audit decision.
- Do not add `id-token: write` or any deletion capability until a cross-run persistence and audit design has been implemented and tested.

The current code has a durable single-host SQLite audit index, but no GitHub Actions adapter that persists and reloads that index across separate runs. Therefore the PR-based approval workflow is a design requirement, not yet implemented. No approval workflow is enabled by this document.

## Security boundary

The OIDC verifier must use a dedicated workflow identity, not the general CI workflow:

- Repository: `loxchi-s/dorker-skills`
- Dedicated workflow ref: `loxchi-s/dorker-skills/.github/workflows/artifact-gc-audit.yml@refs/heads/main`
- Audience: `dorker-artifact-gc`
- Environment: `artifact-gc`
- Environment subject: `repo:loxchi-s/dorker-skills:environment:artifact-gc`

Configure the verifier's exact `allowed_workflow_refs` and `allowed_subjects` to those values before enabling
the workflow. Do not broaden either allowlist with wildcards. Keep repository name and immutable numeric
repository ID checks enabled.

## Required GitHub repository configuration

1. Keep the repository private.
2. Configure branch protection or a ruleset for `main`:
   - Require a pull request before merging.
   - Require at least one approval.
   - Dismiss stale approvals when new commits are pushed.
   - Require approval of the latest reviewable push where available.
   - Require the Agent Lab CI status check.
   - Require CODEOWNERS review for protected paths.
   - Restrict direct pushes and force pushes.
3. Add at least one independent trusted maintainer to `.github/CODEOWNERS` if the repository owner is also the PR author; an author cannot approve their own PR.
4. The `artifact-gc` Environment may remain present, but do not rely on Environment Required reviewers on this private GitHub Pro repository.
5. Restrict who may run Actions and keep secrets out of workflow inputs, artifacts, logs, and prompts.
6. Pin every third-party action to a reviewed full commit SHA before implementing a privileged workflow.

The current `.github/CODEOWNERS` assigns security-sensitive paths to `@loxchi-s`. This file declares review ownership but does not enforce approval by itself; branch protection/rulesets must be configured in GitHub settings. A second independent maintainer must be added before relying on code-owner review when `loxchi-s` authors the PR.

## Workflow contract (not yet enabled)

The eventual `.github/workflows/artifact-gc-audit.yml` must satisfy all of the following:

- Trigger only with `workflow_dispatch`; no `push`, `pull_request`, `schedule`, or reusable-call trigger.
- Use a single job bound to `environment: artifact-gc`.
- Set job-level permissions to `contents: read` and `id-token: write`; do not grant write permissions
  to repository contents, packages, deployments, or pull requests.
- Use a fixed audience `dorker-artifact-gc`; never accept audience, repository, workflow-ref, or policy
  values from dispatch inputs.
- Accept only a bounded action selector and a lowercase 64-character plan token. Validate all inputs
  before token acquisition.
- Acquire the token only after the environment gate. Verify issuer, RS256 signature, key ID, audience,
  expiry/not-before/issued-at, repository name and immutable ID, exact workflow ref, exact environment
  subject, actor ID, and actor login.
- For plan creation, record a plan only. For approval/rejection, require the plan token and a different
  signed actor ID. Reject duplicate decisions and unknown plan tokens.
- Do not implement blob deletion, shell execution, arbitrary commands, dynamic action selection, or
  user-controlled network access in this workflow.
- Use a bounded timeout, concurrency group, minimal checkout, and sanitized logs. Never print the JWT,
  bootstrap request token, or authorization headers.
- Fail closed if identity verification, policy loading, SQLite audit persistence, or audit-chain
  verification fails.

## Pre-enable checklist

- [ ] Add a dedicated workflow and exact verifier policy; leave CI permissions unchanged.
- [ ] Add tests for the environment subject and dedicated workflow-ref policy.
- [ ] Test a plan run and a separate-actor decision run using synthetic signed JWTs.
- [ ] Verify no token or bootstrap credential is written to SQLite, artifacts, or logs.
- [ ] Configure and independently review environment protection and branch protection in GitHub settings.
- [ ] Review action SHAs, dependency pins, runner trust, database persistence/backup, and audit export.
- [ ] Obtain explicit approval before adding `id-token: write` to any workflow.

## Known limitations

The SQLite hash chain is tamper-evident only within the database; it is not an externally signed checkpoint.
A GitHub environment approval is not currently imported as a separately verified reviewer identity.
This design authorizes audit events only and does not authorize deletion.

# Protected GitHub Actions OIDC Workflow Design

## Status

**Design only.** No workflow is enabled by this document. The current CI workflow remains read-only with
`contents: read`; it must not receive `id-token: write`. No artifact deletion API exists.

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

1. Create the `artifact-gc` environment.
2. Require at least one designated reviewer; prevent self-review where the GitHub plan/settings support it.
3. Restrict deployments to the protected `main` branch.
4. Protect `main` with required review and status checks. Require CODEOWNERS review for the workflow,
   OIDC verifier/policy, and artifact audit code.
5. Restrict who may run workflow dispatch. Review organization/repository Actions permissions.
6. Pin every third-party action to a reviewed full commit SHA before implementation.
7. Keep secrets out of workflow inputs, artifacts, logs, and prompts.

Environment approval is an additional deployment gate; it is **not** proof of the reviewer's identity in the
OIDC `actor` claim. The JWT actor identifies the workflow run initiator. Therefore the GC plan creator and
the approval workflow dispatcher must be different immutable GitHub actor IDs. The index enforces this
distinction. A second environment reviewer provides a separate GitHub-side gate, not a replacement for
the distinct-dispatcher check.

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

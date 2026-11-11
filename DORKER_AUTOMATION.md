# Dorker scheduled automation

## Architecture

GitHub Actions is the scheduler and execution boundary. The workflow invokes a deterministic, read-only Python auditor; it does not instantiate a second agent runtime or execute skill definitions. The existing Agent Lab remains a separate scaffold and receives no new runtime capabilities from this workflow.

The auditor uses the workflow-provided GITHUB_TOKEN for authenticated GET requests to repository metadata, Actions runs, pull requests, and code-scanning alerts. Dependabot alerts use a separate GitHub App installation token scoped to `loxchi-s/dorker-skills`, with only `Dependabot alerts: read` and `Metadata: read` permissions. The App token is created only when both repository Actions credentials are configured. The workflow writes JSON and Markdown summary reports to the job workspace and uploads them as a 30-day artifact. Vulnerability alert payloads are intentionally discarded after counting and are never persisted in reports. It does not write repository contents, create issues or pull requests, merge, deploy, invoke Supabase, or run arbitrary model-generated commands.

## Schedule (Asia/Bangkok)

| Thailand time | UTC cron | Audit slot |
|---|---|---|
| 06:00 | 0 23 * * * (previous UTC day) | repo_ci |
| 10:00 | 0 3 * * * | security |
| 14:00 | 0 7 * * * | quality |
| 18:00 | 0 11 * * * | pr_readiness |
| 22:00 | 0 15 * * * | daily_summary |

GitHub Actions scheduled events may be delayed, particularly during high load. These are target times, not a minute-level execution guarantee. The workflow routes scheduled events using the exact github.event.schedule expression; it does not infer the slot from actual start time. Manual dispatch requires an explicit slot. Scheduled jobs remain disabled until a repository Actions variable named `DORKER_AUTOMATION_ENABLED` is set to the string `true`; manual dispatch bypasses this gate for an owner-directed smoke test after the workflow exists on the default branch.

## Slot responsibilities

- repo_ci: repository metadata, recent workflow runs, and open pull requests.
- security: open Dependabot and code-scanning alert counts; alert details are not persisted.
- quality: recent workflow outcomes and open pull-request inventory.
- pr_readiness: open pull-request inventory only. It does not inspect mergeability, required checks, branch protection, conflicts, or provide a merge recommendation.
- daily_summary: consolidated inventory across repository, CI, PR, and security endpoints.

The auditor caps pagination at five pages per list endpoint. A truncated response or unavailable endpoint is reported as incomplete. Alert counts are null when their endpoint is unavailable; the report never silently interprets an inaccessible endpoint as zero alerts. A 403/404 on security endpoints is recorded as unavailable.

## Failure and recovery semantics

Each run is independent and read-only. The workflow does not claim exactly-once execution. Concurrency prevents overlapping runs for the same scheduled slot/ref but does not provide a distributed idempotency guarantee. Re-running a job creates a new report artifact and does not mutate repository state. API transport errors, malformed JSON shapes, invalid UTF-8, response-size limits, and unavailable permissions are classified as incomplete endpoint data or failed configuration checks. Review endpoint status before relying on the summary.

## Security boundaries

- `GITHUB_TOKEN` permissions are read-only for contents, Actions, pull requests, and code-scanning alerts; it does not receive the Dependabot alerts permission.
- The GitHub App token is scoped to the single `dorker-skills` repository and explicitly requests only `vulnerability-alerts: read` and `metadata: read`.
- Third-party actions are pinned to immutable commit SHAs.
- The API client only sends the token to https://api.github.com, uses HTTPS, applies request timeouts, and bounds response size.
- Security alert details are not included in report JSON, Markdown, logs, or artifacts; only counts and endpoint status are retained.
- No secrets are printed or included in report output.
- PR titles and other untrusted text are not rendered into Markdown tables.
- No skill registry entry is enabled and no model is asked to execute commands.

## Acceptance criteria

- [ ] Five cron expressions map deterministically to the five documented Thailand-time slots.
- [ ] Manual dispatch accepts only the five supported slot values.
- [ ] All API calls are GET-only, bounded by request timeout, response-size limit, and pagination limit.
- [ ] Dependabot and code-scanning response details are excluded from all persisted reports; counts remain available.
- [ ] Inaccessible or truncated endpoints produce an incomplete report and do not imply zero alerts.
- [ ] Dependabot requests use the dedicated GitHub App token; missing credentials or failed token minting produce an unavailable endpoint with a null count.
- [ ] Unit tests, Python compilation, Agent Lab CI, CodeQL, and OSV checks pass on the final PR head.
- [ ] After merge, a manual workflow dispatch completes and uploads both report artifacts while scheduled execution remains gated.
- [ ] No merge, deployment, repository write, or Supabase mutation is performed by this workflow.

## Validation

Run locally:

    python -m unittest discover -s tests -p 'test_dorker_daily_audit.py' -v
    python -m py_compile tools/dorker_daily_audit.py

The first manual GitHub Actions dispatch after merge is required to validate workflow trigger parsing, GITHUB_TOKEN permissions, GitHub App token creation, Dependabot endpoint availability, and artifact upload. Configure repository Actions secrets `DORKER_APP_ID` (App ID `5709420`) and `DORKER_APP_PRIVATE_KEY` (the generated PEM contents) before expecting a complete security report. Never commit the PEM file or print its contents. The schedule remains disabled until an owner sets `DORKER_AUTOMATION_ENABLED=true` in repository Actions variables. Scheduled execution is not considered operationally validated until the owner enables the gate and a scheduled run is observed.

## Rollback

1. Set the repository Actions variable `DORKER_AUTOMATION_ENABLED` to `false` (or remove it) to stop scheduled jobs; manual dispatch remains available for diagnosis.
2. Revert this PR's changes to the workflow, audit worker, tests, CI integration, and documentation in a follow-up commit.
3. Confirm that no report artifacts are being generated after the workflow is disabled.
4. No database, Supabase, production deployment, or canonical dataset rollback is required because this workflow is read-only.

## Operational impact and known limitations

The workflow performs read-only API requests five times per day and stores summary artifacts for 30 days. GitHub may delay scheduled start times. Dependabot inventory requires repository Actions secrets `DORKER_APP_ID` and `DORKER_APP_PRIVATE_KEY` for the installed read-only GitHub App. If credentials are absent or token creation fails, the endpoint is marked unavailable and the report remains incomplete. Pagination is intentionally capped at five pages; larger inventories are marked incomplete. This workflow does not create issues, auto-fix code, approve PRs, or merge changes.

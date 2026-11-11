# Dorker scheduled automation

## Architecture

GitHub Actions is the scheduler and execution boundary. The workflow invokes a deterministic, read-only Python auditor; it does not instantiate a second agent runtime or execute skill definitions. The existing Agent Lab remains a separate scaffold and receives no new runtime capabilities from this workflow.

The auditor uses the workflow-provided GitHub token for authenticated GET requests only. Permissions are limited to repository contents, Actions runs, pull requests, and security-event reads. It writes JSON and Markdown reports to the job workspace and uploads them as a 30-day artifact. It does not write repository contents, create issues or pull requests, merge, deploy, invoke Supabase, or run arbitrary model-generated commands.

## Schedule (Asia/Bangkok)

| Thailand time | UTC cron | Audit slot |
|---|---|---|
| 06:00 | 0 23 * * * (previous UTC day) | repo_ci |
| 10:00 | 0 3 * * * | security |
| 14:00 | 0 7 * * * | quality |
| 18:00 | 0 11 * * * | pr_readiness |
| 22:00 | 0 15 * * * | daily_summary |

GitHub Actions scheduled events may be delayed, particularly during high load. These are target times, not a minute-level execution guarantee. The workflow routes scheduled events using the exact github.event.schedule expression; it does not infer the slot from actual start time. Manual dispatch requires an explicit slot.

## Slot responsibilities

- repo_ci: repository metadata, recent workflow runs, and open pull requests.
- security: open Dependabot and code-scanning alert inventory.
- quality: recent workflow outcomes and open pull-request inventory.
- pr_readiness: open pull-request inventory and merge-readiness metadata exposed by the REST list endpoint.
- daily_summary: consolidated inventory across repository, CI, PR, and security endpoints.

The auditor caps pagination at five pages per list endpoint. A truncated response or unavailable endpoint is reported as incomplete; absence of visible alerts is not proof that no vulnerabilities exist. A 403/404 on security endpoints is recorded as unavailable, not silently interpreted as zero alerts.

## Failure and recovery semantics

Each run is independent and read-only. The workflow does not claim exactly-once execution. Concurrency prevents overlapping runs for the same scheduled slot/ref but does not provide a distributed idempotency guarantee. Re-running a job creates a new report artifact and does not mutate repository state. API transport errors and malformed responses produce an incomplete report or a failed configuration check; review endpoint status before relying on the summary.

## Security boundaries

- permissions are explicitly read-only and omit contents: write, issues: write, pull-requests: write, and id-token: write.
- Third-party actions are pinned to immutable commit SHAs.
- The API client only sends the token to https://api.github.com, uses HTTPS, and applies request timeouts.
- No secrets are printed or included in report output.
- PR titles and other untrusted text are not rendered into Markdown tables.
- No skill registry entry is enabled and no model is asked to execute commands.

## Validation

Local tests:

    python -m unittest discover -s tests -p 'test_dorker_daily_audit.py' -v
    python -m py_compile tools/dorker_daily_audit.py

The first GitHub Actions run is required to validate workflow triggers, repository token permissions, security endpoint availability, artifact upload, and real schedule routing. Until those runs complete, scheduled automation is implemented but not operationally validated.

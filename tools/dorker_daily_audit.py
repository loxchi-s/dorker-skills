#!/usr/bin/env python3
"""Read-only, deterministic GitHub repository audit for scheduled Dorker runs."""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEDULE_TO_SLOT = {
    "0 23 * * *": "repo_ci",
    "0 3 * * *": "security",
    "0 7 * * *": "quality",
    "0 11 * * *": "pr_readiness",
    "0 15 * * *": "daily_summary",
}
SLOT_DESCRIPTIONS = {
    "repo_ci": "Repository, open pull requests, and recent workflow health",
    "security": "Dependabot and code-scanning alert inventory",
    "quality": "Recent CI outcomes and open pull-request inventory",
    "pr_readiness": "Open pull-request readiness signals",
    "daily_summary": "Daily consolidated repository, CI, PR, and security snapshot",
}
SLOT_ENDPOINTS = {
    "repo_ci": ("repository", "workflow_runs", "pull_requests"),
    "security": ("repository", "dependabot_alerts", "code_scanning_alerts"),
    "quality": ("repository", "workflow_runs", "pull_requests"),
    "pr_readiness": ("repository", "pull_requests"),
    "daily_summary": ("repository", "workflow_runs", "pull_requests", "dependabot_alerts", "code_scanning_alerts"),
}
API_ROOT = "https://api.github.com"
MAX_PAGES = 5


class AuditError(RuntimeError):
    """Invalid audit configuration or unsafe API response."""


class GitHubAPIError(RuntimeError):
    def __init__(self, status: int) -> None:
        super().__init__("GitHub API request failed")
        self.status = status


class GitHubClient:
    """Read-only REST client with bounded pagination and request timeouts."""

    def __init__(self, token: str, timeout: float = 20.0) -> None:
        if not token:
            raise AuditError("GITHUB_TOKEN is required")
        self._token = token
        self._timeout = timeout

    def _request(self, url: str) -> tuple[Any, str | None]:
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme != "https" or parsed.netloc != "api.github.com":
            raise AuditError("Refusing to send credentials to an untrusted host")
        request = urllib.request.Request(
            url,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": "Bearer " + self._token,
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "dorker-read-only-audit",
            },
            method="GET",
        )
        try:
            with urllib.request.urlopen(request, timeout=self._timeout) as response:
                return json.loads(response.read().decode("utf-8")), response.headers.get("Link")
        except urllib.error.HTTPError as exc:
            raise GitHubAPIError(exc.code) from None
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            raise AuditError("GitHub API transport or response decoding failed") from exc

    def get(self, path: str) -> Any:
        return self._request(API_ROOT + path)[0]

    def list(self, path: str) -> tuple[list[Any], bool]:
        items: list[Any] = []
        url = API_ROOT + path
        for _ in range(MAX_PAGES):
            payload, link_header = self._request(url)
            if not isinstance(payload, list):
                raise AuditError("GitHub list endpoint returned a non-list payload")
            items.extend(payload)
            next_url = None
            if link_header:
                for part in link_header.split(","):
                    match = re.match(r'\s*<([^>]+)>\s*;\s*rel="next"', part)
                    if match:
                        next_url = match.group(1)
                        break
            if not next_url:
                return items, False
            url = next_url
        return items, True


def resolve_slot(schedule: str | None, dispatch_slot: str | None) -> str:
    if dispatch_slot:
        if dispatch_slot not in SLOT_ENDPOINTS:
            raise AuditError("Unsupported workflow_dispatch slot")
        return dispatch_slot
    try:
        return SCHEDULE_TO_SLOT[schedule or ""]
    except KeyError as exc:
        raise AuditError("Unknown schedule expression; refusing to guess the task slot") from exc


def endpoint_path(repo: str, name: str) -> str:
    encoded = urllib.parse.quote(repo, safe="/")
    paths = {
        "repository": "/repos/" + encoded,
        "workflow_runs": "/repos/" + encoded + "/actions/runs?per_page=100",
        "pull_requests": "/repos/" + encoded + "/pulls?state=open&per_page=100",
        "dependabot_alerts": "/repos/" + encoded + "/dependabot/alerts?state=open&per_page=100",
        "code_scanning_alerts": "/repos/" + encoded + "/code-scanning/alerts?state=open&per_page=100",
    }
    return paths[name]


def collect_report(client: GitHubClient, repo: str, slot: str) -> dict[str, Any]:
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo):
        raise AuditError("GITHUB_REPOSITORY must use owner/repository format")
    report: dict[str, Any] = {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "repository": repo,
        "slot": slot,
        "task": SLOT_DESCRIPTIONS[slot],
        "read_only": True,
        "complete": True,
        "endpoints": {},
        "summary": {},
    }
    for name in SLOT_ENDPOINTS[slot]:
        try:
            if name == "repository":
                report["endpoints"][name] = {"status": "ok", "data": client.get(endpoint_path(repo, name))}
            else:
                items, truncated = client.list(endpoint_path(repo, name))
                report["endpoints"][name] = {
                    "status": "ok", "count": len(items), "items": items, "truncated": truncated,
                }
                if truncated:
                    report["complete"] = False
        except GitHubAPIError as exc:
            report["complete"] = False
            report["endpoints"][name] = {"status": "unavailable", "http_status": exc.status}
        except AuditError:
            report["complete"] = False
            report["endpoints"][name] = {"status": "error", "reason": "transport_or_payload_error"}

    repo_data = report["endpoints"].get("repository", {}).get("data", {})
    runs = report["endpoints"].get("workflow_runs", {}).get("items", [])
    prs = report["endpoints"].get("pull_requests", {}).get("items", [])
    dependabot = report["endpoints"].get("dependabot_alerts", {}).get("items", [])
    code_alerts = report["endpoints"].get("code_scanning_alerts", {}).get("items", [])
    report["summary"] = {
        "default_branch": repo_data.get("default_branch"),
        "open_pull_requests": len(prs),
        "workflow_runs_observed": len(runs),
        "workflow_failures_observed": sum(
            run.get("conclusion") in {"failure", "timed_out", "action_required"} for run in runs
        ),
        "dependabot_alerts_open": len(dependabot),
        "code_scanning_alerts_open": len(code_alerts),
    }
    return report


def safe_cell(value: Any) -> str:
    return str(value if value is not None else "unknown").replace("|", r"\|").replace("\r", " ").replace("\n", " ")


def render_markdown(report: dict[str, Any]) -> str:
    summary = report["summary"]
    lines = [
        "# Dorker scheduled audit", "",
        "- Repository: " + safe_cell(report["repository"]),
        "- Slot: " + safe_cell(report["slot"]),
        "- Task: " + safe_cell(report["task"]),
        "- Generated (UTC): " + safe_cell(report["generated_at"]),
        "- Read-only: true",
        "- Data completeness: " + ("complete" if report["complete"] else "incomplete"),
        "", "## Observed signals", "", "| Signal | Observed value |", "|---|---:|",
    ]
    for key, value in summary.items():
        lines.append("| " + safe_cell(key) + " | " + safe_cell(value) + " |")
    lines.extend(["", "## Endpoint coverage", "", "| Endpoint | Status | Records |", "|---|---|---:|"])
    for name, result in report["endpoints"].items():
        lines.append("| " + safe_cell(name) + " | " + safe_cell(result.get("status")) + " | " + safe_cell(result.get("count", "n/a")) + " |")
    lines.extend([
        "", "This is an inventory of API-visible signals, not a security certification or merge recommendation.",
        "Unavailable endpoints and pagination truncation make the report incomplete; review endpoint status before drawing conclusions.", "",
    ])
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--schedule", default=os.getenv("DORKER_SCHEDULE", ""))
    parser.add_argument("--slot", default=os.getenv("DORKER_SLOT", ""))
    parser.add_argument("--repository", default=os.getenv("GITHUB_REPOSITORY", ""))
    parser.add_argument("--output-dir", default="reports")
    args = parser.parse_args()
    try:
        slot = resolve_slot(args.schedule or None, args.slot or None)
        report = collect_report(GitHubClient(os.getenv("GITHUB_TOKEN", "")), args.repository, slot)
        output_dir = Path(args.output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / "dorker-audit.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        (output_dir / "dorker-audit.md").write_text(render_markdown(report), encoding="utf-8")
        print("Audit slot: " + slot)
        print("Data complete: " + str(report["complete"]).lower())
        return 0
    except AuditError as exc:
        print("::error::" + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

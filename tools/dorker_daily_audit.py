#!/usr/bin/env python3
"""Read-only, deterministic GitHub repository audit for scheduled Dorker runs."""
from __future__ import annotations

import argparse
import http.client
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
ALERT_ENDPOINTS = frozenset({"dependabot_alerts", "code_scanning_alerts"})
API_ROOT = "https://api.github.com"
MAX_PAGES = 5
MAX_RESPONSE_BYTES = 2_000_000


class AuditError(RuntimeError):
    """Represent invalid audit configuration or an unsafe API response."""


class GitHubAPIError(RuntimeError):
    """Represent an HTTP error returned by the GitHub REST API."""

    def __init__(self, status: int) -> None:
        """Initialize the exception with an HTTP status code."""
        super().__init__("GitHub API request failed")
        self.status = status


class GitHubClient:
    """Provide bounded, read-only GitHub REST API access."""

    def __init__(self, token: str, timeout: float = 20.0) -> None:
        """Initialize the client with a token and per-request timeout."""
        if not token:
            raise AuditError("GITHUB_TOKEN is required")
        self._token = token
        self._timeout = timeout

    def _request(self, url: str) -> tuple[Any, str | None]:
        """Issue one authenticated GET request to the GitHub API host."""
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
                raw = response.read(MAX_RESPONSE_BYTES + 1)
                if len(raw) > MAX_RESPONSE_BYTES:
                    raise AuditError("GitHub API response exceeded the 2 MB safety limit")
                return json.loads(raw.decode("utf-8")), response.headers.get("Link")
        except urllib.error.HTTPError as exc:
            raise GitHubAPIError(exc.code) from None
        except (urllib.error.URLError, TimeoutError, OSError, http.client.HTTPException, json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise AuditError("GitHub API transport or response decoding failed") from exc

    def get(self, path: str) -> dict[str, Any]:
        """Fetch an object response and reject unexpected JSON top-level types."""
        payload = self._request(API_ROOT + path)[0]
        if not isinstance(payload, dict):
            raise AuditError("GitHub object endpoint returned an unsupported payload")
        return payload

    def list(self, path: str) -> tuple[list[dict[str, Any]], bool]:
        """Fetch a list endpoint with bounded pagination and item validation."""
        items: list[dict[str, Any]] = []
        url = API_ROOT + path
        for _ in range(MAX_PAGES):
            payload, link_header = self._request(url)
            if isinstance(payload, list):
                page_items = payload
            elif isinstance(payload, dict) and isinstance(payload.get("workflow_runs"), list):
                # GitHub Actions returns {total_count, workflow_runs}, unlike other list endpoints.
                page_items = payload["workflow_runs"]
            else:
                raise AuditError("GitHub list endpoint returned an unsupported payload")
            if any(not isinstance(item, dict) for item in page_items):
                raise AuditError("GitHub list endpoint contained a non-object item")
            items.extend(page_items)
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
    """Resolve a scheduled cron or validated manual input to an audit slot."""
    if dispatch_slot:
        if dispatch_slot not in SLOT_ENDPOINTS:
            raise AuditError("Unsupported workflow_dispatch slot")
        return dispatch_slot
    try:
        return SCHEDULE_TO_SLOT[schedule or ""]
    except KeyError as exc:
        raise AuditError("Unknown schedule expression; refusing to guess the task slot") from exc


def endpoint_path(repo: str, name: str) -> str:
    """Build a fixed GitHub REST path for a supported endpoint."""
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
    """Collect an audit snapshot while excluding sensitive alert payloads."""
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo):
        raise AuditError("GITHUB_REPOSITORY must use owner/repository format")
    if slot not in SLOT_ENDPOINTS:
        raise AuditError("Unsupported audit slot")
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
    summary: dict[str, Any] = {
        "default_branch": None,
        "open_pull_requests": None,
        "workflow_runs_observed": None,
        "workflow_failures_observed": None,
        "dependabot_alerts_open": None,
        "code_scanning_alerts_open": None,
    }
    for name in SLOT_ENDPOINTS[slot]:
        try:
            if name == "repository":
                repository_data = client.get(endpoint_path(repo, name))
                summary["default_branch"] = repository_data.get("default_branch")
                report["endpoints"][name] = {"status": "ok"}
            else:
                items, truncated = client.list(endpoint_path(repo, name))
                entry = {"status": "ok", "count": len(items), "truncated": truncated}
                if name == "pull_requests":
                    summary["open_pull_requests"] = len(items)
                elif name == "workflow_runs":
                    summary["workflow_runs_observed"] = len(items)
                    summary["workflow_failures_observed"] = sum(
                        run.get("conclusion") in {"failure", "timed_out", "action_required"}
                        for run in items
                    )
                elif name == "dependabot_alerts":
                    summary["dependabot_alerts_open"] = len(items)
                elif name == "code_scanning_alerts":
                    summary["code_scanning_alerts_open"] = len(items)
                report["endpoints"][name] = entry
                if truncated:
                    report["complete"] = False
        except GitHubAPIError as exc:
            report["complete"] = False
            report["endpoints"][name] = {"status": "unavailable", "http_status": exc.status}
        except AuditError:
            report["complete"] = False
            report["endpoints"][name] = {"status": "error", "reason": "transport_or_payload_error"}

    report["summary"] = summary
    return report


def safe_cell(value: Any) -> str:
    """Escape untrusted values before placing them in Markdown table cells."""
    return str(value if value is not None else "unknown").replace("|", r"\|").replace("\r", " ").replace("\n", " ")


def render_markdown(report: dict[str, Any]) -> str:
    """Render the summary and endpoint coverage without embedding API payloads."""
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
    """Parse workflow inputs, write report artifacts, and return a process status."""
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

"""Provider-neutral, bounded HTTP client for the remote audit contract.

This client does not verify OIDC claims or make local persistence authoritative.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import random
import re
import socket
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Callable, Protocol
from urllib.parse import quote, urlsplit

_IDEMPOTENCY_KEY = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_MAX_RESPONSE_BYTES = 256 * 1024


class AuditClientError(RuntimeError):
    """Base class for remote audit client failures."""


class AuditRequestRejected(AuditClientError):
    """The service returned a definitive non-retryable error."""

    def __init__(self, status: int, code: str):
        super().__init__(f"audit request rejected: HTTP {status} ({code})")
        self.status = status
        self.code = code


class AuditOutcomeIndeterminate(AuditClientError):
    """A write may have committed, but its outcome could not be resolved."""


class AuditServiceUnavailable(AuditClientError):
    """The service definitively rejected the request as temporarily unavailable."""


@dataclass(frozen=True, slots=True)
class HttpResponse:
    status: int
    body: bytes


class HttpTransport(Protocol):
    def __call__(
        self, method: str, url: str, headers: dict[str, str],
        body: bytes | None, timeout_seconds: float,
    ) -> HttpResponse: ...


def _urllib_transport(
    method: str, url: str, headers: dict[str, str],
    body: bytes | None, timeout_seconds: float,
) -> HttpResponse:
    request = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            payload = response.read(_MAX_RESPONSE_BYTES + 1)
            return HttpResponse(response.status, payload)
    except urllib.error.HTTPError as error:
        payload = error.read(_MAX_RESPONSE_BYTES + 1)
        return HttpResponse(error.code, payload)


def _strict_json(data: bytes) -> dict[str, object]:
    if len(data) > _MAX_RESPONSE_BYTES:
        raise AuditClientError("audit response exceeds 256 KiB")

    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON object key")
            result[key] = value
        return result

    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise AuditClientError("audit service returned invalid JSON") from exc
    if not isinstance(value, dict):
        raise AuditClientError("audit response must be a JSON object")
    return value


class RemoteAuditHttpClient:
    """Small synchronous client with bounded retries and stable idempotency."""

    def __init__(
        self,
        base_url: str,
        token_provider: Callable[[], str],
        *,
        transport: HttpTransport = _urllib_transport,
        timeout_seconds: float = 5.0,
        max_attempts: int = 3,
        backoff_base_seconds: float = 0.1,
        max_backoff_seconds: float = 2.0,
        sleeper: Callable[[float], None] = time.sleep,
        jitter: Callable[[float], float] = random.uniform,
    ) -> None:
        parsed = urlsplit(base_url)
        if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password:
            raise ValueError("base_url must be an HTTPS origin without embedded credentials")
        if parsed.query or parsed.fragment:
            raise ValueError("base_url must not contain query or fragment")
        if not callable(token_provider) or not callable(transport):
            raise TypeError("token_provider and transport must be callable")
        if not 0 < timeout_seconds <= 30:
            raise ValueError("timeout_seconds must be in (0, 30]")
        if not 1 <= max_attempts <= 5:
            raise ValueError("max_attempts must be from 1 to 5")
        if not 0 <= backoff_base_seconds <= 5 or not 0 <= max_backoff_seconds <= 10:
            raise ValueError("backoff values exceed configured bounds")
        self._base_url = base_url.rstrip("/")
        self._token_provider = token_provider
        self._transport = transport
        self._timeout = timeout_seconds
        self._max_attempts = max_attempts
        self._backoff_base = backoff_base_seconds
        self._max_backoff = max_backoff_seconds
        self._sleep = sleeper
        self._jitter = jitter

    def record_plan(self, *, idempotency_key: str, plan: dict[str, object]) -> dict[str, object]:
        return self._write(
            "/v1/audit/plans",
            {"idempotency_key": idempotency_key, "plan": plan},
            idempotency_key,
        )

    def record_decision(
        self, *, idempotency_key: str, approval_token: str, decision: str,
    ) -> dict[str, object]:
        if decision not in ("approve", "reject"):
            raise ValueError("decision must be 'approve' or 'reject'")
        return self._write(
            "/v1/audit/decisions",
            {
                "idempotency_key": idempotency_key,
                "approval_token": approval_token,
                "decision": decision,
            },
            idempotency_key,
        )

    def lookup_idempotency(self, key: str) -> dict[str, object]:
        self._validate_key(key)
        return self._request("GET", f"/v1/audit/idempotency/{quote(key, safe='')}", None, None)

    def list_audit_events(
        self, *, limit: int = 100, cursor: str | None = None,
    ) -> dict[str, object]:
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 1000:
            raise ValueError("limit must be an integer from 1 to 1000")
        if cursor is not None and (
            not isinstance(cursor, str) or not cursor or len(cursor) > 2048
            or any(ord(char) < 0x21 or ord(char) > 0x7e for char in cursor)
        ):
            raise ValueError("cursor must be 1..2048 printable ASCII characters")
        query = f"?limit={limit}"
        if cursor is not None:
            query += f"&cursor={quote(cursor, safe='')}"
        result = self._request("GET", "/v1/audit/events" + query, None, None)
        self._validate_event_page(result)
        return result

    def list_all_audit_events(
        self, *, limit: int = 100, max_pages: int = 1000,
        expected_start_sequence: int = 1,
        expected_previous_hash: str = "0" * 64,
        expected_head_hash: str | None = None,
    ) -> list[dict[str, object]]:
        if isinstance(max_pages, bool) or not isinstance(max_pages, int) or not 1 <= max_pages <= 10_000:
            raise ValueError("max_pages must be an integer from 1 to 10000")
        events: list[dict[str, object]] = []
        cursor: str | None = None
        seen_cursors: set[str] = set()
        for _ in range(max_pages):
            page = self.list_audit_events(limit=limit, cursor=cursor)
            batch = page["events"]
            assert isinstance(batch, list)
            events.extend(batch)
            next_cursor = page.get("next_cursor")
            if next_cursor is None:
                self.verify_event_chain(
                    events, expected_start_sequence=expected_start_sequence,
                    expected_previous_hash=expected_previous_hash,
                    expected_head_hash=expected_head_hash,
                )
                return events
            if not isinstance(next_cursor, str) or next_cursor in seen_cursors:
                raise AuditClientError("audit pagination cursor is invalid or repeated")
            seen_cursors.add(next_cursor)
            cursor = next_cursor
        raise AuditClientError("audit pagination exceeded max_pages")

    @staticmethod
    def _validate_event_page(page: dict[str, object]) -> None:
        if set(page) - {"events", "next_cursor"}:
            raise AuditClientError("audit event page contains unknown fields")
        events = page.get("events")
        if not isinstance(events, list) or len(events) > 1000:
            raise AuditClientError("audit event page must contain at most 1000 events")
        for event in events:
            if not isinstance(event, dict):
                raise AuditClientError("audit event must be an object")
            allowed = {
                "sequence", "event_id", "event_type", "actor_id", "actor_login",
                "timestamp", "details", "idempotency_key", "request_hash", "previous_hash", "event_hash",
            }
            if set(event) - allowed:
                raise AuditClientError("audit event contains unknown fields")
            sequence = event.get("sequence")
            if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 1:
                raise AuditClientError("audit event has invalid sequence")
            for field in ("event_id", "event_type", "actor_login", "timestamp"):
                if not isinstance(event.get(field), str) or not event[field]:
                    raise AuditClientError(f"audit event has invalid {field}")
            actor_id = event.get("actor_id")
            if isinstance(actor_id, bool) or not isinstance(actor_id, int) or actor_id < 1:
                raise AuditClientError("audit event has invalid actor_id")
            if not isinstance(event.get("details"), dict):
                raise AuditClientError("audit event details must be an object")
            if not isinstance(event.get("idempotency_key"), str) or not event["idempotency_key"]:
                raise AuditClientError("audit event has invalid idempotency_key")
            for field in ("request_hash", "previous_hash", "event_hash"):
                if not isinstance(event.get(field), str) or not re.fullmatch(r"[0-9a-f]{64}", event[field]):
                    raise AuditClientError(f"audit event has invalid {field}")
        next_cursor = page.get("next_cursor")
        if next_cursor is not None and (
            not isinstance(next_cursor, str) or not next_cursor
            or len(next_cursor) > 2048
        ):
            raise AuditClientError("audit page has invalid next_cursor")

    @staticmethod
    def compute_event_hash(event: dict[str, object]) -> str:
        """Hash the v1 canonical remote event payload (excluding event_hash)."""
        fields = (
            "sequence", "event_id", "event_type", "actor_id", "actor_login",
            "timestamp", "details", "idempotency_key", "request_hash", "previous_hash",
        )
        if not isinstance(event, dict) or set(event) != set(fields) | {"event_hash"}:
            raise AuditClientError("audit event does not match the canonical v1 schema")
        payload = {field: event[field] for field in fields}
        try:
            encoded = json.dumps(
                payload, sort_keys=True, separators=(",", ":"),
                ensure_ascii=True, allow_nan=False,
            ).encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise AuditClientError("audit event is not canonically serializable") from exc
        return hashlib.sha256(encoded).hexdigest()

    @staticmethod
    def verify_event_chain(
        events: list[dict[str, object]], *,
        expected_start_sequence: int = 1,
        expected_previous_hash: str = "0" * 64,
        expected_head_hash: str | None = None,
    ) -> bool:
        if isinstance(expected_start_sequence, bool) or not isinstance(expected_start_sequence, int) or expected_start_sequence < 1:
            raise ValueError("expected_start_sequence must be a positive integer")
        if not isinstance(expected_previous_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", expected_previous_hash):
            raise ValueError("expected_previous_hash must be a SHA-256 digest")
        if expected_head_hash is not None and (
            not isinstance(expected_head_hash, str)
            or not re.fullmatch(r"[0-9a-f]{64}", expected_head_hash)
        ):
            raise ValueError("expected_head_hash must be a SHA-256 digest")
        previous = expected_previous_hash
        expected_sequence = expected_start_sequence
        seen_ids: set[str] = set()
        for event in events:
            RemoteAuditHttpClient._validate_event_page({"events": [event]})
            event_id = event["event_id"]
            if event_id in seen_ids:
                raise AuditClientError("duplicate audit event_id")
            seen_ids.add(event_id)
            if event["sequence"] != expected_sequence:
                raise AuditClientError("audit event sequence gap or duplicate")
            if event["previous_hash"] != previous:
                raise AuditClientError("audit event previous_hash does not match chain")
            calculated_hash = RemoteAuditHttpClient.compute_event_hash(event)
            if not hmac.compare_digest(calculated_hash, event["event_hash"]):
                raise AuditClientError("audit event hash does not match canonical payload")
            previous = event["event_hash"]
            expected_sequence += 1
        if expected_head_hash is not None and previous != expected_head_hash:
            raise AuditClientError("audit chain head does not match trusted checkpoint")
        return True

    def _write(
        self, path: str, payload: dict[str, object], idempotency_key: str,
    ) -> dict[str, object]:
        self._validate_key(idempotency_key)
        body = json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        ).encode("utf-8")
        try:
            result = self._request("POST", path, body, idempotency_key)
        except AuditOutcomeIndeterminate:
            # The exact request bytes and key are reused by _request on every attempt.
            raise
        required = ("request_id", "idempotency_key", "event_id", "sequence", "event_hash", "replayed")
        if any(field not in result for field in required):
            raise AuditClientError("audit success response is missing required fields")
        if result["idempotency_key"] != idempotency_key or not isinstance(result["replayed"], bool):
            raise AuditClientError("audit success response violates idempotency contract")
        if not isinstance(result["sequence"], int) or isinstance(result["sequence"], bool) or result["sequence"] < 1:
            raise AuditClientError("audit success response has invalid sequence")
        if not isinstance(result["event_hash"], str) or not re.fullmatch(r"[0-9a-f]{64}", result["event_hash"]):
            raise AuditClientError("audit success response has invalid event hash")
        return result

    @staticmethod
    def _validate_key(key: str) -> None:
        if not isinstance(key, str) or not _IDEMPOTENCY_KEY.fullmatch(key):
            raise ValueError("idempotency_key must be 1..128 safe ASCII characters")

    def _request(
        self, method: str, path: str, body: bytes | None, idempotency_key: str | None,
    ) -> dict[str, object]:
        url = self._base_url + path
        last_transport_error: BaseException | None = None
        for attempt in range(self._max_attempts):
            token = self._token_provider()
            if not isinstance(token, str) or not token or len(token) > 16_384:
                raise AuditClientError("token provider returned an invalid token")
            headers = {
                "Accept": "application/json",
                "Authorization": f"Bearer {token}",
            }
            if body is not None:
                headers["Content-Type"] = "application/json"
                headers["Idempotency-Key"] = idempotency_key or ""
            try:
                response = self._transport(method, url, headers, body, self._timeout)
            except (TimeoutError, socket.timeout, ConnectionError, OSError) as exc:
                last_transport_error = exc
                if attempt + 1 == self._max_attempts:
                    break
                self._pause(attempt)
                continue

            if len(response.body) > _MAX_RESPONSE_BYTES:
                raise AuditClientError("audit response exceeds 256 KiB")
            if 200 <= response.status < 300:
                return _strict_json(response.body)
            envelope = _strict_json(response.body)
            error = envelope.get("error")
            code = error.get("code") if isinstance(error, dict) else "unknown_error"
            retryable = error.get("retryable") if isinstance(error, dict) else False
            if response.status in (429, 503) and retryable is True:
                if attempt + 1 < self._max_attempts:
                    self._pause(attempt)
                    continue
                raise AuditServiceUnavailable("audit service unavailable after retry budget")
            raise AuditRequestRejected(response.status, str(code))

        if method == "POST":
            raise AuditOutcomeIndeterminate(
                "write outcome is unknown; resolve using the same idempotency key"
            ) from last_transport_error
        raise AuditServiceUnavailable("audit read failed after retry budget") from last_transport_error

    def _pause(self, attempt: int) -> None:
        ceiling = min(self._max_backoff, self._backoff_base * (2 ** attempt))
        if ceiling > 0:
            delay = self._jitter(0.0, ceiling)
            self._sleep(max(0.0, min(delay, ceiling)))

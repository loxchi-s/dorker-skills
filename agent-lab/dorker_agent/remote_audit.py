"""Provider-neutral, bounded HTTP client for the remote audit contract.

This client does not verify OIDC claims or make local persistence authoritative.
"""
from __future__ import annotations

import json
import random
import re
import socket
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Callable, Protocol
from urllib.parse import urlsplit

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
        return self._request("GET", f"/v1/audit/idempotency/{key}", None, None)

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
                if method == "POST":
                    raise AuditOutcomeIndeterminate(
                        "write outcome unresolved after retry budget; retry later with the same key"
                    )
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

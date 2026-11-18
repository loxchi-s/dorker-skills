"""WSGI transport adapter for the remote audit application service."""
from __future__ import annotations

import threading
import time
import uuid

from .request_rate_limiter import RequestRateLimiter

_MAX_BODY_BYTES = 64 * 1024


class AuditWSGIAdapter:
    """Translate WSGI environ/start_response into service calls and HTTP responses."""

    def __init__(self, service, *, rate_limiter: RequestRateLimiter, request_timeout_seconds: float) -> None:
        self._service = service
        self._rate_limiter = rate_limiter
        self._request_timeout_seconds = request_timeout_seconds
        self._request_slots = threading.BoundedSemaphore(1)

    def __call__(self, environ, start_response):
        started = time.monotonic()
        client_key = environ.get("REMOTE_ADDR", "unknown")
        allowed, retry_after = self._rate_limiter.allow(client_key)
        acquired = False
        if not allowed:
            status, headers, payload = self._service.error_response(
                429, "rate_limited", "request rate limit exceeded", str(uuid.uuid4()),
            )
            headers["Retry-After"] = str(retry_after)
        elif not self._request_slots.acquire(blocking=False):
            status, headers, payload = self._service.error_response(
                503, "capacity_limited", "request concurrency limit reached", str(uuid.uuid4()), True,
            )
            headers["Retry-After"] = "1"
        else:
            acquired = True
            try:
                raw_length = environ.get("CONTENT_LENGTH") or "0"
                try:
                    length = int(raw_length)
                except (TypeError, ValueError):
                    length = -1
                if length < 0:
                    status, headers, payload = self._service.error_response(
                        400, "invalid_request", "Content-Length is invalid", str(uuid.uuid4()),
                    )
                elif length > _MAX_BODY_BYTES:
                    status, headers, payload = self._service.error_response(
                        413, "invalid_request", "request body exceeds 64 KiB", str(uuid.uuid4()),
                    )
                elif time.monotonic() - started >= self._request_timeout_seconds:
                    status, headers, payload = self._service.error_response(
                        408, "request_timeout", "request deadline exceeded", str(uuid.uuid4()), True,
                    )
                else:
                    stream = environ.get("wsgi.input")
                    if length and not callable(getattr(stream, "read", None)):
                        status, headers, payload = self._service.error_response(
                            400, "invalid_request", "request body stream is invalid", str(uuid.uuid4()),
                        )
                    else:
                        try:
                            body = stream.read(length) if length else b""
                        except Exception:
                            body = None
                        if not isinstance(body, bytes) or len(body) != length:
                            status, headers, payload = self._service.error_response(
                                400, "invalid_request", "request body could not be read completely", str(uuid.uuid4()),
                            )
                        elif time.monotonic() - started >= self._request_timeout_seconds:
                            status, headers, payload = self._service.error_response(
                                408, "request_timeout", "request body deadline exceeded", str(uuid.uuid4()), True,
                            )
                        else:
                            authorization = environ.get("HTTP_AUTHORIZATION", "")
                            method = environ.get("REQUEST_METHOD", "GET")
                            target = environ.get("PATH_INFO", "/")
                            query = environ.get("QUERY_STRING", "")
                            if (
                                not isinstance(authorization, str) or len(authorization) > 16_500
                                or not isinstance(method, str)
                                or not isinstance(target, str)
                                or not isinstance(query, str)
                            ):
                                status, headers, payload = self._service.error_response(
                                    431, "invalid_request", "request headers or target exceed service limits", str(uuid.uuid4()),
                                )
                            else:
                                headers_in = {"Authorization": authorization}
                                if query:
                                    target += "?" + query
                                status, headers, payload = self._service.handle(method, target, headers_in, body)
                                if time.monotonic() - started > self._request_timeout_seconds:
                                    status, headers, payload = self._service.error_response(
                                        504, "request_deadline_exceeded", "request processing deadline exceeded", str(uuid.uuid4()), True,
                                    )
            finally:
                if acquired:
                    self._request_slots.release()

        phrase = {200: "OK", 400: "Bad Request", 401: "Unauthorized", 403: "Forbidden",
                  404: "Not Found", 408: "Request Timeout", 409: "Conflict",
                  413: "Payload Too Large", 422: "Unprocessable Entity",
                  429: "Too Many Requests", 431: "Request Header Fields Too Large",
                  503: "Service Unavailable", 504: "Gateway Timeout"}.get(status, "Error")
        response_headers = list(headers.items()) + [("Content-Length", str(len(payload)))]
        start_response(f"{status} {phrase}", response_headers)
        return [payload]


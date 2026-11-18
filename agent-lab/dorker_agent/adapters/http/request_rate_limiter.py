"""Bounded process-local request rate limiting for the HTTP adapter."""
from __future__ import annotations

from collections import OrderedDict
from math import ceil
import threading
import time
from typing import Callable


class RequestRateLimiter:
    """Bounded process-local token buckets for a single-worker WSGI deployment."""

    def __init__(
        self, *, global_rate_per_minute: float = 30, global_burst: int = 5,
        per_client_rate_per_minute: float = 10, per_client_burst: int = 3,
        max_clients: int = 2048, clock: Callable[[], float] = time.monotonic,
    ) -> None:
        values = (global_rate_per_minute, per_client_rate_per_minute)
        if any(isinstance(v, bool) or not isinstance(v, (int, float)) or v <= 0 for v in values):
            raise ValueError("request rates must be positive numbers")
        bursts = (global_burst, per_client_burst, max_clients)
        if any(isinstance(v, bool) or not isinstance(v, int) or v < 1 for v in bursts):
            raise ValueError("burst and max_clients values must be positive integers")
        if not callable(clock):
            raise TypeError("clock must be callable")
        self._global_rate = float(global_rate_per_minute) / 60.0
        self._global_capacity = float(global_burst)
        self._global_tokens = float(global_burst)
        self._global_updated = clock()
        self._client_rate = float(per_client_rate_per_minute) / 60.0
        self._client_capacity = float(per_client_burst)
        self._max_clients = max_clients
        self._clock = clock
        self._clients: OrderedDict[str, tuple[float, float]] = OrderedDict()
        self._lock = threading.Lock()

    @staticmethod
    def _refill(tokens: float, updated: float, now: float, rate: float, capacity: float) -> tuple[float, float]:
        return min(capacity, tokens + max(0.0, now - updated) * rate), now

    def allow(self, client_key: str) -> tuple[bool, int]:
        if not isinstance(client_key, str) or not client_key or len(client_key) > 128:
            client_key = "unknown"
        now = self._clock()
        with self._lock:
            global_tokens, global_updated = self._refill(
                self._global_tokens, self._global_updated, now,
                self._global_rate, self._global_capacity,
            )
            client = self._clients.get(client_key)
            if client is None:
                if len(self._clients) >= self._max_clients:
                    self._clients.popitem(last=False)
                client_tokens, client_updated = self._client_capacity, now
            else:
                client_tokens, client_updated = self._refill(
                    client[0], client[1], now, self._client_rate, self._client_capacity,
                )
                self._clients.move_to_end(client_key)

            global_wait = max(0.0, (1.0 - global_tokens) / self._global_rate)
            client_wait = max(0.0, (1.0 - client_tokens) / self._client_rate)
            self._global_tokens, self._global_updated = global_tokens, global_updated
            self._clients[client_key] = (client_tokens, client_updated)
            if global_wait > 0.0 or client_wait > 0.0:
                return False, max(1, ceil(max(global_wait, client_wait)))

            self._global_tokens -= 1.0
            self._clients[client_key] = (client_tokens - 1.0, client_updated)
            return True, 0


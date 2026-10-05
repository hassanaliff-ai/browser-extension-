"""Reject oversized file-scan requests before multipart parsing spools them."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from collections import OrderedDict, deque
import math
import threading
import time
from typing import Any

from starlette.responses import JSONResponse


class SignInRateLimit:
    """Bound sign-in work per client using a shared sliding window.

    One instance covers both password and TOTP endpoints. The caller supplies
    the connection's client address, never a client-controlled forwarded
    header. State is thread-safe and bounded, but process-local; multi-worker
    deployments should also enforce a shared limit at their ingress.
    """

    def __init__(
        self,
        *,
        max_attempts: int = 20,
        window_seconds: int = 60,
        max_clients: int = 4096,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if any(type(value) is not int or value < 1 for value in (max_attempts, window_seconds, max_clients)):
            raise ValueError("Sign-in limits must be positive integers")
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self.max_clients = max_clients
        self.clock = clock
        self._attempts: OrderedDict[str, deque[float]] = OrderedDict()
        self._lock = threading.Lock()

    def retry_after(self, client_id: str) -> int:
        """Consume an attempt and return 0, or reject with a wait in seconds."""
        if not isinstance(client_id, str) or not client_id or len(client_id) > 256:
            raise ValueError("A bounded client identifier is required")
        with self._lock:
            now = self.clock()
            cutoff = now - self.window_seconds
            # Entries are ordered by their last accepted attempt, allowing
            # expired clients to be retired without sweeping the whole map.
            while self._attempts:
                oldest = next(iter(self._attempts.values()))
                if oldest[-1] > cutoff:
                    break
                self._attempts.popitem(last=False)
            attempts = self._attempts.get(client_id)
            if attempts is None:
                if len(self._attempts) >= self.max_clients:
                    # Do not evict active identities: cycling through clients
                    # must not reset existing limits or grow memory forever.
                    oldest = next(iter(self._attempts.values()))
                    return max(1, math.ceil(oldest[-1] + self.window_seconds - now))
                attempts = deque()
                self._attempts[client_id] = attempts
            while attempts and attempts[0] <= cutoff:
                attempts.popleft()
            if len(attempts) >= self.max_attempts:
                return max(1, math.ceil(attempts[0] + self.window_seconds - now))
            attempts.append(now)
            self._attempts.move_to_end(client_id)
            return 0


class _RequestTooLarge(Exception):
    pass


class DownloadRequestLimit:
    """Bound the complete multipart request, including chunked transfers."""

    def __init__(self, app: Callable[..., Awaitable[Any]], *, max_bytes: int) -> None:
        if not isinstance(max_bytes, int) or isinstance(max_bytes, bool) or max_bytes < 1:
            raise ValueError("Upload limit must be a positive integer")
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: dict, receive: Callable, send: Callable) -> None:
        path = scope.get("path", "")
        root_path = scope.get("root_path", "").rstrip("/")
        # Mounted ASGI apps retain the full request path. Match the route
        # relative to the mount, so the integrated /monitor service is guarded.
        if root_path and path.startswith(root_path + "/"):
            path = path[len(root_path):]
        if scope["type"] != "http" or path not in {
            "/api/downloads/scan-file", "/api/admin/downloads/scan-file",
        }:
            await self.app(scope, receive, send)
            return

        for name, value in scope.get("headers", []):
            if name.lower() == b"content-length":
                try:
                    declared_length = int(value)
                except ValueError:
                    break
                if declared_length > self.max_bytes:
                    await self._reject(scope, receive, send)
                    return
                break

        received = 0
        too_large = False
        response_started = False
        response_replaced = False

        async def limited_receive() -> dict:
            nonlocal received, too_large
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_bytes:
                    too_large = True
                    raise _RequestTooLarge
            return message

        async def tracked_send(message: dict) -> None:
            nonlocal response_started, response_replaced
            if too_large:
                # Starlette's multipart parser converts receive exceptions
                # into a generic 400. Replace that response with the 413.
                if message["type"] == "http.response.start" and not response_replaced:
                    response_replaced = True
                    await self._reject(scope, receive, send)
                return
            if message["type"] == "http.response.start":
                response_started = True
            await send(message)

        try:
            await self.app(scope, limited_receive, tracked_send)
        except _RequestTooLarge:
            if response_started:
                raise
            if not response_replaced:
                await self._reject(scope, receive, send)

    @staticmethod
    async def _reject(scope: dict, receive: Callable, send: Callable) -> None:
        response = JSONResponse(
            {"detail": "Download scan request exceeds the size limit"},
            status_code=413,
        )
        await response(scope, receive, send)

"""Reject oversized file-scan requests before multipart parsing spools them."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

from starlette.responses import JSONResponse


class _RequestTooLarge(Exception):
    pass


class DownloadRequestLimit:
    """Bound the complete multipart request, including chunked transfers."""

    def __init__(self, app: Callable[..., Awaitable[Any]], *, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: dict, receive: Callable, send: Callable) -> None:
        if scope["type"] != "http" or scope.get("path") != "/api/downloads/scan-file":
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

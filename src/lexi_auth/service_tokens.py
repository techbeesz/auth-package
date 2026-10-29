"""Service tokens for calls that are NOT made on behalf of a user (cron jobs, queue consumers).

When you ARE handling a user's request, forward the user's token instead:
    httpx.post(url, headers=principal.auth_headers())

Usage:
    tokens = ServiceTokenClient.from_env()          # LEXI_SERVICE_CLIENT_ID / _SECRET / LEXI_TOKEN_URL
    headers = {"Authorization": f"Bearer {await tokens.get()}"}
"""
from __future__ import annotations

import asyncio
import os
import time

import httpx


class ServiceTokenError(RuntimeError):
    pass


class ServiceTokenClient:
    def __init__(
        self,
        token_url: str,
        client_id: str,
        client_secret: str,
        *,
        refresh_margin_seconds: int = 60,
        client: httpx.AsyncClient | None = None,
    ):
        self.token_url = token_url
        self.client_id = client_id
        self.client_secret = client_secret
        self.refresh_margin = refresh_margin_seconds
        self._client = client or httpx.AsyncClient(timeout=5.0)
        self._owns_client = client is None
        self._token: str | None = None
        self._expires_at = 0.0
        self._lock = asyncio.Lock()

    @classmethod
    def from_env(cls) -> "ServiceTokenClient":
        try:
            return cls(
                os.environ.get("LEXI_TOKEN_URL", "http://auth:8000/internal/oauth/token"),
                os.environ["LEXI_SERVICE_CLIENT_ID"],
                os.environ["LEXI_SERVICE_CLIENT_SECRET"],
            )
        except KeyError as e:
            raise ServiceTokenError(f"missing env var {e.args[0]}") from None

    async def get(self) -> str:
        if self._token and time.time() < self._expires_at - self.refresh_margin:
            return self._token
        async with self._lock:
            if self._token and time.time() < self._expires_at - self.refresh_margin:
                return self._token
            resp = await self._client.post(
                self.token_url,
                data={"grant_type": "client_credentials"},
                auth=(self.client_id, self.client_secret),
            )
            if resp.status_code != 200:
                raise ServiceTokenError(f"token endpoint returned {resp.status_code}: {resp.text[:200]}")
            body = resp.json()
            self._token = body["access_token"]
            self._expires_at = time.time() + int(body.get("expires_in", 300))
            return self._token

    async def headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {await self.get()}"}

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()

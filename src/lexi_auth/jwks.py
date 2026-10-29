"""Fetches and caches the auth service's public signing keys (JWKS).

- Keys are cached for `jwks_cache_seconds`; verification needs no network call.
- An unknown `kid` triggers one refetch (throttled), so key rotation needs no restarts.
- If the auth service is unreachable, the last good key set keeps working.
"""
from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Protocol

import httpx
import jwt

from .errors import TokenError

log = logging.getLogger("lexi_auth.jwks")

ALLOWED_ALGORITHMS = ("ES256",)


def _parse_jwks(data: dict[str, Any]) -> dict[str, jwt.PyJWK]:
    keys: dict[str, jwt.PyJWK] = {}
    for raw in data.get("keys", []):
        kid = raw.get("kid")
        if not kid or raw.get("use", "sig") != "sig":
            continue
        if raw.get("alg") not in ALLOWED_ALGORITHMS:
            continue
        try:
            keys[kid] = jwt.PyJWK(raw, algorithm=raw["alg"])
        except jwt.PyJWTError:
            log.warning("skipping unparsable JWK kid=%s", kid)
    return keys


class KeyProvider(Protocol):
    async def get_key(self, kid: str) -> jwt.PyJWK: ...
    async def warm(self) -> None: ...
    async def aclose(self) -> None: ...


class StaticJWKS:
    """Fixed key set. Used in tests, or if you want to pin keys from a file."""

    def __init__(self, jwks: dict[str, Any]):
        self._keys = _parse_jwks(jwks)

    async def get_key(self, kid: str) -> jwt.PyJWK:
        try:
            return self._keys[kid]
        except KeyError:
            raise TokenError("unknown_key") from None

    async def warm(self) -> None:
        return None

    async def aclose(self) -> None:
        return None


class RemoteJWKS:
    def __init__(
        self,
        url: str,
        *,
        cache_seconds: int = 600,
        min_refetch_seconds: int = 30,
        timeout: float = 3.0,
        client: httpx.AsyncClient | None = None,
    ):
        self.url = url
        self.cache_seconds = cache_seconds
        self.min_refetch_seconds = min_refetch_seconds
        self._client = client or httpx.AsyncClient(timeout=timeout)
        self._owns_client = client is None
        self._keys: dict[str, jwt.PyJWK] = {}
        self._fetched_at = 0.0       # last successful fetch
        self._attempted_at = 0.0     # last attempt (successful or not)
        self._lock = asyncio.Lock()

    async def _refresh(self, *, force: bool) -> None:
        async with self._lock:
            now = time.monotonic()
            # Another coroutine may have refreshed while we waited for the lock.
            if not force and now - self._fetched_at < self.cache_seconds:
                return
            if now - self._attempted_at < self.min_refetch_seconds and self._keys:
                return
            self._attempted_at = now
            try:
                resp = await self._client.get(self.url)
                resp.raise_for_status()
                keys = _parse_jwks(resp.json())
            except Exception as exc:  # network error, bad JSON, 5xx...
                if self._keys:
                    log.warning("JWKS refresh failed, using cached keys: %s", exc)
                    return
                log.error("JWKS fetch failed and no cached keys: %s", exc)
                raise TokenError("jwks_unavailable") from exc
            if keys:
                self._keys = keys
                self._fetched_at = now

    async def get_key(self, kid: str) -> jwt.PyJWK:
        if time.monotonic() - self._fetched_at >= self.cache_seconds:
            await self._refresh(force=False)
        key = self._keys.get(kid)
        if key is None:
            await self._refresh(force=True)   # maybe a freshly rotated key
            key = self._keys.get(kid)
        if key is None:
            raise TokenError("unknown_key")
        return key

    async def warm(self) -> None:
        """Fetch keys now (at startup) so the first request doesn't wait for them.

        Never raises: a service must still start while the auth service is briefly down.
        """
        try:
            await self._refresh(force=True)
        except TokenError:
            log.warning("JWKS warm-up failed; will retry on the first request")

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()

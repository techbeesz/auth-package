"""FastAPI integration: dependencies every service uses to know who is calling.

Typical use in a service:

    from lexi_auth import LexiAuth, Principal

    auth = LexiAuth.from_env()
    app = FastAPI(lifespan=auth.lifespan)

    @app.get("/api/orgs/{org_id}/campaigns")
    async def list_campaigns(org_id: str, p: Principal = Depends(auth.org_scoped("campaign:read"))):
        ...  # query with WHERE org_id = p.org_id
"""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import Awaitable, Callable, Mapping

from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketException, status

from .config import AuthSettings
from .errors import TokenError, forbidden, unauthorized
from .jwks import KeyProvider, RemoteJWKS
from .principal import DEFAULT_ROLE_PERMISSIONS, Principal
from .verifier import TokenVerifier

log = logging.getLogger("lexi_auth")

UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})

Dependency = Callable[..., Awaitable[Principal]]


class LexiAuth:
    def __init__(
        self,
        settings: AuthSettings | None = None,
        *,
        keys: KeyProvider | None = None,
        role_permissions: Mapping[str, frozenset[str]] = DEFAULT_ROLE_PERMISSIONS,
    ):
        self.settings = settings or AuthSettings.from_env()
        self.keys = keys or RemoteJWKS(
            self.settings.jwks_url,
            cache_seconds=self.settings.jwks_cache_seconds,
            min_refetch_seconds=self.settings.jwks_min_refetch_seconds,
            timeout=self.settings.jwks_timeout_seconds,
        )
        self.verifier = TokenVerifier(self.settings, self.keys, role_permissions)

    @classmethod
    def from_env(cls, **kwargs) -> "LexiAuth":
        return cls(AuthSettings.from_env(), **kwargs)

    # ------------------------------------------------------------------ lifecycle
    @asynccontextmanager
    async def lifespan(self, app: FastAPI):
        await self.warm()
        try:
            yield
        finally:
            await self.keys.aclose()

    async def warm(self) -> None:
        """Fetch the signing keys at startup. Call it from your own lifespan if you have one."""
        await self.keys.warm()

    async def aclose(self) -> None:
        await self.keys.aclose()

    # ------------------------------------------------------------------ core
    def _extract(self, request: Request) -> tuple[str | None, bool]:
        """Returns (token, came_from_cookie). Authorization header wins over cookie."""
        auth = request.headers.get("authorization", "")
        if auth[:7].lower() == "bearer ":
            return auth[7:].strip() or None, False
        return request.cookies.get(self.settings.access_cookie), True

    def _check_csrf(self, request: Request) -> None:
        """Only cookie-authenticated, state-changing requests can be forged cross-site."""
        if not self.settings.csrf_enabled or request.method not in UNSAFE_METHODS:
            return
        if not request.headers.get(self.settings.csrf_header):
            raise forbidden("csrf_header_missing")
        origin = request.headers.get("origin")
        if origin and origin.rstrip("/") not in self.settings.allowed_origins:
            raise forbidden("bad_origin")

    @staticmethod
    def _log_rejection(request: Request, code: str, level: int = logging.INFO) -> None:
        # Never log the token, the Cookie header or the Authorization header.
        log.log(
            level, "auth_rejected code=%s method=%s path=%s request_id=%s",
            code, request.method, request.url.path, request.headers.get("x-request-id") or "-",
        )

    async def authenticate(self, request: Request) -> Principal:
        token, from_cookie = self._extract(request)
        if not token:
            self._log_rejection(request, "missing_token")
            raise unauthorized("missing_token")
        if from_cookie:
            try:
                self._check_csrf(request)
            except HTTPException as e:
                self._log_rejection(request, e.detail["code"])
                raise
        try:
            principal = await self.verifier.verify(token)
        except TokenError as e:
            if e.code == "jwks_unavailable":
                # Our infrastructure problem, not the caller's. Don't make the browser refresh-loop.
                self._log_rejection(request, "auth_unavailable", logging.WARNING)
                raise HTTPException(503, detail={"code": "auth_unavailable"}) from None
            self._log_rejection(request, e.code)
            raise unauthorized(e.code) from None
        if from_cookie and principal.is_service:
            self._log_rejection(request, "service_token_in_cookie")
            raise unauthorized("invalid_token")    # service tokens never travel in browser cookies
        request.state.principal = principal
        return principal

    # ------------------------------------------------------------------ dependencies
    async def principal(self, request: Request) -> Principal:
        """Any valid caller: a user OR an internal service. Use on /internal/* endpoints."""
        return await self.authenticate(request)

    async def user(self, request: Request) -> Principal:
        """A signed-in user (any org, any role)."""
        p = await self.authenticate(request)
        if not p.is_user:
            raise forbidden("user_required")
        return p

    def require(self, permission: str) -> Dependency:
        """A signed-in user whose role grants `permission` in their active org."""
        async def dep(request: Request) -> Principal:
            p = await self.user(request)
            if not p.can(permission):
                raise forbidden("forbidden")
            return p
        dep.__name__ = f"require_{permission.replace(':', '_')}"
        return dep

    def org_scoped(self, permission: str | None = None, *, path_param: str = "org_id") -> Dependency:
        """For routes like /api/orgs/{org_id}/...: the org in the URL must equal the org in the token.

        A mismatch returns 403 {"code": "org_mismatch"}; the frontend should call
        /api/auth/switch-org and retry.
        """
        async def dep(request: Request) -> Principal:
            p = await self.user(request)
            path_org = request.path_params.get(path_param)
            if path_org is None:
                raise RuntimeError(f"route has no '{{{path_param}}}' path parameter")
            if path_org != p.org_id:
                raise forbidden("org_mismatch")
            if permission and not p.can(permission):
                raise forbidden("forbidden")
            return p
        dep.__name__ = f"org_scoped_{(permission or 'any').replace(':', '_')}"
        return dep

    def service(self, *allowed: str) -> Dependency:
        """Only internal service tokens (optionally only from specific services, e.g. 'svc_campaign')."""
        allowed_set = frozenset(allowed)

        async def dep(request: Request) -> Principal:
            p = await self.authenticate(request)
            if not p.is_service:
                raise forbidden("service_required")
            if allowed_set and p.subject not in allowed_set:
                raise forbidden("service_not_allowed")
            return p
        return dep

    # ------------------------------------------------------------------ websockets
    async def websocket_user(self, websocket: WebSocket) -> Principal:
        """Authenticate a browser WebSocket (cookie is sent on the upgrade request).

        Usage:
            @app.websocket("/api/orgs/{org_id}/meetings/{mid}/ws")
            async def ws(websocket: WebSocket, org_id: str, p: Principal = Depends(auth.websocket_user)):
        """
        origin = (websocket.headers.get("origin") or "").rstrip("/")
        if self.settings.csrf_enabled and origin not in self.settings.allowed_origins:
            raise WebSocketException(code=status.WS_1008_POLICY_VIOLATION, reason="bad_origin")
        auth = websocket.headers.get("authorization", "")
        token = auth[7:].strip() if auth[:7].lower() == "bearer " else websocket.cookies.get(
            self.settings.access_cookie
        )
        if not token:
            raise WebSocketException(code=status.WS_1008_POLICY_VIOLATION, reason="missing_token")
        try:
            p = await self.verifier.verify(token)
        except TokenError as e:
            raise WebSocketException(code=status.WS_1008_POLICY_VIOLATION, reason=e.code) from None
        if not p.is_user:
            raise WebSocketException(code=status.WS_1008_POLICY_VIOLATION, reason="user_required")
        org = websocket.path_params.get("org_id")
        if org is not None and org != p.org_id:
            raise WebSocketException(code=status.WS_1008_POLICY_VIOLATION, reason="org_mismatch")
        return p

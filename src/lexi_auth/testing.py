"""Helpers for testing services that use lexi_auth, with real signed tokens and no auth service.

    from lexi_auth.testing import TokenFactory

    tokens = TokenFactory()
    auth = tokens.make_auth()                    # LexiAuth that trusts this factory's key
    app = create_app(auth=auth)
    client = TestClient(app)
    r = client.get("/api/orgs/org_1/campaigns",
                   headers={"Authorization": f"Bearer {tokens.user(org_id='org_1', role='admin')}"})
"""
from __future__ import annotations

import json
import secrets
import time
from typing import Any

import jwt
from cryptography.hazmat.primitives.asymmetric import ec
from jwt.algorithms import ECAlgorithm

from .config import AuthSettings
from .fastapi import LexiAuth
from .jwks import StaticJWKS

TEST_ISSUER = "https://auth.test.beesz.com"
TEST_AUDIENCE = "https://api.test.beesz.com"
TEST_ORIGIN = "https://app.test.beesz.com"
TEST_USER_ID = "00000000-0000-4000-8000-000000000001"
TEST_ORG_ID = "00000000-0000-4000-8000-0000000000a1"
TEST_SESSION_ID = "00000000-0000-4000-8000-0000000000f1"


class TokenFactory:
    def __init__(self, *, kid: str = "test-key", issuer: str = TEST_ISSUER, audience: str = TEST_AUDIENCE):
        self.kid = kid
        self.issuer = issuer
        self.audience = audience
        self.private_key = ec.generate_private_key(ec.SECP256R1())

    def jwks(self) -> dict[str, Any]:
        jwk = json.loads(ECAlgorithm.to_jwk(self.private_key.public_key()))
        return {"keys": [{**jwk, "kid": self.kid, "use": "sig", "alg": "ES256"}]}

    def settings(self, **overrides: Any) -> AuthSettings:
        base = dict(
            issuer=self.issuer,
            audience=self.audience,
            jwks_url="http://unused",
            access_cookie="lp_at",
            allowed_origins=(TEST_ORIGIN,),
        )
        base.update(overrides)
        return AuthSettings(**base)

    def make_auth(self, **setting_overrides: Any) -> LexiAuth:
        return LexiAuth(self.settings(**setting_overrides), keys=StaticJWKS(self.jwks()))

    def sign(self, claims: dict[str, Any], *, headers: dict[str, Any] | None = None) -> str:
        h = {"kid": self.kid, "typ": "at+jwt"}
        h.update(headers or {})
        return jwt.encode(claims, self.private_key, algorithm="ES256", headers=h)

    def user(
        self,
        *,
        user_id: str = TEST_USER_ID,
        org_id: str = TEST_ORG_ID,
        role: str = "member",
        session_id: str = TEST_SESSION_ID,
        ttl: int = 600,
        **extra: Any,
    ) -> str:
        now = int(time.time())
        claims = {
            "iss": self.issuer, "aud": self.audience, "sub": user_id,
            "iat": now, "nbf": now, "exp": now + ttl,
            "jti": "at_" + secrets.token_hex(8), "sid": session_id,
            "org_id": org_id, "org_role": role, "ver": 1,
        }
        claims.update(extra)
        return self.sign(claims)

    def service(self, name: str = "svc_test", *, ttl: int = 300, **extra: Any) -> str:
        now = int(time.time())
        claims = {
            "iss": self.issuer, "aud": self.audience, "sub": name,
            "iat": now, "nbf": now, "exp": now + ttl,
            "jti": "st_" + secrets.token_hex(8), "token_use": "service", "ver": 1,
        }
        claims.update(extra)
        return self.sign(claims)

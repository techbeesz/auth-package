"""Pure token verification (no FastAPI). Turns a JWT string into a Principal or raises TokenError."""
from __future__ import annotations

import uuid
from typing import Mapping

import jwt

from .config import AuthSettings
from .errors import TokenError
from .jwks import ALLOWED_ALGORITHMS, KeyProvider
from .principal import DEFAULT_ROLE_PERMISSIONS, ROLES, Principal

ACCESS_TOKEN_TYP = "at+jwt"
USER_REQUIRED = ["exp", "iat", "iss", "aud", "sub", "sid", "org_id", "org_role"]
SERVICE_REQUIRED = ["exp", "iat", "iss", "aud", "sub"]


def _is_uuid(value: object) -> bool:
    try:
        uuid.UUID(str(value))
        return True
    except ValueError:
        return False


class TokenVerifier:
    def __init__(
        self,
        settings: AuthSettings,
        keys: KeyProvider,
        role_permissions: Mapping[str, frozenset[str]] = DEFAULT_ROLE_PERMISSIONS,
    ):
        self.settings = settings
        self.keys = keys
        self.role_permissions = role_permissions

    async def verify(self, token: str) -> Principal:
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError:
            raise TokenError("malformed_token") from None

        if header.get("alg") not in ALLOWED_ALGORITHMS:     # blocks alg=none and HS256 confusion
            raise TokenError("bad_algorithm")
        if header.get("typ") != ACCESS_TOKEN_TYP:           # blocks ID tokens / other JWTs
            raise TokenError("wrong_token_type")
        kid = header.get("kid")
        if not isinstance(kid, str) or not kid:
            raise TokenError("missing_kid")

        key = await self.keys.get_key(kid)

        try:
            unverified = jwt.decode(token, options={"verify_signature": False})
        except jwt.PyJWTError:
            raise TokenError("malformed_token") from None
        is_service = unverified.get("token_use") == "service"

        try:
            claims = jwt.decode(
                token,
                key.key,
                algorithms=list(ALLOWED_ALGORITHMS),
                audience=self.settings.audience,
                issuer=self.settings.issuer,
                leeway=self.settings.leeway_seconds,
                options={"require": SERVICE_REQUIRED if is_service else USER_REQUIRED},
            )
        except jwt.ExpiredSignatureError:
            raise TokenError("token_expired") from None
        except jwt.InvalidAudienceError:
            raise TokenError("bad_audience") from None
        except jwt.InvalidIssuerError:
            raise TokenError("bad_issuer") from None
        except jwt.MissingRequiredClaimError as e:
            raise TokenError(f"missing_claim:{e.claim}") from None
        except jwt.PyJWTError:
            raise TokenError("invalid_token") from None

        ver = claims.get("ver", 1)
        if ver not in self.settings.supported_token_versions:
            raise TokenError("unsupported_token_version")

        sub = claims["sub"]
        if is_service:
            if not isinstance(sub, str) or not sub.startswith("svc_"):
                raise TokenError("invalid_token")
            return Principal(
                kind="service", subject=sub, org_id=None, role=None, session_id=None,
                token=token, claims=claims, permissions=frozenset(),
            )

        # User and org IDs are UUIDs, so services can store and query them as uuid columns.
        if not _is_uuid(sub) or not _is_uuid(claims["org_id"]):
            raise TokenError("invalid_token")
        role = claims["org_role"]
        if role not in ROLES:
            raise TokenError("unknown_role")
        return Principal(
            kind="user",
            subject=sub,
            org_id=claims["org_id"],
            role=role,
            session_id=claims["sid"],
            token=token,
            claims=claims,
            permissions=self.role_permissions.get(role, frozenset()),
        )

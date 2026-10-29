"""Settings for lexi_auth. Every value can be set through LEXI_* environment variables."""
from __future__ import annotations

import os
from dataclasses import dataclass, field


def _env_required(name: str) -> str:
    """A value with no safe default: a wrong guess would make every request fail with a 401."""
    raw = os.environ.get(name, "").strip()
    if not raw:
        raise RuntimeError(f"{name} must be set (lexi_auth has no safe default for it)")
    return raw


def _env_list(raw: str) -> tuple[str, ...]:
    return tuple(x.strip().rstrip("/") for x in raw.split(",") if x.strip())


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class AuthSettings:
    # Who issues tokens and who they are for. Must match the auth service config.
    issuer: str = "https://auth.beesz.com"
    audience: str = "https://api.beesz.com"

    # Where to fetch the auth service's public keys. Internal URL: never goes through the internet.
    jwks_url: str = "http://auth:8000/.well-known/jwks.json"
    jwks_cache_seconds: int = 600          # normal refresh interval
    jwks_min_refetch_seconds: int = 30     # throttle refetches triggered by an unknown `kid`
    jwks_timeout_seconds: float = 3.0

    # Browser cookie that carries the access token. Must match the auth service.
    access_cookie: str = "__Host-lp_at"

    # CSRF defence for cookie-authenticated requests.
    csrf_header: str = "X-Lexi-CSRF"
    allowed_origins: tuple[str, ...] = ("https://app.beesz.com",)
    csrf_enabled: bool = True

    leeway_seconds: int = 30               # allowed clock skew
    supported_token_versions: tuple[int, ...] = field(default=(1,))

    @classmethod
    def from_env(cls) -> "AuthSettings":
        """Reads LEXI_* env vars. Raises RuntimeError if a required one is missing or blank:
        LEXI_ISSUER, LEXI_AUDIENCE, LEXI_JWKS_URL, LEXI_ACCESS_COOKIE, LEXI_ALLOWED_ORIGINS."""
        d = cls()
        return cls(
            issuer=_env_required("LEXI_ISSUER"),
            audience=_env_required("LEXI_AUDIENCE"),
            jwks_url=_env_required("LEXI_JWKS_URL"),
            jwks_cache_seconds=int(os.environ.get("LEXI_JWKS_CACHE_SECONDS", d.jwks_cache_seconds)),
            jwks_min_refetch_seconds=int(
                os.environ.get("LEXI_JWKS_MIN_REFETCH_SECONDS", d.jwks_min_refetch_seconds)
            ),
            jwks_timeout_seconds=float(os.environ.get("LEXI_JWKS_TIMEOUT_SECONDS", d.jwks_timeout_seconds)),
            access_cookie=_env_required("LEXI_ACCESS_COOKIE"),
            csrf_header=os.environ.get("LEXI_CSRF_HEADER", d.csrf_header),
            allowed_origins=_env_list(_env_required("LEXI_ALLOWED_ORIGINS")),
            csrf_enabled=_env_bool("LEXI_CSRF_ENABLED", d.csrf_enabled),
            leeway_seconds=int(os.environ.get("LEXI_LEEWAY_SECONDS", d.leeway_seconds)),
        )

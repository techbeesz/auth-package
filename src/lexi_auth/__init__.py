"""lexi_auth: verify Beesz access tokens inside any FastAPI service."""
from .config import AuthSettings
from .errors import TokenError
from .fastapi import LexiAuth
from .jwks import RemoteJWKS, StaticJWKS
from .principal import DEFAULT_ROLE_PERMISSIONS, ROLES, Principal
from .service_tokens import ServiceTokenClient, ServiceTokenError
from .verifier import TokenVerifier

__all__ = [
    "AuthSettings",
    "DEFAULT_ROLE_PERMISSIONS",
    "LexiAuth",
    "Principal",
    "ROLES",
    "RemoteJWKS",
    "ServiceTokenClient",
    "ServiceTokenError",
    "StaticJWKS",
    "TokenError",
    "TokenVerifier",
]
__version__ = "0.1.0"

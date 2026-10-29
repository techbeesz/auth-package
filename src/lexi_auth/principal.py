"""Who is calling: a user acting inside one org, or one of our own services."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal, Mapping

ROLES: tuple[str, ...] = ("viewer", "member", "admin", "owner")  # lowest -> highest

# Role -> permissions. This table is the single source of truth for every service.
# Add new permissions here (and bump the package version) when a service needs one.
DEFAULT_ROLE_PERMISSIONS: Mapping[str, frozenset[str]] = {
    "viewer": frozenset({
        "org:read",
        "campaign:read",
        "meeting:read",
        "credits:read",
    }),
    "member": frozenset({
        "org:read",
        "campaign:read", "campaign:write",
        "meeting:read", "meeting:write",
        "credits:read",
    }),
    "admin": frozenset({
        "org:read", "org:manage", "members:manage",
        "campaign:read", "campaign:write",
        "meeting:read", "meeting:write",
        "credits:read",
    }),
    "owner": frozenset({
        "org:read", "org:manage", "members:manage",
        "campaign:read", "campaign:write",
        "meeting:read", "meeting:write",
        "credits:read", "billing:manage",
    }),
}


@dataclass(frozen=True)
class Principal:
    kind: Literal["user", "service"]
    subject: str                 # user UUID, or svc_... for service tokens
    org_id: str | None           # always set for users; None for service tokens
    role: str | None             # always set for users; None for service tokens
    session_id: str | None       # users only
    token: str = field(repr=False)  # raw JWT, forward it on internal calls
    claims: Mapping[str, object] = field(repr=False, default_factory=dict)
    permissions: frozenset[str] = field(repr=False, default=frozenset())

    @property
    def is_user(self) -> bool:
        return self.kind == "user"

    @property
    def is_service(self) -> bool:
        return self.kind == "service"

    @property
    def user_id(self) -> str:
        if not self.is_user:
            raise AttributeError("service principals have no user_id")
        return self.subject

    @property
    def service_name(self) -> str:
        if not self.is_service:
            raise AttributeError("user principals have no service_name")
        return self.subject

    def can(self, permission: str) -> bool:
        return permission in self.permissions

    def has_role_at_least(self, role: str) -> bool:
        if self.role not in ROLES or role not in ROLES:
            return False
        return ROLES.index(self.role) >= ROLES.index(role)

    def auth_headers(self) -> dict[str, str]:
        """Headers to forward this identity on an internal service-to-service call."""
        return {"Authorization": f"Bearer {self.token}"}

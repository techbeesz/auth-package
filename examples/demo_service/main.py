"""Example downstream service ("campaign") showing every lexi_auth pattern.

Copy this shape into your real services:
  1. one `auth = LexiAuth.from_env()` per service
  2. org-scoped routes under /api/orgs/{org_id}/...  ->  Depends(auth.org_scoped("perm"))
  3. org_id for queries ALWAYS comes from the token (p.org_id), never from the request body
  4. internal calls on behalf of a user forward the user's token (p.auth_headers())
  5. background jobs use a service token (ServiceTokenClient)
"""
from __future__ import annotations

import os
import time
import uuid
from contextlib import asynccontextmanager

import httpx
from fastapi import Depends, FastAPI
from pydantic import BaseModel, Field

from lexi_auth import LexiAuth, Principal, ServiceTokenClient

AUTH_INTERNAL_URL = os.environ.get("AUTH_INTERNAL_URL", "http://auth:8000")


class CampaignIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)


def create_app(auth: LexiAuth | None = None) -> FastAPI:
    auth = auth or LexiAuth.from_env()
    http = httpx.AsyncClient(timeout=3.0)
    service_tokens = ServiceTokenClient.from_env() if os.environ.get("LEXI_SERVICE_CLIENT_ID") else None
    campaigns: dict[str, list[dict]] = {}   # stand-in for a DB table with an org_id column (single worker only)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        await auth.warm()
        yield
        await auth.aclose()
        await http.aclose()
        if service_tokens:
            await service_tokens.aclose()

    app = FastAPI(title="demo-campaign", lifespan=lifespan)

    @app.get("/api/orgs/{org_id}/campaigns")
    async def list_campaigns(org_id: str, p: Principal = Depends(auth.org_scoped("campaign:read"))):
        # Real code: SELECT ... FROM campaigns WHERE org_id = $1   (p.org_id)
        rows = campaigns.get(p.org_id, [])
        # Show creator names: forward the user's own token to the auth service (internal network).
        ids = sorted({c["created_by"] for c in rows})
        names: dict[str, str] = {}
        if ids:
            r = await http.post(f"{AUTH_INTERNAL_URL}/internal/users/lookup",
                                json={"ids": ids}, headers=p.auth_headers())
            if r.status_code == 200:
                names = {u["id"]: u["name"] or u["email"] for u in r.json()["users"]}
        return {"org_id": p.org_id, "campaigns": [{**c, "created_by_name": names.get(c["created_by"])} for c in rows]}

    @app.post("/api/orgs/{org_id}/campaigns", status_code=201)
    async def create_campaign(
        org_id: str, body: CampaignIn, p: Principal = Depends(auth.org_scoped("campaign:write"))
    ):
        # Real code would debit credits first: POST credits/internal/debits with p.auth_headers()
        row = {
            "id": f"cmp_{uuid.uuid4().hex[:12]}",
            "org_id": p.org_id,          # from the TOKEN
            "created_by": p.user_id,     # from the TOKEN
            "name": body.name,
            "created_at": int(time.time()),
        }
        campaigns.setdefault(p.org_id, []).append(row)
        return row

    @app.get("/api/orgs/{org_id}/campaigns/whoami")
    async def whoami(org_id: str, p: Principal = Depends(auth.org_scoped())):
        return {
            "user_id": p.user_id, "org_id": p.org_id, "role": p.role, "session_id": p.session_id,
            "permissions": sorted(p.permissions),
        }

    @app.post("/internal/campaigns/nightly-job")
    async def nightly_job(p: Principal = Depends(auth.service("svc_scheduler"))):
        """Only callable by another service's token, e.g. a scheduler. Gateway never routes /internal."""
        return {"ran_by": p.service_name}

    @app.get("/internal/campaigns/demo-service-token")
    async def demo_service_token():
        """Shows how a background job gets a service token. (Demo only: don't expose tokens like this.)"""
        if not service_tokens:
            return {"configured": False}
        token = await service_tokens.get()
        return {"configured": True, "token_prefix": token[:20] + "..."}

    @app.get("/healthz")
    async def healthz():
        return {"status": "ok"}

    return app


app = create_app()

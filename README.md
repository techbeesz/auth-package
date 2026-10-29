# lexi-auth

The one piece of auth code every Beesz FastAPI service imports. It answers **"who is calling,
in which org, with which role?"** by verifying the access token **locally**. There's no call to
the auth service per request: public keys are fetched once and cached.

It does:
- Reads the token from the `Authorization: Bearer` header (service-to-service) or the access cookie (browser).
- Verifies the ES256 signature, `iss`, `aud`, `exp`, `typ=at+jwt`, and required claims. It rejects `alg=none` and HS256.
- Applies CSRF protection to cookie requests (requires the `X-Lexi-CSRF` header and checks `Origin`).
- Enforces tenancy: the `{org_id}` in the URL must equal the token's `org_id`.
- Maps roles to permissions (one table for all services, in `principal.py`).
- Supports service tokens for jobs and workers, WebSocket auth, and test helpers.

## Install in a service

```txt
# requirements.txt of each service: pin a version (git tag)
lexi-auth @ https://github.com/techbeesz/auth-package/archive/refs/tags/v0.1.0.tar.gz
```
The tag's tarball installs with plain pip or uv, so service images don't need git.
For local work on the package itself: `pip install -e ../auth-package`.

## Configure (env vars, same values in every service)

These five are **required**. `LexiAuth.from_env()` raises `RuntimeError` at startup if any is
missing or blank, instead of starting and rejecting every request with `401 bad_issuer`.

| Variable | Dev VM value | Notes |
|---|---|---|
| `LEXI_ISSUER` | `https://test-api.beesz.com/auth` | = the token's `iss` (auth service `TOKEN_ISSUER`) |
| `LEXI_AUDIENCE` | `https://test-api.beesz.com` | = the token's `aud` (auth service `TOKEN_AUDIENCE`) |
| `LEXI_JWKS_URL` | `http://auth-service-api:8000/.well-known/jwks.json` | internal Docker network |
| `LEXI_ACCESS_COOKIE` | `__Secure-bz_at_dev` | access cookie set by the auth service |
| `LEXI_ALLOWED_ORIGINS` | `https://test.workspace.beesz.com` | comma-separated; CSRF origin check |

Optional: `LEXI_CSRF_HEADER`, `LEXI_CSRF_ENABLED`, `LEXI_LEEWAY_SECONDS`, `LEXI_JWKS_CACHE_SECONDS`,
`LEXI_JWKS_MIN_REFETCH_SECONDS`, `LEXI_JWKS_TIMEOUT_SECONDS`, and, only for background jobs,
`LEXI_SERVICE_CLIENT_ID` / `_SECRET` and `LEXI_TOKEN_URL` (see below).

User and org IDs (`p.user_id`, `p.org_id`) are UUID strings. Tokens whose `sub` or `org_id`
isn't a UUID are rejected.

## Use it

```python
# app/auth.py
from lexi_auth import LexiAuth
auth = LexiAuth.from_env()

# app/main.py
app = FastAPI(lifespan=auth.lifespan)       # fetches the signing keys at startup

# app/routes/campaigns.py
from fastapi import Depends
from lexi_auth import Principal
from app.auth import auth

@router.get("/api/orgs/{org_id}/campaigns")
async def list_campaigns(org_id: str, p: Principal = Depends(auth.org_scoped("campaign:read"))):
    return await db.fetch("select * from campaigns where org_id = $1", p.org_id)   # org from TOKEN

@router.post("/api/orgs/{org_id}/campaigns", status_code=201)
async def create(org_id: str, body: CampaignIn, p: Principal = Depends(auth.org_scoped("campaign:write"))):
    await db.execute("insert into campaigns (id, org_id, created_by, name) values ($1,$2,$3,$4)",
                     new_id(), p.org_id, p.user_id, body.name)
```
If the service already has its own lifespan, call `await auth.warm()` before `yield` and
`await auth.aclose()` after it. `warm()` never raises: if the auth service is down, it logs a
warning and the keys are fetched on the first request instead.

Every rejected request is logged at INFO on the `lexi_auth` logger (WARNING for
`auth_unavailable`), without the token or cookies:
`auth_rejected code=token_expired method=GET path=/deals request_id=<X-Request-Id or ->`.

| Dependency | Allows |
|---|---|
| `auth.org_scoped("perm")` | Users whose active org = `{org_id}` in the path and whose role grants `perm`. **Use this on nearly every route.** |
| `auth.org_scoped()` | Same, but any role |
| `auth.require("perm")` | Users with `perm`, for routes without `{org_id}` |
| `auth.user` | Any signed-in user |
| `auth.principal` | A user **or** a service token. Use on `/internal/*` endpoints |
| `auth.service("svc_scheduler")` | Only that service's token |
| `auth.websocket_user` | WebSocket upgrade (checks `Origin`, cookie, and org) |

`Principal` has `user_id`, `org_id`, `role`, `session_id`, `can(perm)`,
`has_role_at_least("admin")`, and `auth_headers()`.

**Two rules for every service:**
1. Every table with customer data has an `org_id` column, and every query filters on `p.org_id`.
2. `org_id` **never** comes from the request body or query string; only from `p`.

### Calling another service on behalf of the user

```python
r = await http.post("http://credits:8000/internal/debits", json={...}, headers=p.auth_headers())
```
The receiving service verifies the same token with `Depends(auth.principal)`.

### Background jobs (no user)

```python
from lexi_auth import ServiceTokenClient
tokens = ServiceTokenClient.from_env()              # gets/caches a 5-min token from the auth service
await http.post(url, headers=await tokens.headers())
```
Create the client credentials with `python -m app.cli client-secret svc_campaign` in the auth service.

### Testing your service: real tokens, no auth service

```python
from lexi_auth.testing import TokenFactory
tokens = TokenFactory()
client = TestClient(create_app(auth=tokens.make_auth()))
org = "00000000-0000-4000-8000-00000000000a"           # org IDs are UUIDs
client.get(f"/api/orgs/{org}/campaigns",
           headers={"Authorization": f"Bearer {tokens.user(org_id=org, role='viewer')}"})
```
Write your app with a `create_app(auth=None)` factory so tests can inject this.

If your app calls `LexiAuth.from_env()` at import time, the tests must set the five required
`LEXI_*` env vars (any values) before importing it, e.g. at the top of `conftest.py`:
```python
os.environ.setdefault("LEXI_ISSUER", "test")   # likewise the other four
```

## Errors your frontend will see

| Status | `detail.code` | Frontend action |
|---|---|---|
| 401 | `missing_token`, `token_expired`, `invalid_token`, ... | `POST /api/auth/refresh`, then retry once. If that fails, send the user to login |
| 403 | `org_mismatch` | `POST /api/auth/switch-org` with the org from the URL, then retry |
| 403 | `forbidden` | Hide or disable the action |
| 403 | `csrf_header_missing` / `bad_origin` | Bug: send `X-Lexi-CSRF: 1` |
| 503 | `auth_unavailable` | Auth service unreachable and no keys cached yet. Retry later |

## Adding a permission

Edit `DEFAULT_ROLE_PERMISSIONS` in `src/lexi_auth/principal.py`, bump the version in
`pyproject.toml`, tag it, and upgrade the services that need it.

## Develop

```bash
pip install -e ".[dev]" && pytest                      # library tests
cd examples/demo_service && pytest                     # example service tests
```
`examples/demo_service/` is a complete example service. The auth service's `docker compose up` runs it.

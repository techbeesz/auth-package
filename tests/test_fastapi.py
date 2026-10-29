import base64
import json
import logging
import time

import jwt
import pytest
from fastapi import Depends, FastAPI, WebSocket
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from lexi_auth import LexiAuth, Principal, StaticJWKS, TokenError
from lexi_auth.testing import TEST_ORIGIN, TEST_USER_ID, TokenFactory

ORG = "00000000-0000-4000-8000-00000000000a"


@pytest.fixture
def tokens():
    return TokenFactory()


@pytest.fixture
def client(tokens):
    auth = tokens.make_auth()
    app = FastAPI()

    @app.get("/api/orgs/{org_id}/things")
    async def list_things(org_id: str, p: Principal = Depends(auth.org_scoped("campaign:read"))):
        return {"user": p.user_id, "org": p.org_id, "role": p.role}

    @app.post("/api/orgs/{org_id}/things")
    async def create_thing(org_id: str, p: Principal = Depends(auth.org_scoped("campaign:write"))):
        return {"ok": True}

    @app.delete("/api/orgs/{org_id}")
    async def delete_org(org_id: str, p: Principal = Depends(auth.org_scoped("billing:manage"))):
        return {"ok": True}

    @app.post("/internal/debit")
    async def internal(p: Principal = Depends(auth.principal)):
        return {"kind": p.kind, "sub": p.subject}

    @app.post("/internal/svc-only")
    async def svc_only(p: Principal = Depends(auth.service("svc_campaign"))):
        return {"sub": p.subject}

    @app.websocket("/api/orgs/{org_id}/ws")
    async def ws(websocket: WebSocket, org_id: str, p: Principal = Depends(auth.websocket_user)):
        await websocket.accept()
        await websocket.send_json({"user": p.user_id})
        await websocket.close()

    return TestClient(app)


def bearer(t):
    return {"Authorization": f"Bearer {t}"}


def b64(d):
    return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()


# ------------------------------------------------------------------ happy paths
def test_valid_bearer(client, tokens):
    r = client.get(f"/api/orgs/{ORG}/things", headers=bearer(tokens.user(org_id=ORG, role="viewer")))
    assert r.status_code == 200
    assert r.json() == {"user": TEST_USER_ID, "org": ORG, "role": "viewer"}


def test_valid_cookie(client, tokens):
    client.cookies.set("lp_at", tokens.user(org_id=ORG))
    assert client.get(f"/api/orgs/{ORG}/things").status_code == 200


# ------------------------------------------------------------------ token attacks
def test_missing_token(client):
    r = client.get(f"/api/orgs/{ORG}/things")
    assert r.status_code == 401 and r.json()["detail"]["code"] == "missing_token"


def test_expired(client, tokens):
    t = tokens.user(org_id=ORG, iat=int(time.time()) - 4000, exp=int(time.time()) - 3000)
    r = client.get(f"/api/orgs/{ORG}/things", headers=bearer(t))
    assert r.status_code == 401 and r.json()["detail"]["code"] == "token_expired"


def test_wrong_audience(client, tokens):
    t = tokens.user(org_id=ORG, aud="https://other.example")
    assert client.get(f"/api/orgs/{ORG}/things", headers=bearer(t)).json()["detail"]["code"] == "bad_audience"


def test_wrong_issuer(client, tokens):
    t = tokens.user(org_id=ORG, iss="https://evil.example")
    assert client.get(f"/api/orgs/{ORG}/things", headers=bearer(t)).json()["detail"]["code"] == "bad_issuer"


def test_alg_none(client, tokens):
    good = jwt.decode(tokens.user(org_id=ORG), options={"verify_signature": False})
    t = b64({"alg": "none", "typ": "at+jwt", "kid": "test-key"}) + "." + b64(good) + "."
    r = client.get(f"/api/orgs/{ORG}/things", headers=bearer(t))
    assert r.status_code == 401 and r.json()["detail"]["code"] == "bad_algorithm"


def test_hs256_with_public_key_as_secret(client, tokens):
    from cryptography.hazmat.primitives import serialization
    pub_pem = tokens.private_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    claims = jwt.decode(tokens.user(org_id=ORG), options={"verify_signature": False})
    header = b64({"alg": "HS256", "typ": "at+jwt", "kid": "test-key"})
    body = b64(claims)
    import hashlib, hmac
    sig = base64.urlsafe_b64encode(
        hmac.new(pub_pem, f"{header}.{body}".encode(), hashlib.sha256).digest()).rstrip(b"=").decode()
    r = client.get(f"/api/orgs/{ORG}/things", headers=bearer(f"{header}.{body}.{sig}"))
    assert r.status_code == 401 and r.json()["detail"]["code"] == "bad_algorithm"


def test_signed_by_other_key(client):
    attacker = TokenFactory()  # same kid, different key
    r = client.get(f"/api/orgs/{ORG}/things", headers=bearer(attacker.user(org_id=ORG)))
    assert r.status_code == 401 and r.json()["detail"]["code"] == "invalid_token"


def test_unknown_kid(client, tokens):
    t = tokens.sign(jwt.decode(tokens.user(org_id=ORG), options={"verify_signature": False}),
                    headers={"kid": "nope"})
    assert client.get(f"/api/orgs/{ORG}/things", headers=bearer(t)).json()["detail"]["code"] == "unknown_key"


def test_missing_typ(client, tokens):
    t = tokens.sign(jwt.decode(tokens.user(org_id=ORG), options={"verify_signature": False}),
                    headers={"typ": "JWT"})
    assert client.get(f"/api/orgs/{ORG}/things", headers=bearer(t)).json()["detail"]["code"] == "wrong_token_type"


def test_missing_org_claim(client, tokens):
    claims = jwt.decode(tokens.user(org_id=ORG), options={"verify_signature": False})
    del claims["org_id"]
    r = client.get(f"/api/orgs/{ORG}/things", headers=bearer(tokens.sign(claims)))
    assert r.status_code == 401


def test_unknown_role(client, tokens):
    r = client.get(f"/api/orgs/{ORG}/things", headers=bearer(tokens.user(org_id=ORG, role="god")))
    assert r.status_code == 401


# ------------------------------------------------------------------ tenancy and permissions
def test_org_mismatch(client, tokens):
    r = client.get("/api/orgs/org_B/things", headers=bearer(tokens.user(org_id=ORG)))
    assert r.status_code == 403 and r.json()["detail"]["code"] == "org_mismatch"


def test_permission_denied(client, tokens):
    r = client.post(f"/api/orgs/{ORG}/things", headers=bearer(tokens.user(org_id=ORG, role="viewer")))
    assert r.status_code == 403 and r.json()["detail"]["code"] == "forbidden"
    r = client.delete(f"/api/orgs/{ORG}", headers=bearer(tokens.user(org_id=ORG, role="admin")))
    assert r.status_code == 403
    r = client.delete(f"/api/orgs/{ORG}", headers=bearer(tokens.user(org_id=ORG, role="owner")))
    assert r.status_code == 200


# ------------------------------------------------------------------ CSRF
def test_cookie_post_requires_csrf_header(client, tokens):
    client.cookies.set("lp_at", tokens.user(org_id=ORG))
    r = client.post(f"/api/orgs/{ORG}/things")
    assert r.status_code == 403 and r.json()["detail"]["code"] == "csrf_header_missing"
    r = client.post(f"/api/orgs/{ORG}/things", headers={"X-Lexi-CSRF": "1", "Origin": "https://evil.example"})
    assert r.status_code == 403 and r.json()["detail"]["code"] == "bad_origin"
    r = client.post(f"/api/orgs/{ORG}/things", headers={"X-Lexi-CSRF": "1", "Origin": TEST_ORIGIN})
    assert r.status_code == 200


def test_bearer_post_needs_no_csrf(client, tokens):
    r = client.post(f"/api/orgs/{ORG}/things", headers=bearer(tokens.user(org_id=ORG)))
    assert r.status_code == 200


# ------------------------------------------------------------------ service tokens
def test_service_token_on_internal(client, tokens):
    r = client.post("/internal/debit", headers=bearer(tokens.service("svc_campaign")))
    assert r.json() == {"kind": "service", "sub": "svc_campaign"}
    r = client.post("/internal/debit", headers=bearer(tokens.user(org_id=ORG)))
    assert r.json()["kind"] == "user"


def test_service_only_endpoint(client, tokens):
    assert client.post("/internal/svc-only", headers=bearer(tokens.service("svc_campaign"))).status_code == 200
    assert client.post("/internal/svc-only", headers=bearer(tokens.service("svc_other"))).status_code == 403
    assert client.post("/internal/svc-only", headers=bearer(tokens.user(org_id=ORG))).status_code == 403


def test_service_token_cannot_hit_org_routes(client, tokens):
    r = client.get(f"/api/orgs/{ORG}/things", headers=bearer(tokens.service("svc_campaign")))
    assert r.status_code == 403


def test_service_token_rejected_in_cookie(client, tokens):
    client.cookies.set("lp_at", tokens.service("svc_campaign"))
    assert client.post("/internal/debit", headers={"X-Lexi-CSRF": "1"}).status_code == 401


# ------------------------------------------------------------------ websockets
def test_websocket_ok(client, tokens):
    client.cookies.set("lp_at", tokens.user(org_id=ORG))
    with client.websocket_connect(f"/api/orgs/{ORG}/ws", headers={"Origin": TEST_ORIGIN}) as ws:
        assert ws.receive_json() == {"user": TEST_USER_ID}


def test_websocket_bad_origin(client, tokens):
    client.cookies.set("lp_at", tokens.user(org_id=ORG))
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect(f"/api/orgs/{ORG}/ws", headers={"Origin": "https://evil.example"}):
            pass


def test_websocket_org_mismatch(client, tokens):
    client.cookies.set("lp_at", tokens.user(org_id="org_B"))
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect(f"/api/orgs/{ORG}/ws", headers={"Origin": TEST_ORIGIN}):
            pass


# ------------------------------------------------------------------ logging
def test_rejection_is_logged_without_token(client, tokens, caplog):
    t = tokens.user(org_id=ORG, aud="https://other.example")
    with caplog.at_level(logging.INFO, logger="lexi_auth"):
        client.get(f"/api/orgs/{ORG}/things", headers={**bearer(t), "X-Request-Id": "req-1"})
    assert f"auth_rejected code=bad_audience method=GET path=/api/orgs/{ORG}/things request_id=req-1" in caplog.text
    assert t not in caplog.text and t.split(".")[1] not in caplog.text


def test_csrf_and_cookie_rejections_are_logged(client, tokens, caplog):
    client.cookies.set("lp_at", tokens.user(org_id=ORG))
    with caplog.at_level(logging.INFO, logger="lexi_auth"):
        client.post(f"/api/orgs/{ORG}/things")
    assert "auth_rejected code=csrf_header_missing method=POST" in caplog.text
    assert "request_id=-" in caplog.text
    assert client.cookies["lp_at"] not in caplog.text


def test_auth_unavailable_logged_as_warning(tokens, caplog):
    class DownKeys:
        async def get_key(self, kid):
            raise TokenError("jwks_unavailable")

    auth = LexiAuth(tokens.settings(), keys=DownKeys())
    app = FastAPI()

    @app.get("/me")
    async def me(p: Principal = Depends(auth.user)):
        return {}

    with caplog.at_level(logging.INFO, logger="lexi_auth"):
        r = TestClient(app).get("/me", headers=bearer(tokens.user(org_id=ORG)))
    assert r.status_code == 503
    [rec] = [r for r in caplog.records if "auth_rejected" in r.getMessage()]
    assert rec.levelno == logging.WARNING and "code=auth_unavailable" in rec.getMessage()


def test_lifespan_warms_keys(tokens):
    class CountingKeys(StaticJWKS):
        warmed = 0

        async def warm(self):
            CountingKeys.warmed += 1

    auth = LexiAuth(tokens.settings(), keys=CountingKeys(tokens.jwks()))
    with TestClient(FastAPI(lifespan=auth.lifespan)):
        assert CountingKeys.warmed == 1


def test_user_and_org_ids_must_be_uuids(client, tokens):
    # e.g. a token minted before auth-service switched to UUID IDs
    for claims in ({"user_id": "usr_01JA3K8ZQ4M7P2"}, {"org_id": "org_01J8ZT5NWE"}):
        t = tokens.user(**{"org_id": ORG, **claims})
        org = claims.get("org_id", ORG)
        r = client.get(f"/api/orgs/{org}/things", headers=bearer(t))
        assert r.status_code == 401 and r.json()["detail"]["code"] == "invalid_token"

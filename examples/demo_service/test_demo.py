"""How to test YOUR services: real signed tokens from TokenFactory, no auth service needed."""
from fastapi.testclient import TestClient

from lexi_auth.testing import TokenFactory

from main import create_app

tokens = TokenFactory()
client = TestClient(create_app(auth=tokens.make_auth()))


ORG_A, ORG_B = "00000000-0000-4000-8000-00000000000a", "00000000-0000-4000-8000-00000000000b"
USER_A, USER_B = "00000000-0000-4000-8000-0000000000a1", "00000000-0000-4000-8000-0000000000b1"


def bearer(t):
    return {"Authorization": f"Bearer {t}"}


def test_create_and_list_is_org_isolated():
    a = tokens.user(user_id=USER_A, org_id=ORG_A, role="member")
    b = tokens.user(user_id=USER_B, org_id=ORG_B, role="member")
    assert client.post(f"/api/orgs/{ORG_A}/campaigns", json={"name": "Spring"}, headers=bearer(a)).status_code == 201
    assert client.get(f"/api/orgs/{ORG_B}/campaigns", headers=bearer(b)).json()["campaigns"] == []
    # B tries to read A's org by changing the URL
    assert client.get(f"/api/orgs/{ORG_A}/campaigns", headers=bearer(b)).status_code == 403


def test_viewer_cannot_create():
    v = tokens.user(org_id=ORG_A, role="viewer")
    assert client.post(f"/api/orgs/{ORG_A}/campaigns", json={"name": "x"}, headers=bearer(v)).status_code == 403


def test_internal_job_requires_scheduler_service_token():
    assert client.post("/internal/campaigns/nightly-job", headers=bearer(tokens.service("svc_scheduler"))).status_code == 200
    assert client.post("/internal/campaigns/nightly-job", headers=bearer(tokens.user())).status_code == 403

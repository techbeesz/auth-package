import httpx
import pytest

from lexi_auth import RemoteJWKS, TokenError
from lexi_auth.testing import TokenFactory


def make_transport(state):
    def handler(request):
        state["calls"] += 1
        if state.get("fail"):
            return httpx.Response(503)
        return httpx.Response(200, json=state["jwks"])
    return httpx.MockTransport(handler)


async def test_caches_and_refetches_on_unknown_kid():
    a, b = TokenFactory(kid="k1"), TokenFactory(kid="k2")
    state = {"calls": 0, "jwks": a.jwks()}
    jwks = RemoteJWKS("http://auth/jwks", min_refetch_seconds=0,
                      client=httpx.AsyncClient(transport=make_transport(state)))
    await jwks.get_key("k1")
    await jwks.get_key("k1")
    assert state["calls"] == 1                      # cached

    state["jwks"] = {"keys": a.jwks()["keys"] + b.jwks()["keys"]}   # rotation: new key published
    await jwks.get_key("k2")
    assert state["calls"] == 2                      # unknown kid -> one refetch


async def test_unknown_kid_refetch_is_throttled():
    a = TokenFactory(kid="k1")
    state = {"calls": 0, "jwks": a.jwks()}
    jwks = RemoteJWKS("http://auth/jwks", min_refetch_seconds=60,
                      client=httpx.AsyncClient(transport=make_transport(state)))
    await jwks.get_key("k1")
    for _ in range(5):
        with pytest.raises(TokenError):
            await jwks.get_key("garbage")
    assert state["calls"] == 1                      # attackers can't make us hammer the auth service


async def test_keeps_cached_keys_when_auth_service_down():
    a = TokenFactory(kid="k1")
    state = {"calls": 0, "jwks": a.jwks()}
    jwks = RemoteJWKS("http://auth/jwks", cache_seconds=0, min_refetch_seconds=0,
                      client=httpx.AsyncClient(transport=make_transport(state)))
    await jwks.get_key("k1")
    state["fail"] = True
    assert await jwks.get_key("k1")                 # stale-but-valid key still used


async def test_warm_fetches_keys_up_front():
    a = TokenFactory(kid="k1")
    state = {"calls": 0, "jwks": a.jwks()}
    jwks = RemoteJWKS("http://auth/jwks", client=httpx.AsyncClient(transport=make_transport(state)))
    await jwks.warm()
    assert state["calls"] == 1
    await jwks.get_key("k1")
    assert state["calls"] == 1                      # first request needs no fetch


async def test_warm_swallows_fetch_errors():
    a = TokenFactory(kid="k1")
    state = {"calls": 0, "fail": True, "jwks": a.jwks()}
    jwks = RemoteJWKS("http://auth/jwks", client=httpx.AsyncClient(transport=make_transport(state)))
    await jwks.warm()                               # auth service down: the service still starts
    state["fail"] = False
    assert await jwks.get_key("k1")                 # and recovers on the first request


async def test_no_keys_and_down_is_unavailable():
    state = {"calls": 0, "fail": True, "jwks": {}}
    jwks = RemoteJWKS("http://auth/jwks", client=httpx.AsyncClient(transport=make_transport(state)))
    with pytest.raises(TokenError) as e:
        await jwks.get_key("k1")
    assert e.value.code == "jwks_unavailable"

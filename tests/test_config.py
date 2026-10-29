import pytest

from lexi_auth import AuthSettings

REQUIRED = {
    "LEXI_ISSUER": "https://issuer.example",
    "LEXI_AUDIENCE": "https://api.example",
    "LEXI_JWKS_URL": "http://auth:8000/.well-known/jwks.json",
    "LEXI_ACCESS_COOKIE": "bz_at",
    "LEXI_ALLOWED_ORIGINS": "https://app.example/, https://other.example",
}


@pytest.fixture
def env(monkeypatch):
    for name, value in REQUIRED.items():
        monkeypatch.setenv(name, value)
    return monkeypatch


def test_from_env_reads_required_vars(env):
    s = AuthSettings.from_env()
    assert s.issuer == "https://issuer.example"
    assert s.access_cookie == "bz_at"
    assert s.allowed_origins == ("https://app.example", "https://other.example")
    assert s.leeway_seconds == AuthSettings().leeway_seconds     # optional vars keep defaults


@pytest.mark.parametrize("name", sorted(REQUIRED))
@pytest.mark.parametrize("value", [None, "", "   "])
def test_from_env_fails_fast_on_missing_var(env, name, value):
    if value is None:
        env.delenv(name)
    else:
        env.setenv(name, value)
    with pytest.raises(RuntimeError, match=f"^{name} must be set"):
        AuthSettings.from_env()


def test_direct_construction_keeps_defaults(monkeypatch):
    for name in REQUIRED:
        monkeypatch.delenv(name, raising=False)
    assert AuthSettings().issuer == "https://auth.beesz.com"

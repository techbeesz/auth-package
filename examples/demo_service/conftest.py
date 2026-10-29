"""main.py builds `app = create_app()` at import time, which calls LexiAuth.from_env().
Set the required LEXI_* vars (any values) before the tests import it; the tests inject their own auth."""
import os

for name in ("LEXI_ISSUER", "LEXI_AUDIENCE", "LEXI_JWKS_URL", "LEXI_ACCESS_COOKIE", "LEXI_ALLOWED_ORIGINS"):
    os.environ.setdefault(name, "http://test.invalid")

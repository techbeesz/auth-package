from __future__ import annotations

from fastapi import HTTPException


def unauthorized(code: str) -> HTTPException:
    """401: the caller is not (or no longer) authenticated. Browser should call /api/auth/refresh."""
    return HTTPException(
        status_code=401,
        detail={"code": code},
        headers={"WWW-Authenticate": 'Bearer realm="beesz"'},
    )


def forbidden(code: str) -> HTTPException:
    """403: authenticated, but not allowed to do this."""
    return HTTPException(status_code=403, detail={"code": code})


class TokenError(Exception):
    """Raised by the verifier. `code` is safe to return to clients."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code

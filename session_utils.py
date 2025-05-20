from __future__ import annotations

"""Session & authentication helper shared by *both* LearnUs back-end apps.

Motivation
----------
The original implementation kept an in-memory ``_SESSIONS`` dictionary to map
random tokens to an in-process ``LearnUsClient`` instance.  When the service
was deployed with *multiple* worker processes this broke because each worker
maintained its own private dictionary.  Depending on which worker handled the
request the token could therefore be missing – leading to the flaky behaviour
(401 responses, empty pages) observed by the user.

To eliminate this single-process assumption we switch to **stateless signed
tokens** powered by `PyJWT`.  Every issued token embeds the minimal amount of
information we need to be able to lazily recreate a ``LearnUsClient`` in any
process:

* ``sub`` – The LearnUs username (student ID) or the special value ``guest``
* ``pwd`` – The plaintext password (absent for guest sessions)
* ``iat`` / ``exp`` – Issue + expiry timestamps (seconds since epoch)
* ``guest`` – Flag so that guest tokens can be distinguished quickly

All payload data are **signed** with an application-wide secret so the client
cannot tamper with the contents.  As long as every worker knows the secret the
same token can be validated everywhere without any shared state.

The module also maintains a *per-process* in-memory cache so that repeat API
calls handled by the same worker do **not** have to re-authenticate against
LearnUs each time.  Cache entries carry the same TTL as the token itself and
are evicted automatically.
"""

from typing import Optional, Dict
import os
import time
from functools import wraps

import jwt  # PyJWT
from fastapi import HTTPException, status, Header

from learnus_client import LearnUsClient, LearnUsLoginError

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
# Use env-var so deployments can override the default.  The default value is
# fine for personal projects but *DO NOT* use it in public production!
_SECRET_KEY = os.getenv("SESSION_SECRET", "__learnus_dev_secret_change_me__")
_ALGORITHM = "HS256"
_DEFAULT_EXP_SECS = 60 * 60 * 6  # 6 hours validity

# ---------------------------------------------------------------------------
# Local cache (per process) mapping *token* -> LearnUsClient
# ---------------------------------------------------------------------------
_CLIENT_CACHE: Dict[str, LearnUsClient] = {}


def _purge_expired():
    """Remove expired client instances from the local cache."""
    now = time.time()
    expired = []
    for tok, client in _CLIENT_CACHE.items():
        try:
            payload = jwt.decode(tok, _SECRET_KEY, algorithms=[_ALGORITHM])
            if payload.get("exp", 0) < now:
                expired.append(tok)
        except jwt.PyJWTError:
            expired.append(tok)
    for t in expired:
        _CLIENT_CACHE.pop(t, None)


# ---------------------------------------------------------------------------
# Token helpers
# ---------------------------------------------------------------------------

def issue_token(username: str, password: str, *, guest: bool = False, exp_secs: int = _DEFAULT_EXP_SECS) -> str:
    """Return signed token for *username* / *password* with given lifetime."""
    now = int(time.time())
    payload = {
        "sub": username if not guest else "guest",
        "pwd": password if not guest else "",
        "guest": guest,
        "iat": now,
        "exp": now + exp_secs,
    }
    return jwt.encode(payload, _SECRET_KEY, algorithm=_ALGORITHM)


def verify_token(token: str) -> dict:
    """Return decoded payload or raise HTTP 401 if the token is invalid/expired."""
    try:
        payload = jwt.decode(token, _SECRET_KEY, algorithms=[_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired")
    except jwt.PyJWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")


# ---------------------------------------------------------------------------
# Client retrieval
# ---------------------------------------------------------------------------

def get_learnus_client(token: str) -> Optional[LearnUsClient]:
    """Return ``LearnUsClient`` for *token*.

    If the token belongs to a guest session we simply return ``None``.
    If a cached client exists, reuse it.  Otherwise perform a *fresh login*
    using the credentials embedded in the token and cache the resulting
    instance for subsequent calls.
    """
    payload = verify_token(token)

    if payload.get("guest"):
        return None

    # quick path: cached in the current worker
    client = _CLIENT_CACHE.get(token)
    if client is not None:
        return client

    # otherwise perform login
    username = payload["sub"]
    password = payload["pwd"]

    new_client = LearnUsClient()
    try:
        new_client.login(username, password)
    except LearnUsLoginError as e:
        # authentication failed – treat as invalid token
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e))

    # cache and return
    _purge_expired()
    _CLIENT_CACHE[token] = new_client
    return new_client


# ---------------------------------------------------------------------------
# Decorator sugar for dependency injection
# ---------------------------------------------------------------------------

def fastapi_get_client(token_header_name: str = "X-Auth-Token"):
    """Return a *dependency* that extracts the given header & returns client.

    Example::

        from fastapi import Depends, Header
        from session_utils import fastapi_get_client

        get_client = fastapi_get_client()

        @app.get("/courses")
        def courses(client: LearnUsClient = Depends(get_client)):
            ...
    """

    def dependency(x_auth_token: Optional[str] = Header(None)):
        if not x_auth_token:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing token")
        return get_learnus_client(x_auth_token)

    from fastapi import Header  # local import to prevent circular

    return dependency


__all__ = [
    "issue_token",
    "verify_token",
    "get_learnus_client",
    "fastapi_get_client",
] 
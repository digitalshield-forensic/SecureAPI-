"""Password hashing (scrypt, stdlib) and JWT helpers."""
import base64
import hashlib
import hmac
import os
import time
import uuid

import jwt

from .config import Settings

_N, _R, _P, _DKLEN = 2**14, 8, 1, 32
_MAXMEM = 64 * 1024 * 1024


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=_N, r=_R, p=_P, dklen=_DKLEN, maxmem=_MAXMEM)
    return "$".join(["scrypt", str(_N), str(_R), str(_P),
                     base64.b64encode(salt).decode(), base64.b64encode(dk).decode()])


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, n, r, p, salt, expected = stored.split("$")
        if scheme != "scrypt":
            return False
        expected_b = base64.b64decode(expected)
        dk = hashlib.scrypt(password.encode(), salt=base64.b64decode(salt), n=int(n), r=int(r),
                            p=int(p), dklen=len(expected_b), maxmem=_MAXMEM)
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(dk, expected_b)


# Verified against when the username doesn't exist, so "unknown user" and
# "wrong password" cost the same CPU time (limits timing-based enumeration).
DUMMY_HASH = hash_password("dummy-password-for-timing-equalisation")


def create_token(user_id: str, settings: Settings) -> tuple[str, str, int]:
    now = int(time.time())
    claims = {"sub": user_id, "jti": uuid.uuid4().hex, "iat": now,
              "exp": now + settings.access_token_ttl_s,
              "iss": settings.jwt_issuer, "aud": settings.jwt_audience}
    return jwt.encode(claims, settings.jwt_secret, algorithm="HS256"), claims["jti"], claims["exp"]


def decode_token(token: str, settings: Settings) -> dict:
    return jwt.decode(
        token, settings.jwt_secret,
        algorithms=["HS256"],                       # pinned: "none"/RS-confusion rejected
        audience=settings.jwt_audience, issuer=settings.jwt_issuer, leeway=5,
        options={"require": ["exp", "iat", "sub", "jti", "iss", "aud"]},
    )

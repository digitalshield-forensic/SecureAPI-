"""Configuration. Fails closed: the app refuses to start with a weak JWT secret."""
import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    jwt_secret: str
    db_path: str = "notes.db"
    jwt_issuer: str = "secure-notes-api"
    jwt_audience: str = "secure-notes-clients"
    access_token_ttl_s: int = 900             # 15 minutes
    max_body_bytes: int = 16 * 1024           # 16 KiB request cap
    lockout_threshold: int = 5                # failed logins before lock
    lockout_seconds: int = 900
    # (max requests, window seconds)
    global_ip_limit: tuple = (300, 60)        # every request, per client IP
    auth_ip_limit: tuple = (10, 60)           # /auth/register + /auth/login, per IP
    user_limit: tuple = (60, 60)              # authenticated requests, per user
    max_notes_per_user: int = 200
    trusted_proxy_hops: int = 0               # 0 = never trust X-Forwarded-For
    enable_docs: bool = False                 # /docs + /openapi.json off by default

    def __post_init__(self):
        if len(self.jwt_secret) < 32:
            raise ValueError("NOTES_JWT_SECRET must be at least 32 characters")

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            jwt_secret=os.environ.get("NOTES_JWT_SECRET", ""),
            db_path=os.environ.get("NOTES_DB_PATH", "notes.db"),
            enable_docs=os.environ.get("NOTES_ENABLE_DOCS") == "1",
            trusted_proxy_hops=int(os.environ.get("NOTES_TRUSTED_PROXY_HOPS", "0")),
        )

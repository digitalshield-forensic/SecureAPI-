"""Secure Notes API — FastAPI application factory."""
import logging
import sqlite3
import time
import uuid
from typing import Optional

import jwt
from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from starlette.exceptions import HTTPException as StarletteHTTPException

from .config import Settings
from .db import connect, init_db
from .middleware import SECURITY_HEADERS, SecurityMiddleware, error_payload
from .ratelimit import SlidingWindowLimiter
from .schemas import (AdminUserOut, LoginIn, NoteIn, NoteOut, RegisterIn, TokenOut, UserOut)
from .security import DUMMY_HASH, create_token, decode_token, hash_password, verify_password

log = logging.getLogger("notes")
audit_log = logging.getLogger("notes.audit")

INVALID_CREDS = "Invalid username or password"   # one message for every login failure


def _safe(v, n=64) -> str:
    """Neutralise attacker-controlled values before logging (log-injection defence)."""
    return repr(str(v)[:n])


def client_ip(request: Request, hops: int) -> str:
    if hops > 0:  # only trust the entries appended by OUR proxies (rightmost N)
        parts = [p.strip() for p in request.headers.get("x-forwarded-for", "").split(",") if p.strip()]
        if len(parts) >= hops:
            return parts[-hops]
    return request.client.host if request.client else "unknown"


def create_app(settings: Optional[Settings] = None) -> FastAPI:
    settings = settings or Settings.from_env()
    init_db(settings.db_path)
    limiter = SlidingWindowLimiter()
    db_path = settings.db_path

    def rid(request: Request) -> str:
        return getattr(request.state, "request_id", "-")

    def audit(event: str, request: Request, user_id: str = "-", **kv) -> None:
        extra = " ".join(f"{k}={_safe(v)}" for k, v in kv.items())
        audit_log.info("event=%s user=%s ip=%s rid=%s %s", event, user_id,
                       client_ip(request, settings.trusted_proxy_hops), rid(request), extra)

    def enforce(key: str, rule: tuple, request: Request) -> None:
        ok, retry = limiter.hit(key, *rule)
        if not ok:
            audit("rate_limited", request, bucket=key.split(":")[0])
            raise HTTPException(429, "Too many requests", headers={"Retry-After": str(retry)})

    def global_ip_limit(request: Request) -> None:
        enforce("ip:" + client_ip(request, settings.trusted_proxy_hops), settings.global_ip_limit, request)

    def auth_ip_limit(request: Request) -> None:
        enforce("auth:" + client_ip(request, settings.trusted_proxy_hops), settings.auth_ip_limit, request)

    app = FastAPI(
        title="Secure Notes API", version="1.0.0",
        docs_url="/docs" if settings.enable_docs else None,
        redoc_url=None,
        openapi_url="/openapi.json" if settings.enable_docs else None,
        dependencies=[Depends(global_ip_limit)],
    )
    app.add_middleware(SecurityMiddleware, max_body_bytes=settings.max_body_bytes)
    app.state.settings, app.state.limiter = settings, limiter

    # ---------------- secure, uniform error handling ----------------
    @app.exception_handler(StarletteHTTPException)
    async def http_error(request: Request, exc: StarletteHTTPException):
        return JSONResponse(error_payload(exc.status_code, str(exc.detail), rid(request)),
                            status_code=exc.status_code, headers=getattr(exc, "headers", None))

    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, exc: RequestValidationError):
        # Report field + rule only. NEVER echo `input` (could contain passwords/tokens).
        issues = [{"field": ".".join(str(p) for p in e["loc"])[:100], "message": str(e["msg"])[:200]}
                  for e in exc.errors()[:10]]
        return JSONResponse(error_payload(422, "Request validation failed", rid(request), issues),
                            status_code=422)

    @app.exception_handler(Exception)
    async def unhandled(request: Request, exc: Exception):
        log.exception("unhandled error rid=%s", rid(request))   # detail stays server-side
        return JSONResponse(error_payload(500, "Internal server error", rid(request)),
                            status_code=500, headers={**SECURITY_HEADERS, "X-Request-ID": rid(request)})

    # ---------------- authentication / authorisation deps ----------------
    bearer = HTTPBearer(auto_error=False)

    def unauthorized() -> HTTPException:
        return HTTPException(401, "Authentication required", headers={"WWW-Authenticate": "Bearer"})

    def current_user(request: Request, creds: Optional[HTTPAuthorizationCredentials] = Depends(bearer)) -> dict:
        if creds is None or len(creds.credentials) > 2048:
            raise unauthorized()
        try:
            claims = decode_token(creds.credentials, settings)
        except jwt.PyJWTError:
            audit("token_rejected", request)
            raise unauthorized()
        with connect(db_path) as db:
            revoked = db.execute("SELECT 1 FROM revoked_tokens WHERE jti=?", (claims["jti"],)).fetchone()
            user = db.execute("SELECT id, username, role, is_active FROM users WHERE id=?",
                              (claims["sub"],)).fetchone()
        if revoked or user is None or not user["is_active"]:
            audit("token_rejected", request, reason="revoked_or_inactive")
            raise unauthorized()
        enforce("user:" + user["id"], settings.user_limit, request)
        # Role is read from the DB on every request, never trusted from the token.
        return {"id": user["id"], "username": user["username"], "role": user["role"],
                "jti": claims["jti"], "exp": claims["exp"]}

    def require_admin(request: Request, user: dict = Depends(current_user)) -> dict:
        if user["role"] != "admin":
            audit("authz_denied", request, user["id"], need="admin")
            raise HTTPException(403, "Forbidden")
        return user

    # ---------------- routes ----------------
    @app.get("/healthz")
    def healthz():
        return {"status": "ok"}

    @app.post("/auth/register", status_code=201, response_model=UserOut,
              dependencies=[Depends(auth_ip_limit)])
    def register(body: RegisterIn, request: Request):
        uid = str(uuid.uuid4())
        pw_hash = hash_password(body.password)
        try:
            with connect(db_path) as db:
                db.execute("INSERT INTO users(id, username, password_hash, role, created_at) "
                           "VALUES (?,?,?,?,?)", (uid, body.username.lower(), pw_hash, "user", time.time()))
        except sqlite3.IntegrityError:
            raise HTTPException(409, "Username unavailable")
        audit("register", request, uid)
        return {"id": uid, "username": body.username.lower(), "role": "user"}  # role is never client-set

    @app.post("/auth/login", response_model=TokenOut, dependencies=[Depends(auth_ip_limit)])
    def login(body: LoginIn, request: Request):
        now = time.time()
        token = None
        with connect(db_path) as db:
            u = db.execute("SELECT * FROM users WHERE username=?", (body.username.lower(),)).fetchone()
            if u is None:
                verify_password(body.password, DUMMY_HASH)      # equalise timing
                reason = "unknown_user"
            elif u["locked_until"] > now:
                verify_password(body.password, DUMMY_HASH)
                reason = "locked"
            elif not verify_password(body.password, u["password_hash"]) or not u["is_active"]:
                reason = "bad_password" if u["is_active"] else "inactive"
                db.execute("UPDATE users SET failed_logins = failed_logins + 1 WHERE id=?", (u["id"],))
                db.execute("UPDATE users SET locked_until=?, failed_logins=0 "
                           "WHERE id=? AND failed_logins >= ?",
                           (now + settings.lockout_seconds, u["id"], settings.lockout_threshold))
            else:
                reason = None
                db.execute("UPDATE users SET failed_logins=0, locked_until=0 WHERE id=?", (u["id"],))
                token, _, _ = create_token(u["id"], settings)
        # (transaction committed above, so failed-attempt counters persist even though we now raise)
        if token is None:
            audit("login_failed", request, reason=reason, username=body.username)
            raise HTTPException(401, INVALID_CREDS, headers={"WWW-Authenticate": "Bearer"})
        audit("login_ok", request, u["id"])
        return {"access_token": token, "token_type": "bearer", "expires_in": settings.access_token_ttl_s}

    @app.post("/auth/logout", status_code=204)
    def logout(request: Request, user: dict = Depends(current_user)):
        with connect(db_path) as db:
            db.execute("DELETE FROM revoked_tokens WHERE expires_at < ?", (time.time(),))
            db.execute("INSERT OR IGNORE INTO revoked_tokens(jti, expires_at) VALUES (?,?)",
                       (user["jti"], user["exp"]))
        audit("logout", request, user["id"])
        return Response(status_code=204)

    # --- notes: every query is scoped by owner_id (object-level authorisation) ---
    def _note_row(db, note_id: str, owner: str):
        return db.execute("SELECT * FROM notes WHERE id=? AND owner_id=?", (note_id, owner)).fetchone()

    def _not_found() -> HTTPException:     # same answer for "doesn't exist" and "not yours"
        return HTTPException(404, "Note not found")

    @app.post("/notes", status_code=201, response_model=NoteOut)
    def create_note(body: NoteIn, user: dict = Depends(current_user)):
        nid, now = str(uuid.uuid4()), time.time()
        with connect(db_path) as db:
            cur = db.execute(   # atomic quota check + insert
                "INSERT INTO notes(id, owner_id, title, body, created_at, updated_at) "
                "SELECT ?,?,?,?,?,? WHERE (SELECT COUNT(*) FROM notes WHERE owner_id=?) < ?",
                (nid, user["id"], body.title, body.body, now, now, user["id"], settings.max_notes_per_user))
            if cur.rowcount == 0:
                raise HTTPException(403, "Note quota exceeded")
            return dict(_note_row(db, nid, user["id"]))

    @app.get("/notes", response_model=list[NoteOut])
    def list_notes(limit: int = Query(20, ge=1, le=50), offset: int = Query(0, ge=0, le=10_000),
                   user: dict = Depends(current_user)):
        with connect(db_path) as db:
            rows = db.execute("SELECT * FROM notes WHERE owner_id=? ORDER BY created_at, id LIMIT ? OFFSET ?",
                              (user["id"], limit, offset)).fetchall()
        return [dict(r) for r in rows]

    @app.get("/notes/{note_id}", response_model=NoteOut)
    def get_note(note_id: uuid.UUID, user: dict = Depends(current_user)):
        with connect(db_path) as db:
            row = _note_row(db, str(note_id), user["id"])
        if row is None:
            raise _not_found()
        return dict(row)

    @app.put("/notes/{note_id}", response_model=NoteOut)
    def update_note(note_id: uuid.UUID, body: NoteIn, user: dict = Depends(current_user)):
        with connect(db_path) as db:
            cur = db.execute("UPDATE notes SET title=?, body=?, updated_at=? WHERE id=? AND owner_id=?",
                             (body.title, body.body, time.time(), str(note_id), user["id"]))
            row = _note_row(db, str(note_id), user["id"]) if cur.rowcount else None
        if row is None:
            raise _not_found()
        return dict(row)

    @app.delete("/notes/{note_id}", status_code=204)
    def delete_note(note_id: uuid.UUID, user: dict = Depends(current_user)):
        with connect(db_path) as db:
            cur = db.execute("DELETE FROM notes WHERE id=? AND owner_id=?", (str(note_id), user["id"]))
        if cur.rowcount == 0:
            raise _not_found()
        return Response(status_code=204)

    # --- admin ---
    @app.get("/admin/users", response_model=list[AdminUserOut])
    def admin_list_users(limit: int = Query(20, ge=1, le=50), offset: int = Query(0, ge=0, le=10_000),
                         admin: dict = Depends(require_admin)):
        with connect(db_path) as db:
            rows = db.execute("SELECT id, username, role, is_active, created_at FROM users "
                              "ORDER BY created_at, id LIMIT ? OFFSET ?", (limit, offset)).fetchall()
        return [{**dict(r), "is_active": bool(r["is_active"])} for r in rows]

    @app.post("/admin/users/{user_id}/disable", status_code=204)
    def admin_disable_user(user_id: uuid.UUID, request: Request, admin: dict = Depends(require_admin)):
        if str(user_id) == admin["id"]:
            raise HTTPException(409, "Admins cannot disable themselves")
        with connect(db_path) as db:
            cur = db.execute("UPDATE users SET is_active=0 WHERE id=?", (str(user_id),))
        if cur.rowcount == 0:
            raise HTTPException(404, "User not found")
        audit("user_disabled", request, admin["id"], target=str(user_id))
        return Response(status_code=204)

    return app

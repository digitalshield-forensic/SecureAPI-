# Secure Notes API

A small REST API (FastAPI + SQLite) where **security is part of the design, not a bolt-on**:
authentication, authorization, input validation, rate limiting and safe error handling are
implemented, documented, and verified by 69 abuse-case tests.

```
app/
  main.py        routes, auth dependencies, error handlers (app factory)
  middleware.py  request IDs, security headers, body-size cap (pure ASGI)
  security.py    scrypt password hashing, JWT create/verify
  ratelimit.py   sliding-window limiter
  schemas.py     strict request/response models
  db.py          SQLite, parameterised queries only
  config.py      settings; refuses to start with a weak secret
  cli.py         out-of-band admin bootstrap
tests/           abuse-case suite (AC-nn IDs)
openapi.json     machine-readable interface spec
```

## Quick start

```bash
pip install -r requirements.txt
export NOTES_JWT_SECRET=$(python -c "import secrets;print(secrets.token_urlsafe(48))")
python -m app.cli create-admin root          # optional; admins are never created via the API
uvicorn app.wsgi:app --no-server-header      # serve behind a TLS-terminating proxy
python -m pytest -q                          # run the abuse-case tests
```

| Env var | Default | Meaning |
|---|---|---|
| `NOTES_JWT_SECRET` | *(required, ≥32 chars)* | HS256 signing key. App will not start without it. |
| `NOTES_DB_PATH` | `notes.db` | SQLite file |
| `NOTES_ENABLE_DOCS` | off | `1` exposes `/docs` and `/openapi.json` (keep off in prod) |
| `NOTES_TRUSTED_PROXY_HOPS` | `0` | Number of reverse proxies in front of the app (see D8) |

---

## 1. Interface

All bodies are JSON (`Content-Type: application/json`). Protected routes need
`Authorization: Bearer <access_token>`. Full schema: `openapi.json`.

| Method & path | Auth | Purpose | Success | Notable errors |
|---|---|---|---|---|
| `GET /healthz` | none | liveness | 200 | 429 |
| `POST /auth/register` | none | create a **user-role** account | 201 `{id, username, role}` | 409 username taken, 422, 429 |
| `POST /auth/login` | none | exchange credentials for token | 200 `{access_token, token_type, expires_in}` | 401 (single generic message), 422, 429 |
| `POST /auth/logout` | user | revoke the presented token | 204 | 401 |
| `POST /notes` | user | create note | 201 note | 403 quota, 422 |
| `GET /notes?limit=&offset=` | user | list **own** notes (limit 1–50, offset ≤10 000) | 200 `[note]` | 422 |
| `GET /notes/{id}` | owner | read note | 200 note | 404 |
| `PUT /notes/{id}` | owner | replace note | 200 note | 404, 422 |
| `DELETE /notes/{id}` | owner | delete note | 204 | 404 |
| `GET /admin/users` | admin | list accounts | 200 `[user]` | 403 |
| `POST /admin/users/{id}/disable` | admin | disable account (effective immediately) | 204 | 403, 404, 409 self-disable |

**Constraints:** username `^[A-Za-z0-9_.-]{3,32}$` (case-insensitive unique) · password 12–128 chars ·
note title 1–120 chars (no control chars) · note body ≤ 4000 chars · request body ≤ 16 KiB ·
`{id}` must be a UUID · unknown JSON fields are rejected.

**Error format (every error, including 404/405/500):**
```json
{"error": {"code": "validation_error", "message": "Request validation failed",
           "request_id": "a6bee77240964392aeb587ff6970277f",
           "issues": [{"field": "body.password", "message": "String should have at least 12 characters"}]}}
```
`issues` appears only on 422. 429 responses carry `Retry-After`; 401 carries `WWW-Authenticate: Bearer`.
Every response carries `X-Request-ID` (also written to the audit log) for support correlation.

**Example**
```bash
curl -X POST :8000/auth/register -H 'content-type: application/json' \
     -d '{"username":"alice","password":"correct horse battery"}'
TOKEN=$(curl -s -X POST :8000/auth/login -H 'content-type: application/json' \
     -d '{"username":"alice","password":"correct horse battery"}' | jq -r .access_token)
curl -X POST :8000/notes -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' \
     -d '{"title":"hello","body":"world"}'
```

---

## 2. Threat model (what we defend against)

**Assets:** user credentials, note contents, admin capability, service availability.
**Attackers:** anonymous internet client; authenticated low-privilege user; someone holding a stolen/expired token.
**Out of scope here:** TLS termination, host/OS hardening, DB-at-rest encryption, malicious admins (see §5).

| STRIDE | Threat | Control |
|---|---|---|
| **S**poofing | credential stuffing / brute force, user enumeration, forged JWTs | scrypt, lockout, per-IP limits, uniform login errors + timing equalisation, pinned-alg JWT with iss/aud/exp |
| **T**ampering | SQL injection, mass assignment, oversized/malformed payloads | parameterised SQL, `extra="forbid"` models, strict regex/length validation, body cap |
| **R**epudiation | "I never did that" | structured audit log with request ID, user ID, IP |
| **I**nfo disclosure | IDOR, verbose errors, stack traces, validation echo, cacheable responses | owner-scoped queries + 404, generic 500, no input echo, `no-store`, docs off |
| **D**oS | login floods, giant bodies, giant passwords (hash-DoS), data hoarding, unbounded lists | 3-tier rate limits, 16 KiB cap, 128-char password max, note quota, bounded pagination |
| **E**levation | self-assigned admin, token role tampering, deleted/disabled user keeps access | role never accepted from client; role + active flag re-read from DB every request; admins via CLI only |

---

## 3. Security design decisions

Each decision lists the choice, why, and the trade-off we accepted.

**D1 — Authentication: short-lived signed bearer tokens (JWT HS256).**
15-minute lifetime; claims `sub, jti, iat, exp, iss, aud` all *required*; algorithm list pinned to `["HS256"]`
so `alg:none` and algorithm-confusion tokens fail. Bearer-in-header (not cookie) means browsers never attach
credentials automatically → no CSRF surface, and no CORS is enabled at all.
*Trade-off:* JWTs are stateless, so we add a `revoked_tokens` table (checked per request) to make logout real.
There is no refresh token; clients re-login every 15 min. A real deployment would add rotating refresh tokens.

**D2 — Password storage: scrypt (N=2¹⁴, r=8, p=1), 16-byte random salt, constant-time compare.**
Memory-hard, in the standard library (no native dependency). Parameters are stored in the hash string so they can
be raised later and old hashes still verify. Passwords are capped at **128 chars** so an attacker can't burn CPU
by submitting megabyte "passwords", and min **12** with no composition rules (NIST 800-63B direction).
*Trade-off:* the weak-password list is tiny; production should check against a breach corpus (e.g. HIBP k-anonymity).

**D3 — Login hardening: one generic failure for every cause.**
Unknown user, wrong password, locked and disabled accounts all return the *identical* 401 body. When the user
doesn't exist (or is locked) we still run a scrypt verification against a dummy hash, so response time doesn't
reveal which case occurred. After 5 consecutive failures the account locks for 15 min (counter resets on success).
*Trade-off:* lockout lets an attacker deliberately lock a victim out; mitigated by the per-IP login limiter and the
short, auto-expiring lock. Registration still reveals "username taken" (409) — unavoidable without email verification;
it is rate-limited.

**D4 — Authorization: deny by default, enforced server-side in two layers.**
*Function level:* every route except `/healthz`, `/auth/register`, `/auth/login` depends on `current_user`;
admin routes additionally depend on `require_admin`. *Object level:* every note query includes
`AND owner_id = <caller>` **in the SQL itself**, so there is no code path that fetches a foreign row and "forgets"
to check. Foreign and nonexistent notes both return the same 404 (no existence oracle). Note IDs are random UUIDv4
(non-enumerable), a second line of defence — not the primary one.

**D5 — Role and status come from the database on every request, never from the token.**
Disabling a user or demoting an admin takes effect on the next request even though their token is still
cryptographically valid. *Cost:* one indexed SELECT per request. Admin accounts can't be created over the API
(no role field is accepted — it's rejected, not ignored), only via `python -m app.cli create-admin`.

**D6 — Input validation: allow-list at the edge, strict schemas.**
Pydantic models with `extra="forbid"` (blocks mass assignment), explicit min/max lengths on every string,
ASCII allow-list regex for usernames (blocks Unicode look-alikes; Pydantic's regex engine is linear-time, so no
ReDoS), control-character rejection, UUID-typed path params, bounded `limit/offset`. Wrong `Content-Type` fails
validation. SQL injection is prevented by **parameterised queries everywhere** (validation is defence-in-depth,
and note text is deliberately allowed to contain quotes/SQL — the tests prove it's stored inertly).
Output is `application/json` + `nosniff` + CSP `default-src 'none'`; HTML-escaping is the *client's* job and the API
never renders HTML.

**D7 — Resource limits.** 16 KiB body cap enforced twice: on the declared `Content-Length` (fast reject) and on bytes
actually streamed (catches chunked/lying clients). Max 200 notes/user, enforced by a single atomic
`INSERT … SELECT … WHERE count < N` (no check-then-insert race).

**D8 — Rate limiting: three independent sliding-window tiers.**

| Tier | Key | Default | Protects |
|---|---|---|---|
| global | client IP | 300 / 60 s | anything unauthenticated, 404 scanning |
| auth | client IP | 10 / 60 s | login brute force, registration spam |
| user | user ID | 60 / 60 s | abusive or compromised accounts |

Rejected requests aren't counted (so a blocked client isn't punished forever), 429 includes `Retry-After`, limiter
memory is bounded (100k keys). **Client IP:** `X-Forwarded-For` is *ignored* by default because it's attacker-controlled
(test AC-41). Behind *N* trusted proxies set `NOTES_TRUSTED_PROXY_HOPS=N`; we then take the N-th entry from the
**right** (the one our own proxy appended), never the leftmost (test AC-42).
*Trade-off:* in-memory state is per-process; with multiple workers/instances use Redis (the `hit()` interface is the seam).

**D9 — Secure error handling.** One global handler per class: HTTP errors, validation errors, and *unhandled
exceptions* all return the same JSON envelope. 500s say only "Internal server error" + request ID; the traceback goes
to server logs. Validation errors report field + rule but **never echo the submitted value** (it may be a password).
Security headers (`nosniff`, `no-store`, CSP, `X-Frame-Options`, HSTS, `Referrer-Policy`) are added by middleware to
every response, including errors. `/docs` and `/openapi.json` are off unless explicitly enabled.

**D10 — Audit logging.** Security events (`login_ok/failed`, `token_rejected`, `authz_denied`, `rate_limited`,
`user_disabled`, `register`, `logout`) are logged with user ID, IP and request ID. Passwords, tokens and hashes are never
logged; attacker-controlled values (e.g. attempted usernames) are `repr()`-quoted and truncated to prevent log injection.

**D11 — Fail closed on misconfiguration.** Missing/short `NOTES_JWT_SECRET` → process exits at startup.

---

## 4. Abuse-case tests (`python -m pytest -q` → 69 passed)

| ID | Attacker goal | Verified behaviour |
|---|---|---|
| AC-01/02 | call API unauthenticated / with malformed header | 401 + `WWW-Authenticate` |
| AC-03/04 | forge token: `alg:none`, wrong key, expired, wrong `aud`/`iss` | 401 (control case proves forge helper produces valid tokens) |
| AC-05 | reuse token after logout | 401 |
| AC-06 | brute-force password; enumerate accounts | lock after 5; identical response for locked/unknown/wrong; lock expiry; counter reset |
| AC-07 | steal plaintext passwords from DB | scrypt hashes, unique salts |
| AC-10/11 | IDOR: read/modify/delete another user's note; probe existence | 404 for all; same body as "doesn't exist"; data untouched |
| AC-12 | normal user hits admin endpoints | 403 (401 if anonymous) |
| AC-13/14 | mass assignment; role claim in token | `role`/`owner_id` fields → 422; token role ignored |
| AC-15/16 | disabled user keeps using live token; admin locks self out | token dies immediately; self-disable → 409 |
| AC-20…25 | SQLi, path traversal, Unicode usernames, control chars, wrong types, 10 000-char password, weak passwords | rejected 422 or stored inertly; tables intact |
| AC-26/27 | memory exhaustion with huge body (declared and chunked) | 413 |
| AC-28…30 | wrong content-type, broken JSON, absurd pagination, non-UUID IDs | 422/404 |
| AC-31 | fill the database | quota 403, per-user |
| AC-40…45 | login flood, XFF spoofing, per-user flood, unauthenticated flood, registration spam | 429 + `Retry-After`; spoofed header ignored; trusted-proxy mode keyed correctly |
| AC-50…52 | trigger error to learn internals; echo secrets via validation | generic 500, no secret/traceback; no input echo; uniform 404/405 |
| AC-53…57 | missing headers, exposed docs, CORS, weak secret, case-variant duplicate usernames | headers on every response; docs 404; no CORS; refuses to boot; 409 |

---

## 5. Known limitations / production hardening checklist

- **TLS:** terminate HTTPS at a proxy; HSTS is sent but only meaningful over TLS.
- **Multi-instance:** move rate limiter + revocation list to Redis; swap SQLite for Postgres.
- **Secrets:** load `NOTES_JWT_SECRET` from a secret manager; support key rotation (`kid`) — currently rotation logs everyone out.
- **Refresh tokens, MFA, email verification, password reset** are not implemented.
- **Breached-password check** and a larger denylist should replace the demo list in `schemas.py`.
- **Audit logs** go to the standard logger; ship to a tamper-resistant sink and alert on `login_failed`/`rate_limited` spikes.
- **Dependency hygiene:** pin versions, run `pip-audit`/Dependabot in CI.
- **Rate limiting at the edge** (WAF/CDN) should complement, not replace, the in-app limits.

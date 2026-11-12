"""Abuse-case tests. Each test = one attacker goal. IDs (AC-nn) map to README table."""
import sqlite3

import jwt
import pytest

from .conftest import JSON, PW, SECRET


def note(c, h, title="t", body="b"):
    r = c.post("/notes", json={"title": title, "body": body}, headers=h)
    assert r.status_code == 201, r.text
    return r.json()["id"]


# ---------- happy path (so security tests aren't passing vacuously) ----------
def test_happy_path(ctx):
    _, h = ctx.signup("alice")
    nid = note(ctx.client, h, "hello", "world")
    assert ctx.client.get(f"/notes/{nid}", headers=h).json()["title"] == "hello"
    assert ctx.client.put(f"/notes/{nid}", json={"title": "x", "body": ""}, headers=h).json()["title"] == "x"
    assert ctx.client.delete(f"/notes/{nid}", headers=h).status_code == 204
    assert ctx.client.get(f"/notes/{nid}", headers=h).status_code == 404


# ---------- AC-01..07 authentication ----------
def test_ac01_no_token_rejected(ctx):
    r = ctx.client.get("/notes")
    assert r.status_code == 401 and r.headers["www-authenticate"] == "Bearer"


@pytest.mark.parametrize("hdr", ["Bearer", "Bearer garbage", "Basic YWxpY2U6cHc=", "Bearer " + "a" * 5000])
def test_ac02_malformed_credentials_rejected(ctx, hdr):
    assert ctx.client.get("/notes", headers={"Authorization": hdr}).status_code == 401


def test_ac03_alg_none_forgery_rejected(ctx):
    uid, _ = ctx.signup("alice")
    assert ctx.client.get("/notes", headers=ctx.forge(secret="", alg="none", sub=uid)).status_code == 401


def test_ac04_wrong_secret_expired_wrong_aud_rejected(ctx):
    uid, good = ctx.signup("alice")
    assert ctx.client.get("/notes", headers=ctx.forge(sub=uid)).status_code == 200        # control: forge helper works
    assert ctx.client.get("/notes", headers=ctx.forge(secret="y" * 48, sub=uid)).status_code == 401
    assert ctx.client.get("/notes", headers=ctx.forge(sub=uid, exp=1)).status_code == 401
    assert ctx.client.get("/notes", headers=ctx.forge(sub=uid, aud="other-service")).status_code == 401
    assert ctx.client.get("/notes", headers=ctx.forge(sub=uid, iss="evil")).status_code == 401


def test_ac05_logout_revokes_token(ctx):
    _, h = ctx.signup("alice")
    assert ctx.client.post("/auth/logout", headers=h).status_code == 204
    assert ctx.client.get("/notes", headers=h).status_code == 401


def test_ac06_brute_force_lockout_and_no_enumeration(ctx):
    ctx.signup("alice")
    for _ in range(5):
        assert ctx.client.post("/auth/login", json={"username": "alice", "password": "wrong-pw"}).status_code == 401
    locked = ctx.client.post("/auth/login", json={"username": "alice", "password": PW})   # correct pw, still refused
    unknown = ctx.client.post("/auth/login", json={"username": "nobody", "password": PW})
    wrong = ctx.client.post("/auth/login", json={"username": "alice", "password": "nope"})
    assert locked.status_code == unknown.status_code == wrong.status_code == 401
    assert locked.json()["error"]["message"] == unknown.json()["error"]["message"] == wrong.json()["error"]["message"]


def test_ac06b_lockout_expires_and_success_resets_counter(ctx):
    ctx.signup("alice")
    for _ in range(3):
        ctx.client.post("/auth/login", json={"username": "alice", "password": "bad"})
    ctx.login("alice")                                    # success resets counter
    for _ in range(4):
        ctx.client.post("/auth/login", json={"username": "alice", "password": "bad"})
    ctx.login("alice")                                    # 4 < threshold: still allowed
    for _ in range(5):
        ctx.client.post("/auth/login", json={"username": "alice", "password": "bad"})
    with sqlite3.connect(ctx.settings.db_path) as db:     # simulate lock window passing
        db.execute("UPDATE users SET locked_until=0")
    ctx.login("alice")


def test_ac07_passwords_stored_hashed_and_salted(ctx):
    ctx.signup("alice"); ctx.signup("bob")
    with sqlite3.connect(ctx.settings.db_path) as db:
        hashes = [r[0] for r in db.execute("SELECT password_hash FROM users")]
    assert all(h.startswith("scrypt$") and PW not in h for h in hashes)
    assert len(set(hashes)) == 2                          # same password -> different salts


# ---------- AC-10..16 authorisation ----------
def test_ac10_idor_cannot_read_update_delete_others_notes(ctx):
    _, a = ctx.signup("alice"); _, b = ctx.signup("bobby")
    nid = note(ctx.client, a, "secret")
    c = ctx.client
    assert c.get(f"/notes/{nid}", headers=b).status_code == 404
    assert c.put(f"/notes/{nid}", json={"title": "pwn", "body": ""}, headers=b).status_code == 404
    assert c.delete(f"/notes/{nid}", headers=b).status_code == 404
    assert c.get("/notes", headers=b).json() == []
    assert c.get(f"/notes/{nid}", headers=a).json()["title"] == "secret"     # untouched


def test_ac11_not_found_and_forbidden_indistinguishable(ctx):
    _, a = ctx.signup("alice"); _, b = ctx.signup("bobby")
    nid = note(ctx.client, a)
    other = ctx.client.get(f"/notes/{nid}", headers=b)
    missing = ctx.client.get("/notes/11111111-1111-4111-8111-111111111111", headers=b)
    assert other.status_code == missing.status_code == 404
    assert other.json()["error"]["message"] == missing.json()["error"]["message"]


def test_ac12_non_admin_cannot_reach_admin_routes(ctx):
    uid, h = ctx.signup("alice")
    assert ctx.client.get("/admin/users", headers=h).status_code == 403
    assert ctx.client.post(f"/admin/users/{uid}/disable", headers=h).status_code == 403
    assert ctx.client.get("/admin/users").status_code == 401


def test_ac13_mass_assignment_role_escalation_blocked(ctx):
    r = ctx.client.post("/auth/register", json={"username": "mallory", "password": PW, "role": "admin"})
    assert r.status_code == 422
    r = ctx.client.post("/auth/register", json={"username": "mallory", "password": PW})
    assert r.json()["role"] == "user"
    h = ctx.login("mallory")
    nid = note(ctx.client, h)
    r = ctx.client.put(f"/notes/{nid}", json={"title": "x", "body": "", "owner_id": "someone-else"}, headers=h)
    assert r.status_code == 422


def test_ac14_role_comes_from_db_not_token(ctx):
    uid, _ = ctx.signup("alice")
    # attacker forges a validly-signed token (e.g. leaked secret scenario) claiming admin: role claim is ignored
    assert ctx.client.get("/admin/users", headers=ctx.forge(sub=uid, role="admin")).status_code == 403


def test_ac15_disabled_user_loses_access_immediately(ctx):
    uid, h = ctx.signup("alice")
    admin = ctx.make_admin()
    users = ctx.client.get("/admin/users", headers=admin).json()
    assert {u["username"] for u in users} == {"alice", "root"} and "password_hash" not in users[0]
    assert ctx.client.post(f"/admin/users/{uid}/disable", headers=admin).status_code == 204
    assert ctx.client.get("/notes", headers=h).status_code == 401                 # live token dies
    assert ctx.client.post("/auth/login", json={"username": "alice", "password": PW}).status_code == 401


def test_ac16_admin_cannot_disable_self(ctx):
    admin = ctx.make_admin()
    me = [u for u in ctx.client.get("/admin/users", headers=admin).json() if u["username"] == "root"][0]
    assert ctx.client.post(f"/admin/users/{me['id']}/disable", headers=admin).status_code == 409


# ---------- AC-20..31 input validation ----------
@pytest.mark.parametrize("name", ["admin' OR '1'='1", "a b", "ab", "x" * 33, "ünïcode", "../etc", "<script>"])
def test_ac20_bad_usernames_rejected_at_register(ctx, name):
    assert ctx.client.post("/auth/register", json={"username": name, "password": PW}).status_code == 422


def test_ac21_sql_injection_is_inert(ctx):
    _, h = ctx.signup("alice")
    for payload in [{"username": "alice' OR '1'='1", "password": "x"}, {"username": "alice", "password": "' OR '1'='1"}]:
        assert ctx.client.post("/auth/login", json=payload).status_code == 401
    evil = "x'); DROP TABLE notes;--"
    nid = note(ctx.client, h, evil, evil)
    assert ctx.client.get(f"/notes/{nid}", headers=h).json()["title"] == evil     # stored literally
    assert ctx.client.get("/notes", headers=h).status_code == 200                  # table still exists


def test_ac22_extra_fields_rejected(ctx):
    _, h = ctx.signup("alice")
    assert ctx.client.post("/notes", json={"title": "t", "body": "", "is_admin": True}, headers=h).status_code == 422


@pytest.mark.parametrize("body", [{"title": ""}, {"title": "   "}, {"title": "a" * 121}, {"title": "a\nb"},
                                  {"title": "ok", "body": "a" * 4001}, {"title": "ok", "body": "nul\x00byte"},
                                  {"title": 123}, {"title": ["x"]}, {"title": None}, {}])
def test_ac23_note_field_validation(ctx, body):
    _, h = ctx.signup("alice")
    assert ctx.client.post("/notes", json=body, headers=h).status_code == 422


def test_ac24_oversized_password_rejected_before_hashing(ctx):
    r = ctx.client.post("/auth/register", json={"username": "alice", "password": "A" * 10_000})
    assert r.status_code == 422                       # max_length=128; scrypt never ran on 10k chars


def test_ac25_weak_password_rejected(ctx):
    for pw in ["short", "password1234", "alice-alice-alice"]:
        assert ctx.client.post("/auth/register", json={"username": "alice", "password": pw}).status_code == 422


def test_ac26_body_size_limit_content_length(ctx):
    _, h = ctx.signup("alice")
    r = ctx.client.post("/notes", content=b"x" * 20_000, headers={**h, **JSON})
    assert r.status_code == 413


def test_ac27_body_size_limit_chunked_stream(ctx):
    _, h = ctx.signup("alice")

    def gen():                                        # no Content-Length -> only streaming enforcement catches it
        yield b'{"title":"'
        for _ in range(10):
            yield b"a" * 4000
        yield b'","body":""}'
    r = ctx.client.post("/notes", content=gen(), headers={**h, **JSON})
    assert r.status_code == 413


def test_ac28_invalid_content_type_and_malformed_json(ctx):
    _, h = ctx.signup("alice")
    assert ctx.client.post("/notes", content='{"title":"t"}', headers={**h, "Content-Type": "text/plain"}).status_code == 422
    assert ctx.client.post("/notes", content="{not json", headers={**h, **JSON}).status_code == 422


@pytest.mark.parametrize("q", ["limit=100000", "limit=0", "limit=-1", "offset=-5", "offset=99999999", "limit=abc"])
def test_ac29_pagination_bounds(ctx, q):
    _, h = ctx.signup("alice")
    assert ctx.client.get(f"/notes?{q}", headers=h).status_code == 422


@pytest.mark.parametrize("nid", ["1", "../../etc/passwd", "1 OR 1=1", "%27%20OR%201%3D1", "null"])
def test_ac30_path_param_must_be_uuid(ctx, nid):
    _, h = ctx.signup("alice")
    assert ctx.client.get(f"/notes/{nid}", headers=h).status_code in (404, 422)
    assert ctx.client.get(f"/notes/{nid}", headers=h).status_code != 200


def test_ac31_note_quota(make):
    ctx = make(max_notes_per_user=3)
    _, h = ctx.signup("alice"); _, b = ctx.signup("bobby")
    for _ in range(3):
        note(ctx.client, h)
    assert ctx.client.post("/notes", json={"title": "4th", "body": ""}, headers=h).status_code == 403
    note(ctx.client, b)                               # quota is per-user, not global


# ---------- AC-40..45 rate limiting ----------
def test_ac40_login_rate_limited_per_ip(make):
    ctx = make(auth_ip_limit=(3, 60))
    for _ in range(3):
        assert ctx.client.post("/auth/login", json={"username": "a", "password": "b"}).status_code == 401
    r = ctx.client.post("/auth/login", json={"username": "a", "password": "b"})
    assert r.status_code == 429 and int(r.headers["retry-after"]) >= 1


def test_ac41_x_forwarded_for_spoofing_does_not_bypass(make):
    ctx = make(auth_ip_limit=(2, 60))                 # trusted_proxy_hops=0 -> header ignored
    codes = [ctx.client.post("/auth/login", json={"username": "a", "password": "b"},
                             headers={"X-Forwarded-For": f"9.9.9.{i}"}).status_code for i in range(4)]
    assert codes == [401, 401, 429, 429]


def test_ac42_behind_trusted_proxy_uses_proxy_appended_ip(make):
    ctx = make(auth_ip_limit=(2, 60), trusted_proxy_hops=1)
    post = lambda xff: ctx.client.post("/auth/login", json={"username": "a", "password": "b"},
                                       headers={"X-Forwarded-For": xff}).status_code
    assert [post("spoof1, 10.0.0.1"), post("spoof2, 10.0.0.1"), post("spoof3, 10.0.0.1")] == [401, 401, 429]
    assert post("spoof1, 10.0.0.2") == 401            # different real client -> its own bucket


def test_ac43_per_user_limit_on_api(make):
    ctx = make(user_limit=(5, 60))
    _, h = ctx.signup("alice"); _, b = ctx.signup("bobby")
    assert [ctx.client.get("/notes", headers=h).status_code for _ in range(6)] == [200] * 5 + [429]
    assert ctx.client.get("/notes", headers=b).status_code == 200      # other users unaffected


def test_ac44_global_ip_limit_covers_unauthenticated_flood(make):
    ctx = make(global_ip_limit=(5, 60))
    assert [ctx.client.get("/healthz").status_code for _ in range(6)] == [200] * 5 + [429]


def test_ac45_register_flood_limited(make):
    ctx = make(auth_ip_limit=(3, 60))
    codes = [ctx.client.post("/auth/register", json={"username": f"user{i}", "password": PW}).status_code
             for i in range(5)]
    assert codes == [201, 201, 201, 429, 429]


# ---------- AC-50..56 secure error handling & hardening ----------
def test_ac50_unhandled_exception_leaks_nothing(ctx):
    @ctx.app.get("/boom")
    def boom():
        raise RuntimeError("db password=hunter2 at /srv/app/secret.py")
    r = ctx.client.get("/boom")
    assert r.status_code == 500
    assert "hunter2" not in r.text and "secret.py" not in r.text and "Traceback" not in r.text
    assert r.json()["error"]["message"] == "Internal server error" and r.json()["error"]["request_id"]
    assert r.headers["x-content-type-options"] == "nosniff"


def test_ac51_validation_errors_do_not_echo_input(ctx):
    r = ctx.client.post("/auth/register", json={"username": "alice", "password": "Sup3r-sec"})   # too short
    assert r.status_code == 422
    assert "Sup3r-sec" not in r.text


def test_ac52_uniform_json_errors_for_404_405(ctx):
    r404, r405 = ctx.client.get("/nope"), ctx.client.delete("/auth/login")
    assert r404.status_code == 404 and r405.status_code == 405
    assert r404.json()["error"]["code"] == "not_found" and "x-request-id" in r404.headers


def test_ac53_security_headers_everywhere(ctx):
    for r in [ctx.client.get("/healthz"), ctx.client.get("/notes"), ctx.client.get("/nope")]:
        assert r.headers["x-content-type-options"] == "nosniff"
        assert r.headers["cache-control"] == "no-store"
        assert "frame-ancestors 'none'" in r.headers["content-security-policy"]
        assert "strict-transport-security" in r.headers


def test_ac54_docs_and_openapi_hidden_by_default(ctx, make):
    assert ctx.client.get("/docs").status_code == 404 and ctx.client.get("/openapi.json").status_code == 404
    assert make(enable_docs=True).client.get("/openapi.json").status_code == 200


def test_ac55_no_cors_headers_for_foreign_origin(ctx):
    r = ctx.client.get("/healthz", headers={"Origin": "https://evil.example"})
    assert "access-control-allow-origin" not in r.headers


def test_ac56_refuses_to_start_with_weak_secret(tmp_path):
    from app.config import Settings
    with pytest.raises(ValueError):
        Settings(jwt_secret="short", db_path=str(tmp_path / "x.db"))
    with pytest.raises(ValueError):
        Settings.from_env()                            # unset env var -> empty secret -> refuse


def test_ac57_duplicate_username_case_insensitive(ctx):
    ctx.signup("Alice")
    assert ctx.client.post("/auth/register", json={"username": "alice", "password": PW}).status_code == 409
    assert ctx.client.post("/auth/register", json={"username": "ALICE", "password": PW}).status_code == 409

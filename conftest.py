import time

import jwt
import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.db import insert_user
from app.main import create_app
from app.security import hash_password

SECRET = "x" * 48
PW = "correct horse battery staple"
JSON = {"Content-Type": "application/json"}


class Ctx:
    def __init__(self, tmp_path, **overrides):
        base = dict(jwt_secret=SECRET, db_path=str(tmp_path / "t.db"),
                    global_ip_limit=(10_000, 60), auth_ip_limit=(10_000, 60), user_limit=(10_000, 60))
        base.update(overrides)
        self.settings = Settings(**base)
        self.app = create_app(self.settings)
        self.client = TestClient(self.app, raise_server_exceptions=False)

    def signup(self, name, pw=PW):
        r = self.client.post("/auth/register", json={"username": name, "password": pw})
        assert r.status_code == 201, r.text
        return r.json()["id"], self.login(name, pw)

    def login(self, name, pw=PW):
        r = self.client.post("/auth/login", json={"username": name, "password": pw})
        assert r.status_code == 200, r.text
        return {"Authorization": f"Bearer {r.json()['access_token']}"}

    def make_admin(self, name="root", pw=PW):
        insert_user(self.settings.db_path, name, hash_password(pw), role="admin")
        return self.login(name, pw)

    def forge(self, secret=SECRET, alg="HS256", **over):
        now = int(time.time())
        claims = {"sub": "x", "jti": "j1", "iat": now, "exp": now + 600,
                  "iss": self.settings.jwt_issuer, "aud": self.settings.jwt_audience}
        claims.update(over)
        return {"Authorization": "Bearer " + jwt.encode(claims, secret, algorithm=alg)}


@pytest.fixture
def make(tmp_path):
    return lambda **kw: Ctx(tmp_path, **kw)


@pytest.fixture
def ctx(make):
    return make()

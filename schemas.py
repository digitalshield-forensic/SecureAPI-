"""Request/response models. Strict: unknown fields rejected, every string length-bounded."""
import re

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

USERNAME_RE = r"^[A-Za-z0-9_.-]{3,32}$"
_CTRL_BODY = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")   # allows \t \n \r
_CTRL_ALL = re.compile(r"[\x00-\x1f\x7f]")
_COMMON = {"password1234", "123456789012", "qwertyuiop12", "letmein12345", "administrator"}


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class RegisterIn(Strict):
    username: str = Field(pattern=USERNAME_RE)
    password: str = Field(min_length=12, max_length=128)  # max stops hash-DoS via huge passwords

    @model_validator(mode="after")
    def _strength(self):
        low = self.password.lower()
        if low in _COMMON or self.username.lower() in low:
            raise ValueError("password is too weak")
        return self


class LoginIn(Strict):
    username: str = Field(min_length=1, max_length=32)
    password: str = Field(min_length=1, max_length=128)


class NoteIn(Strict):
    title: str = Field(min_length=1, max_length=120)
    body: str = Field(default="", max_length=4000)

    @field_validator("title")
    @classmethod
    def _title(cls, v: str) -> str:
        v = v.strip()
        if not v or _CTRL_ALL.search(v):
            raise ValueError("title must be non-empty and contain no control characters")
        return v

    @field_validator("body")
    @classmethod
    def _body(cls, v: str) -> str:
        if _CTRL_BODY.search(v):
            raise ValueError("body contains control characters")
        return v


class UserOut(BaseModel):
    id: str
    username: str
    role: str


class AdminUserOut(UserOut):
    is_active: bool
    created_at: float


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


class NoteOut(BaseModel):
    id: str
    title: str
    body: str
    created_at: float
    updated_at: float

from __future__ import annotations
import hashlib, secrets, uuid
from datetime import datetime, timedelta, timezone
from typing import Any
from jose import jwt
from ..config import settings


def create_access_token(user_id: uuid.UUID, email: str, status: str,
                        extra_claims: dict[str, Any] | None = None,
                        expires_delta: timedelta | None = None) -> tuple[str, int]:
    expire_minutes = (expires_delta.total_seconds() / 60 if expires_delta
                      else settings.access_token_expire_minutes)
    expire = datetime.now(timezone.utc) + timedelta(minutes=expire_minutes)
    now = datetime.now(timezone.utc)
    payload: dict[str, Any] = {
        "sub": str(user_id), "email": email, "status": status,
        "iat": int(now.timestamp()), "exp": int(expire.timestamp()), "type": "access",
    }
    if extra_claims:
        payload.update(extra_claims)
    token = jwt.encode(payload, settings.secret_key, algorithm=settings.algorithm)
    return token, int(timedelta(minutes=expire_minutes).total_seconds())


def decode_access_token(token: str) -> dict[str, Any]:
    return jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])


def generate_refresh_token() -> tuple[str, str]:
    raw = secrets.token_urlsafe(48)
    return raw, hashlib.sha256(raw.encode()).hexdigest()


def hash_token(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def create_email_token(email: str, token_type: str, expires_hours: int = 24) -> str:
    expire = datetime.now(timezone.utc) + timedelta(hours=expires_hours)
    payload = {"sub": email, "type": token_type,
               "exp": int(expire.timestamp()), "iat": int(datetime.now(timezone.utc).timestamp())}
    return jwt.encode(payload, settings.secret_key, algorithm=settings.algorithm)


def decode_email_token(token: str, expected_type: str) -> str:
    payload = jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])
    if payload.get("type") != expected_type:
        raise ValueError(f"Expected token type '{expected_type}'")
    return payload["sub"]


def generate_auth_code() -> str:
    return secrets.token_urlsafe(32)

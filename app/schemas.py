from __future__ import annotations
import uuid
from datetime import datetime
from pydantic import BaseModel, EmailStr, field_validator


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str
    display_name: str = ""

    @field_validator("password")
    @classmethod
    def password_strength(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters")
        return v


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class UserOut(BaseModel):
    id: uuid.UUID
    email: str
    display_name: str | None
    status: str
    email_verified: bool
    created_at: datetime
    model_config = {"from_attributes": True}


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    refresh_token: str | None = None
    scope: str = "openid"


class ClientCreate(BaseModel):
    client_id: str
    client_secret: str
    name: str
    redirect_uris: list[str] = []
    scopes: list[str] = ["openid", "profile", "email"]


class ClientOut(BaseModel):
    client_id: str
    name: str
    redirect_uris: list[str]
    scopes: list[str]
    model_config = {"from_attributes": True}


class IntrospectResponse(BaseModel):
    active: bool
    sub: str | None = None
    email: str | None = None
    status: str | None = None
    scope: str | None = None
    exp: int | None = None
    client_id: str | None = None

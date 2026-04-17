from __future__ import annotations
import enum, uuid
from datetime import datetime, timezone
from sqlalchemy import JSON, Boolean, DateTime, Enum, ForeignKey, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from .database import Base


class UserStatus(str, enum.Enum):
    pending = "pending"
    approved = "approved"
    suspended = "suspended"
    admin = "admin"


class ApprovalStatus(str, enum.Enum):
    pending = "pending"
    approved = "approved"
    rejected = "rejected"


class User(Base):
    __tablename__ = "users"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email: Mapped[str] = mapped_column(String, unique=True, nullable=False, index=True)
    password_hash: Mapped[str | None] = mapped_column(String)
    display_name: Mapped[str | None] = mapped_column(String)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    status: Mapped[UserStatus] = mapped_column(Enum(UserStatus, create_type=False), default=UserStatus.pending, nullable=False)
    email_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    refresh_tokens: Mapped[list[RefreshToken]] = relationship("RefreshToken", back_populates="user", cascade="all, delete-orphan")
    app_approvals: Mapped[list[AppApproval]] = relationship("AppApproval", foreign_keys="AppApproval.user_id", back_populates="user", cascade="all, delete-orphan")


class AppApproval(Base):
    __tablename__ = "app_approvals"
    user_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), primary_key=True)
    app_id: Mapped[str] = mapped_column(String, primary_key=True)
    status: Mapped[ApprovalStatus] = mapped_column(Enum(ApprovalStatus, create_type=False), default=ApprovalStatus.pending, nullable=False)
    requested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    reviewed_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    user: Mapped[User] = relationship("User", foreign_keys=[user_id], back_populates="app_approvals")


class OAuthClient(Base):
    __tablename__ = "oauth_clients"
    client_id: Mapped[str] = mapped_column(String, primary_key=True)
    client_secret: Mapped[str] = mapped_column(String, nullable=False)
    name: Mapped[str] = mapped_column(String, nullable=False)
    redirect_uris: Mapped[list[str]] = mapped_column(JSON, default=list)
    scopes: Mapped[list[str]] = mapped_column(JSON, default=list)


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"
    token_hash: Mapped[str] = mapped_column(String, primary_key=True)
    user_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False, index=True)
    client_id: Mapped[str | None] = mapped_column(String)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    user: Mapped[User] = relationship("User", back_populates="refresh_tokens")


class AuthCode(Base):
    __tablename__ = "auth_codes"
    code: Mapped[str] = mapped_column(String, primary_key=True)
    user_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    client_id: Mapped[str] = mapped_column(String, nullable=False)
    redirect_uri: Mapped[str] = mapped_column(String, nullable=False)
    scope: Mapped[str] = mapped_column(String, default="openid")
    code_challenge: Mapped[str | None] = mapped_column(String)
    code_challenge_method: Mapped[str | None] = mapped_column(String)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    used: Mapped[bool] = mapped_column(Boolean, default=False)

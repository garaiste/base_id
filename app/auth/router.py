from __future__ import annotations
import logging
from datetime import datetime, timedelta, timezone
from typing import Annotated
from fastapi import APIRouter, Depends, Form, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from jose import JWTError
from passlib.context import CryptContext
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from ..auth.email import send_password_reset_email, send_verification_email
from ..auth.tokens import (create_access_token, create_email_token,
                           decode_email_token, generate_refresh_token, hash_token)
from ..config import settings
from ..database import get_db
from ..deps import get_current_user, get_optional_user
from ..models import RefreshToken, User, UserStatus

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/auth", tags=["auth"])
templates = Jinja2Templates(directory="app/templates")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def _set_auth_cookie(response: Response, token: str, expires_in: int) -> None:
    response.set_cookie(key="access_token", value=token, httponly=True, samesite="lax",
                        secure=settings.base_url.startswith("https"), max_age=expires_in, path="/")


def _clear_auth_cookie(response: Response) -> None:
    response.delete_cookie("access_token", path="/")


async def _issue_tokens(user: User, db: AsyncSession, client_id: str | None = None) -> tuple[str, str, int]:
    access, expires_in = create_access_token(user_id=user.id, email=user.email, status=user.status.value)
    raw_refresh, refresh_hash = generate_refresh_token()
    rt = RefreshToken(token_hash=refresh_hash, user_id=user.id, client_id=client_id,
                      expires_at=datetime.now(timezone.utc) + timedelta(days=settings.refresh_token_expire_days))
    db.add(rt)
    return access, raw_refresh, expires_in


@router.get("/register", response_class=HTMLResponse)
async def register_page(request: Request):
    return templates.TemplateResponse(request, "register.html")


@router.post("/register", response_class=HTMLResponse)
async def register(request: Request, db: Annotated[AsyncSession, Depends(get_db)],
                   email: str = Form(...), password: str = Form(...), display_name: str = Form("")):
    error = None
    if len(password) < 8:
        error = "Password must be at least 8 characters."
    elif not email or "@" not in email:
        error = "Please enter a valid email address."
    if error:
        return templates.TemplateResponse(request, "register.html", {"error": error}, status_code=400)

    existing = await db.execute(select(User).where(User.email == email.lower()))
    if existing.scalar_one_or_none():
        return templates.TemplateResponse(request, "register.html",
            {"error": "An account with that email already exists."}, status_code=400)

    initial_status = UserStatus.pending
    if settings.admin_email and email.lower() == settings.admin_email.lower():
        initial_status = UserStatus.admin

    user = User(email=email.lower(), password_hash=pwd_context.hash(password),
                display_name=display_name.strip() or None, status=initial_status)
    db.add(user)
    await db.flush()

    try:
        token = create_email_token(user.email, "email_verify")
        await send_verification_email(user.email, token)
    except Exception:
        logger.exception("Failed to send verification email to %s", user.email)

    return templates.TemplateResponse(request, "verify_sent.html", {"email": email})


@router.get("/verify-email", response_class=HTMLResponse)
async def verify_email(request: Request, token: str, db: Annotated[AsyncSession, Depends(get_db)]):
    try:
        email = decode_email_token(token, "email_verify")
    except (JWTError, ValueError, KeyError):
        return templates.TemplateResponse(request, "verify_done.html",
            {"success": False, "error": "This verification link is invalid or has expired."})
    result = await db.execute(select(User).where(User.email == email))
    user = result.scalar_one_or_none()
    if not user:
        return templates.TemplateResponse(request, "verify_done.html",
            {"success": False, "error": "Account not found."})
    user.email_verified = True
    return templates.TemplateResponse(request, "verify_done.html", {"success": True})


@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, next: str = ""):
    return templates.TemplateResponse(request, "login.html", {"next": next})


@router.post("/login")
async def login(request: Request, db: Annotated[AsyncSession, Depends(get_db)],
                email: str = Form(...), password: str = Form(...), next: str = Form("")):
    result = await db.execute(select(User).where(User.email == email.lower()))
    user = result.scalar_one_or_none()

    def _bad():
        return templates.TemplateResponse(request, "login.html",
            {"error": "Invalid email or password.", "next": next}, status_code=400)

    if not user or not user.password_hash or not pwd_context.verify(password, user.password_hash):
        return _bad()
    if not user.email_verified:
        return templates.TemplateResponse(request, "login.html",
            {"error": "Please verify your email address before logging in.", "next": next}, status_code=400)

    access, _refresh, expires_in = await _issue_tokens(user, db)
    response = RedirectResponse(url=next or "/auth/dashboard", status_code=302)
    _set_auth_cookie(response, access, expires_in)
    return response


@router.get("/logout")
async def logout():
    response = RedirectResponse(url="/auth/login", status_code=302)
    _clear_auth_cookie(response)
    return response


@router.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request, current_user: Annotated[User, Depends(get_current_user)],
                    db: Annotated[AsyncSession, Depends(get_db)]):
    return templates.TemplateResponse(request, "dashboard.html",
        {"user": current_user, "app_approvals": current_user.app_approvals})


@router.get("/forgot-password", response_class=HTMLResponse)
async def forgot_password_page(request: Request):
    return templates.TemplateResponse(request, "forgot_password.html")


@router.post("/forgot-password", response_class=HTMLResponse)
async def forgot_password(request: Request, db: Annotated[AsyncSession, Depends(get_db)], email: str = Form(...)):
    result = await db.execute(select(User).where(User.email == email.lower()))
    user = result.scalar_one_or_none()
    if user and user.email_verified:
        try:
            token = create_email_token(user.email, "password_reset", expires_hours=1)
            await send_password_reset_email(user.email, token)
        except Exception:
            logger.exception("Failed to send password reset email")
    return templates.TemplateResponse(request, "forgot_password.html", {"sent": True})


@router.get("/reset-password", response_class=HTMLResponse)
async def reset_password_page(request: Request, token: str = ""):
    return templates.TemplateResponse(request, "reset_password.html", {"token": token})


@router.post("/reset-password", response_class=HTMLResponse)
async def reset_password(request: Request, db: Annotated[AsyncSession, Depends(get_db)],
                         token: str = Form(...), new_password: str = Form(...)):
    if len(new_password) < 8:
        return templates.TemplateResponse(request, "reset_password.html",
            {"token": token, "error": "Password must be at least 8 characters."}, status_code=400)
    try:
        email = decode_email_token(token, "password_reset")
    except (JWTError, ValueError, KeyError):
        return templates.TemplateResponse(request, "reset_password.html",
            {"token": "", "error": "This reset link is invalid or has expired."}, status_code=400)
    result = await db.execute(select(User).where(User.email == email))
    user = result.scalar_one_or_none()
    if not user:
        return templates.TemplateResponse(request, "reset_password.html",
            {"token": "", "error": "Account not found."}, status_code=400)
    user.password_hash = pwd_context.hash(new_password)
    tokens = await db.execute(select(RefreshToken).where(RefreshToken.user_id == user.id, RefreshToken.revoked.is_(False)))
    for rt in tokens.scalars():
        rt.revoked = True
    return templates.TemplateResponse(request, "reset_password.html", {"token": "", "done": True})


@router.post("/token/refresh")
async def refresh_access_token(db: Annotated[AsyncSession, Depends(get_db)], refresh_token: str = Form(...)):
    token_hash = hash_token(refresh_token)
    result = await db.execute(select(RefreshToken).where(RefreshToken.token_hash == token_hash))
    rt = result.scalar_one_or_none()
    if not rt or rt.revoked or rt.expires_at < datetime.now(timezone.utc):
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token")
    rt.revoked = True
    user_result = await db.execute(select(User).where(User.id == rt.user_id))
    user = user_result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    access, raw_refresh, expires_in = await _issue_tokens(user, db, client_id=rt.client_id)
    return {"access_token": access, "token_type": "bearer", "expires_in": expires_in, "refresh_token": raw_refresh}

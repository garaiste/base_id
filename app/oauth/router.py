from __future__ import annotations
import base64, hashlib, logging, secrets
from datetime import datetime, timedelta, timezone
from typing import Annotated
from urllib.parse import urlencode
from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from jose import JWTError
from passlib.context import CryptContext
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from ..auth.tokens import (create_access_token, decode_access_token,
                           generate_auth_code, generate_refresh_token, hash_token)
from ..config import settings
from ..database import get_db
from ..deps import get_current_user, get_optional_user
from ..models import AuthCode, OAuthClient, RefreshToken, User, UserStatus

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/oauth", tags=["oauth"])
templates = Jinja2Templates(directory="app/templates")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


async def _get_client(client_id: str, db: AsyncSession) -> OAuthClient:
    result = await db.execute(select(OAuthClient).where(OAuthClient.client_id == client_id))
    client = result.scalar_one_or_none()
    if not client:
        raise HTTPException(status_code=400, detail="Unknown client_id")
    return client


def _pkce_verify(code_verifier: str, code_challenge: str, method: str) -> bool:
    if method == "S256":
        digest = hashlib.sha256(code_verifier.encode()).digest()
        computed = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
        return secrets.compare_digest(computed, code_challenge)
    return secrets.compare_digest(code_verifier, code_challenge)


@router.get("/authorize", response_class=HTMLResponse)
async def authorize_get(request: Request, client_id: str, redirect_uri: str,
                        response_type: str = "code", scope: str = "openid", state: str = "",
                        code_challenge: str = "", code_challenge_method: str = "S256",
                        db: AsyncSession = Depends(get_db),
                        current_user: User | None = Depends(get_optional_user)):
    if response_type != "code":
        raise HTTPException(status_code=400, detail="Only response_type=code is supported")
    client = await _get_client(client_id, db)
    if redirect_uri not in client.redirect_uris:
        raise HTTPException(status_code=400, detail="redirect_uri not registered")
    if not current_user:
        return RedirectResponse(url="/auth/login?next=" + str(request.url), status_code=302)
    if current_user.status not in (UserStatus.approved, UserStatus.admin):
        return templates.TemplateResponse(request, "oauth_authorize.html",
            {"client": client, "user": current_user, "pending": True})
    return templates.TemplateResponse(request, "oauth_authorize.html",
        {"client": client, "user": current_user,
         "scopes": [s for s in scope.split() if s], "redirect_uri": redirect_uri,
         "state": state, "code_challenge": code_challenge,
         "code_challenge_method": code_challenge_method, "pending": False})


@router.post("/authorize")
async def authorize_post(request: Request, db: Annotated[AsyncSession, Depends(get_db)],
                         current_user: Annotated[User, Depends(get_current_user)],
                         client_id: str = Form(...), redirect_uri: str = Form(...),
                         scope: str = Form("openid"), state: str = Form(""),
                         code_challenge: str = Form(""), code_challenge_method: str = Form("S256"),
                         action: str = Form("approve")):
    client = await _get_client(client_id, db)
    if redirect_uri not in client.redirect_uris:
        raise HTTPException(status_code=400, detail="redirect_uri mismatch")
    if action != "approve":
        params = urlencode({"error": "access_denied", "state": state})
        return RedirectResponse(url=f"{redirect_uri}?{params}", status_code=302)
    if current_user.status not in (UserStatus.approved, UserStatus.admin):
        params = urlencode({"error": "access_denied", "state": state})
        return RedirectResponse(url=f"{redirect_uri}?{params}", status_code=302)
    code = generate_auth_code()
    auth_code = AuthCode(code=code, user_id=current_user.id, client_id=client_id,
                         redirect_uri=redirect_uri, scope=scope,
                         code_challenge=code_challenge or None,
                         code_challenge_method=code_challenge_method if code_challenge else None,
                         expires_at=datetime.now(timezone.utc) + timedelta(minutes=10))
    db.add(auth_code)
    params = {"code": code}
    if state:
        params["state"] = state
    return RedirectResponse(url=f"{redirect_uri}?{urlencode(params)}", status_code=302)


@router.post("/token")
async def token_endpoint(request: Request, db: Annotated[AsyncSession, Depends(get_db)],
                         grant_type: str = Form(...), code: str = Form(""),
                         redirect_uri: str = Form(""), code_verifier: str = Form(""),
                         refresh_token: str = Form(""), client_id: str = Form(""), client_secret: str = Form("")):
    auth_header = request.headers.get("Authorization", "")
    if auth_header.lower().startswith("basic "):
        try:
            decoded = base64.b64decode(auth_header[6:]).decode()
            client_id, client_secret = decoded.split(":", 1)
        except Exception:
            pass
    client = await _get_client(client_id, db)
    if not pwd_context.verify(client_secret, client.client_secret):
        raise HTTPException(status_code=401, detail="Invalid client credentials")
    if grant_type == "authorization_code":
        return await _handle_auth_code(db, client, code, redirect_uri, code_verifier)
    elif grant_type == "refresh_token":
        return await _handle_refresh(db, client, refresh_token)
    raise HTTPException(status_code=400, detail=f"Unsupported grant_type: {grant_type}")


async def _handle_auth_code(db, client, code, redirect_uri, code_verifier):
    result = await db.execute(select(AuthCode).where(AuthCode.code == code))
    auth_code = result.scalar_one_or_none()
    if not auth_code or auth_code.used:
        raise HTTPException(status_code=400, detail="Invalid authorization code")
    if auth_code.expires_at < datetime.now(timezone.utc):
        raise HTTPException(status_code=400, detail="Authorization code expired")
    if auth_code.client_id != client.client_id or auth_code.redirect_uri != redirect_uri:
        raise HTTPException(status_code=400, detail="client_id or redirect_uri mismatch")
    if auth_code.code_challenge:
        if not code_verifier or not _pkce_verify(code_verifier, auth_code.code_challenge,
                                                  auth_code.code_challenge_method or "S256"):
            raise HTTPException(status_code=400, detail="code_verifier invalid")
    auth_code.used = True
    user_result = await db.execute(select(User).where(User.id == auth_code.user_id))
    user = user_result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=400, detail="User not found")
    access, expires_in = create_access_token(user.id, user.email, user.status.value,
        extra_claims={"scope": auth_code.scope, "client_id": client.client_id})
    raw_refresh, refresh_hash = generate_refresh_token()
    db.add(RefreshToken(token_hash=refresh_hash, user_id=user.id, client_id=client.client_id,
                        expires_at=datetime.now(timezone.utc) + timedelta(days=settings.refresh_token_expire_days)))
    return {"access_token": access, "token_type": "bearer", "expires_in": expires_in,
            "refresh_token": raw_refresh, "scope": auth_code.scope}


async def _handle_refresh(db, client, raw_refresh):
    result = await db.execute(select(RefreshToken).where(RefreshToken.token_hash == hash_token(raw_refresh)))
    rt = result.scalar_one_or_none()
    if not rt or rt.revoked or rt.expires_at < datetime.now(timezone.utc):
        raise HTTPException(status_code=400, detail="Invalid or expired refresh token")
    if rt.client_id != client.client_id:
        raise HTTPException(status_code=400, detail="Token not issued to this client")
    rt.revoked = True
    user_result = await db.execute(select(User).where(User.id == rt.user_id))
    user = user_result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=400, detail="User not found")
    access, expires_in = create_access_token(user.id, user.email, user.status.value,
        extra_claims={"client_id": client.client_id})
    new_raw, new_hash = generate_refresh_token()
    db.add(RefreshToken(token_hash=new_hash, user_id=user.id, client_id=client.client_id,
                        expires_at=datetime.now(timezone.utc) + timedelta(days=settings.refresh_token_expire_days)))
    return {"access_token": access, "token_type": "bearer", "expires_in": expires_in, "refresh_token": new_raw}


@router.post("/introspect")
async def introspect(request: Request, db: Annotated[AsyncSession, Depends(get_db)],
                     token: str = Form(...), client_id: str = Form(""), client_secret: str = Form("")):
    auth_header = request.headers.get("Authorization", "")
    if auth_header.lower().startswith("basic "):
        try:
            decoded = base64.b64decode(auth_header[6:]).decode()
            client_id, client_secret = decoded.split(":", 1)
        except Exception:
            pass
    if client_id:
        client = await _get_client(client_id, db)
        if not pwd_context.verify(client_secret, client.client_secret):
            raise HTTPException(status_code=401, detail="Invalid client credentials")
    try:
        payload = decode_access_token(token)
    except JWTError:
        return {"active": False}
    if payload.get("type") != "access":
        return {"active": False}
    return {"active": True, "sub": payload.get("sub"), "email": payload.get("email"),
            "status": payload.get("status"), "scope": payload.get("scope", "openid"),
            "exp": payload.get("exp"), "iat": payload.get("iat"), "client_id": payload.get("client_id")}


@router.post("/revoke")
async def revoke(db: Annotated[AsyncSession, Depends(get_db)], token: str = Form(...)):
    result = await db.execute(select(RefreshToken).where(RefreshToken.token_hash == hash_token(token)))
    rt = result.scalar_one_or_none()
    if rt:
        rt.revoked = True
    return JSONResponse(status_code=200, content={})


@router.get("/userinfo")
async def userinfo(current_user: Annotated[User, Depends(get_current_user)]):
    return {"sub": str(current_user.id), "email": current_user.email,
            "email_verified": current_user.email_verified,
            "name": current_user.display_name, "status": current_user.status.value}

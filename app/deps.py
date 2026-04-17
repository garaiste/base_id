from __future__ import annotations
from typing import Annotated
from fastapi import Cookie, Depends, Header, HTTPException, status
from jose import JWTError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
from .auth.tokens import decode_access_token
from .database import get_db
from .models import User, UserStatus


async def _resolve_user(token: str, db: AsyncSession) -> User:
    try:
        payload = decode_access_token(token)
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token",
                            headers={"WWW-Authenticate": "Bearer"})
    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Bad token")
    result = await db.execute(
        select(User).options(selectinload(User.app_approvals)).where(User.id == user_id)
    )
    user = result.scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    return user


async def get_current_user(
    db: Annotated[AsyncSession, Depends(get_db)],
    authorization: Annotated[str | None, Header()] = None,
    access_token: Annotated[str | None, Cookie()] = None,
) -> User:
    token: str | None = access_token
    if not token and authorization and authorization.lower().startswith("bearer "):
        token = authorization[7:]
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated",
                            headers={"WWW-Authenticate": "Bearer"})
    return await _resolve_user(token, db)


async def get_current_active_user(current_user: Annotated[User, Depends(get_current_user)]) -> User:
    if current_user.status == UserStatus.suspended:
        raise HTTPException(status_code=403, detail="Account suspended")
    if current_user.status == UserStatus.pending:
        raise HTTPException(status_code=403, detail="Account pending approval")
    return current_user


async def get_admin_user(current_user: Annotated[User, Depends(get_current_user)]) -> User:
    if current_user.status != UserStatus.admin:
        raise HTTPException(status_code=403, detail="Admin access required")
    return current_user


async def get_optional_user(
    db: Annotated[AsyncSession, Depends(get_db)],
    authorization: Annotated[str | None, Header()] = None,
    access_token: Annotated[str | None, Cookie()] = None,
) -> User | None:
    token: str | None = access_token
    if not token and authorization and authorization.lower().startswith("bearer "):
        token = authorization[7:]
    if not token:
        return None
    try:
        return await _resolve_user(token, db)
    except HTTPException:
        return None

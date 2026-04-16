from __future__ import annotations
import logging
from datetime import datetime, timezone
from typing import Annotated
from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from passlib.context import CryptContext
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from ..auth.email import send_approval_email
from ..database import get_db
from ..deps import get_admin_user
from ..models import AppApproval, ApprovalStatus, OAuthClient, User, UserStatus

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/admin", tags=["admin"])
templates = Jinja2Templates(directory="app/templates")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


@router.get("/users", response_class=HTMLResponse)
async def users_list(request: Request, db: Annotated[AsyncSession, Depends(get_db)],
                     admin: Annotated[User, Depends(get_admin_user)], status_filter: str = ""):
    q = select(User).order_by(User.created_at.desc())
    if status_filter:
        q = q.where(User.status == status_filter)
    result = await db.execute(q)
    return templates.TemplateResponse(request, "admin/users.html",
        {"admin": admin, "users": result.scalars().all(),
         "status_filter": status_filter, "statuses": [s.value for s in UserStatus]})


@router.get("/users/{user_id}", response_class=HTMLResponse)
async def user_detail(request: Request, user_id: str, db: Annotated[AsyncSession, Depends(get_db)],
                      admin: Annotated[User, Depends(get_admin_user)]):
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return templates.TemplateResponse(request, "admin/user_detail.html",
        {"admin": admin, "user": user, "statuses": [s.value for s in UserStatus]})


@router.post("/users/{user_id}/status")
async def update_user_status(user_id: str, db: Annotated[AsyncSession, Depends(get_db)],
                             admin: Annotated[User, Depends(get_admin_user)], new_status: str = Form(...)):
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    try:
        status_enum = UserStatus(new_status)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid status: {new_status}")
    was_pending = user.status != UserStatus.approved
    user.status = status_enum
    if status_enum == UserStatus.approved and was_pending:
        try:
            await send_approval_email(user.email, user.display_name)
        except Exception:
            logger.exception("Failed to send approval email")
    return RedirectResponse(url=f"/admin/users/{user_id}", status_code=302)


@router.get("/clients", response_class=HTMLResponse)
async def clients_list(request: Request, db: Annotated[AsyncSession, Depends(get_db)],
                       admin: Annotated[User, Depends(get_admin_user)]):
    result = await db.execute(select(OAuthClient))
    return templates.TemplateResponse(request, "admin/clients.html",
        {"admin": admin, "clients": result.scalars().all()})


@router.post("/clients")
async def create_client(db: Annotated[AsyncSession, Depends(get_db)],
                        admin: Annotated[User, Depends(get_admin_user)],
                        client_id: str = Form(...), client_secret: str = Form(...),
                        name: str = Form(...), redirect_uris: str = Form(...),
                        scopes: str = Form("openid profile email")):
    existing = await db.execute(select(OAuthClient).where(OAuthClient.client_id == client_id))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="client_id already exists")
    db.add(OAuthClient(client_id=client_id, client_secret=pwd_context.hash(client_secret), name=name,
                       redirect_uris=[u.strip() for u in redirect_uris.splitlines() if u.strip()],
                       scopes=[s.strip() for s in scopes.split() if s.strip()]))
    return RedirectResponse(url="/admin/clients", status_code=302)


@router.post("/clients/{client_id}/delete")
async def delete_client(client_id: str, db: Annotated[AsyncSession, Depends(get_db)],
                        admin: Annotated[User, Depends(get_admin_user)]):
    result = await db.execute(select(OAuthClient).where(OAuthClient.client_id == client_id))
    client = result.scalar_one_or_none()
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")
    await db.delete(client)
    return RedirectResponse(url="/admin/clients", status_code=302)


@router.post("/approvals/{user_id}/{app_id}")
async def update_app_approval(user_id: str, app_id: str, db: Annotated[AsyncSession, Depends(get_db)],
                              admin: Annotated[User, Depends(get_admin_user)], decision: str = Form(...)):
    result = await db.execute(select(AppApproval).where(
        AppApproval.user_id == user_id, AppApproval.app_id == app_id))
    approval = result.scalar_one_or_none()
    if not approval:
        raise HTTPException(status_code=404, detail="Approval request not found")
    try:
        approval.status = ApprovalStatus(decision)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid decision")
    approval.reviewed_at = datetime.now(timezone.utc)
    approval.reviewed_by = admin.id
    return RedirectResponse(url=f"/admin/users/{user_id}", status_code=302)

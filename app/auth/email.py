from __future__ import annotations
import logging
import httpx
from ..config import settings

logger = logging.getLogger(__name__)


async def send_email(to: str, subject: str, html: str) -> None:
    if not settings.resend_api_key:
        logger.warning("RESEND_API_KEY not set — email not sent to %s", to)
        return
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            "https://api.resend.com/emails",
            headers={"Authorization": f"Bearer {settings.resend_api_key}"},
            json={"from": f"{settings.email_from_name} <{settings.email_from}>",
                  "to": [to], "subject": subject, "html": html},
            timeout=10,
        )
        resp.raise_for_status()


def _base_html(title: str, body: str) -> str:
    return f"""<!DOCTYPE html><html><head><meta charset="utf-8"><title>{title}</title></head>
<body style="font-family:sans-serif;max-width:560px;margin:40px auto;color:#1a1a1a;line-height:1.6">
  <div style="background:#fff;border:1px solid #e5e7eb;border-radius:8px;padding:40px">
    <h2 style="margin-top:0">{title}</h2>{body}
    <hr style="border:none;border-top:1px solid #e5e7eb;margin:32px 0">
    <p style="color:#6b7280;font-size:13px;margin:0">Sent by {settings.app_name}.</p>
  </div></body></html>"""


async def send_verification_email(to: str, token: str) -> None:
    link = f"{settings.base_url}/auth/verify-email?token={token}"
    html = _base_html("Verify your email address",
        f'<p>Click below to verify your email. Expires in 24 hours.</p>'
        f'<p style="margin:32px 0"><a href="{link}" style="background:#2563eb;color:#fff;'
        f'padding:12px 24px;border-radius:6px;text-decoration:none;font-weight:600">Verify email</a></p>'
        f'<p style="color:#6b7280;font-size:13px">Or copy: <a href="{link}">{link}</a></p>')
    await send_email(to, f"Verify your email — {settings.app_name}", html)


async def send_password_reset_email(to: str, token: str) -> None:
    link = f"{settings.base_url}/auth/reset-password?token={token}"
    html = _base_html("Reset your password",
        f'<p>Click below to reset your password. Expires in 1 hour.</p>'
        f'<p style="margin:32px 0"><a href="{link}" style="background:#2563eb;color:#fff;'
        f'padding:12px 24px;border-radius:6px;text-decoration:none;font-weight:600">Reset password</a></p>')
    await send_email(to, f"Reset your password — {settings.app_name}", html)


async def send_approval_email(to: str, display_name: str | None) -> None:
    name = display_name or "there"
    html = _base_html("Your account has been approved!",
        f'<p>Hi {name}, your <strong>{settings.app_name}</strong> account has been approved.</p>'
        f'<p style="margin:32px 0"><a href="{settings.base_url}/auth/login" style="background:#2563eb;'
        f'color:#fff;padding:12px 24px;border-radius:6px;text-decoration:none;font-weight:600">Sign in</a></p>')
    await send_email(to, f"You\'re approved — {settings.app_name}", html)

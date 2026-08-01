"""
Clerk webhook endpoint — account lifecycle events delivered via Svix.

Clerk signs every webhook POST with the Svix signing secret
(CLERK_WEBHOOK_SECRET); we verify the signature before touching the DB, so
this endpoint is NOT authenticated with a user JWT and deliberately does NOT
go through `get_current_user`.

Handled events:
  - session.revoked / session.removed / user.deleted / user.banned
      → immediately deactivate the local users row (is_active=False) so any
        in-flight JWT stops being accepted by get_optional_user.
  - user.updated → reactivate (is_active=True) if the user was unbanned.
  - session.created → no-op (log only).

Setup (Clerk Dashboard → Webhooks): create an endpoint at
https://<your-domain>/api/webhooks/clerk and subscribe to the events above.
Docs: https://clerk.com/docs/integrations/webhooks

The route is exempt from the per-IP default rate limit: Clerk's delivery IPs
are fixed and can burst (e.g. mass sign-out), and a 429 on a revocation
would delay the access kill-switch. Signature verification is the auth
boundary here.
"""
import logging

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from svix.webhooks import Webhook, WebhookVerificationError

from cybersec.apps.api.deps import get_db
from cybersec.apps.api.rate_limit import limiter
from cybersec.config.settings import settings
from cybersec.database.models import User

logger = logging.getLogger(__name__)

router = APIRouter()

# Events that must immediately revoke the user's local access.
REVOKE_EVENTS = {"session.revoked", "session.removed", "user.deleted", "user.banned"}


def _clerk_user_id_from_event(payload: dict) -> str | None:
    """Extract the Clerk user id from a webhook event payload.

    Session events carry it as data.user_id; user events as data.id.
    """
    data = payload.get("data") or {}
    return data.get("user_id") or data.get("id")


async def _set_active(db: AsyncSession, clerk_user_id: str, is_active: bool) -> None:
    """Flip the local users row's is_active flag and commit."""
    result = await db.execute(
        select(User).where(User.clerk_user_id == clerk_user_id)
    )
    user = result.scalar_one_or_none()
    if user is None:
        logger.warning(
            "Webhook: no local user found for clerk_user_id=%s — nothing to do",
            clerk_user_id,
        )
        return
    user.is_active = is_active
    await db.commit()
    logger.info(
        "Webhook: set is_active=%s for clerk_user_id=%s (users.id=%s)",
        is_active,
        clerk_user_id,
        user.id,
    )


@router.post("/clerk")
@limiter.exempt
async def clerk_webhook(request: Request, db: AsyncSession = Depends(get_db)):
    """Verify a Svix-signed Clerk webhook and apply the account lifecycle event."""
    body = await request.body()

    secret = settings.CLERK_WEBHOOK_SECRET
    if not secret:
        logger.error("CLERK_WEBHOOK_SECRET is not configured — rejecting webhook")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Webhook secret not configured",
        )

    try:
        payload = Webhook(secret).verify(body, dict(request.headers))
    except WebhookVerificationError:
        logger.warning("Webhook: invalid Svix signature — rejected")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid webhook signature",
        )
    except Exception as e:
        logger.exception("Webhook: unexpected verification error: %s", e)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid webhook signature",
        )

    event_type = payload.get("type", "")
    clerk_user_id = _clerk_user_id_from_event(payload)
    logger.info("Webhook: received event type=%s clerk_user_id=%s", event_type, clerk_user_id)

    if event_type in REVOKE_EVENTS:
        if not clerk_user_id:
            logger.warning("Webhook: %s event without a user id", event_type)
            return Response(status_code=status.HTTP_200_OK)
        await _set_active(db, clerk_user_id, is_active=False)
    elif event_type == "user.updated":
        if not clerk_user_id:
            logger.warning("Webhook: user.updated event without a user id")
            return Response(status_code=status.HTTP_200_OK)
        banned = bool((payload.get("data") or {}).get("banned"))
        await _set_active(db, clerk_user_id, is_active=not banned)
    elif event_type == "session.created":
        logger.info("Webhook: session.created — no-op")
    else:
        logger.info("Webhook: unhandled event type %s — no-op", event_type)

    return Response(status_code=status.HTTP_200_OK)

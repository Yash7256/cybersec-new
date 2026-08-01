"""
User synchronization module for Clerk authentication.

Maintains a local `users` row for every Clerk-authenticated user who hits the API.
Implements a three-path upsert strategy:
  1. Fast path — clerk_user_id already exists → return immediately
  2. Legacy migration — email match on a legacy row → link in-place, preserve FKs
  3. New user — insert fresh row (Clerk identity only, no local password)
"""
import logging
import httpx
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from cybersec.database.models import User
from cybersec.config.settings import settings

logger = logging.getLogger(__name__)


async def fetch_clerk_user_email(clerk_user_id: str) -> str | None:
    """Fetch the user's email address from Clerk's Backend API using CLERK_SECRET_KEY."""
    if not settings.CLERK_SECRET_KEY:
        logger.warning("CLERK_SECRET_KEY not set, cannot fetch user details from Clerk API")
        return None
    try:
        async with httpx.AsyncClient() as client:
            headers = {"Authorization": f"Bearer {settings.CLERK_SECRET_KEY}"}
            # Clerk Backend API user endpoint
            response = await client.get(
                f"https://api.clerk.com/v1/users/{clerk_user_id}",
                headers=headers,
                timeout=5.0
            )
            if response.status_code == 200:
                data = response.json()
                emails = data.get("email_addresses", [])
                if emails:
                    return emails[0].get("email_address")
            else:
                logger.warning(
                    "Clerk API returned status %d when fetching user details for %s",
                    response.status_code,
                    clerk_user_id
                )
    except Exception as e:
        logger.warning("Failed to fetch user email from Clerk API: %s", e)
    return None


async def sync_clerk_user(
    clerk_user_id: str,
    email: str | None,
    db: AsyncSession,
) -> User:
    """Upsert a local users row for the given Clerk identity.

    Args:
        clerk_user_id: The Clerk user identifier (format: user_XXXX).
        email: The email address from the Clerk JWT payload, or None if not exposed.
        db: An open async SQLAlchemy session.

    Returns:
        The existing or newly-created User ORM object.
    """
    # -------------------------------------------------------------------------
    # Path 1 — Fast path: row already exists with this clerk_user_id
    # -------------------------------------------------------------------------
    result = await db.execute(
        select(User).where(User.clerk_user_id == clerk_user_id)
    )
    existing_user = result.scalar_one_or_none()

    if existing_user is not None:
        logger.debug(
            "sync_clerk_user: fast path — clerk_user_id=%s already synced (users.id=%s)",
            clerk_user_id,
            existing_user.id,
        )
        # If email is not set locally but we have a way to populate it, do so
        if not existing_user.email:
            fetched_email = email or await fetch_clerk_user_email(clerk_user_id)
            if fetched_email:
                existing_user.email = fetched_email
                await db.commit()
        return existing_user

    # If email wasn't provided in the JWT payload, fetch it from Clerk API
    if email is None:
        email = await fetch_clerk_user_email(clerk_user_id)

    # -------------------------------------------------------------------------
    # Path 2 — Match by email: if a row with this email exists, link it
    # -------------------------------------------------------------------------
    if email is not None:
        email_result = await db.execute(
            select(User).where(User.email == email)
        )
        matching_user = email_result.scalar_one_or_none()

        if matching_user is not None:
            logger.info(
                "sync_clerk_user: email match — linking email=%s to clerk_user_id=%s "
                "(users.id=%s preserved, all FK references intact)",
                email,
                clerk_user_id,
                matching_user.id,
            )
            matching_user.clerk_user_id = clerk_user_id
            await db.commit()
            return matching_user

    # -------------------------------------------------------------------------
    # Path 3 — New Clerk user: insert a fresh row
    # -------------------------------------------------------------------------
    logger.debug(
        "sync_clerk_user: new user — creating row for clerk_user_id=%s email=%s",
        clerk_user_id,
        email,
    )
    new_user = User(
        clerk_user_id=clerk_user_id,
        email=email,
        is_active=True,
    )
    db.add(new_user)

    try:
        await db.commit()
        await db.refresh(new_user)
        return new_user
    except IntegrityError:
        # Race condition: another concurrent request created the same row first.
        # Roll back and re-query to return the winner's row.
        await db.rollback()
        logger.debug(
            "sync_clerk_user: IntegrityError on insert for clerk_user_id=%s "
            "— concurrent upsert detected, re-querying",
            clerk_user_id,
        )
        result = await db.execute(
            select(User).where(User.clerk_user_id == clerk_user_id)
        )
        return result.scalar_one()

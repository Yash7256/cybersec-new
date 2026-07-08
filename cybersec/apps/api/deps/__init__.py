"""
Dependencies — DB session, default user bypass.

Authentication has been disabled. get_optional_user and get_current_user
always return a default active superuser ('paid' tier) from the database.
If the DB is temporarily unavailable a transient User object is returned
so routes never receive a 401/503.
"""
import logging
import uuid

from fastapi import Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from cybersec.database.models import User
from cybersec.database.session import get_db

logger = logging.getLogger(__name__)

# HTTPBearer kept to avoid breaking any existing route signatures
http_bearer = HTTPBearer(auto_error=False)


async def get_optional_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(http_bearer),
    db: AsyncSession = Depends(get_db),
) -> User | None:
    """Extract the current user. Always returns the default active paid/superuser.

    Creates the user in the database if it doesn't already exist to preserve
    foreign key constraints.
    """
    try:
        stmt = select(User).where(User.clerk_user_id == "default_user")
        result = await db.execute(stmt)
        user = result.scalars().first()
        if not user:
            user = User(
                email="user@cybersec.local",
                clerk_user_id="default_user",
                is_active=True,
                is_superuser=True,
                tier="paid"
            )
            db.add(user)
            await db.commit()
            await db.refresh(user)
        return user
    except Exception as e:
        logger.error(f"Error getting/creating default user: {e}")
        # Return a transient fallback User object so the API doesn't crash if DB is not ready
        return User(
            id=uuid.UUID("00000000-0000-0000-0000-000000000000"),
            email="user@cybersec.local",
            clerk_user_id="default_user",
            is_active=True,
            is_superuser=True,
            tier="paid"
        )


async def get_current_user(
    user: User | None = Depends(get_optional_user),
) -> User:
    """Require a valid authenticated user. Always returns the resolved default user."""
    if user is None:
        return User(
            id=uuid.UUID("00000000-0000-0000-0000-000000000000"),
            email="user@cybersec.local",
            clerk_user_id="default_user",
            is_active=True,
            is_superuser=True,
            tier="paid"
        )
    return user


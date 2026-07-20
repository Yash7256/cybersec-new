"""
Dependencies — DB session, JWT validation, user sync.
"""
import logging
import uuid
from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
import jwt
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cybersec.apps.api.clerk_jwks import get_clerk_public_key, ClerkJWKSUnavailable
from cybersec.apps.api.user_sync import sync_clerk_user
from cybersec.config.settings import settings
from cybersec.database.models import User
from cybersec.database.session import get_db

logger = logging.getLogger(__name__)

http_bearer = HTTPBearer(auto_error=False)


async def get_optional_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(http_bearer),
    db: AsyncSession = Depends(get_db),
) -> Optional[User]:
    """Extract and validate the current user from a Clerk JWT.

    If no credentials are provided or validation fails, returns None
    (caller must enforce auth if required).
    """
    if credentials is None:
        return None

    token = credentials.credentials

    # Validate JWT with Clerk's public keys
    try:
        unverified_header = jwt.get_unverified_header(token)
        kid = unverified_header.get("kid")
        if not kid:
            logger.warning("JWT missing kid header")
            return None

        public_key = await get_clerk_public_key(kid)

        payload = jwt.decode(
            token,
            public_key,
            algorithms=["RS256"],
            issuer=settings.CLERK_ISSUER.rstrip("/"),
            options={"verify_aud": False},  # Clerk doesn't include aud by default
        )
    except (jwt.PyJWTError, ClerkJWKSUnavailable, KeyError) as e:
        logger.warning("JWT validation failed: %s (issuer configured: %s)", e, settings.CLERK_ISSUER)
        return None
    except Exception as e:
        logger.exception("Unexpected error during JWT validation: %s", e)
        return None

    clerk_user_id = payload.get("sub")
    email = payload.get("email") or payload.get("email_address")

    if not clerk_user_id:
        logger.warning("JWT missing sub claim")
        return None

    # Sync / upsert local user row
    try:
        user = await sync_clerk_user(clerk_user_id, email, db)
        if not user.is_active:
            logger.warning("User %s is inactive", clerk_user_id)
            return None
        return user
    except Exception as e:
        logger.exception("Failed to sync user %s: %s", clerk_user_id, e)
        return None


async def get_current_user(
    user: Optional[User] = Depends(get_optional_user),
) -> User:
    """Require a valid authenticated user. Raises 401 if not authenticated."""
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user
"""
Dependencies — DB session, JWT validation, user sync.
"""
import logging
import uuid
from typing import Optional

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
import jwt
from slowapi.util import get_remote_address
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cybersec.apps.api.clerk_jwks import get_clerk_public_key, ClerkJWKSUnavailable
from cybersec.apps.api.user_sync import sync_clerk_user
from cybersec.config.settings import settings
from cybersec.core.metrics_registry import registry
from cybersec.database.models import User
from cybersec.database.session import get_db

logger = logging.getLogger(__name__)

http_bearer = HTTPBearer(auto_error=False)

# Bounded cardinality for the per-IP failure counter: beyond this many
# distinct failing client IPs, stop creating new series and fall back to
# log-based alerting instead of blowing up the metrics payload.
MAX_AUTH_FAILURE_IP_SERIES = 1000

_auth_failure_ips: set[str] = set()


def _auth_failure_by_ip(request: Request) -> None:
    """Track auth failures per client IP, with bounded cardinality."""
    ip = get_remote_address(request)
    if ip in _auth_failure_ips or len(_auth_failure_ips) < MAX_AUTH_FAILURE_IP_SERIES:
        _auth_failure_ips.add(ip)
        registry().counter(
            "auth_validation_failures_by_ip",
            "Auth validation failures, by client IP (series cardinality capped)",
            labels={"ip": ip},
        ).inc()
    else:
        logger.warning(
            "Auth validation failure from IP beyond cardinality cap — "
            "relying on log-based alerting: %s",
            ip,
        )


def _auth_failure(reason: str, request: Optional[Request]) -> None:
    """Record an auth validation failure in Prometheus metrics."""
    registry().counter(
        "auth_validation_failures_total",
        "Auth validation failures, by reason "
        "(missing_kid, unknown_kid, jwt_error, missing_sub, "
        "inactive_user, sync_error, unexpected_error)",
        labels={"reason": reason},
    ).inc()
    if request is not None:
        _auth_failure_by_ip(request)


async def get_optional_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(http_bearer),
    db: AsyncSession = Depends(get_db),
    request: Request = None,
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
            _auth_failure("missing_kid", request)
            return None

        public_key = await get_clerk_public_key(kid)

        # Audience verification is opt-in via CLERK_AUDIENCE for backward compatibility.
        # When unset, keep the previous permissive behavior (Clerk session tokens omit
        # "aud" by default). When set, PyJWT enforces the claim.
        decode_kwargs: dict = {
            "algorithms": ["RS256"],
            "issuer": settings.CLERK_ISSUER.rstrip("/"),
        }
        if settings.CLERK_AUDIENCE:
            decode_kwargs["audience"] = settings.CLERK_AUDIENCE
        else:
            decode_kwargs["options"] = {"verify_aud": False}

        payload = jwt.decode(token, public_key, **decode_kwargs)
    except KeyError as e:
        # get_clerk_public_key raises KeyError for kids not in the JWKS cache —
        # a burst of these is a signature-forgery/probing signal, not normal
        # user behavior (see docs/auth-monitoring.md).
        logger.warning("JWT validation failed: %s (issuer configured: %s)", e, settings.CLERK_ISSUER)
        _auth_failure("unknown_kid", request)
        return None
    except (jwt.PyJWTError, ClerkJWKSUnavailable) as e:
        logger.warning("JWT validation failed: %s (issuer configured: %s)", e, settings.CLERK_ISSUER)
        _auth_failure("jwt_error", request)
        return None
    except Exception as e:
        logger.exception("Unexpected error during JWT validation: %s", e)
        _auth_failure("unexpected_error", request)
        return None

    clerk_user_id = payload.get("sub")
    email = payload.get("email") or payload.get("email_address")

    if not clerk_user_id:
        logger.warning("JWT missing sub claim")
        _auth_failure("missing_sub", request)
        return None

    # Sync / upsert local user row
    try:
        user = await sync_clerk_user(clerk_user_id, email, db)
        if not user.is_active:
            logger.warning("User %s is inactive", clerk_user_id)
            _auth_failure("inactive_user", request)
            return None
        return user
    except Exception as e:
        logger.exception("Failed to sync user %s: %s", clerk_user_id, e)
        _auth_failure("sync_error", request)
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
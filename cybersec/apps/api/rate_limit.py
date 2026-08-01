"""
Rate limiting configuration.

`limiter` — the app-wide SlowAPI limiter keyed on client IP. It is attached
to the FastAPI app and enforced by SlowAPIMiddleware with a default of
100 requests/minute/IP as the outer bound for every route.

`user_limiter` — a second, per-user limiter keyed on the authenticated
Clerk user's JWT "sub" claim via `get_user_or_ip`, falling back to the
client IP for anonymous requests. It is NOT attached to the middleware;
instead it is applied as a route-level decorator
(`@user_limiter.shared_limit(...)`) on the expensive scan endpoints in
tools.py. A single compromised/leaked token therefore cannot be reused from
many IPs to hammer scan endpoints (30 scans/minute/user across all scan
endpoints), while legitimate users behind shared NAT/corp proxies keep
their own per-user budget instead of sharing a single per-IP one.

The JWT is decoded WITHOUT verifying the signature purely to extract the
"sub" claim for bucketing — this is safe because the value is only used as
a rate-limit key, never for authentication.
"""
import logging

import jwt
from fastapi import Request
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

logger = logging.getLogger(__name__)

# Per-user budget shared across all scan-heavy endpoints.
SCAN_RATE_LIMIT = "30/minute"
SCAN_SCOPE = "user_scans"


def get_user_or_ip(request: Request) -> str:
    """Rate-limit key: the JWT sub claim if a Bearer token is present, else the client IP.

    The token is decoded without signature verification — this is only a
    bucketing key, not an authentication decision.
    """
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header[len("Bearer "):].strip()
        if token:
            try:
                payload = jwt.decode(token, options={"verify_signature": False})
                sub = payload.get("sub")
                if sub:
                    key = f"user:{sub}"
                    request.state.rate_limit_user_key = key
                    return key
            except Exception:
                logger.debug(
                    "get_user_or_ip: token not usable for rate-limit keying — "
                    "falling back to client IP"
                )
    return get_remote_address(request)


limiter = Limiter(key_func=get_remote_address, default_limits=["100/minute"])

user_limiter = Limiter(key_func=get_user_or_ip)


def rate_limit_exceeded_handler(request: Request, exc: RateLimitExceeded):
    """429 handler for both limiters.

    Delegates to SlowAPI's JSON handler so the response body stays clean.
    Logs at WARNING when the per-user limiter trips (keyed on the JWT sub),
    as a leaked-token / abuse signal for monitoring.
    """
    user_key = getattr(request.state, "rate_limit_user_key", None)
    if user_key:
        logger.warning(
            "Per-user rate limit tripped for %s at %s",
            user_key,
            request.url.path,
        )
    return _rate_limit_exceeded_handler(request, exc)

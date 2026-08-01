"""
Tests for the per-user rate limiter on scan-heavy endpoints.

A second SlowAPI limiter (`user_limiter`) keys requests on the JWT "sub"
claim (falling back to client IP) so a leaked/compromised token can't be
reused from many IPs, while different users keep independent budgets.
"""
from __future__ import annotations

import logging
import uuid

import jwt
import pytest
from fastapi import APIRouter, FastAPI, Request
from fastapi.testclient import TestClient
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

from cybersec.apps.api.rate_limit import (
    SCAN_RATE_LIMIT,
    SCAN_SCOPE,
    limiter,
    rate_limit_exceeded_handler,
    user_limiter,
)
from cybersec.apps.api.routes import tools as tools_module

SCAN_URL = "/api/tools/port_scan"

# Replica of the real scan endpoint wiring: same user_limiter, same shared
# scope — exercises the exact rate-limit path the production routes use
# without launching real scans.
test_router = APIRouter()


@test_router.post("/port_scan")
@user_limiter.shared_limit(SCAN_RATE_LIMIT, scope=SCAN_SCOPE)
async def fake_port_scan(request: Request):
    return {"ok": True}


@pytest.fixture()
def client():
    app = FastAPI()
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, rate_limit_exceeded_handler)
    app.add_middleware(SlowAPIMiddleware)
    app.include_router(test_router, prefix="/api/tools")
    test_client = TestClient(app)
    yield test_client
    # The limiters are module-level singletons with in-memory storage —
    # clear their buckets so tests don't pollute each other's windows.
    limiter._limiter.storage.reset()
    user_limiter._limiter.storage.reset()


def _bearer(sub: str) -> dict:
    """A token with the given sub claim (signature is irrelevant for keying)."""
    token = jwt.encode({"sub": sub}, key="unused", algorithm="HS256")
    return {"Authorization": f"Bearer {token}"}


def _fake_ip_header(ip: str) -> dict:
    return {"X-Forwarded-For": ip}


def test_scan_endpoints_registered_on_user_limiter():
    """Every expensive scan endpoint must carry the per-user 30/min limit."""
    expected = [
        "cybersec.apps.api.routes.tools.run_port_scan",
        "cybersec.apps.api.routes.tools.stream_port_scan",
        "cybersec.apps.api.routes.tools.run_os_fingerprint",
        "cybersec.apps.api.routes.tools.stream_os_fingerprint",
        "cybersec.apps.api.routes.tools.run_subdomain",
        "cybersec.apps.api.routes.tools.stream_subdomain",
    ]
    for name in expected:
        limits = user_limiter._route_limits.get(name, [])
        assert limits, f"no per-user limit registered for {name}"
        assert str(limits[0].limit) == "30 per 1 minute"
        assert limits[0].scope == SCAN_SCOPE


def test_same_user_blocked_after_30_requests(client):
    """>30 scan requests from the same user within a minute must eventually 429."""
    headers = _bearer(f"user_{uuid.uuid4().hex}")

    codes = [
        client.post(SCAN_URL, headers=headers).status_code for _ in range(31)
    ]

    assert codes[:30] == [200] * 30
    assert codes[30] == 429


def test_429_body_is_clean_json(client):
    """The 429 response must be a clean JSON body (no stack trace)."""
    headers = _bearer(f"user_{uuid.uuid4().hex}")
    resp = None
    for _ in range(31):
        resp = client.post(SCAN_URL, headers=headers)
    assert resp.status_code == 429
    assert resp.json() == {"error": "Rate limit exceeded: 30 per 1 minute"}


def test_different_user_not_blocked(client):
    """A second user's requests must not be blocked by the first user's trips."""
    user_a = _bearer(f"user_{uuid.uuid4().hex}")
    user_b = _bearer(f"user_{uuid.uuid4().hex}")

    for _ in range(31):
        client.post(SCAN_URL, headers=user_a)

    assert client.post(SCAN_URL, headers=user_b).status_code == 200


def test_user_limit_ignores_client_ip(monkeypatch, client):
    """Same sub from many IPs still hits the shared per-user bucket."""
    monkeypatch.setattr(
        "cybersec.apps.api.rate_limit.get_remote_address",
        lambda req: req.headers.get("X-Forwarded-For", "0.0.0.0"),
    )
    headers = _bearer(f"user_{uuid.uuid4().hex}")
    ips = ["10.0.0.1", "10.0.0.2", "10.0.0.3"]

    codes = []
    for i in range(31):
        req_headers = {**headers, **_fake_ip_header(ips[i % 3])}
        codes.append(client.post(SCAN_URL, headers=req_headers).status_code)

    assert codes[:30] == [200] * 30
    assert codes[30] == 429


def test_anonymous_requests_fall_back_to_ip(monkeypatch, client):
    """Without a token, each client IP gets its own 30/min bucket."""
    monkeypatch.setattr(
        "cybersec.apps.api.rate_limit.get_remote_address",
        lambda req: req.headers.get("X-Forwarded-For", "0.0.0.0"),
    )
    ip_a, ip_b = "198.51.100.1", "198.51.100.2"

    for _ in range(31):
        client.post(SCAN_URL, headers=_fake_ip_header(ip_a))

    assert client.post(SCAN_URL, headers=_fake_ip_header(ip_a)).status_code == 429
    assert client.post(SCAN_URL, headers=_fake_ip_header(ip_b)).status_code == 200


def test_per_user_trip_logged_with_sub(client, caplog):
    """A per-user trip must log a WARNING including the sub claim."""
    sub = f"user_{uuid.uuid4().hex}"
    headers = _bearer(sub)

    with caplog.at_level(logging.WARNING, logger="cybersec.apps.api.rate_limit"):
        for _ in range(31):
            client.post(SCAN_URL, headers=headers)

    assert any(
        "Per-user rate limit tripped" in record.message
        and f"user:{sub}" in record.message
        for record in caplog.records
    )


def test_anonymous_trip_not_logged_as_user(monkeypatch, client, caplog):
    """IP-keyed trips are not flagged as per-user abuse signals."""
    monkeypatch.setattr(
        "cybersec.apps.api.rate_limit.get_remote_address",
        lambda req: req.headers.get("X-Forwarded-For", "0.0.0.0"),
    )
    with caplog.at_level(logging.WARNING, logger="cybersec.apps.api.rate_limit"):
        for _ in range(31):
            client.post(SCAN_URL, headers=_fake_ip_header("203.0.113.9"))

    assert not any(
        "Per-user rate limit tripped" in record.message
        for record in caplog.records
    )


def test_missing_or_garbage_token_falls_back_to_ip(client):
    """Garbage Authorization values are ignored and keyed by IP."""
    headers = {"Authorization": "Bearer not-a-real-token"}
    codes = [client.post(SCAN_URL, headers=headers).status_code for _ in range(31)]
    assert codes[:30] == [200] * 30
    assert codes[30] == 429

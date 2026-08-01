"""
Tests for the Clerk webhook endpoint (/api/webhooks/clerk).

Verifies Svix signature handling and that account lifecycle events flip the
local users row's is_active flag (and that invalid signatures are rejected
without touching the DB).
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from svix.webhooks import Webhook

from cybersec.apps.api.deps import get_db
from cybersec.apps.api.rate_limit import limiter
from cybersec.apps.api.routes import webhooks as webhooks_module
from cybersec.apps.api.routes.webhooks import router as webhooks_router
from cybersec.database.models import User

WEBHOOK_SECRET = "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw"
CLERK_USER_ID = "user_test_123"


class _FakeResult:
    def __init__(self, user):
        self._user = user

    def scalar_one_or_none(self):
        return self._user


def _make_user(is_active: bool = True) -> User:
    return User(
        id="00000000-0000-0000-0000-000000000001",
        clerk_user_id=CLERK_USER_ID,
        email="test@example.com",
        is_active=is_active,
    )


def _make_db(user) -> AsyncMock:
    db = AsyncMock()
    db.execute.return_value = _FakeResult(user)
    return db


def _make_client(monkeypatch, db: AsyncMock):
    """Build a minimal FastAPI app with just the webhook router and a fake DB."""
    monkeypatch.setattr(webhooks_module.settings, "CLERK_WEBHOOK_SECRET", WEBHOOK_SECRET)

    async def _override_get_db():
        yield db

    app = FastAPI()
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    app.add_middleware(SlowAPIMiddleware)
    app.include_router(webhooks_router, prefix="/api/webhooks", tags=["webhooks"])
    app.dependency_overrides[get_db] = _override_get_db
    return TestClient(app)


def _signed_post(client: TestClient, payload: dict) -> object:
    """POST a Svix-signed webhook payload and return the response."""
    msg_id = "msg_" + uuid.uuid4().hex[:16]
    ts = datetime.now(timezone.utc)
    data = json.dumps(payload)
    signature = Webhook(WEBHOOK_SECRET).sign(msg_id, ts, data)
    headers = {
        "svix-id": msg_id,
        "svix-timestamp": str(int(ts.timestamp())),
        "svix-signature": signature,
        "Content-Type": "application/json",
    }
    return client.post("/api/webhooks/clerk", content=data, headers=headers)


def test_webhook_route_is_exempt_from_rate_limit():
    """The webhook endpoint must not be subject to the per-IP default limit."""
    assert "cybersec.apps.api.routes.webhooks.clerk_webhook" in limiter._exempt_routes


@pytest.mark.parametrize(
    "event_type,data",
    [
        ("session.revoked", {"object": "session", "id": "sess_1", "user_id": CLERK_USER_ID}),
        ("session.removed", {"object": "session", "id": "sess_1", "user_id": CLERK_USER_ID}),
        ("user.deleted", {"object": "user", "id": CLERK_USER_ID, "deleted": True}),
        ("user.banned", {"object": "user", "id": CLERK_USER_ID, "banned": True}),
    ],
)
def test_revoke_events_deactivate_user(monkeypatch, event_type, data):
    """Each revocation event must set the local user's is_active=False."""
    user = _make_user(is_active=True)
    db = _make_db(user)
    client = _make_client(monkeypatch, db)

    response = _signed_post(
        client, {"object": "event", "type": event_type, "data": data}
    )

    assert response.status_code == 200
    assert user.is_active is False
    db.commit.assert_awaited_once()


def test_user_updated_unban_reactivates_user(monkeypatch):
    """user.updated with banned=false must reactivate a deactivated user."""
    user = _make_user(is_active=False)
    db = _make_db(user)
    client = _make_client(monkeypatch, db)

    response = _signed_post(
        client,
        {
            "object": "event",
            "type": "user.updated",
            "data": {"object": "user", "id": CLERK_USER_ID, "banned": False},
        },
    )

    assert response.status_code == 200
    assert user.is_active is True
    db.commit.assert_awaited_once()


def test_user_updated_banned_keeps_user_inactive(monkeypatch):
    """user.updated with banned=true must keep the user deactivated."""
    user = _make_user(is_active=False)
    db = _make_db(user)
    client = _make_client(monkeypatch, db)

    response = _signed_post(
        client,
        {
            "object": "event",
            "type": "user.updated",
            "data": {"object": "user", "id": CLERK_USER_ID, "banned": True},
        },
    )

    assert response.status_code == 200
    assert user.is_active is False
    db.commit.assert_awaited_once()


def test_session_created_is_noop(monkeypatch):
    """session.created must be accepted but perform no DB work."""
    db = _make_db(_make_user())
    client = _make_client(monkeypatch, db)

    response = _signed_post(
        client,
        {
            "object": "event",
            "type": "session.created",
            "data": {"object": "session", "id": "sess_1", "user_id": CLERK_USER_ID},
        },
    )

    assert response.status_code == 200
    db.execute.assert_not_called()
    db.commit.assert_not_called()


def test_invalid_signature_rejected_without_db_touch(monkeypatch):
    """A tampered signature must 401 and leave the user's is_active untouched."""
    user = _make_user(is_active=True)
    db = _make_db(user)
    client = _make_client(monkeypatch, db)

    msg_id = "msg_" + uuid.uuid4().hex[:16]
    ts = datetime.now(timezone.utc)
    data = json.dumps(
        {"object": "event", "type": "user.banned", "data": {"id": CLERK_USER_ID}}
    )
    signature = Webhook(WEBHOOK_SECRET).sign(msg_id, ts, data)
    headers = {
        "svix-id": msg_id,
        "svix-timestamp": str(int(ts.timestamp())),
        "svix-signature": signature[:-4] + "AAAA",  # tamper with the signature
        "Content-Type": "application/json",
    }

    response = client.post("/api/webhooks/clerk", content=data, headers=headers)

    assert response.status_code == 401
    assert user.is_active is True
    db.execute.assert_not_called()
    db.commit.assert_not_called()


def test_unsigned_request_rejected_without_db_touch(monkeypatch):
    """A request with no Svix headers must 401 and not touch the DB."""
    user = _make_user(is_active=True)
    db = _make_db(user)
    client = _make_client(monkeypatch, db)

    response = client.post(
        "/api/webhooks/clerk",
        content=json.dumps({"object": "event", "type": "user.banned", "data": {}}),
        headers={"Content-Type": "application/json"},
    )

    assert response.status_code == 401
    assert user.is_active is True
    db.execute.assert_not_called()
    db.commit.assert_not_called()


def test_revoke_event_for_unknown_user_is_noop(monkeypatch):
    """A revocation for a user with no local row must 200 without failing."""
    db = _make_db(None)
    client = _make_client(monkeypatch, db)

    response = _signed_post(
        client,
        {
            "object": "event",
            "type": "user.deleted",
            "data": {"object": "user", "id": "user_does_not_exist", "deleted": True},
        },
    )

    assert response.status_code == 200
    db.commit.assert_not_called()

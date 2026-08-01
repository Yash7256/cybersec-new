"""
Unit tests for JWT audience verification in get_optional_user.

When CLERK_AUDIENCE is set, tokens with a wrong or missing aud claim must be
rejected (returns None). Tokens whose aud matches must succeed. When
CLERK_AUDIENCE is empty, the previous permissive behavior is preserved.
"""
from __future__ import annotations

import time
from unittest.mock import AsyncMock, patch

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.security import HTTPAuthorizationCredentials

from cybersec.apps.api.deps import get_optional_user
from cybersec.database.models import User

ISSUER = "https://test.clerk.accounts.dev"
AUDIENCE = "cybersec-toolkit-api"
KID = "test-kid-1"


@pytest.fixture(scope="module")
def rsa_keypair():
    """Generate a disposable RSA key pair for signing/verifying test JWTs."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key, private_key.public_key()


def _make_token(private_key, *, aud=None, include_aud=True, sub="user_test_123") -> str:
    """Build a signed RS256 JWT with optional aud claim."""
    now = int(time.time())
    payload = {
        "sub": sub,
        "email": "test@example.com",
        "iss": ISSUER,
        "iat": now,
        "exp": now + 3600,
        "nbf": now,
    }
    if include_aud:
        payload["aud"] = aud if aud is not None else AUDIENCE
    return jwt.encode(
        payload,
        private_key,
        algorithm="RS256",
        headers={"kid": KID},
    )


def _credentials(token: str) -> HTTPAuthorizationCredentials:
    return HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)


def _active_user() -> User:
    return User(
        id="00000000-0000-0000-0000-000000000001",
        clerk_user_id="user_test_123",
        email="test@example.com",
        is_active=True,
    )


@pytest.mark.asyncio
async def test_rejects_wrong_audience_when_clerk_audience_set(rsa_keypair):
    """Wrong aud claim → get_optional_user returns None when CLERK_AUDIENCE is set."""
    private_key, public_key = rsa_keypair
    token = _make_token(private_key, aud="some-other-app")

    with (
        patch("cybersec.apps.api.deps.settings") as mock_settings,
        patch(
            "cybersec.apps.api.deps.get_clerk_public_key",
            new_callable=AsyncMock,
            return_value=public_key,
        ),
        patch(
            "cybersec.apps.api.deps.sync_clerk_user",
            new_callable=AsyncMock,
        ) as mock_sync,
    ):
        mock_settings.CLERK_ISSUER = ISSUER
        mock_settings.CLERK_AUDIENCE = AUDIENCE

        result = await get_optional_user(
            credentials=_credentials(token),
            db=AsyncMock(),
        )

        assert result is None
        mock_sync.assert_not_called()


@pytest.mark.asyncio
async def test_rejects_missing_audience_when_clerk_audience_set(rsa_keypair):
    """Missing aud claim → get_optional_user returns None when CLERK_AUDIENCE is set."""
    private_key, public_key = rsa_keypair
    token = _make_token(private_key, include_aud=False)

    with (
        patch("cybersec.apps.api.deps.settings") as mock_settings,
        patch(
            "cybersec.apps.api.deps.get_clerk_public_key",
            new_callable=AsyncMock,
            return_value=public_key,
        ),
        patch(
            "cybersec.apps.api.deps.sync_clerk_user",
            new_callable=AsyncMock,
        ) as mock_sync,
    ):
        mock_settings.CLERK_ISSUER = ISSUER
        mock_settings.CLERK_AUDIENCE = AUDIENCE

        result = await get_optional_user(
            credentials=_credentials(token),
            db=AsyncMock(),
        )

        assert result is None
        mock_sync.assert_not_called()


@pytest.mark.asyncio
async def test_accepts_matching_audience_when_clerk_audience_set(rsa_keypair):
    """Matching aud claim → get_optional_user returns the synced user."""
    private_key, public_key = rsa_keypair
    token = _make_token(private_key, aud=AUDIENCE)
    user = _active_user()

    with (
        patch("cybersec.apps.api.deps.settings") as mock_settings,
        patch(
            "cybersec.apps.api.deps.get_clerk_public_key",
            new_callable=AsyncMock,
            return_value=public_key,
        ),
        patch(
            "cybersec.apps.api.deps.sync_clerk_user",
            new_callable=AsyncMock,
            return_value=user,
        ) as mock_sync,
    ):
        mock_settings.CLERK_ISSUER = ISSUER
        mock_settings.CLERK_AUDIENCE = AUDIENCE

        result = await get_optional_user(
            credentials=_credentials(token),
            db=AsyncMock(),
        )

        assert result is user
        mock_sync.assert_awaited_once()


@pytest.mark.asyncio
async def test_permissive_when_clerk_audience_unset(rsa_keypair):
    """Empty CLERK_AUDIENCE keeps backward-compatible behavior (no aud required)."""
    private_key, public_key = rsa_keypair
    token = _make_token(private_key, include_aud=False)
    user = _active_user()

    with (
        patch("cybersec.apps.api.deps.settings") as mock_settings,
        patch(
            "cybersec.apps.api.deps.get_clerk_public_key",
            new_callable=AsyncMock,
            return_value=public_key,
        ),
        patch(
            "cybersec.apps.api.deps.sync_clerk_user",
            new_callable=AsyncMock,
            return_value=user,
        ) as mock_sync,
    ):
        mock_settings.CLERK_ISSUER = ISSUER
        mock_settings.CLERK_AUDIENCE = ""

        result = await get_optional_user(
            credentials=_credentials(token),
            db=AsyncMock(),
        )

        assert result is user
        mock_sync.assert_awaited_once()


@pytest.mark.asyncio
async def test_no_credentials_returns_none():
    """No Authorization header → None without attempting decode."""
    result = await get_optional_user(credentials=None, db=AsyncMock())
    assert result is None

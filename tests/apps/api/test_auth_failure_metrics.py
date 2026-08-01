"""
Tests for auth validation failure metrics.

Every failure path in `get_optional_user` must increment the
`auth_validation_failures_total` counter with the right `reason` label
(and the per-IP counter, which is cardinality-bounded).
"""
from __future__ import annotations

import time
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.security import HTTPAuthorizationCredentials

from cybersec.apps.api import deps as deps_module
from cybersec.apps.api.clerk_jwks import ClerkJWKSUnavailable
from cybersec.apps.api.deps import get_optional_user
from cybersec.database.models import User

ISSUER = "https://test.clerk.accounts.dev"
KID = "test-kid-1"


@pytest.fixture(scope="module")
def rsa_keypair():
    """Disposable RSA key pair for signing test JWTs."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key, private_key.public_key()


@pytest.fixture()
def metrics(monkeypatch):
    """Replace the metrics registry with a mock so we can assert on counter() calls."""
    mock_registry = MagicMock()
    monkeypatch.setattr(deps_module, "registry", lambda: mock_registry)
    return mock_registry


def _token(private_key, *, sub="user_test_123", include_sub=True, include_kid=True) -> str:
    """Build a signed RS256 JWT with optional kid header / sub claim."""
    now = int(time.time())
    payload = {
        "email": "test@example.com",
        "iss": ISSUER,
        "iat": now,
        "exp": now + 3600,
        "nbf": now,
    }
    if include_sub:
        payload["sub"] = sub
    headers = {"kid": KID} if include_kid else {}
    return jwt.encode(payload, private_key, algorithm="RS256", headers=headers)


def _credentials(token: str) -> HTTPAuthorizationCredentials:
    return HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)


def _valid_jwt_env(private_key, public_key, mock_settings):
    """Patch settings + key lookup so a properly-signed token validates."""
    mock_settings.CLERK_ISSUER = ISSUER
    mock_settings.CLERK_AUDIENCE = ""
    return patch(
        "cybersec.apps.api.deps.get_clerk_public_key",
        new_callable=AsyncMock,
        return_value=public_key,
    )


def _assert_total_failure(metrics, reason: str) -> None:
    call = metrics.counter.call_args
    assert call.args[0] == "auth_validation_failures_total"
    assert call.kwargs["labels"] == {"reason": reason}
    metrics.counter.return_value.inc.assert_called_once()


def _by_ip_calls(metrics) -> list:
    return [
        c for c in metrics.counter.call_args_list
        if c.args and c.args[0] == "auth_validation_failures_by_ip"
    ]


@pytest.mark.asyncio
async def test_missing_kid_increments_counter(rsa_keypair, metrics):
    """Token without a kid header → reason=missing_kid."""
    private_key, _ = rsa_keypair
    token = _token(private_key, include_kid=False)

    result = await get_optional_user(credentials=_credentials(token), db=AsyncMock())

    assert result is None
    _assert_total_failure(metrics, "missing_kid")


@pytest.mark.asyncio
async def test_unknown_kid_increments_counter(rsa_keypair, metrics):
    """kid not in JWKS cache (KeyError) → reason=unknown_kid."""
    private_key, _ = rsa_keypair
    token = _token(private_key)

    with patch(
        "cybersec.apps.api.deps.get_clerk_public_key",
        new_callable=AsyncMock,
        side_effect=KeyError("Unknown signing key kid='forged_kid'"),
    ):
        result = await get_optional_user(credentials=_credentials(token), db=AsyncMock())

    assert result is None
    _assert_total_failure(metrics, "unknown_kid")


@pytest.mark.asyncio
async def test_jwt_error_increments_counter(rsa_keypair, metrics):
    """JWKS unreachable (ClerkJWKSUnavailable) → reason=jwt_error."""
    private_key, _ = rsa_keypair
    token = _token(private_key)

    with patch(
        "cybersec.apps.api.deps.get_clerk_public_key",
        new_callable=AsyncMock,
        side_effect=ClerkJWKSUnavailable("endpoint unreachable"),
    ):
        result = await get_optional_user(credentials=_credentials(token), db=AsyncMock())

    assert result is None
    _assert_total_failure(metrics, "jwt_error")


@pytest.mark.asyncio
async def test_signature_mismatch_increments_counter(rsa_keypair, metrics):
    """Valid-looking token signed with the wrong key → reason=jwt_error."""
    private_key, public_key = rsa_keypair
    other_private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    token = _token(other_private)  # signed with a different key than we "verify" with

    with (
        patch("cybersec.apps.api.deps.settings") as mock_settings,
        _valid_jwt_env(private_key, public_key, mock_settings),
    ):
        result = await get_optional_user(credentials=_credentials(token), db=AsyncMock())

    assert result is None
    _assert_total_failure(metrics, "jwt_error")


@pytest.mark.asyncio
async def test_missing_sub_increments_counter(rsa_keypair, metrics):
    """Valid signature but no sub claim → reason=missing_sub."""
    private_key, public_key = rsa_keypair
    token = _token(private_key, include_sub=False)

    with (
        patch("cybersec.apps.api.deps.settings") as mock_settings,
        _valid_jwt_env(private_key, public_key, mock_settings),
    ):
        result = await get_optional_user(credentials=_credentials(token), db=AsyncMock())

    assert result is None
    _assert_total_failure(metrics, "missing_sub")


@pytest.mark.asyncio
async def test_inactive_user_increments_counter(rsa_keypair, metrics):
    """Synced user is inactive → reason=inactive_user."""
    private_key, public_key = rsa_keypair
    token = _token(private_key)
    inactive = User(
        id="00000000-0000-0000-0000-000000000001",
        clerk_user_id="user_test_123",
        is_active=False,
    )

    with (
        patch("cybersec.apps.api.deps.settings") as mock_settings,
        _valid_jwt_env(private_key, public_key, mock_settings),
        patch(
            "cybersec.apps.api.deps.sync_clerk_user",
            new_callable=AsyncMock,
            return_value=inactive,
        ),
    ):
        result = await get_optional_user(credentials=_credentials(token), db=AsyncMock())

    assert result is None
    _assert_total_failure(metrics, "inactive_user")


@pytest.mark.asyncio
async def test_sync_error_increments_counter(rsa_keypair, metrics):
    """User sync raises → reason=sync_error."""
    private_key, public_key = rsa_keypair
    token = _token(private_key)

    with (
        patch("cybersec.apps.api.deps.settings") as mock_settings,
        _valid_jwt_env(private_key, public_key, mock_settings),
        patch(
            "cybersec.apps.api.deps.sync_clerk_user",
            new_callable=AsyncMock,
            side_effect=Exception("db boom"),
        ),
    ):
        result = await get_optional_user(credentials=_credentials(token), db=AsyncMock())

    assert result is None
    _assert_total_failure(metrics, "sync_error")


@pytest.mark.asyncio
async def test_unexpected_error_increments_counter(rsa_keypair, metrics):
    """Non-PyJWT error during validation → reason=unexpected_error."""
    private_key, _ = rsa_keypair
    token = _token(private_key)

    with patch(
        "cybersec.apps.api.deps.get_clerk_public_key",
        new_callable=AsyncMock,
        side_effect=RuntimeError("internal oops"),
    ):
        result = await get_optional_user(credentials=_credentials(token), db=AsyncMock())

    assert result is None
    _assert_total_failure(metrics, "unexpected_error")


@pytest.mark.asyncio
async def test_by_ip_counter_uses_client_ip(rsa_keypair, metrics):
    """With a request present, the per-IP counter increments with the client IP."""
    private_key, _ = rsa_keypair
    token = _token(private_key, include_kid=False)
    request = SimpleNamespace(client=SimpleNamespace(host="203.0.113.42"))

    result = await get_optional_user(
        credentials=_credentials(token), db=AsyncMock(), request=request
    )

    assert result is None
    calls = _by_ip_calls(metrics)
    assert len(calls) == 1
    assert calls[0].kwargs["labels"] == {"ip": "203.0.113.42"}


@pytest.mark.asyncio
async def test_by_ip_counter_capped_cardinality(monkeypatch, rsa_keypair, metrics, caplog):
    """Beyond the IP series cap, new IPs are logged at WARNING, not added to metrics."""
    monkeypatch.setattr(deps_module, "MAX_AUTH_FAILURE_IP_SERIES", 2)
    monkeypatch.setattr(deps_module, "_auth_failure_ips", set())
    private_key, _ = rsa_keypair
    token = _token(private_key, include_kid=False)

    for host in ("203.0.113.1", "203.0.113.2", "203.0.113.3"):
        request = SimpleNamespace(client=SimpleNamespace(host=host))
        await get_optional_user(credentials=_credentials(token), db=AsyncMock(), request=request)

    ips = sorted(c.kwargs["labels"]["ip"] for c in _by_ip_calls(metrics))
    assert ips == ["203.0.113.1", "203.0.113.2"]
    assert "203.0.113.3" in caplog.text


def test_registry_dumps_labeled_counter():
    """Labeled counters render as proper Prometheus series with clean HELP/TYPE lines."""
    from cybersec.core.metrics_registry import MetricsRegistry

    reg = MetricsRegistry()
    reg.counter("auth_validation_failures_total", "h", labels={"reason": "unknown_kid"}).inc()
    reg.counter("auth_validation_failures_total", "h", labels={"reason": "jwt_error"}).inc()
    reg.counter("scan_total", "s").inc()

    out = reg.dump_prometheus()
    assert '# TYPE cybersec_auth_validation_failures_total counter' in out
    assert '# HELP cybersec_auth_validation_failures_total h' in out
    assert 'cybersec_auth_validation_failures_total{reason="unknown_kid"} 1' in out
    assert 'cybersec_auth_validation_failures_total{reason="jwt_error"} 1' in out
    assert "cybersec_scan_total 1" in out

import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from sqlalchemy.exc import IntegrityError
from cybersec.apps.api.user_sync import sync_clerk_user, fetch_clerk_user_email
from cybersec.database.models import User

@pytest.mark.asyncio
async def test_fetch_clerk_user_email_success():
    """Test fetch_clerk_user_email fetches the email successfully from Clerk API."""
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "email_addresses": [{"email_address": "test@example.com"}]
    }

    with patch("cybersec.apps.api.user_sync.settings") as mock_settings, \
         patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_settings.CLERK_SECRET_KEY = "mock_key"
        mock_get.return_value = mock_response

        email = await fetch_clerk_user_email("user_123")
        assert email == "test@example.com"
        mock_get.assert_called_once_with(
            "https://api.clerk.com/v1/users/user_123",
            headers={"Authorization": "Bearer mock_key"},
            timeout=5.0
        )

@pytest.mark.asyncio
async def test_fetch_clerk_user_email_no_key():
    """Test fetch_clerk_user_email returns None if CLERK_SECRET_KEY is missing."""
    with patch("cybersec.apps.api.user_sync.settings") as mock_settings:
        mock_settings.CLERK_SECRET_KEY = ""
        email = await fetch_clerk_user_email("user_123")
        assert email is None

@pytest.mark.asyncio
async def test_sync_clerk_user_fast_path():
    """Test sync_clerk_user returns the existing user immediately if clerk_user_id matches."""
    db = AsyncMock()
    mock_user = User(id="user_1", clerk_user_id="user_123", email="test@example.com")
    
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = mock_user
    db.execute.return_value = mock_result

    user = await sync_clerk_user("user_123", "test@example.com", db)
    assert user == mock_user
    db.commit.assert_not_called()

@pytest.mark.asyncio
async def test_sync_clerk_user_email_match():
    """Test sync_clerk_user updates clerk_user_id of existing user with same email."""
    db = AsyncMock()
    existing_user = User(id="user_1", clerk_user_id="user_old", email="test@example.com")
    
    # 1st execution: select by clerk_user_id -> None
    # 2nd execution: select by email -> existing_user
    mock_result_clerk = MagicMock()
    mock_result_clerk.scalar_one_or_none.return_value = None
    
    mock_result_email = MagicMock()
    mock_result_email.scalar_one_or_none.return_value = existing_user
    
    db.execute.side_effect = [mock_result_clerk, mock_result_email]

    user = await sync_clerk_user("user_new", "test@example.com", db)
    assert user == existing_user
    assert existing_user.clerk_user_id == "user_new"
    db.commit.assert_awaited_once()

@pytest.mark.asyncio
async def test_sync_clerk_user_fetch_email_from_api():
    """Test sync_clerk_user fetches email from Clerk API when missing in payload."""
    db = AsyncMock()
    
    mock_result_clerk = MagicMock()
    mock_result_clerk.scalar_one_or_none.return_value = None
    
    mock_result_email = MagicMock()
    mock_result_email.scalar_one_or_none.return_value = None
    
    db.execute.side_effect = [mock_result_clerk, mock_result_email]

    with patch("cybersec.apps.api.user_sync.fetch_clerk_user_email", new_callable=AsyncMock) as mock_fetch:
        mock_fetch.return_value = "fetched@example.com"
        
        user = await sync_clerk_user("user_123", None, db)
        
        mock_fetch.assert_called_once_with("user_123")
        assert user.email == "fetched@example.com"
        assert user.clerk_user_id == "user_123"
        db.add.assert_called_once_with(user)
        db.commit.assert_awaited_once()

"""Tests for the OAuth auth infrastructure."""

import time
from unittest.mock import patch

from dont_track_me.core.auth import (
    AuthenticationRequired,
    TokenData,
    TokenStore,
    get_platform_credentials,
)

# Keyring is imported lazily inside TokenStore methods, so we patch the
# keyring module directly rather than dont_track_me.core.auth.keyring.
_KEYRING = "keyring"


def test_token_data_not_expired():
    token = TokenData(
        access_token="test",
        expires_at=time.time() + 3600,
        platform="test",
    )
    assert not token.is_expired


def test_token_data_expired():
    token = TokenData(
        access_token="test",
        expires_at=time.time() - 100,
        platform="test",
    )
    assert token.is_expired


def test_token_data_no_expiry():
    token = TokenData(access_token="test", platform="test")
    assert not token.is_expired


@patch(f"{_KEYRING}.get_password")
@patch(f"{_KEYRING}.set_password")
def test_token_store_save_load(mock_set_pw, mock_get_pw):
    """Save and load should round-trip through keyring."""
    stored = {}

    def set_pw(service, user, data):
        stored[(service, user)] = data

    def get_pw(service, user):
        return stored.get((service, user))

    mock_set_pw.side_effect = set_pw
    mock_get_pw.side_effect = get_pw

    token = TokenData(
        access_token="abc123",
        refresh_token="refresh456",
        expires_at=time.time() + 3600,
        platform="reddit",
    )

    TokenStore.save("reddit", token)
    loaded = TokenStore.load("reddit")

    assert loaded is not None
    assert loaded.access_token == "abc123"
    assert loaded.refresh_token == "refresh456"
    assert loaded.platform == "reddit"


@patch(f"{_KEYRING}.get_password", return_value=None)
def test_token_store_load_missing(mock_get_pw):
    assert TokenStore.load("nonexistent") is None


@patch(f"{_KEYRING}.get_password")
def test_token_store_is_authenticated(mock_get_pw):
    token = TokenData(
        access_token="test",
        expires_at=time.time() + 3600,
        platform="reddit",
    )
    mock_get_pw.return_value = token.model_dump_json()
    assert TokenStore.is_authenticated("reddit") is True


@patch(f"{_KEYRING}.get_password")
def test_token_store_not_authenticated_expired(mock_get_pw):
    token = TokenData(
        access_token="test",
        expires_at=time.time() - 100,
        platform="reddit",
    )
    mock_get_pw.return_value = token.model_dump_json()
    assert TokenStore.is_authenticated("reddit") is False


def test_authentication_required_exception():
    exc = AuthenticationRequired("reddit")
    assert exc.platform == "reddit"
    assert "dtm auth reddit" in str(exc)


@patch.dict(
    "os.environ",
    {"DTM_REDDIT_CLIENT_ID": "env_id", "DTM_REDDIT_CLIENT_SECRET": "env_secret"},
)
def test_get_platform_credentials_from_env():
    client_id, client_secret = get_platform_credentials("reddit")
    assert client_id == "env_id"
    assert client_secret == "env_secret"


# --- get_default_country tests ---


@patch.dict("os.environ", {"DTM_COUNTRY": "fr"})
def test_get_default_country_from_env():
    from dont_track_me.core.config import get_default_country

    assert get_default_country() == "fr"


@patch.dict("os.environ", {}, clear=True)
@patch("dont_track_me.core.config.load_config", return_value={})
def test_get_default_country_fallback(mock_config):
    from dont_track_me.core.config import get_default_country

    assert get_default_country() == "us"

"""OAuth infrastructure — token storage, OAuth flow, and OAuthModule base class."""

from __future__ import annotations

import asyncio
import contextlib
import os
import secrets
import time
import webbrowser
from abc import abstractmethod
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse

import httpx
from pydantic import BaseModel

from dont_track_me.core.base import BaseModule
from dont_track_me.core.config import load_config

KEYRING_SERVICE_PREFIX = "dont-track-me"
REDIRECT_PORT = 8914
REDIRECT_URI = f"http://localhost:{REDIRECT_PORT}/callback"


class AuthenticationRequired(Exception):
    """Raised when a module requires authentication but no token is available."""

    def __init__(self, platform: str) -> None:
        self.platform = platform
        super().__init__(f"Not authenticated. Run: dtm auth {platform}")


class TokenData(BaseModel):
    """Stored OAuth token data."""

    access_token: str
    refresh_token: str | None = None
    expires_at: float | None = None  # Unix timestamp
    token_type: str = "Bearer"
    scope: str = ""
    platform: str = ""

    @property
    def is_expired(self) -> bool:
        if self.expires_at is None:
            return False
        return time.time() > self.expires_at - 60  # 60s buffer


class TokenStore:
    """Store and retrieve OAuth tokens via keyring (system credential store)."""

    @staticmethod
    def _service_name(platform: str) -> str:
        return f"{KEYRING_SERVICE_PREFIX}:{platform}"

    @staticmethod
    def save(platform: str, token: TokenData) -> None:
        """Save token to system keyring."""
        import keyring

        token.platform = platform
        keyring.set_password(
            TokenStore._service_name(platform),
            "oauth_token",
            token.model_dump_json(),
        )

    @staticmethod
    def load(platform: str) -> TokenData | None:
        """Load token from system keyring. Returns None if not found."""
        import keyring

        data = keyring.get_password(
            TokenStore._service_name(platform),
            "oauth_token",
        )
        if data is None:
            return None
        try:
            return TokenData.model_validate_json(data)
        except (ValueError, KeyError):
            return None

    @staticmethod
    def delete(platform: str) -> None:
        """Delete stored token."""
        import keyring
        import keyring.errors

        with contextlib.suppress(keyring.errors.PasswordDeleteError):
            keyring.delete_password(
                TokenStore._service_name(platform),
                "oauth_token",
            )

    @staticmethod
    def is_authenticated(platform: str) -> bool:
        """Check if a valid (non-expired) token exists."""
        token = TokenStore.load(platform)
        if token is None:
            return False
        return not token.is_expired


def get_platform_credentials(platform: str) -> tuple[str, str]:
    """Get OAuth client_id and client_secret from config or env vars.

    Checks env vars first (DTM_YOUTUBE_CLIENT_ID, etc.), then TOML config.
    """
    prefix = f"DTM_{platform.upper()}"
    client_id = os.environ.get(f"{prefix}_CLIENT_ID")
    client_secret = os.environ.get(f"{prefix}_CLIENT_SECRET")

    if client_id and client_secret:
        return client_id, client_secret

    config = load_config()
    platform_config = config.get(platform, {})
    client_id = client_id or platform_config.get("client_id")
    client_secret = client_secret or platform_config.get("client_secret")

    if not client_id or not client_secret:
        raise ValueError(
            f"No credentials for {platform}. Set DTM_{platform.upper()}_CLIENT_ID "
            f"and DTM_{platform.upper()}_CLIENT_SECRET env vars, or add them to "
            f"~/.config/dont-track-me/config.toml under [{platform}]."
        )

    return client_id, client_secret


class _OAuthCallbackHandler(BaseHTTPRequestHandler):
    """HTTP handler that captures the OAuth redirect callback."""

    auth_code: str | None = None
    state: str | None = None
    error: str | None = None

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)

        if "error" in params:
            _OAuthCallbackHandler.error = params["error"][0]
        elif "code" in params:
            _OAuthCallbackHandler.auth_code = params["code"][0]
            _OAuthCallbackHandler.state = params.get("state", [None])[0]

        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()

        if _OAuthCallbackHandler.error:
            body = "<h1>Authentication failed</h1><p>You can close this tab.</p>"
        else:
            body = "<h1>Authentication successful!</h1><p>You can close this tab and return to the terminal.</p>"

        self.wfile.write(body.encode())

    def log_message(self, format: str, *args: Any) -> None:
        pass  # Suppress HTTP server logs


class OAuthFlow:
    """Execute an OAuth 2.0 authorization code flow with local redirect."""

    def __init__(
        self,
        authorize_url: str,
        token_url: str,
        client_id: str,
        client_secret: str,
        scopes: list[str],
        extra_params: dict[str, str] | None = None,
    ) -> None:
        self.authorize_url = authorize_url
        self.token_url = token_url
        self.client_id = client_id
        self.client_secret = client_secret
        self.scopes = scopes
        self.extra_params = extra_params or {}

    def run(self) -> TokenData:
        """Run the full OAuth flow: open browser → capture code → exchange for token."""
        # Reset handler state
        _OAuthCallbackHandler.auth_code = None
        _OAuthCallbackHandler.state = None
        _OAuthCallbackHandler.error = None

        state = secrets.token_urlsafe(32)

        params = {
            "client_id": self.client_id,
            "redirect_uri": REDIRECT_URI,
            "response_type": "code",
            "scope": " ".join(self.scopes),
            "state": state,
            **self.extra_params,
        }

        auth_url = f"{self.authorize_url}?{urlencode(params)}"

        # Start local server
        server = HTTPServer(("localhost", REDIRECT_PORT), _OAuthCallbackHandler)
        server_thread = Thread(target=server.handle_request, daemon=True)
        server_thread.start()

        # Open browser
        webbrowser.open(auth_url)

        # Wait for callback
        server_thread.join(timeout=120)
        server.server_close()

        if _OAuthCallbackHandler.error:
            raise RuntimeError(f"OAuth error: {_OAuthCallbackHandler.error}")

        if _OAuthCallbackHandler.auth_code is None:
            raise RuntimeError("OAuth flow timed out — no authorization code received.")

        if _OAuthCallbackHandler.state != state:
            raise RuntimeError("OAuth state mismatch — possible CSRF attack.")

        # Exchange code for token
        return self._exchange_code(_OAuthCallbackHandler.auth_code)

    def _exchange_code(self, code: str) -> TokenData:
        """Exchange authorization code for access/refresh tokens."""
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "client_id": self.client_id,
            "client_secret": self.client_secret,
        }

        with httpx.Client(timeout=15) as client:
            resp = client.post(self.token_url, data=data)
            resp.raise_for_status()
            token_data = resp.json()

        expires_at = None
        if "expires_in" in token_data:
            expires_at = time.time() + token_data["expires_in"]

        return TokenData(
            access_token=token_data["access_token"],
            refresh_token=token_data.get("refresh_token"),
            expires_at=expires_at,
            token_type=token_data.get("token_type", "Bearer"),
            scope=token_data.get("scope", ""),
        )


async def refresh_token(
    token: TokenData,
    token_url: str,
    client_id: str,
    client_secret: str,
) -> TokenData:
    """Refresh an expired OAuth token."""
    if not token.refresh_token:
        raise AuthenticationRequired(token.platform)

    data = {
        "grant_type": "refresh_token",
        "refresh_token": token.refresh_token,
        "client_id": client_id,
        "client_secret": client_secret,
    }

    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.post(token_url, data=data)
        resp.raise_for_status()
        token_data = resp.json()

    expires_at = None
    if "expires_in" in token_data:
        expires_at = time.time() + token_data["expires_in"]

    return TokenData(
        access_token=token_data["access_token"],
        refresh_token=token_data.get("refresh_token", token.refresh_token),
        expires_at=expires_at,
        token_type=token_data.get("token_type", "Bearer"),
        scope=token_data.get("scope", token.scope),
        platform=token.platform,
    )


class OAuthModule(BaseModule):
    """Base class for modules that require OAuth authentication."""

    platform_name: str  # e.g. "reddit", "youtube"

    def is_authenticated(self) -> bool:
        """Check if a valid token exists for this platform."""
        return TokenStore.is_authenticated(self.platform_name)

    def ensure_authenticated(self) -> TokenData:
        """Get token or raise AuthenticationRequired."""
        token = TokenStore.load(self.platform_name)
        if token is None:
            raise AuthenticationRequired(self.platform_name)
        if token.is_expired and token.refresh_token:
            # Try to refresh synchronously for simplicity
            try:
                client_id, client_secret = get_platform_credentials(self.platform_name)
                token_url = self._get_token_url()
                new_token = asyncio.get_event_loop().run_until_complete(
                    refresh_token(token, token_url, client_id, client_secret)
                )
                TokenStore.save(self.platform_name, new_token)
                return new_token
            except Exception as exc:
                raise AuthenticationRequired(self.platform_name) from exc
        if token.is_expired:
            raise AuthenticationRequired(self.platform_name)
        return token

    @abstractmethod
    def _get_token_url(self) -> str:
        """Return the token endpoint URL for refreshing."""
        ...

"""Reddit API client — async httpx wrapper for OAuth-authenticated Reddit API calls."""

from __future__ import annotations

from typing import Any

import httpx

from dont_track_me.core.auth import TokenData

BASE_URL = "https://oauth.reddit.com"
USER_AGENT = "dont-track-me:v0.1.0 (privacy research toolkit)"

# Reddit OAuth endpoints
AUTHORIZE_URL = "https://www.reddit.com/api/v1/authorize"
TOKEN_URL = "https://www.reddit.com/api/v1/access_token"
SCOPES = ["identity", "mysubreddits", "read", "account", "edit"]

# Privacy-hostile settings that can be disabled
TRACKING_PREFS = {
    "activity_relevant_ads": {
        "safe_value": False,
        "description": "Reddit uses your activity to personalize ads",
    },
    "third_party_data_personalized_ads": {
        "safe_value": False,
        "description": "Third-party data is used to personalize ads shown to you",
    },
    "third_party_site_data_personalized_ads": {
        "safe_value": False,
        "description": "Your activity on other sites is used for Reddit ad targeting",
    },
    "third_party_site_data_personalized_content": {
        "safe_value": False,
        "description": "Your activity on other sites personalizes Reddit content",
    },
    "allow_clicktracking": {
        "safe_value": False,
        "description": "Reddit tracks your link clicks",
    },
    "public_votes": {
        "safe_value": False,
        "description": "Your upvotes and downvotes are publicly visible",
    },
    "show_presence": {
        "safe_value": False,
        "description": "Your online status is visible to others",
    },
}


class RedditClient:
    """Async client for Reddit's OAuth API."""

    def __init__(self, token: TokenData) -> None:
        self.token = token
        self._headers = {
            "Authorization": f"Bearer {token.access_token}",
            "User-Agent": USER_AGENT,
        }

    async def get_prefs(self) -> dict[str, Any]:
        """Get user preferences including privacy settings."""
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(
                f"{BASE_URL}/api/v1/me/prefs",
                headers=self._headers,
            )
            resp.raise_for_status()
            return resp.json()

    async def update_prefs(self, prefs: dict[str, Any]) -> dict[str, Any]:
        """Update user preferences."""
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.patch(
                f"{BASE_URL}/api/v1/me/prefs",
                headers=self._headers,
                json=prefs,
            )
            resp.raise_for_status()
            return resp.json()

    async def get_subscribed_subreddits(self) -> list[str]:
        """Get list of subscribed subreddit names."""
        subreddits: list[str] = []
        after: str | None = None

        async with httpx.AsyncClient(timeout=15) as client:
            while True:
                params: dict[str, Any] = {"limit": 100}
                if after:
                    params["after"] = after

                resp = await client.get(
                    f"{BASE_URL}/subreddits/mine/subscriber",
                    headers=self._headers,
                    params=params,
                )
                resp.raise_for_status()
                data = resp.json()

                for child in data.get("data", {}).get("children", []):
                    name = child.get("data", {}).get("display_name", "")
                    if name:
                        subreddits.append(name)

                after = data.get("data", {}).get("after")
                if not after:
                    break

        return subreddits

    async def subscribe(self, subreddit: str) -> bool:
        """Subscribe to a subreddit. Returns True on success."""
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(
                f"{BASE_URL}/api/subscribe",
                headers=self._headers,
                data={"action": "sub", "sr_name": subreddit},
            )
            return resp.status_code == 200

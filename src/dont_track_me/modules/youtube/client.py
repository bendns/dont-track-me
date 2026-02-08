"""YouTube Data API v3 client — async httpx wrapper."""

from __future__ import annotations

from typing import Any

import httpx

from dont_track_me.core.auth import TokenData

BASE_URL = "https://www.googleapis.com/youtube/v3"

# YouTube OAuth endpoints
AUTHORIZE_URL = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_URL = "https://oauth2.googleapis.com/token"
SCOPES = ["https://www.googleapis.com/auth/youtube"]


class YouTubeClient:
    """Async client for YouTube Data API v3."""

    def __init__(self, token: TokenData) -> None:
        self.token = token
        self._headers = {
            "Authorization": f"Bearer {token.access_token}",
        }

    async def get_subscriptions(self) -> list[dict[str, str]]:
        """Get all user subscriptions.

        Returns list of {channel_id, channel_title}.
        Costs 1 quota unit per page (50 results).
        """
        subscriptions: list[dict[str, str]] = []
        page_token: str | None = None

        async with httpx.AsyncClient(timeout=15) as client:
            while True:
                params: dict[str, Any] = {
                    "part": "snippet",
                    "mine": "true",
                    "maxResults": 50,
                }
                if page_token:
                    params["pageToken"] = page_token

                resp = await client.get(
                    f"{BASE_URL}/subscriptions",
                    headers=self._headers,
                    params=params,
                )
                resp.raise_for_status()
                data = resp.json()

                for item in data.get("items", []):
                    snippet = item.get("snippet", {})
                    resource = snippet.get("resourceId", {})
                    subscriptions.append(
                        {
                            "channel_id": resource.get("channelId", ""),
                            "channel_title": snippet.get("title", ""),
                        }
                    )

                page_token = data.get("nextPageToken")
                if not page_token:
                    break

        return subscriptions

    async def subscribe(self, channel_id: str) -> bool:
        """Subscribe to a channel.

        Costs ~50 quota units. With 10K daily quota, that's ~200 subscribes/day.
        """
        body = {
            "snippet": {
                "resourceId": {
                    "kind": "youtube#channel",
                    "channelId": channel_id,
                }
            }
        }

        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(
                f"{BASE_URL}/subscriptions",
                headers=self._headers,
                params={"part": "snippet"},
                json=body,
            )
            return resp.status_code in (200, 201)

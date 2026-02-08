"""YouTube channel classification database for bias analysis and diversification.

Channel IDs are the stable identifier (handles/names can change).
"""

import random

# {category: {perspective: [{id, name}]}}
CHANNELS: dict[str, dict[str, list[dict[str, str]]]] = {
    "politics": {
        "left": [
            {"id": "UC1yBKRuGpC1tSM73A0ZjYjQ", "name": "The Young Turks"},
            {"id": "UCtoaZpBnrd0lhycxYJ0QWIA", "name": "HasanAbi"},
            {"id": "UCNvsIonJdJ5E4EXMa65VYpA", "name": "ContraPoints"},
            {"id": "UC2PA-AKmVpU6NKCGtZq_rKQ", "name": "Philosophy Tube"},
            {"id": "UCvlj0IzjSnNoIn1fwY3Kngg", "name": "Some More News"},
        ],
        "right": [
            {"id": "UCnQC_G5Xsjhp9fEJKuIcrSw", "name": "Ben Shapiro"},
            {"id": "UCJdKr0Bgd_5saZYqLCa9mng", "name": "PragerU"},
            {"id": "UCL_f53ZEJxp8TtlOkHwMV9Q", "name": "Jordan B Peterson"},
            {"id": "UCIveFvW-ARp_B_RckhKnM5A", "name": "Steven Crowder"},
            {"id": "UCnQFq8M1ceN3saFRfOaHBqw", "name": "Matt Walsh"},
        ],
        "center": [
            {"id": "UCuMo0RRtnNDuMB8DV5stEag", "name": "Breaking Points"},
            {"id": "UCPQXVp2WiKm-8DKD0lN_zYQ", "name": "The Hill"},
            {"id": "UCe02lGcO-ahAURWuxAJnjdA", "name": "Tim Pool"},
            {"id": "UCsXVk37bltHxD1rDPwtNM8Q", "name": "Kurzgesagt"},
        ],
        "international": [
            {"id": "UCknLrEdhRCp1aegoMqRaCZg", "name": "DW News"},
            {"id": "UCQfwfsi5VrQ8yKZ-UWmAEFg", "name": "France 24 English"},
            {"id": "UCNye-wNBqNL5ZzHSJj3l8Bg", "name": "Al Jazeera English"},
            {"id": "UCHDkGM1Gp9ZGl7IQ1NO6gBw", "name": "WION"},
            {"id": "UC7fWeaHhqgM4Lba7jedRkVw", "name": "TRT World"},
        ],
    },
    "education": {
        "science": [
            {"id": "UCHnyfMqiRRG1u-2MsSQLbXA", "name": "Veritasium"},
            {"id": "UCsXVk37bltHxD1rDPwtNM8Q", "name": "Kurzgesagt"},
            {"id": "UC6107grRI4m0o2-emgoDnAA", "name": "SmarterEveryDay"},
            {"id": "UCo8bcnLyZH8tBIH9V1mLgqQ", "name": "PBS Space Time"},
            {"id": "UCYO_jab_esuFRV4b17AJtAw", "name": "3Blue1Brown"},
        ],
        "history": [
            {"id": "UCNIuvl7V8cR6x3N1OGYAi0w", "name": "Oversimplified"},
            {"id": "UC22BdTgxefuvUivrMic_GkQ", "name": "History Matters"},
            {"id": "UCMmaBzfCCwZ2KqaBJjkj0fw", "name": "Kings and Generals"},
            {"id": "UCCODtTcd5M1JavPCOr_Uydg", "name": "Extra History"},
        ],
        "philosophy": [
            {"id": "UCiRiQGCHGjDLT9FQXFW0I3A", "name": "Academy of Ideas"},
            {"id": "UCVBQ399Z65GkMPoOpTOkaHg", "name": "Einzelgänger"},
            {"id": "UCgNg3vwj3xt7QOrcIDaHdFg", "name": "Then & Now"},
            {"id": "UC9yt3wz-6j19RwD5m5f6HSg", "name": "Pursuit of Wonder"},
        ],
        "technology": [
            {"id": "UCXuqSBlHAE6Xw-yeJA0Tunw", "name": "Linus Tech Tips"},
            {"id": "UCBJycsmduvYEL83R_U4JriQ", "name": "MKBHD"},
            {"id": "UCsBjURrPoezykLs9EqgamOA", "name": "Fireship"},
            {"id": "UCVls1GmFKf6WlTraIb_IaJg", "name": "NetworkChuck"},
        ],
    },
    "entertainment": {
        "gaming": [
            {"id": "UC-lHJZR3Gqxm24_Vd_AJ5Yw", "name": "PewDiePie"},
            {"id": "UC7_YxT-KID8kRbqZo7MyscQ", "name": "Markiplier"},
            {"id": "UCYzPXprvl5Y-Sf0g4vX-m6g", "name": "jacksepticeye"},
            {"id": "UCX6OQ3DkcsbYNE6H8uQQuVA", "name": "MrBeast"},
        ],
        "music": [
            {"id": "UC2Qw1dzXDBAZPwS7zm37g8g", "name": "COLORS"},
            {"id": "UC4eYXhJI4-7wSWc8UNRwD4A", "name": "NPR Tiny Desk"},
        ],
        "comedy": [
            {"id": "UCx-KWLTKlB83hDI6UKECtJQ", "name": "Key & Peele"},
            {"id": "UCqFzWxSCi39LnW1JKFR3oGQ", "name": "Saturday Night Live"},
            {"id": "UCwWhs_6x42TyRM4Wstoq8HA", "name": "The Daily Show"},
            {"id": "UCPDis9pjXuqyI7RYLJ-TTSA", "name": "Russell Howard"},
        ],
        "cooking": [
            {"id": "UCJHA_jMfCvEnv-3kRjTCQXw", "name": "Binging with Babish"},
            {"id": "UCcjhYlDx7SRyCP6LVlad2hQ", "name": "Joshua Weissman"},
            {"id": "UC8gFadPgK2r1ndqLI04Xvvw", "name": "Maangchi"},
        ],
    },
    "sports": {
        "football": [
            {"id": "UCGlUhRSdRSGm3P7FwJ9YNtQ", "name": "Copa90"},
            {"id": "UCqZQlzSHbVJrwrn5XvzrG0g", "name": "GOAL"},
        ],
        "fitness": [
            {"id": "UCe0TLA0EsQbE-MjuHXevj2A", "name": "ATHLEAN-X"},
            {"id": "UCERm5yFZ1SptUEU4wZ2vJvw", "name": "Jeff Nippard"},
            {"id": "UCFKE7WVJfvaHW5q283SxchA", "name": "Yoga With Adriene"},
        ],
    },
}


def get_all_categories() -> list[str]:
    return list(CHANNELS.keys())


def classify_channel(channel_id: str) -> tuple[str, str, str] | None:
    """Classify a channel by its ID.

    Returns (category, perspective, name) or None if unknown.
    """
    for category, perspectives in CHANNELS.items():
        for perspective, channels in perspectives.items():
            for ch in channels:
                if ch["id"] == channel_id:
                    return category, perspective, ch["name"]
    return None


def get_balanced_channels(
    categories: list[str] | None = None,
    per_perspective: int = 2,
) -> list[dict[str, str]]:
    """Pick channels evenly across all perspectives.

    Returns list of {channel_id, name, category, perspective}.
    """
    if categories is None:
        categories = get_all_categories()

    result: list[dict[str, str]] = []
    for cat in categories:
        if cat not in CHANNELS:
            continue
        for perspective, channels in CHANNELS[cat].items():
            sample_size = min(per_perspective, len(channels))
            for ch in random.sample(channels, sample_size):
                result.append(
                    {
                        "channel_id": ch["id"],
                        "name": ch["name"],
                        "category": cat,
                        "perspective": perspective,
                    }
                )

    random.shuffle(result)
    return result

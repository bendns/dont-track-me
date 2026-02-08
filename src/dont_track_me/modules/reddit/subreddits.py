"""Subreddit classification database for bias analysis and diversification."""

import random

SUBREDDITS: dict[str, dict[str, list[str]]] = {
    "politics": {
        "left": [
            "progressive",
            "SandersForPresident",
            "DemocraticSocialism",
            "socialism",
            "LateStageCapitalism",
            "antiwork",
            "GreenParty",
            "WayOfTheBern",
            "Political_Revolution",
        ],
        "right": [
            "Conservative",
            "Republican",
            "Libertarian",
            "Anarcho_Capitalism",
            "walkaway",
            "LouderWithCrowder",
            "JordanPeterson",
            "benshapiro",
            "TimPool",
        ],
        "center": [
            "moderatepolitics",
            "centrist",
            "NeutralPolitics",
            "PoliticalDiscussion",
            "neoliberal",
            "tuesday",
            "Ask_Politics",
            "PoliticalPhilosophy",
        ],
        "international": [
            "worldpolitics",
            "geopolitics",
            "europe",
            "ukpolitics",
            "CanadaPolitics",
            "AustralianPolitics",
            "IndianPolitics",
            "france",
            "de",
        ],
    },
    "news": {
        "mainstream": [
            "news",
            "worldnews",
            "UpliftingNews",
            "nottheonion",
            "inthenews",
        ],
        "investigative": [
            "journalism",
            "media_criticism",
            "Documentaries",
            "longform",
            "TrueReddit",
        ],
        "local": [
            "nyc",
            "LosAngeles",
            "chicago",
            "bayarea",
            "london",
            "toronto",
        ],
    },
    "religion": {
        "christianity": [
            "Christianity",
            "Catholicism",
            "OrthodoxChristianity",
            "Reformed",
            "OpenChristian",
        ],
        "islam": [
            "islam",
            "progressive_islam",
            "MuslimLounge",
            "converts",
            "Sufism",
        ],
        "judaism": [
            "Judaism",
            "Jewish",
            "jewishguns",
        ],
        "buddhism": [
            "Buddhism",
            "zenbuddhism",
            "theravada",
            "Meditation",
        ],
        "hinduism": [
            "hinduism",
            "yoga",
            "Vedanta",
        ],
        "atheism": [
            "atheism",
            "TrueAtheism",
            "DebateAnAtheist",
            "humanism",
            "secularism",
        ],
    },
    "science_tech": {
        "science": [
            "science",
            "askscience",
            "EverythingScience",
            "space",
            "physics",
            "biology",
        ],
        "technology": [
            "technology",
            "programming",
            "linux",
            "opensource",
            "netsec",
            "privacy",
        ],
        "ai": [
            "MachineLearning",
            "artificial",
            "ChatGPT",
            "LocalLLaMA",
            "singularity",
        ],
    },
    "culture": {
        "music": [
            "Music",
            "hiphopheads",
            "Metal",
            "classicalmusic",
            "Jazz",
            "kpop",
            "country",
            "indieheads",
            "EDM",
        ],
        "art": [
            "Art",
            "museum",
            "ArtHistory",
            "StreetArt",
            "photography",
            "cinema",
        ],
        "books": [
            "books",
            "literature",
            "suggestmeabook",
            "philosophy",
            "history",
        ],
        "sports": [
            "sports",
            "soccer",
            "nba",
            "nfl",
            "formula1",
            "Cricket",
            "tennis",
            "MMA",
            "running",
        ],
    },
    "lifestyle": {
        "cooking": [
            "Cooking",
            "food",
            "MealPrepSunday",
            "AskCulinary",
            "veganrecipes",
            "BBQ",
        ],
        "outdoors": [
            "hiking",
            "camping",
            "fishing",
            "gardening",
            "Bushcraft",
            "birdwatching",
        ],
        "fitness": [
            "Fitness",
            "bodyweightfitness",
            "running",
            "yoga",
            "CrossFit",
            "Swimming",
        ],
        "gaming": [
            "gaming",
            "pcgaming",
            "PS5",
            "NintendoSwitch",
            "patientgamers",
            "boardgames",
        ],
    },
}


def get_all_categories() -> list[str]:
    return list(SUBREDDITS.keys())


def classify_subreddit(name: str) -> tuple[str, str] | None:
    """Classify a subreddit by category and perspective.

    Returns (category, perspective) or None if unknown.
    """
    name_lower = name.lower()
    for category, perspectives in SUBREDDITS.items():
        for perspective, subs in perspectives.items():
            if any(s.lower() == name_lower for s in subs):
                return category, perspective
    return None


def get_balanced_subreddits(
    categories: list[str] | None = None,
    per_perspective: int = 2,
) -> list[dict[str, str]]:
    """Pick subreddits evenly across all perspectives.

    Returns list of {subreddit, category, perspective}.
    """
    if categories is None:
        categories = get_all_categories()

    result: list[dict[str, str]] = []
    for cat in categories:
        if cat not in SUBREDDITS:
            continue
        for perspective, subs in SUBREDDITS[cat].items():
            sample_size = min(per_perspective, len(subs))
            for sub in random.sample(subs, sample_size):
                result.append(
                    {
                        "subreddit": sub,
                        "category": cat,
                        "perspective": perspective,
                    }
                )

    random.shuffle(result)
    return result

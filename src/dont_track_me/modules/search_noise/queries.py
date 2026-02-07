"""Curated search query database organized by category and perspective.

Each category contains multiple perspectives with balanced query lists.
The goal: generate searches that span the full spectrum so no single
ideological or lifestyle profile can be inferred.
"""

QUERIES: dict[str, dict[str, list[str]]] = {
    "politics": {
        "left": [
            "progressive policy benefits research",
            "universal healthcare advantages studies",
            "wealth inequality solutions economic research",
            "climate change policy green new deal",
            "workers rights union benefits history",
            "social safety net poverty reduction",
            "democratic socialism explained",
            "racial justice reform policy",
            "minimum wage increase economic impact",
            "free public education benefits society",
            "immigration reform pathway citizenship",
            "gun control legislation effectiveness",
            "renewable energy transition jobs",
            "affordable housing policy solutions",
            "LGBTQ rights legislation progress",
        ],
        "right": [
            "conservative economic policy benefits",
            "tax reform economic growth research",
            "free market capitalism advantages",
            "second amendment rights importance",
            "small government benefits efficiency",
            "traditional values family policy",
            "border security national sovereignty",
            "deregulation business growth studies",
            "school choice education reform",
            "fiscal responsibility balanced budget",
            "military strength national defense",
            "law enforcement support community safety",
            "religious liberty protection policy",
            "energy independence fossil fuels",
            "constitutional originalism legal theory",
        ],
        "center": [
            "bipartisan policy solutions research",
            "moderate political views benefits",
            "political compromise democracy",
            "centrist approach governance",
            "cross-party cooperation examples",
            "pragmatic policy making evidence based",
            "independent voter perspectives",
            "balanced approach immigration reform",
            "mixed economy advantages research",
            "civil discourse political dialogue",
        ],
        "libertarian": [
            "individual liberty policy freedom",
            "libertarian philosophy explained",
            "government overreach examples",
            "free market solutions social problems",
            "civil liberties protection importance",
            "non-interventionist foreign policy",
            "cryptocurrency decentralization benefits",
            "private property rights economics",
            "voluntary association community",
            "drug decriminalization policy results",
        ],
        "green": [
            "green party platform environment",
            "ecological economics sustainability",
            "degrowth movement research",
            "environmental justice communities",
            "biodiversity conservation policy",
            "sustainable agriculture transition",
            "circular economy implementation",
            "climate activism grassroots movements",
            "rewilding projects ecosystem restoration",
            "zero waste lifestyle community",
        ],
    },
    "religion": {
        "christianity": [
            "christian theology studies modern",
            "bible study commentary analysis",
            "church history reformation",
            "christian philosophy ethics",
            "gospel teachings daily life",
            "catholic social teaching principles",
            "protestant reformation history",
            "orthodox christianity traditions",
            "christian meditation prayer practices",
            "theology of liberation explained",
        ],
        "islam": [
            "islamic philosophy research history",
            "quran studies interpretation modern",
            "islamic golden age science contributions",
            "sufi poetry rumi spiritual",
            "islamic finance principles ethics",
            "ramadan traditions cultural significance",
            "islamic art architecture history",
            "muslim contributions civilization",
            "sharia law academic understanding",
            "interfaith dialogue islam christianity",
        ],
        "judaism": [
            "jewish philosophy talmud study",
            "torah commentary modern interpretation",
            "jewish cultural traditions holidays",
            "kabbalah mysticism spirituality",
            "jewish contributions science arts",
            "hebrew language learning history",
            "jewish diaspora history culture",
            "synagogue traditions community",
            "jewish ethics tikkun olam",
            "israeli culture society modern",
        ],
        "buddhism": [
            "buddhist meditation techniques mindfulness",
            "zen philosophy daily practice",
            "tibetan buddhism teachings dalai lama",
            "buddhist philosophy suffering enlightenment",
            "theravada buddhism traditions",
            "buddhist art temples architecture",
            "mindfulness based stress reduction",
            "buddhist economics simplicity",
            "karma dharma explained simply",
            "buddhist approach modern life",
        ],
        "hinduism": [
            "hindu philosophy vedanta upanishads",
            "yoga spiritual practice origins",
            "bhagavad gita teachings explained",
            "hindu festivals traditions diwali",
            "ayurveda traditional medicine",
            "hindu temples architecture history",
            "sanskrit language ancient texts",
            "meditation hindu tradition",
            "hindu mythology stories meaning",
            "karma reincarnation philosophy",
        ],
        "atheism": [
            "secular humanism philosophy ethics",
            "atheist philosophy critical thinking",
            "science religion relationship debate",
            "secular ethics moral philosophy",
            "rationalism enlightenment history",
            "freethought movement history",
            "naturalism philosophical worldview",
            "secular meditation mindfulness",
            "humanist approach community building",
            "evidence based worldview philosophy",
        ],
    },
    "news_sources": {
        "mainstream_left": [
            "CNN latest news today",
            "MSNBC news coverage analysis",
            "New York Times editorial today",
            "Washington Post investigation",
            "The Guardian world news",
            "NPR news morning edition",
            "BBC news world coverage",
            "HuffPost news latest",
        ],
        "mainstream_right": [
            "Fox News latest coverage",
            "Wall Street Journal opinion",
            "Daily Telegraph news today",
            "New York Post breaking news",
            "The Economist analysis weekly",
            "National Review commentary",
            "Daily Mail news today",
            "Washington Times editorial",
        ],
        "international": [
            "Al Jazeera world news coverage",
            "Reuters international breaking news",
            "France 24 news europe",
            "Deutsche Welle world news",
            "NHK Japan news english",
            "RT news international coverage",
            "South China Morning Post asia",
            "Times of India news today",
        ],
        "independent": [
            "ProPublica investigative journalism",
            "The Intercept news investigation",
            "Substack independent journalism",
            "local news community reporting",
            "Associated Press fact check",
            "Snopes fact checking latest",
            "Politifact truth meter check",
            "AllSides media bias news",
        ],
    },
    "interests": {
        "sports": [
            "football soccer world cup highlights",
            "NBA basketball season scores",
            "tennis grand slam results",
            "Formula 1 race results standings",
            "cricket world cup scores",
            "rugby six nations highlights",
            "golf PGA tour leaderboard",
            "MMA UFC fight results",
        ],
        "arts": [
            "contemporary art exhibition museum",
            "classical music concert schedule",
            "modern dance performance review",
            "film festival independent cinema",
            "poetry literary magazine new",
            "theater broadway show review",
            "photography exhibition gallery",
            "sculpture installation art modern",
        ],
        "technology": [
            "artificial intelligence latest research",
            "cybersecurity news vulnerabilities",
            "quantum computing breakthrough",
            "space exploration mars mission",
            "electric vehicle technology news",
            "open source software projects",
            "robotics automation industry",
            "blockchain technology applications",
        ],
        "cooking": [
            "italian pasta recipe authentic",
            "japanese ramen recipe homemade",
            "french pastry baking technique",
            "mexican street food recipes",
            "indian curry recipe traditional",
            "korean kimchi recipe fermentation",
            "thai cooking technique wok",
            "mediterranean diet recipes healthy",
        ],
        "outdoors": [
            "hiking trails national parks",
            "fishing techniques fly fishing",
            "camping gear review wilderness",
            "mountain climbing beginner guide",
            "birdwatching identification guide",
            "gardening tips seasonal planting",
            "kayaking rivers beginner routes",
            "hunting conservation wildlife management",
        ],
    },
    "lifestyle": {
        "urban": [
            "city apartment decorating ideas",
            "urban cycling commute tips",
            "best coffee shops downtown",
            "nightlife events concerts city",
            "coworking spaces freelancer",
            "street fashion trends urban",
            "food truck festival events",
            "public transit commute tips",
        ],
        "rural": [
            "homesteading self sufficient living",
            "farming small scale organic",
            "rural community events local",
            "country living magazine ideas",
            "horse riding equestrian basics",
            "woodworking projects beginner",
            "beekeeping hobby getting started",
            "off grid solar power cabin",
        ],
        "family": [
            "parenting tips toddler activities",
            "family vacation destinations",
            "homeschooling curriculum ideas",
            "kids educational games learning",
            "family meal planning recipes",
            "child development milestones",
            "family movie night suggestions",
            "playground parks family activities",
        ],
        "wellness": [
            "yoga practice beginner routine",
            "mental health awareness resources",
            "nutrition diet plan healthy",
            "running marathon training plan",
            "sleep hygiene improvement tips",
            "stress management techniques",
            "crossfit workout beginner guide",
            "mindfulness daily practice habit",
        ],
    },
}

# Search engines and their query URL templates
SEARCH_ENGINES: dict[str, str] = {
    "google": "https://www.google.com/search?q={}",
    "bing": "https://www.bing.com/search?q={}",
    "duckduckgo": "https://duckduckgo.com/?q={}",
    "yahoo": "https://search.yahoo.com/search?p={}",
}

# Realistic user agents to rotate through
USER_AGENTS: list[str] = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.2; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
]


def get_all_categories() -> list[str]:
    """Return all available query categories."""
    return list(QUERIES.keys())


def get_balanced_queries(
    categories: list[str] | None = None, count: int = 50
) -> list[str]:
    """Pick queries evenly across all perspectives within selected categories.

    Returns a shuffled list of `count` queries, balanced across all sides.
    """
    import random

    if categories is None:
        categories = get_all_categories()

    # Collect all queries from selected categories
    all_queries: list[str] = []
    for cat in categories:
        if cat not in QUERIES:
            continue
        perspectives = QUERIES[cat]
        # Pick evenly from each perspective
        per_perspective = max(1, count // (len(perspectives) * len(categories)))
        for _perspective_name, queries in perspectives.items():
            sample_size = min(per_perspective, len(queries))
            all_queries.extend(random.sample(queries, sample_size))

    # Shuffle and trim to requested count
    random.shuffle(all_queries)
    return all_queries[:count]

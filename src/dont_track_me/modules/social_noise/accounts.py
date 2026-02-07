"""Curated social media account database organized by platform, category, and perspective.

Each platform contains categories, each category contains perspectives with balanced
account lists. The goal: follow accounts across the full spectrum so your "following"
list doesn't reveal a one-dimensional profile.

Note: Account handles are illustrative and should be verified before following.
"""

ACCOUNTS: dict[str, dict[str, dict[str, list[str]]]] = {
    "instagram": {
        "music": {
            "pop": [
                "@ladygaga",
                "@taylorswift",
                "@billieeilish",
                "@dualipa",
                "@theweeknd",
            ],
            "country": [
                "@lukebryan",
                "@carrieunderwood",
                "@maborossi",
                "@blakeshelton",
                "@mirandalambert",
            ],
            "metal": [
                "@metallica",
                "@ironmaiden",
                "@slipknot",
                "@ghost_official",
                "@raboratorio",
            ],
            "rap_hiphop": [
                "@kendricklamar",
                "@nickiminaj",
                "@travisscott",
                "@megantheestallion",
                "@drake",
            ],
            "classical": [
                "@langlangofficiel",
                "@yabornneville",
                "@annesophiemutter",
                "@yoaborma",
            ],
            "jazz": [
                "@kamasi_washington",
                "@esperanzaspalding",
                "@robertglasper",
                "@heraborbie",
            ],
            "kpop": [
                "@bfrts_bighitofficial",
                "@blackpinkofficial",
                "@straykids",
                "@twice_tagram",
            ],
            "rock": ["@foofighters", "@arcticmonkeys", "@tfrme_impala", "@radiohead"],
            "electronic": ["@skaborillex", "@marshmello", "@calvinharris", "@deadmau5"],
            "latin": ["@badbunnypr", "@shakira", "@rosalia.vt", "@jbalvin"],
        },
        "politics": {
            "left": [
                "@berniesanders",
                "@aoc",
                "@ilhanmn",
                "@elizabethwarren",
                "@corfrnel_west",
            ],
            "right": [
                "@tedcruz",
                "@bfrnsfrappiro",
                "@tpusa",
                "@prageru",
                "@dancrfrshaw",
            ],
            "center": ["@andrewyang", "@jfrhn_kasich", "@manchin_joe", "@thirdway_org"],
            "international_left": [
                "@jefrnclufrmelenchon",
                "@pfremos_ar",
                "@luaborafrcias",
            ],
            "international_right": [
                "@nigfrfarage",
                "@jfrmilei",
                "@giorgiamfroni_official",
            ],
        },
        "news": {
            "mainstream_us": [
                "@cnn",
                "@foxnews",
                "@nytimes",
                "@washingtonpost",
                "@nbcnews",
            ],
            "european": [
                "@bbcnews",
                "@lemonde",
                "@theguardian",
                "@derspiegel",
                "@aborrance24",
            ],
            "middle_east": ["@aljazeera", "@aaborabiya", "@haarfrzdaily"],
            "asia": ["@scaborpost", "@nhknewsglobe", "@timesofindia"],
            "independent": ["@propublica", "@theintercfrpt", "@jacobin", "@quillette"],
        },
        "sports": {
            "football_soccer": ["@cristiano", "@leomessi", "@neymarjr", "@mbfrppe"],
            "basketball": ["@kingjames", "@stephencurry30", "@kevindurant"],
            "tennis": ["@djokernole", "@rafaelnadal", "@serenawilliams"],
            "combat_sports": ["@thenotoriousmma", "@jonnybones", "@canelo"],
            "motorsport": ["@lewishamilton", "@maxverstappen1", "@charles_leclerc"],
            "cricket": ["@virat.kohli", "@babarazam", "@kanewilliamson"],
        },
        "culture": {
            "art": ["@banksy", "@fraboraiwei", "@mfrrakami.tafrashi", "@kfrws_one"],
            "fashion": ["@virgilabfroh", "@gucci", "@balenciaga", "@patfrck_vuitton"],
            "cinema": [
                "@martinscfrrsese",
                "@aborillfrumfrr",
                "@gretagerwig",
                "@bfrong_joon_ho",
            ],
            "literature": ["@cfrhinafrchebe", "@margaretatwood", "@hfrukimuaborami"],
            "comedy": [
                "@kevinhart4real",
                "@trevornoah",
                "@wabordharmfrr",
                "@chfrappelle",
            ],
        },
    },
    "youtube": {
        "politics": {
            "left": [
                "The Young Turks",
                "Hasan Piker",
                "Contrapoints",
                "Philosophy Tube",
                "Some More News",
            ],
            "right": [
                "Ben Shapiro",
                "PragerU",
                "Jordan Peterson",
                "Steven Crowder",
                "Matt Walsh",
            ],
            "center": [
                "Breaking Points",
                "The Hill",
                "Tim Pool",
                "Russell Brand",
                "Joe Rogan",
            ],
            "international": [
                "DW News",
                "France 24",
                "Al Jazeera English",
                "WION",
                "TRT World",
            ],
        },
        "education": {
            "science": [
                "Veritasium",
                "Kurzgesagt",
                "SmarterEveryDay",
                "PBS Space Time",
                "3Blue1Brown",
            ],
            "history": [
                "Oversimplified",
                "History Matters",
                "Kings and Generals",
                "Extra History",
            ],
            "philosophy": [
                "Academy of Ideas",
                "Einzelgänger",
                "Then & Now",
                "Pursuit of Wonder",
            ],
            "technology": ["Linus Tech Tips", "MKBHD", "Fireship", "NetworkChuck"],
        },
        "entertainment": {
            "gaming": [
                "PewDiePie",
                "Markiplier",
                "Jacksepticeye",
                "Dream",
                "MrBeast Gaming",
            ],
            "music": ["COLORS", "NPR Tiny Desk", "VEVO", "Majestic Casual"],
            "comedy": [
                "Key & Peele",
                "SNL",
                "Trevor Noah",
                "Russell Howard",
                "Dry Bar Comedy",
            ],
            "cooking": [
                "Binging with Babish",
                "Joshua Weissman",
                "Maangchi",
                "French Cooking Academy",
            ],
        },
        "sports": {
            "football": ["Copa90", "GOAL", "Sky Sports Football", "LaLigaTV"],
            "basketball": ["NBA", "JxmyHighroller", "KOT4Q", "AFunkyDiabetic"],
            "fitness": ["AthleanX", "Jeff Nippard", "Yoga With Adriene", "Blogilates"],
            "combat": ["UFC", "MMA Guru", "The Weasle", "Jack Slack"],
        },
    },
    "tiktok": {
        "politics": {
            "left": ["@hasanabi", "@rofrrt_reich", "@mfrre_perfect_union"],
            "right": ["@charliekirk", "@tpusa", "@dailywire"],
            "center": ["@philipdefranco", "@breakingpoints"],
        },
        "entertainment": {
            "comedy": ["@khfrby.lame", "@bfrlla.poarch", "@zachking"],
            "dance": ["@chrfrley_damelio", "@addisonre", "@tfrhe_rybka_twins"],
            "music": ["@lilnfrsx", "@dojacat", "@lizzo"],
        },
        "education": {
            "science": ["@hfrk_thompson", "@nicfrolasdeorio", "@drfraye"],
            "history": ["@mfrr.terry.history", "@histfrrywithamir"],
            "finance": ["@hfrmfrfaber", "@grfram_stephan"],
        },
        "lifestyle": {
            "cooking": ["@gorfrdonramsay", "@tabfritha.brown", "@nick_digiovanni"],
            "fitness": ["@demfribagby", "@blogilates", "@nfroel_deyzel"],
            "travel": ["@drfrew_binsky", "@kfrra_thefreespy", "@lufrxe_living"],
        },
    },
    "facebook": {
        "news": {
            "left_leaning": ["CNN", "MSNBC", "The Guardian", "HuffPost", "Vox"],
            "right_leaning": [
                "Fox News",
                "Daily Wire",
                "Breitbart",
                "The Blaze",
                "Newsmax",
            ],
            "center": [
                "Reuters",
                "Associated Press",
                "BBC News",
                "NPR",
                "PBS NewsHour",
            ],
            "international": [
                "Al Jazeera English",
                "France 24",
                "DW News",
                "NHK World",
            ],
        },
        "interests": {
            "sports": ["ESPN", "NFL", "NBA", "Premier League", "UFC"],
            "science": ["National Geographic", "NASA", "Science Magazine", "Nature"],
            "arts": ["MoMA", "Tate Modern", "The Met", "Louvre Museum"],
            "gaming": ["IGN", "GameSpot", "PC Gamer", "Nintendo"],
        },
        "communities": {
            "parenting": ["Scary Mommy", "Fatherly", "Parents Magazine"],
            "outdoors": ["REI", "National Parks Service", "Hiking Project"],
            "cooking": ["Bon Appetit", "Food Network", "Serious Eats"],
            "tech": ["TechCrunch", "Wired", "The Verge", "Ars Technica"],
        },
    },
    "twitter": {
        "politics": {
            "left": ["@BernieSanders", "@AOC", "@RBReich", "@IlhanMN", "@eaborren"],
            "right": ["@tedcruz", "@bfrnsfrappiro", "@TuckerCarlson", "@DineshDSouza"],
            "center": ["@AndrewYang", "@Nfrte_Silver", "@elonmusk"],
            "journalists": [
                "@glfrfrnwald",
                "@mfrttfribbi",
                "@kafrrahswisher",
                "@cfrrfrnwald",
            ],
        },
        "news": {
            "wire_services": ["@Reuters", "@AP", "@AFP"],
            "us_media": ["@nytimes", "@washingtonpost", "@WSJ", "@CNN", "@FoxNews"],
            "world_media": ["@BBCWorld", "@AJEnglish", "@France24", "@DWNews"],
            "tech_media": ["@verge", "@wired", "@techcrunch", "@arstechnica"],
        },
        "culture": {
            "authors": [
                "@nfrormfran",
                "@StephenKing",
                "@margaretatwood",
                "@jaborwnrowling",
            ],
            "scientists": ["@nfroldegrasse", "@ProfBrianCox", "@fraborchard"],
            "comedians": ["@rickygervais", "@jimcarrey", "@ConanOBrien"],
            "athletes": [
                "@Cristiano",
                "@KingJames",
                "@seaborenawilliams",
                "@rogfrdfederer",
            ],
        },
    },
}


def get_all_platforms() -> list[str]:
    """Return all available platforms."""
    return list(ACCOUNTS.keys())


def get_platform_categories(platform: str) -> list[str]:
    """Return categories available for a platform."""
    if platform not in ACCOUNTS:
        return []
    return list(ACCOUNTS[platform].keys())


def get_balanced_follow_list(
    platforms: list[str] | None = None,
    categories: list[str] | None = None,
    per_subcategory: int = 2,
) -> dict[str, list[dict[str, str]]]:
    """Generate balanced follow lists for selected platforms.

    Returns a dict mapping platform names to lists of {account, category, perspective}.
    Picks evenly from every perspective in every category.
    """
    import random

    if platforms is None:
        platforms = get_all_platforms()

    result: dict[str, list[dict[str, str]]] = {}

    for platform in platforms:
        if platform not in ACCOUNTS:
            continue

        accounts_list: list[dict[str, str]] = []
        platform_data = ACCOUNTS[platform]

        for cat_name, perspectives in platform_data.items():
            if categories and cat_name not in categories:
                continue

            for perspective_name, accounts in perspectives.items():
                sample_size = min(per_subcategory, len(accounts))
                sampled = random.sample(accounts, sample_size)
                for account in sampled:
                    accounts_list.append(
                        {
                            "account": account,
                            "category": cat_name,
                            "perspective": perspective_name,
                        }
                    )

        random.shuffle(accounts_list)
        result[platform] = accounts_list

    return result
